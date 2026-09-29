#!/usr/bin/env python3
"""Bounded candidate for a Home-wide operation roster over runtime shards.

The Home's own journal names accepting operations and their runtime shard.
A pending entry precedes the shard write; a completed pointer follows it;
acknowledgment follows completion. A cut issuer reads the journal rather than
scanning currently visible files. This is a candidate, not a production schema.
"""

from collections import deque
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class State:
    home_revision: int = 0
    pending: bool = False
    journal: bool = False  # completed pointer to (chat-b, program-operation)
    shard_exists: bool = False
    stored: bool = False  # immutable operation and witness in chat-b.sqlite
    accepted: bool = False  # Home may expose the new program to work
    operation: str = "new"  # new, pending, stored, completed, accepted, crashed_*
    gate: str = "new"  # new, prepared, home, checked, ref, stale, committed
    basis: tuple[int, bool] | None = None
    home_owner: int = -1
    ref_owner: int = -1
    admission: tuple[int, bool, bool, bool, bool, bool, bool, bool] | None = None
    ref_up: bool = True
    outage_used: bool = False


def steps(s: State, defect: str = ""):
    # The first Home write durably registers an in-flight operation and its
    # target shard. A missing shard is a repair obligation, never absence.
    if s.operation == "new" and s.home_owner == -1:
        if defect == "scan_only":
            yield "unregistered shard accepts", replace(
                s, shard_exists=True, stored=True, accepted=True,
                operation="accepted")
        else:
            yield "register pending", replace(
                s, home_revision=s.home_revision + (defect != "omit_pending"),
                pending=defect != "omit_pending", operation="pending")
    if s.operation == "pending":
        yield "crash before shard write", replace(s, operation="crashed_pending")
    if s.operation in ("pending", "crashed_pending"):
        yield "write shard operation", replace(
            s, shard_exists=True, stored=True, operation="stored")
    if s.operation == "stored":
        yield "crash after shard write", replace(s, operation="crashed_stored")
        if defect == "early_ack":
            yield "ack before Home completion", replace(
                s, accepted=True, operation="accepted")
    if s.operation in ("stored", "crashed_stored") and s.home_owner == -1:
        yield "complete Home pointer", replace(
            s, home_revision=s.home_revision + 1, pending=False,
            journal=True, operation="completed")
    if s.operation == "completed":
        yield "ack", replace(s, accepted=True, operation="accepted")

    if s.gate == "new" and (not s.pending or defect == "ignore_pending"):
        # The issuer verifies every completed pointer resolves to a stored
        # immutable operation. The Home identity is a host capability input.
        if not s.journal or (s.shard_exists and s.stored):
            yield "capture Home roster", replace(
                s, gate="prepared", basis=(s.home_revision, s.journal))
    if s.gate == "prepared" and s.home_owner == -1:
        yield "take Home exclusion", replace(s, gate="home", home_owner=0)
    if s.gate == "home":
        if ((s.home_revision, s.journal) == s.basis or defect == "trust_precheck") and (
                not s.pending or defect == "ignore_pending"):
            yield "recheck", replace(s, gate="checked")
        else:
            yield "stale", replace(s, gate="stale", home_owner=-1)
    if s.gate == "checked" and s.ref_up and s.ref_owner == -1:
        yield "take ref", replace(
            s, gate="ref", ref_owner=0,
            home_owner=(-1 if defect == "release_home" else s.home_owner))
    if s.gate == "ref" and s.ref_up:
        yield "cas", replace(
            s, gate="committed",
            admission=(s.home_revision, s.pending, s.journal,
                       s.stored, s.accepted,
                       s.operation in ("pending", "stored", "crashed_pending", "crashed_stored"),
                       s.home_owner == 0,
                       s.ref_owner == 0),
            home_owner=-1, ref_owner=-1)
    if not s.outage_used and s.ref_up and s.ref_owner == -1:
        yield "ref outage", replace(s, ref_up=False, outage_used=True)
    if not s.ref_up:
        yield "ref restored", replace(s, ref_up=True)
        if s.gate in ("home", "checked"):
            yield "abort on outage", replace(s, gate="stale", home_owner=-1)


def violation(s: State):
    if s.accepted and not s.journal:
        return "usable program omitted from Home operation roster"
    if s.journal and not s.stored:
        return "Home pointer lacks the runtime operation"
    if s.gate == "stale" and (s.home_owner == 0 or s.ref_owner == 0):
        return "aborted gate stranded exclusion"
    if s.admission:
        revision, pending, journal, stored, accepted, inflight, home_locked, ref_locked = s.admission
        if pending or inflight:
            return "gate certified a pending cross-store admission"
        if (accepted and not journal) or (journal and not stored):
            return "gate certified an incomplete accepting population"
        if (revision, journal) != s.basis:
            return "gate trusted a stale Home roster"
        if not home_locked or not ref_locked:
            return "gate released exclusion before ref CAS"
    return None


def explore(defect="", depth=10):
    start = State()
    queue = deque([(start, ())])
    seen = {start}
    while queue:
        state, trace = queue.popleft()
        error = violation(state)
        if error:
            return len(seen), error, trace
        if len(trace) >= depth:
            continue
        for event, after in steps(state, defect):
            if after not in seen:
                seen.add(after)
                queue.append((after, trace + (event,)))
    return len(seen), None, ()


def scenario(events, defect=""):
    state = State()
    for wanted in events:
        matches = [after for event, after in steps(state, defect) if event == wanted]
        assert len(matches) == 1, (wanted, state)
        state = matches[0]
    return state


def main():
    complete = scenario(("register pending", "write shard operation",
                         "complete Home pointer", "ack", "capture Home roster",
                         "take Home exclusion", "recheck", "take ref", "cas"))
    assert complete.admission and violation(complete) is None
    for crashed in ("crash before shard write", "crash after shard write"):
        prefix = (("register pending",) if crashed == "crash before shard write"
                  else ("register pending", "write shard operation"))
        pending = scenario(prefix + (crashed,))
        assert pending.pending and "capture Home roster" not in {
            event for event, _ in steps(pending)}
    recovered = scenario(("register pending", "write shard operation",
                          "crash after shard write", "complete Home pointer", "ack",
                          "capture Home roster", "take Home exclusion", "recheck",
                          "take ref", "cas"))
    assert recovered.admission and violation(recovered) is None
    stale = scenario(("capture Home roster", "register pending",
                      "take Home exclusion", "stale"))
    assert stale.gate == "stale" and violation(stale) is None
    missed_shard = scenario(("capture Home roster", "unregistered shard accepts",
                             "take Home exclusion", "recheck", "take ref", "cas"),
                            "scan_only")
    assert violation(missed_shard) == "usable program omitted from Home operation roster"
    outage = scenario(("capture Home roster", "take Home exclusion", "recheck",
                       "ref outage", "abort on outage", "register pending"))
    assert outage.pending and violation(outage) is None

    count, error, _ = explore()
    assert error is None, error
    print(f"Home operation roster: {count} safe states through ten transitions")
    for defect in ("scan_only", "omit_pending", "ignore_pending", "early_ack",
                   "trust_precheck", "release_home"):
        count, error, trace = explore(defect)
        assert error is not None, (defect, count)
        print(f"  {defect}: {error} via {' -> '.join(trace)}")


if __name__ == "__main__":
    main()
