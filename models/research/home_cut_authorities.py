#!/usr/bin/env python3
"""Bounded Home-cut protocol across a norm ledger, runtime roster and ref.

The native authorities are separate SQLite files. A linked operation writes a
pending marker with its first durable component and clears it only after the
second component lands. A gate prepares a pair of revisions, then takes norm,
runtime and ref exclusion in that order and compares both revisions and the
pending marker before CAS. Each step below is atomic within its one authority;
no model step is a cross-database transaction.
"""

from collections import deque
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class State:
    norm: int = 0
    runtime: int = 0
    pending: bool = False
    linked: str = "new"  # new, first, second, done, crashed_first, crashed_second
    gate: str = "new"  # new, prepared, norm, both, checked, ref, stale, committed
    basis: tuple[int, int] | None = None
    norm_owner: int = -1
    runtime_owner: int = -1
    ref_owner: int = -1
    other: str = "new"  # new, norm, runtime, both, done
    norm_write_used: bool = False
    runtime_write_used: bool = False
    ref_up: bool = True
    outage_used: bool = False
    admission: tuple[int, int, bool, str, bool, bool, bool] | None = None


def steps(s: State, defect: str = ""):
    # A linked operation writes its durable marker in the same norm transaction
    # as its first component. Its two files can fail independently.
    if s.linked == "new" and s.norm_owner == -1:
        yield "linked first component", replace(
            s, norm=s.norm + 1, pending=defect != "omit_pending", linked="first")
    if s.linked == "first":
        yield "linked crash after first", replace(s, linked="crashed_first")
    if s.linked in ("first", "crashed_first") and s.runtime_owner == -1:
        yield "linked second component", replace(s, runtime=s.runtime + 1, linked="second")
    if s.linked == "second":
        yield "linked crash after second", replace(s, linked="crashed_second")
    if s.linked in ("second", "crashed_second") and s.norm_owner == -1:
        yield "linked completion", replace(s, norm=s.norm + 1,
                                           pending=False, linked="done")

    if not s.norm_write_used and s.norm_owner == -1:
        yield "independent norm append", replace(
            s, norm=s.norm + 1, norm_write_used=True)
    if not s.runtime_write_used and s.runtime_owner == -1:
        yield "independent runtime admission", replace(
            s, runtime=s.runtime + 1, runtime_write_used=True)

    # Any other operation needing both native stores must take norm first.
    if s.other == "new":
        if defect == "reverse_order" and s.runtime_owner == -1:
            yield "other takes runtime first", replace(
                s, other="runtime", runtime_owner=1)
        elif defect != "reverse_order" and s.norm_owner == -1:
            yield "other takes norm", replace(s, other="norm", norm_owner=1)
    if s.other == "norm" and s.runtime_owner == -1:
        yield "other takes runtime", replace(s, other="both", runtime_owner=1)
    if s.other == "runtime" and s.norm_owner == -1:
        yield "other takes norm second", replace(s, other="both", norm_owner=1)
    if s.other == "both":
        yield "other finishes", replace(
            s, other="done", norm_owner=-1, runtime_owner=-1)

    if s.gate == "new" and (not s.pending or defect == "ignore_pending"):
        yield "prepare", replace(s, gate="prepared", basis=(s.norm, s.runtime))
    if s.gate == "prepared" and s.norm_owner == -1:
        yield "take norm", replace(s, gate="norm", norm_owner=0)
    if s.gate == "norm" and s.runtime_owner == -1:
        yield "take runtime", replace(s, gate="both", runtime_owner=0)
    if s.gate == "both":
        current = (s.norm, s.runtime)
        if (defect == "trust_precheck" or current == s.basis) and (
            not s.pending or defect == "ignore_pending"):
            yield "validate", replace(s, gate="checked")
        else:
            yield "stale", replace(s, gate="stale", norm_owner=-1,
                                   runtime_owner=-1)
    if s.gate == "checked" and s.ref_up and s.ref_owner == -1:
        yield "take ref", replace(s, gate="ref", ref_owner=0,
                                  norm_owner=(-1 if defect == "release_norm" else s.norm_owner),
                                  runtime_owner=(-1 if defect == "release_runtime" else s.runtime_owner))
    if s.gate == "ref" and s.ref_up:
        yield "cas", replace(s, gate="committed",
                             admission=(s.norm, s.runtime, s.pending, s.linked,
                                        s.norm_owner == 0, s.runtime_owner == 0,
                                        s.ref_owner == 0),
                             norm_owner=-1, runtime_owner=-1, ref_owner=-1)
    if not s.outage_used and s.ref_up and s.ref_owner == -1:
        yield "ref outage", replace(s, ref_up=False, outage_used=True)
    if not s.ref_up:
        yield "ref restored", replace(s, ref_up=True)
        if s.gate in ("norm", "both", "checked"):
            yield "abort on outage", replace(s, gate="stale", norm_owner=-1,
                                             runtime_owner=-1)


def violation(s: State):
    if (s.gate == "norm" and s.other == "runtime" and
            s.norm_owner == 0 and s.runtime_owner == 1):
        return "norm/runtime circular wait"
    if s.gate == "stale" and (s.norm_owner == 0 or s.runtime_owner == 0 or s.ref_owner == 0):
        return "aborted attempt stranded exclusion"
    if s.admission:
        norm, runtime, pending, linked, norm_locked, runtime_locked, ref_locked = s.admission
        if pending or linked in ("first", "crashed_first", "second", "crashed_second"):
            return "incomplete linked operation certified as a Home cut"
        if (norm, runtime) != s.basis:
            return "changed authority certified after preparation"
        if not (norm_locked and runtime_locked and ref_locked):
            return "CAS did not hold every authority's exclusion"
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
        for event, next_state in steps(state, defect):
            if next_state not in seen:
                seen.add(next_state)
                queue.append((next_state, trace + (event,)))
    return len(seen), None, ()


def scenario(events, defect=""):
    state = State()
    for wanted in events:
        matches = [after for event, after in steps(state, defect) if event == wanted]
        assert len(matches) == 1, (wanted, state)
        state = matches[0]
    return state


def main():
    admitted = scenario(("prepare", "take norm", "take runtime", "validate",
                         "take ref", "cas"))
    assert admitted.admission and violation(admitted) is None
    shared_order = scenario(("other takes norm", "other takes runtime",
                             "other finishes", "prepare", "take norm",
                             "take runtime", "validate", "take ref", "cas"))
    assert shared_order.admission and violation(shared_order) is None
    crashed = scenario(("linked first component", "linked crash after first"))
    assert crashed.pending and "prepare" not in {event for event, _ in steps(crashed)}
    recovered = scenario(("linked first component", "linked crash after first",
                          "linked second component", "linked completion", "prepare",
                          "take norm", "take runtime", "validate", "take ref", "cas"))
    assert recovered.admission and violation(recovered) is None
    unmarked_crash = scenario(("linked first component", "linked crash after first",
                               "prepare", "take norm", "take runtime", "validate",
                               "take ref", "cas"), "omit_pending")
    assert violation(unmarked_crash) == "incomplete linked operation certified as a Home cut"
    stale = scenario(("prepare", "linked first component", "take norm",
                      "take runtime", "stale"))
    assert stale.gate == "stale" and stale.pending
    interleaved = scenario(("prepare", "linked first component", "take norm",
                            "linked second component", "take runtime", "stale",
                            "linked completion"))
    assert interleaved.linked == "done" and violation(interleaved) is None
    outage = scenario(("prepare", "take norm", "take runtime", "ref outage",
                       "abort on outage", "independent norm append",
                       "independent runtime admission"))
    assert outage.gate == "stale" and violation(outage) is None

    count, error, _ = explore()
    assert error is None, error
    print(f"three-authority Home cut: {count} safe states through ten transitions")
    for defect in ("omit_pending", "ignore_pending", "trust_precheck",
                   "release_norm", "release_runtime", "reverse_order"):
        count, error, trace = explore(defect)
        assert error is not None, (defect, count)
        print(f"  {defect}: {error} via {' -> '.join(trace)}")
    for defect, writer in (("release_norm", "independent norm append"),
                           ("release_runtime", "independent runtime admission")):
        changed = scenario(("prepare", "take norm", "take runtime", "validate",
                            "take ref", writer, "cas"), defect)
        assert violation(changed) == "changed authority certified after preparation"


if __name__ == "__main__":
    main()
