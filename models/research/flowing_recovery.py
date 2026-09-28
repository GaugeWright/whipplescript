#!/usr/bin/env python3
"""Bounded ref-CAS-to-frontier probe for a flowing branch or direct twig.

Run: python3 models/research/flowing_recovery.py

This is an executable design model, not a store implementation. It composes
the norm-ledger exclusion, ref-owned policy, two coordinator identities,
source-unit accounting, and content-neutral admission in one state. The
separate lifecycle and reference-coverage probes retain their own limits.
"""

from collections import deque
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class Attempt:
    op: int
    actor: int
    selected: tuple[str, ...]
    source_cut: int
    base_version: int
    base_content: int
    epoch: int
    owner_fence: int
    norm_revision: int
    principal: str = "original"
    intent: str = "declared contribution"
    door: str = "scheduled"  # manual has exactly the same admission guards
    gate: str = "waiting"


@dataclass(frozen=True)
class Admission:
    op: int
    selected: tuple[str, ...]
    accounted: tuple[str, ...]
    output_id: str
    before_version: int
    after_version: int
    before_content: int
    after_content: int
    outcomes: tuple[tuple[str, str], ...]
    source_cut: int
    epoch: int
    owner_fence: int
    norm_revision: int
    submitted_norm_revision: int
    ledger_held: bool
    principal: str
    gate: str
    held: bool
    enabled: bool


@dataclass(frozen=True)
class State:
    kind: str = "branch"  # branch or a one-member direct twig
    holders: tuple[str, str] = ("branch", "branch")
    source_cut: int = 0
    epoch: int = 0
    held: bool = False
    enabled: bool = True
    owner: int = 0
    owner_fence: int = 0
    norm_revision: int = 0
    original_grant: bool = True
    ledger_owner: int = -1
    validated_revision: int = -1
    validated_grant: bool = False
    ref_up: bool = True
    norm_up: bool = True
    topology_up: bool = True
    actor0_up: bool = True
    trunk_version: int = 0
    trunk_content: int = 0
    attempts: tuple[Attempt, ...] = ()
    admissions: tuple[Admission, ...] = ()
    op_registry: tuple[Attempt, ...] = ()
    next_op: int = 1


def initial(kind: str = "branch") -> State:
    if kind == "twig":
        return State(kind="twig", holders=("twig", "none"))
    return State()


def accounted_ids(s: State) -> frozenset[str]:
    # This is the durable ref entry, not a lagging branch-frontier projection.
    return frozenset(unit for entry in s.admissions for unit in entry.accounted)


def selected_units(s: State, defect: str = "") -> tuple[str, ...]:
    accounted = frozenset() if defect == "frontier_only" else accounted_ids(s)
    ready = ("a",) if s.kind == "twig" else ("a", "b")
    return tuple(unit for unit in ready
                 if s.holders[("a", "b").index(unit)] == s.kind
                 and unit not in accounted)


def submit(s: State, actor: int, selected: tuple[str, ...] | None = None,
           door: str = "scheduled", defect: str = "") -> State:
    if actor != s.owner or (actor == 0 and not s.actor0_up) or not s.ref_up:
        raise ValueError("only the current coordinator can submit")
    if s.held or not s.enabled:
        raise ValueError("source is ineligible")
    available = selected_units(s, defect)
    selected = available if selected is None else selected
    if not selected or any(unit not in available for unit in selected):
        raise ValueError("selection is not ready and unaccounted")
    if "b" in selected and "a" not in selected and "a" not in accounted_ids(s):
        raise ValueError("dependent unit lacks its predecessor")
    op = s.next_op
    if defect == "reuse_op" and s.op_registry:
        op = s.op_registry[0].op
    attempt = Attempt(op, actor, selected, s.source_cut, s.trunk_version,
                      s.trunk_content, s.epoch, s.owner_fence,
                      s.norm_revision, door=door)
    if any(old.op == op and old != attempt for old in s.op_registry):
        if defect != "reuse_op":
            raise ValueError("operation id already binds a different candidate")
    return replace(s, attempts=s.attempts + (attempt,),
                   op_registry=s.op_registry + (attempt,),
                   next_op=s.next_op + (defect != "reuse_op"))


def attempt_at(s: State, op: int) -> Attempt:
    return next(attempt for attempt in s.attempts if attempt.op == op)


def gate(s: State, op: int, verdict: str) -> State:
    if verdict not in ("passed", "failed", "unrun"):
        raise ValueError("unknown gate verdict")
    old = attempt_at(s, op)
    if old.gate != "waiting":
        raise ValueError("attempt already answered")
    return replace(s, attempts=tuple(replace(a, gate=verdict) if a == old else a
                                     for a in s.attempts))


def lock_ledger(s: State, actor: int) -> State:
    if not s.norm_up or s.ledger_owner != -1 or actor != s.owner:
        raise ValueError("ledger exclusion unavailable")
    if not s.original_grant:
        raise ValueError("original declaring principal lost its grant")
    return replace(s, ledger_owner=actor, validated_revision=s.norm_revision,
                   validated_grant=s.original_grant)


def unlock_ledger(s: State, actor: int) -> State:
    if s.ledger_owner != actor:
        raise ValueError("not the ledger holder")
    return replace(s, ledger_owner=-1)


def norm_revoke(s: State) -> State:
    if not s.norm_up or s.ledger_owner != -1:
        raise ValueError("norm ledger write waits for its exclusion")
    return replace(s, norm_revision=s.norm_revision + 1,
                   original_grant=False)


def hold(s: State) -> State:
    if not s.ref_up:
        raise ValueError("Hold cannot be acknowledged without ref authority")
    return replace(s, held=True, epoch=s.epoch + 1)


def release_hold(s: State) -> State:
    if not s.ref_up or not s.held:
        raise ValueError("no acknowledged Hold to release")
    return replace(s, held=False, epoch=s.epoch + 1)


def takeover(s: State) -> State:
    if not s.ref_up or s.owner != 0:
        raise ValueError("takeover unavailable")
    return replace(s, owner=1, owner_fence=s.owner_fence + 1)


def rewrite_source(s: State) -> State:
    # A rebase changes the exact cut, but preserves source-unit identities.
    # It fences a certificate prepared at the prior cut.
    if not s.ref_up:
        raise ValueError("source mutation cannot acknowledge without fence")
    return replace(s, source_cut=s.source_cut + 1, epoch=s.epoch + 1)


def content_after(before: int, selected: tuple[str, ...]) -> int:
    return before + ("a" in selected) - ("b" in selected)


def cas(s: State, op: int, actor: int, defect: str = "") -> State:
    a = attempt_at(s, op)
    after = content_after(s.trunk_content, a.selected)
    noop = after == s.trunk_content
    if a.gate != "passed" and not (defect == "noop_without_gate" and noop):
        raise ValueError("every admission, including a no-op, needs a passed gate")
    if not s.ref_up or not s.enabled:
        raise ValueError("ref authority is unavailable or disabled")
    if (s.held or a.epoch != s.epoch) and not (defect == "manual_bypasses_hold"
                                                and a.door == "manual"):
        raise ValueError("Hold or source epoch fenced the candidate")
    if a.source_cut != s.source_cut:
        raise ValueError("source cut moved")
    if a.base_version != s.trunk_version or a.base_content != s.trunk_content:
        raise ValueError("trunk basis moved")
    if actor != s.owner or a.owner_fence != s.owner_fence:
        raise ValueError("former coordinator is fenced")
    if a.actor != actor:
        raise ValueError("attempt belongs to another coordinator")
    if s.ledger_owner != actor and defect != "cas_after_ledger_release":
        raise ValueError("norm ledger exclusion must remain held through CAS")
    if (not s.validated_grant or s.validated_revision != a.norm_revision
            or (s.norm_revision != a.norm_revision and
                defect != "cas_after_ledger_release")):
        raise ValueError("current norm premises do not match certificate")
    if not all(s.holders[("a", "b").index(unit)] == s.kind
               for unit in a.selected):
        raise ValueError("selected unit is not held by its source")
    if (any(unit in accounted_ids(s) for unit in a.selected)
            and defect != "frontier_only"):
        raise ValueError("source identity already has a durable receipt")
    if any(entry.op == op for entry in s.admissions):
        raise ValueError("operation already admitted")
    outcomes = tuple((unit, "neutralized" if noop else "applied")
                     for unit in a.selected)
    output = a.selected[0] if len(a.selected) == 1 else f"bundle:{op}"
    entry = Admission(op, a.selected,
                      (output,) if defect == "output_only" else a.selected,
                      output, s.trunk_version, s.trunk_version + 1,
                      s.trunk_content, after, outcomes, a.source_cut,
                      s.epoch, s.owner_fence, s.norm_revision,
                      a.norm_revision, s.ledger_owner == actor, a.principal,
                      a.gate, s.held, s.enabled)
    return replace(s, trunk_content=after, trunk_version=s.trunk_version + 1,
                   admissions=s.admissions + (entry,))


def recover(s: State, op: int) -> State:
    if not s.ref_up or not s.topology_up:
        raise ValueError("recovery is indeterminate until both stores answer")
    entry = next((entry for entry in s.admissions if entry.op == op), None)
    if entry is None:
        raise ValueError("no durable ref entry proves admission")
    holders = list(s.holders)
    for unit in entry.selected:
        holders[("a", "b").index(unit)] = "accounted"
    return replace(s, holders=tuple(holders))


def violation(s: State) -> str | None:
    if any(holder == "lost" for holder in s.holders):
        return "declared work was lost"
    registered: dict[int, Attempt] = {}
    for attempt in s.op_registry:
        if attempt.op in registered and registered[attempt.op] != attempt:
            return "one operation id was rebound to another candidate"
        registered[attempt.op] = attempt
    seen: set[str] = set()
    before_version = before_content = 0
    for entry in s.admissions:
        if entry.selected != entry.accounted:
            return "mixed output identity replaced selected source identities"
        if seen.intersection(entry.accounted):
            return "one source identity received two admission receipts"
        seen.update(entry.accounted)
        if (entry.gate != "passed" or entry.held or not entry.enabled):
            return "admission lacked a passed gate or current source policy"
        if (entry.norm_revision != entry.submitted_norm_revision
                or not entry.ledger_held):
            return "admission escaped the current norm ledger exclusion"
        if entry.before_version != before_version or entry.before_content != before_content:
            return "admission did not compare the exact trunk basis"
        if entry.after_version != entry.before_version + 1:
            return "metadata-only admission did not advance ref history"
        if entry.after_content != content_after(entry.before_content, entry.selected):
            return "admission content does not match selected source units"
        if entry.principal != "original":
            return "coordinator substituted the declaring principal"
        before_version, before_content = entry.after_version, entry.after_content
    if (s.trunk_version, s.trunk_content) != (before_version, before_content):
        return "trunk ref and durable admission history disagree"
    for unit, holder in zip(("a", "b"), s.holders):
        if holder == "accounted" and unit not in seen:
            return "frontier advanced without a durable source receipt"
    return None


def scenario() -> None:
    # Two coordinators can observe one unit set. A crash after CAS leaves a
    # durable ref entry even if the source-frontier projection still lags.
    s = initial()
    s = submit(s, 0)
    s = gate(s, 1, "passed")
    s = lock_ledger(s, 0)
    s = cas(s, 1, 0)
    assert s.trunk_content == 0 and s.trunk_version == 1
    assert s.admissions[0].output_id == "bundle:1"
    assert s.admissions[0].accounted == ("a", "b")
    s = replace(s, ledger_owner=-1, actor0_up=False)  # crash before frontier
    s = takeover(s)
    assert selected_units(s) == ()  # the ref entry excludes duplicate work
    try:
        submit(s, 1, ("a", "b"))
    except ValueError as error:
        assert "unaccounted" in str(error)
    else:
        raise AssertionError("replacement coordinator reselected admitted units")
    s = recover(s, 1)
    assert s.holders == ("accounted", "accounted")
    s = rewrite_source(s)
    assert selected_units(s) == ()  # cut rewrite cannot replay source units
    assert violation(s) is None

    # A direct twig is a one-member source, subject to the same gate and CAS.
    twig = initial("twig")
    twig = submit(twig, 0, ("a",))
    twig = gate(twig, 1, "passed")
    twig = lock_ledger(twig, 0)
    twig = recover(cas(twig, 1, 0), 1)
    assert twig.trunk_content == 1 and twig.holders[0] == "accounted"

    # A failed or unrun gate cannot consume the units, including a net-zero
    # candidate. Queue cancellation has no work-disposition authority.
    for verdict in ("failed", "unrun"):
        pending = gate(submit(initial(), 0), 1, verdict)
        pending = lock_ledger(pending, 0)
        try:
            cas(pending, 1, 0)
        except ValueError as error:
            assert "passed gate" in str(error)
        else:
            raise AssertionError("metadata-only admission bypassed gate")
        assert pending.holders == ("branch", "branch")

    # Hold, cut rewrite, norm revocation, and owner takeover each fence an
    # already passed candidate, independent of its content result.
    for name, change in (("Hold", hold), ("rewrite", rewrite_source),
                         ("takeover", takeover)):
        pending = lock_ledger(gate(submit(initial(), 0), 1, "passed"), 0)
        pending = change(pending)
        try:
            cas(pending, 1, 0)
        except ValueError:
            pass
        else:
            raise AssertionError(f"{name} failed to fence the candidate")
    revoked = gate(submit(initial(), 0), 1, "passed")
    revoked = norm_revoke(revoked)
    try:
        lock_ledger(revoked, 0)
    except ValueError:
        pass
    else:
        raise AssertionError("revoked original principal was revalidated")

    # A ref outage after an accepted CAS is not evidence to retry the effect.
    uncertain = cas(lock_ledger(gate(submit(initial(), 0), 1, "passed"), 0), 1, 0)
    uncertain = replace(uncertain, ref_up=False, ledger_owner=-1)
    try:
        recover(uncertain, 1)
    except ValueError as error:
        assert "indeterminate" in str(error)
    else:
        raise AssertionError("ref outage was called an absent admission")
    assert recover(replace(uncertain, ref_up=True), 1).holders == (
        "accounted", "accounted")

    # Independent authority outages leave submitted work in place. A failed
    # norm read cannot be treated as a grant; a failed topology projection
    # cannot be treated as proof that the ref entry was absent.
    pending = gate(submit(initial(), 0), 1, "passed")
    try:
        lock_ledger(replace(pending, norm_up=False), 0)
    except ValueError as error:
        assert "unavailable" in str(error)
    else:
        raise AssertionError("norm outage became admission authority")
    durable = cas(lock_ledger(pending, 0), 1, 0)
    try:
        recover(replace(durable, topology_up=False), 1)
    except ValueError as error:
        assert "indeterminate" in str(error)
    else:
        raise AssertionError("topology outage erased durable accounting")
    assert violation(durable) is None


def mutant_scenarios() -> None:
    # Each mutation must make its forbidden history reachable; it is not a
    # useful model check if all variants say green.
    wrong = cas(lock_ledger(gate(submit(initial(), 0), 1, "passed"), 0), 1, 0,
                "output_only")
    assert violation(wrong) == "mixed output identity replaced selected source identities"

    no_gate = cas(lock_ledger(submit(initial(), 0), 0), 1, 0,
                  "noop_without_gate")
    assert violation(no_gate) == "admission lacked a passed gate or current source policy"

    held = lock_ledger(gate(submit(initial(), 0, door="manual"), 1, "passed"), 0)
    held = cas(hold(held), 1, 0, "manual_bypasses_hold")
    assert violation(held) == "admission lacked a passed gate or current source policy"

    stale = lock_ledger(gate(submit(initial(), 0), 1, "passed"), 0)
    stale = norm_revoke(unlock_ledger(stale, 0))
    stale = cas(stale, 1, 0, "cas_after_ledger_release")
    assert violation(stale) == "admission escaped the current norm ledger exclusion"

    duplicate = cas(lock_ledger(gate(submit(initial(), 0), 1, "passed"), 0), 1, 0)
    duplicate = replace(duplicate, ledger_owner=-1, actor0_up=False)
    duplicate = takeover(duplicate)
    duplicate = submit(duplicate, 1, defect="frontier_only")
    duplicate = gate(duplicate, 2, "passed")
    duplicate = lock_ledger(duplicate, 1)
    duplicate = cas(duplicate, 2, 1, "frontier_only")
    assert violation(duplicate) == "one source identity received two admission receipts"

    rebound = submit(initial(), 0)
    rebound = replace(rebound, source_cut=1, epoch=1)
    rebound = submit(rebound, 0, defect="reuse_op")
    assert violation(rebound) == "one operation id was rebound to another candidate"


def steps(s: State):
    """Small interleaving core; the scenarios above cover specialized edges."""
    if s.next_op <= 2 and selected_units(s) and s.ref_up and not s.held:
        for actor in (0, 1):
            try:
                yield f"submit{actor}", submit(s, actor)
            except ValueError:
                pass
    for a in s.attempts:
        if a.gate == "waiting":
            yield f"pass{a.op}", gate(s, a.op, "passed")
        if a.gate == "passed" and a.actor == s.owner:
            if s.ledger_owner == -1:
                try:
                    yield f"lock{a.actor}", lock_ledger(s, a.actor)
                except ValueError:
                    pass
            if s.ledger_owner == a.actor:
                try:
                    yield f"cas{a.op}", cas(s, a.op, a.actor)
                except ValueError:
                    pass
        if any(entry.op == a.op for entry in s.admissions):
            try:
                yield f"recover{a.op}", recover(s, a.op)
            except ValueError:
                pass
    if s.ledger_owner != -1:
        yield "unlock", unlock_ledger(s, s.ledger_owner)
    if not s.held:
        yield "hold", hold(s)
    if s.owner == 0:
        yield "takeover", takeover(s)
    if s.epoch == 0:
        yield "rewrite", rewrite_source(s)


def explore(depth: int = 9) -> int:
    start = initial()
    queue = deque([(start, 0)])
    visited = {start}
    while queue:
        state, steps_taken = queue.popleft()
        assert violation(state) is None, (state, violation(state))
        if steps_taken >= depth:
            continue
        for _, successor in steps(state):
            if successor not in visited:
                visited.add(successor)
                queue.append((successor, steps_taken + 1))
    return len(visited)


def main() -> None:
    scenario()
    mutant_scenarios()
    count = explore()
    print(f"flowing recovery: {count} safe states through nine transitions")
    print("direct twig, no-op, competing coordinators, recovery, and six mutants passed")


if __name__ == "__main__":
    main()
