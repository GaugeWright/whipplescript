#!/usr/bin/env python3
"""Bounded safety probe for sealing a Home cut while admissions continue.

An operation is usable only when its Home pointer completes. Sealing freezes
the accepted set in epoch zero. An unfinished registration retains that epoch
in its row, so completion can discover lazily that it must move to epoch one
and revalidate. The gate certifies the frozen cut without demanding that the
later journal revision stop changing.

This is a candidate transition shape, not a Home or ref implementation.
"""

from collections import deque
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class Operation:
    phase: str = "absent"  # absent, pending, stored, accepted
    epoch: int = -1
    registered_epoch: int = -1
    registered: bool = False
    rechecked: bool = False


@dataclass(frozen=True)
class State:
    operations: tuple[Operation, Operation] = (Operation(), Operation())
    epoch: int = 0
    sealed: bool = False
    cut: frozenset[int] = frozenset()
    current: frozenset[int] = frozenset()
    next_epoch: frozenset[int] = frozenset()
    gate: str = "new"  # new, checked, ref, committed, stale
    base: int = 0
    checked_base: int = -1
    old_pin: bool = False
    pin_obligation: bool = False


def with_operation(s: State, index: int, op: Operation, **changes):
    operations = list(s.operations)
    operations[index] = op
    return replace(s, operations=tuple(operations), **changes)


def steps(s: State, defect: str = ""):
    for index, op in enumerate(s.operations):
        if op.phase == "absent" and not op.registered:
            yield f"register {index}", with_operation(
                s, index, Operation("pending", s.epoch, s.epoch, True))
        if op.phase == "pending":
            yield f"write shard {index}", with_operation(
                s, index, replace(op, phase="stored"))
        deferred = s.sealed and op.epoch == 0 and op.phase in ("pending", "stored")
        if op.phase == "stored" and deferred and not op.rechecked:
            yield f"recheck {index}", with_operation(
                s, index, replace(op, rechecked=True))
        if op.phase == "stored" and (not deferred or op.rechecked
                                      or defect == "skip_recheck"):
            complete_epoch = (0 if deferred and defect == "keep_old_epoch"
                              else 1 if deferred else op.epoch)
            lane = s.current if complete_epoch == 0 else s.next_epoch
            changed = {"current" if complete_epoch == 0 else "next_epoch": lane | {index}}
            yield f"complete {index}", with_operation(
                s, index, replace(op, phase="accepted", epoch=complete_epoch), **changed)

    if not s.sealed:
        operations = tuple(
            replace(op, phase="absent")
            if defect == "drop_pending" and op.phase in ("pending", "stored")
            else op for op in s.operations)
        cut = (frozenset() if defect == "omit_accepted" else s.current)
        yield "seal", replace(
            s, operations=operations, epoch=1, sealed=True, cut=cut)

    if s.sealed and not s.old_pin:
        yield "start old-version run", replace(
            s, old_pin=True, pin_obligation=(defect != "omit_pin"))
    if s.sealed and s.gate == "new":
        yield "check sealed cut", replace(s, gate="checked", checked_base=s.base)
    if s.gate == "checked":
        yield "take ref", replace(s, gate="ref")
    if s.gate == "ref":
        if s.checked_base == s.base or defect == "trust_old_base":
            yield "cas", replace(s, gate="committed")
        else:
            yield "stale", replace(s, gate="stale")
    if s.gate in ("checked", "ref") and s.base == 0:
        yield "external trunk advance", replace(s, base=1)


def violation(s: State):
    for index, op in enumerate(s.operations):
        if op.registered and op.phase == "absent":
            return "sealing dropped registered work"
        if (op.phase == "accepted" and op.registered_epoch == 0
                and op.epoch == 1 and not op.rechecked):
            return "deferred admission used an obsolete basis"
        if op.phase == "accepted" and op.epoch == 0 and index not in s.current:
            return "accepted old-epoch operation is absent from current"
        if op.phase == "accepted" and op.epoch == 1 and index not in s.next_epoch:
            return "accepted later operation is absent from its next epoch"
    if s.sealed and s.cut != s.current:
        return "later admission changed the sealed candidate"
    if s.old_pin and not s.pin_obligation:
        return "later old-version run lost its temporal obligation"
    if s.gate == "committed" and s.checked_base != s.base:
        return "gate committed against a changed trunk base"
    return None


def explore(defect="", depth=10):
    start = State()
    seen = {start}
    queue = deque([(start, ())])
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
        assert violation(state) is None, (wanted, state, violation(state))
    return state


def main():
    concurrent = scenario((
        "register 0", "write shard 0", "complete 0", "register 1", "seal",
        "check sealed cut", "write shard 1", "recheck 1", "complete 1",
        "take ref", "cas"))
    assert concurrent.cut == frozenset({0})
    assert concurrent.next_epoch == frozenset({1})
    assert concurrent.gate == "committed"
    older_run = scenario((
        "register 0", "write shard 0", "complete 0", "seal",
        "check sealed cut", "start old-version run", "take ref", "cas"))
    assert older_run.old_pin and older_run.pin_obligation
    pending_shard = scenario((
        "register 0", "write shard 0", "seal", "check sealed cut",
        "take ref", "cas", "recheck 0", "complete 0"))
    assert pending_shard.cut == frozenset() and pending_shard.next_epoch == frozenset({0})
    stale = scenario((
        "seal", "check sealed cut", "external trunk advance", "take ref", "stale"))
    assert stale.gate == "stale"

    count, error, _ = explore()
    assert error is None, error
    print(f"Home epoch cut: {count} safe states through ten transitions")
    for defect in ("drop_pending", "keep_old_epoch", "skip_recheck",
                   "omit_accepted", "omit_pin", "trust_old_base"):
        count, error, trace = explore(defect)
        assert error is not None, (defect, count)
        print(f"  {defect}: {error} via {' -> '.join(trace)}")


if __name__ == "__main__":
    main()
