#!/usr/bin/env python3
"""Bounded candidate for one item's exact Home pin across gate retries.

Two possible checked admissions compete for the same item. A completed Home
pointer permits one immutable item-to-operation pin before runtime arrival;
later resumes read that pin instead of inferring an operation from a version
row. A pre-journal item can only retain an explicit legacy-unknown pin. This
assumes a Home-controlled closure of the legacy-store population before the
modeled slice is certified. It does not prove GaugeDesk has wired its doors.
"""

from collections import deque
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class Operation:
    phase: str = "absent"  # absent, pending, stored, completed, refused
    registered_epoch: int = -1
    completed_epoch: int = -1
    rechecked: bool = False


@dataclass(frozen=True)
class State:
    ops: tuple[Operation, Operation] = (Operation(), Operation())
    epoch: int = 0
    sealed: bool = False
    cut: frozenset[int] = frozenset()
    pin: int = -1  # -1 none, 0/1 exact operation, 2 legacy-unknown
    first_pin: int = -1
    instance: int = -1  # 0/1 exact version, 2 pre-journal legacy version
    arrived: bool = False
    used: bool = False
    used_after_seal: bool = False
    legacy_unknown: bool = False
    retention_obligation: bool = False
    legacy_inventory_closed: bool = False
    slice_complete: bool = False


def changed(s: State, index: int, operation: Operation, **rest):
    ops = list(s.ops)
    ops[index] = operation
    return replace(s, ops=tuple(ops), **rest)


def steps(s: State, defect: str = ""):
    for index, op in enumerate(s.ops):
        if op.phase == "absent":
            yield f"register {index}", changed(
                s, index, Operation("pending", s.epoch))
        if op.phase == "pending":
            yield f"write {index}", changed(s, index, replace(op, phase="stored"))
        if op.phase == "stored":
            if s.epoch > op.registered_epoch and not op.rechecked:
                yield f"recheck {index}", changed(
                    s, index, replace(op, rechecked=True))
            if s.epoch == op.registered_epoch or op.rechecked:
                yield f"complete {index}", changed(
                    s, index, replace(op, phase="completed", completed_epoch=s.epoch))
            if defect == "complete_without_recheck" and s.epoch > op.registered_epoch:
                yield f"stale complete {index}", changed(
                    s, index, replace(op, phase="completed", completed_epoch=s.epoch))
        if op.phase in ("pending", "stored"):
            yield f"refuse {index}", changed(s, index, replace(op, phase="refused"))
        if op.phase == "completed" and s.pin == -1 and s.instance == -1:
            yield f"bind {index}", replace(
                s, pin=index, first_pin=index,
                retention_obligation=(s.sealed and op.completed_epoch == 0))
        if defect == "bind_refused" and op.phase == "refused" and s.pin == -1:
            yield f"bind refused {index}", replace(s, pin=index, first_pin=index)
        if defect == "replace_pin" and s.pin in (0, 1) and s.pin != index and op.phase == "completed":
            yield f"replace pin with {index}", replace(s, pin=index)

    if s.pin in (0, 1) and s.instance == -1:
        yield "create pinned instance", replace(s, instance=s.pin)
    if s.instance in (0, 1) and not s.arrived and s.pin == s.instance:
        yield "arrive on pinned instance", replace(s, arrived=True)
    if s.instance in (0, 1) and s.arrived and s.pin == s.instance:
        op = s.ops[s.pin]
        if op.phase == "completed":
            yield "use exact pin", replace(
                s, used=True, used_after_seal=s.sealed,
                retention_obligation=(s.retention_obligation or
                                      (s.sealed and op.completed_epoch == 0 and
                                       defect != "forget_old_obligation")))
    if defect == "instance_without_pin" and s.instance == -1 and s.pin == -1:
        yield "create unpinned instance", replace(s, instance=0, arrived=True)
    if defect == "drop_pin_on_crash" and s.pin in (0, 1):
        yield "crash drops pin", replace(s, pin=-1)

    # A pre-journal instance has an exact version, but no trustworthy mapping
    # to the accepting operation. Its work may continue under explicit unknown
    # while a structural coverage certificate still refuses this slice.
    if (s.instance == -1 and s.pin == -1 and not s.legacy_inventory_closed
            and all(op.phase == "absent" for op in s.ops)):
        yield "load legacy item", replace(s, instance=2, arrived=True)
    if s.instance == 2 and s.pin == -1:
        yield "classify legacy unknown", replace(
            s, pin=2, first_pin=2, legacy_unknown=True)
        if defect == "legacy_bypass":
            yield "use unclassified legacy", replace(s, used=True)
    if s.instance == 2 and s.pin == 2 and s.legacy_unknown:
        yield "resume legacy unknown", replace(s, used=True)

    if not s.sealed:
        yield "seal", replace(
            s, sealed=True, epoch=1,
            cut=frozenset(i for i, op in enumerate(s.ops)
                             if op.phase == "completed" and op.completed_epoch == 0))
    if not s.legacy_inventory_closed and s.instance != 2 and not s.legacy_unknown:
        yield "close legacy inventory", replace(s, legacy_inventory_closed=True)
    if s.sealed and not s.slice_complete and (
        (s.legacy_inventory_closed and not s.legacy_unknown)
        or (defect == "legacy_false_complete" and s.legacy_unknown)
        or (defect == "ignore_legacy_inventory" and not s.legacy_inventory_closed
            and not s.legacy_unknown and s.instance == -1)
    ):
        yield "claim modeled slice complete", replace(s, slice_complete=True)


def violation(s: State):
    if s.first_pin != -1 and s.pin != s.first_pin:
        return "item pin changed or was lost"
    if s.pin in (0, 1) and s.ops[s.pin].phase != "completed":
        return "item pinned a pending or refused target"
    if s.instance in (0, 1) and s.instance != s.pin:
        return "runtime instance lacks its exact Home pin"
    if s.used and s.instance == 2 and (s.pin != 2 or not s.legacy_unknown):
        return "legacy item used without explicit unknown classification"
    if s.used and s.instance in (0, 1) and (s.pin != s.instance or
                                               s.ops[s.pin].phase != "completed"):
        return "runtime used an incomplete or different admission"
    if s.slice_complete and (s.legacy_unknown or s.instance == 2):
        return "legacy evidence was promoted to complete coverage"
    for index, op in enumerate(s.ops):
        if op.phase == "completed" and op.completed_epoch > op.registered_epoch and not op.rechecked:
            return "post-seal target completed without current-basis check"
        if s.sealed and (index in s.cut) != (op.phase == "completed" and op.completed_epoch == 0):
            return "later work changed the sealed operation cut"
    if (s.used_after_seal and s.pin in (0, 1)
            and s.ops[s.pin].completed_epoch == 0 and not s.retention_obligation):
        return "old-version use after a seal lost its retention obligation"
    return None


def explore(defect="", depth=11):
    queue = deque([(State(), ())])
    seen = {State()}
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


def scenario(events):
    state = State()
    for wanted in events:
        matches = [after for event, after in steps(state) if event == wanted]
        assert len(matches) == 1, (wanted, state)
        state = matches[0]
        assert violation(state) is None, (wanted, state, violation(state))
    return state


def main():
    exact = scenario((
        "register 0", "write 0", "complete 0", "bind 0",
        "create pinned instance", "arrive on pinned instance", "seal",
        "use exact pin"))
    assert exact.used and exact.retention_obligation and exact.cut == frozenset({0})
    competing = scenario((
        "register 0", "register 1", "write 0", "write 1", "complete 0",
        "complete 1", "bind 0", "create pinned instance",
        "arrive on pinned instance", "use exact pin"))
    assert competing.pin == 0 and competing.ops[1].phase == "completed"
    legacy = scenario((
        "load legacy item", "classify legacy unknown", "resume legacy unknown", "seal"))
    assert legacy.used and legacy.legacy_unknown and not legacy.slice_complete

    count, error, _ = explore()
    assert error is None, error
    print(f"Home item pin: {count} safe states through eleven transitions")
    for defect in (
        "complete_without_recheck", "bind_refused", "replace_pin",
        "instance_without_pin", "drop_pin_on_crash", "legacy_bypass",
        "legacy_false_complete", "ignore_legacy_inventory",
        "forget_old_obligation",
    ):
        count, error, trace = explore(defect)
        assert error is not None, (defect, count)
        print(f"  {defect}: {error} via {' -> '.join(trace)}")


if __name__ == "__main__":
    main()
