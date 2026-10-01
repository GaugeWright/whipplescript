#!/usr/bin/env python3
"""Bounded authority-isolation probe for two project Homes on one host.

Run: python3 models/research/project_home_coverage.py

The shared Project Host is a placement fact, not an admission authority. Each
operation has one project Home, and that Home alone registers, completes,
permits use and seals it. A gate may certify only that Home's frozen roster.
This models identity and epoch separation, not target-store recovery, keys,
the completeness of accepting paths, or an implementation of DR-0150.
"""

from collections import deque
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class Operation:
    phase: str = "absent"  # absent, pending, stored, completed
    journal_home: int = -1
    use_home: int = -1


@dataclass(frozen=True)
class State:
    # Operation i belongs to project Home i; both Homes run on one host.
    operations: tuple[Operation, Operation] = (Operation(), Operation())
    epochs: tuple[int, int] = (0, 0)
    cuts: tuple[tuple[int, ...] | None, tuple[int, ...] | None] = (None, None)
    expected: tuple[tuple[int, ...] | None, tuple[int, ...] | None] = (None, None)
    gate_cut: tuple[int, ...] | None = None
    gate_home: int = -1


def put(values, index, value):
    result = list(values)
    result[index] = value
    return tuple(result)


def steps(state: State, defect: str = ""):
    for home, op in enumerate(state.operations):
        if op.phase == "absent":
            journal = 1 if defect == "wrong_journal" and home == 0 else home
            yield f"register {home}", replace(
                state, operations=put(state.operations, home,
                                      Operation("pending", journal)))
        if op.phase == "pending":
            yield f"write {home}", replace(
                state, operations=put(state.operations, home,
                                      replace(op, phase="stored")))
        if op.phase == "stored":
            yield f"complete {home}", replace(
                state, operations=put(state.operations, home,
                                      replace(op, phase="completed")))
        if op.phase == "completed" and op.use_home == -1:
            if op.journal_home == home:
                yield f"use {home}", replace(
                    state, operations=put(state.operations, home,
                                          replace(op, use_home=home)))
            if defect == "cross_use" and home == 0:
                yield "use 0 for project 1", replace(
                    state, operations=put(state.operations, home,
                                          replace(op, use_home=1)))

    for home, cut in enumerate(state.cuts):
        if cut is not None:
            continue
        # The oracle is the actual completed population of this project at
        # seal time. The implementation sees only its own journal entries.
        expected = tuple(i for i, op in enumerate(state.operations)
                         if i == home and op.phase == "completed")
        visible = tuple(i for i, op in enumerate(state.operations)
                        if op.phase == "completed" and
                        (op.journal_home == home or defect == "host_union"))
        epochs = (tuple(epoch + 1 for epoch in state.epochs)
                  if defect == "shared_epoch" and home == 1 else
                  put(state.epochs, home, state.epochs[home] + 1))
        yield f"seal {home}", replace(
            state, cuts=put(state.cuts, home, visible),
            expected=put(state.expected, home, expected), epochs=epochs)

    if state.gate_cut is None:
        if state.cuts[0] is not None:
            yield "gate 0", replace(state, gate_cut=state.cuts[0], gate_home=0)
        if defect == "borrow_seal" and state.cuts[1] is not None:
            yield "gate 0 with seal 1", replace(
                state, gate_cut=state.cuts[1], gate_home=1)


def violation(state: State):
    for home, op in enumerate(state.operations):
        if op.phase == "completed" and op.journal_home != home:
            return "operation completed in another project's journal"
        if op.use_home != -1 and op.use_home != home:
            return "another project used this Home's operation"
    for home, cut in enumerate(state.cuts):
        if cut is not None and cut != state.expected[home]:
            return "seal includes or omits another project's operation"
        if state.epochs[home] != int(cut is not None):
            return "another project's seal advanced this Home's epoch"
    if state.gate_cut is not None and (
            state.gate_home != 0 or state.gate_cut != state.cuts[0]):
        return "gate borrowed another project's sealed authority"
    return None


def scenario(events, defect=""):
    state = State()
    for wanted in events:
        matches = [after for event, after in steps(state, defect)
                   if event == wanted]
        assert len(matches) == 1, (wanted, state)
        state = matches[0]
        if not defect:
            assert violation(state) is None, (wanted, state)
    return state


def explore(defect="", depth=11):
    start = State()
    seen = {start}
    queue = deque([(start, ())])
    while queue:
        state, trace = queue.popleft()
        if problem := violation(state):
            return len(seen), problem, trace
        if len(trace) == depth:
            continue
        for event, after in steps(state, defect):
            if after not in seen:
                seen.add(after)
                queue.append((after, trace + (event,)))
    return len(seen), None, ()


def main():
    independent = scenario((
        "register 0", "write 0", "complete 0", "use 0", "seal 0",
        "register 1", "write 1", "complete 1", "use 1", "seal 1",
        "gate 0"))
    assert independent.cuts == ((0,), (1,))
    assert independent.gate_cut == (0,)
    assert independent.epochs == (1, 1)
    count, error, _ = explore()
    assert error is None, error
    print(f"project Home isolation: {count} safe states through eleven transitions")
    for defect, expected in (
        ("wrong_journal", "operation completed in another project's journal"),
        ("host_union", "seal includes or omits another project's operation"),
        ("cross_use", "another project used this Home's operation"),
        ("borrow_seal", "gate borrowed another project's sealed authority"),
        ("shared_epoch", "another project's seal advanced this Home's epoch"),
    ):
        count, error, trace = explore(defect)
        assert error == expected, (defect, count, error, trace)
        print(f"  {defect}: {error} via {' -> '.join(trace)}")


if __name__ == "__main__":
    main()
