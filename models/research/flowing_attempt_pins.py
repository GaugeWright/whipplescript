#!/usr/bin/env python3
"""Bounded failed/cancelled attempt pin and collector interleavings.

Run: python3 models/research/flowing_attempt_pins.py
Two coordinators may check the same owed unit. Each candidate has its own cut.
The unit holder retains the source cut until a ref CAS accounts the unit; that
CAS atomically installs ref-owned source/candidate pins. Attempt pins are
durable across coordinator failure. This abstracts real blobs and stores.
"""

from collections import deque
from dataclasses import dataclass, replace


def at(values, index, value):
    return values[:index] + (value,) + values[index + 1:]


@dataclass(frozen=True)
class State:
    owed: bool = True
    holder_pin: bool = True
    source_available: bool = True
    candidate_available: tuple[bool, bool] = (False, False)
    status: tuple[str, str] = ("idle", "idle")
    source_pins: tuple[bool, bool] = (False, False)
    candidate_pins: tuple[bool, bool] = (False, False)
    admitted_by: int = -1
    ref_source_pin: bool = False
    ref_candidate_pin: bool = False
    receipt: bool = False
    frontier: bool = False
    ref_up: bool = True
    operator_up: tuple[bool, bool] = (True, True)


def steps(state, defect=""):
    for i in range(2):
        if state.status[i] == "idle" and state.owed and state.source_available:
            yield f"prepare{i}", replace(
                state, status=at(state.status, i, "checking"),
                candidate_available=at(state.candidate_available, i, True),
                source_pins=at(state.source_pins, i, True),
                candidate_pins=at(state.candidate_pins, i, True),
            )
        if state.operator_up[i]:
            yield f"crash{i}", replace(state, operator_up=at(state.operator_up, i, False))
        else:
            yield f"recover{i}", replace(state, operator_up=at(state.operator_up, i, True))
        if state.status[i] == "checking" and state.operator_up[i]:
            yield f"fail{i}", replace(state, status=at(state.status, i, "failed"))
            # Cancellation must win at the ref authority before acknowledgement.
            if state.ref_up and state.admitted_by == -1:
                yield f"cancel{i}", replace(state, status=at(state.status, i, "cancelled"))
            if state.ref_up and state.owed:
                yield f"cas{i}", replace(
                    state, owed=False, holder_pin=False, admitted_by=i,
                    status=at(state.status, i, "admitted"),
                    ref_source_pin=True, ref_candidate_pin=True,
                )
        if (state.status[i] == "checking" and state.admitted_by != -1 and
                state.admitted_by != i and state.ref_up):
            yield f"observe_winner{i}", replace(
                state, status=at(state.status, i, "superseded"))
        if state.status[i] in ("failed", "cancelled", "superseded") and (
                state.source_pins[i] or state.candidate_pins[i]):
            next_source = at(state.source_pins, i, False)
            next_candidate = at(state.candidate_pins, i, False)
            if defect == "release_other_attempt":
                other = 1 - i
                next_source = at(next_source, other, False)
                next_candidate = at(next_candidate, other, False)
            yield f"release{i}", replace(
                state, source_pins=next_source,
                candidate_pins=next_candidate,
            )
        if (state.status[i] == "admitted" and state.receipt and state.frontier and
                (state.source_pins[i] or state.candidate_pins[i])):
            yield f"release{i}", replace(
                state, source_pins=at(state.source_pins, i, False),
                candidate_pins=at(state.candidate_pins, i, False),
            )
        if state.candidate_available[i] and not (
                state.candidate_pins[i] or
                (state.admitted_by == i and state.ref_candidate_pin)):
            yield f"collect_candidate{i}", replace(
                state, candidate_available=at(state.candidate_available, i, False))
    if state.admitted_by != -1:
        if not state.receipt and state.ref_up:
            yield "recover_receipt", replace(state, receipt=True)
        if not state.frontier and state.ref_up:
            yield "reconcile_frontier", replace(state, frontier=True)
        if state.receipt and state.frontier and (
                state.ref_source_pin or state.ref_candidate_pin):
            yield "release_ref_pins", replace(
                state, ref_source_pin=False, ref_candidate_pin=False)
    if (state.holder_pin and state.owed and defect == "drop_owed_holder_pin") or (
            state.holder_pin and not state.owed):
        yield "release_holder", replace(state, holder_pin=False)
    if (state.source_available and not state.holder_pin and
            not state.ref_source_pin and not any(state.source_pins)):
        yield "collect_source", replace(state, source_available=False)
    if state.ref_up:
        yield "ref_outage", replace(state, ref_up=False)
    else:
        yield "ref_restore", replace(state, ref_up=True)


def violation(state):
    if state.owed and not state.source_available:
        return "owed unit lost its source cut"
    for i in range(2):
        if state.status[i] == "checking" and not state.candidate_available[i]:
            return f"checking attempt {i} lost its candidate cut"
    if state.admitted_by != -1 and not (state.receipt and state.frontier):
        if not state.source_available:
            return "admitted unit lost source before recovery"
        if not state.candidate_available[state.admitted_by]:
            return "admitted unit lost candidate before recovery"
    if state.owed == (state.admitted_by != -1):
        return "unit accounting and trunk CAS split"
    return None


def trace(events, defect=""):
    state = State()
    for wanted in events:
        matches = [successor for event, successor in steps(state, defect)
                   if event == wanted]
        assert len(matches) == 1, (wanted, state)
        state = matches[0]
        if not defect:
            assert violation(state) is None, (wanted, violation(state))
    return state


def explore(defect="", depth=9):
    first = State()
    queue = deque([(first, ())])
    seen = {first}
    while queue:
        state, history = queue.popleft()
        if problem := violation(state):
            return len(seen), problem, history
        if len(history) == depth:
            continue
        for event, next_state in steps(state, defect):
            if next_state not in seen:
                seen.add(next_state)
                queue.append((next_state, history + (event,)))
    return len(seen), None, ()


def main():
    failed = trace(("prepare0", "prepare1", "fail0", "crash0", "recover0", "release0",
                    "collect_candidate0", "cas1", "recover_receipt",
                    "reconcile_frontier"))
    assert failed.admitted_by == 1 and failed.candidate_available[1]
    cancelled = trace(("prepare0", "cancel0", "release0", "collect_candidate0",
                       "prepare1", "cas1"))
    assert cancelled.admitted_by == 1 and not cancelled.candidate_available[0]
    outage = trace(("prepare0", "ref_outage"))
    assert "cancel0" not in {name for name, _ in steps(outage)}
    winner = trace(("prepare0", "prepare1", "cas0", "crash0", "fail1",
                    "release1", "collect_candidate1", "recover_receipt",
                    "reconcile_frontier"))
    assert winner.admitted_by == 0 and winner.candidate_available[0]

    count, problem, _ = explore()
    assert problem is None, problem
    print(f"attempt pin interleavings: {count} safe states through depth 9")
    for defect, expected, depth in (
        ("drop_owed_holder_pin", "owed unit lost its source cut", 4),
        ("release_other_attempt", "checking attempt 1 lost its candidate cut", 5),
    ):
        count, problem, history = explore(defect, depth)
        assert problem == expected, (defect, problem, history)
        print(f"{defect}: {problem}; " + " -> ".join(history))


if __name__ == "__main__":
    main()
