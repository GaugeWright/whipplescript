#!/usr/bin/env python3
"""Compose private-pin/closure and norm/ref CAS probes at one branch head.

Run: python3 models/research/flowing_full_seam.py
One selected unit, a second member twig, one candidate and two coordinators.
Content reconciliation, dependency coverage and physical lock scheduling remain
outside this bounded product.
"""

from collections import deque
from dataclasses import dataclass, field, replace

import composed_admission as gate
import private_pin_closure as work


@dataclass(frozen=True)
class State:
    admission: gate.State = field(default_factory=gate.State)
    obligations: work.State = field(default_factory=work.State)
    candidate_branch_cut: int = -1
    admitted_branch_cut: int = -1


def steps(state: State, defect: str = ""):
    a, w = state.admission, state.obligations
    for event, next_a in gate.steps(a):
        if event == "gate_pass":
            if w.units[0] != "branch" or not w.branch_pins[0]:
                continue
            yield event, replace(state, admission=next_a,
                                 candidate_branch_cut=w.branch_cut)
        elif event == "hold":
            # Close uses this ref-owned mutation below. A separate Hold has
            # the same eligibility effect and can race a candidate.
            yield event, replace(state, admission=next_a)
        elif event.startswith("cas_owner"):
            if not w.ref_up or (
                w.branch_cut != state.candidate_branch_cut
                and defect != "trust_stale_branch_cut"
            ):
                continue
            if defect == "disable_without_ref_fence" and not w.ref_enabled:
                yield event, replace(state, admission=next_a,
                                     admitted_branch_cut=w.branch_cut)
            elif w.ref_enabled and w.units[0] == "branch":
                next_w = (w if defect == "cas_omits_unit_accounting"
                          else work.admit(w, 0))
                yield event, replace(state, admission=next_a,
                                     obligations=next_w,
                                     admitted_branch_cut=w.branch_cut)
        else:
            yield event, replace(state, admission=next_a)

    for event, next_w in work.steps(w):
        if event.startswith("admit"):
            continue  # Only the ref CAS above may account a unit.
        if event == "disable":
            if defect == "disable_without_ref_fence":
                yield event, replace(state, obligations=next_w)
            elif a.held:
                yield event, replace(state, obligations=next_w)
            else:
                holds = [next_a for name, next_a in gate.steps(a)
                         if name == "hold"]
                if holds:
                    yield event, replace(state, admission=holds[0],
                                         obligations=next_w)
        elif event == "close":
            if not a.admission or a.receipt or defect == "close_omits_recovery":
                yield event, replace(state, obligations=next_w)
        else:
            yield event, replace(state, obligations=next_w)


def violation(state: State):
    a, w = state.admission, state.obligations
    if problem := gate.violation(a):
        return problem
    if problem := work.violation(w):
        return problem
    if (a.trunk == 1) != (0 in w.trunk_receipts):
        return "trunk CAS and selected-unit accounting split"
    if a.trunk and state.admitted_branch_cut != state.candidate_branch_cut:
        return "stale branch cut admitted"
    if w.close == "closed" and a.admission and not a.receipt:
        return "closure omitted recovery of the accepted admission"
    return None


def scenario(events):
    state = State()
    for wanted in events:
        matches = [successor for event, successor in steps(state)
                   if event == wanted]
        assert len(matches) == 1, (wanted, state)
        state = matches[0]
        assert violation(state) is None, (wanted, state, violation(state))
    return state


def scenarios():
    prefix = ("write0", "declare0", "handoff0", "gate_pass")
    integrated = scenario(prefix + (
        "lock_and_validate_owner0", "cas_owner0", "recover_receipt",
        "request_close", "disable", "resolve0", "resolve1", "close",
    ))
    assert integrated.obligations.close == "closed"
    assert integrated.obligations.units[0] == "accounted"

    # A close request does not itself beat an already eligible CAS.
    winner = scenario(prefix + (
        "lock_and_validate_owner0", "request_close", "cas_owner0",
        "disable", "recover_receipt", "resolve0", "resolve1", "close",
    ))
    assert winner.admission.receipt

    parked_member = scenario((
        "write0", "declare0", "handoff0", "write1", "declare1",
        "handoff1", "gate_pass", "lock_and_validate_owner0", "cas_owner0",
        "recover_receipt", "request_close", "disable", "resolve0",
        "park1", "close",
    ))
    assert parked_member.obligations.units == ("accounted", "parked")
    assert parked_member.obligations.close_report == ("twig1: none/parked",)

    held = scenario(prefix + ("lock_and_validate_owner0", "request_close",
                              "disable"))
    assert not any(name.startswith("cas_owner") for name, _ in steps(held))

    # A second member changes the branch cut after capture. The old candidate
    # must not pass merely because its norm and owner premises are still good.
    stale = scenario(prefix + ("write1", "declare1", "handoff1",
                               "lock_and_validate_owner0"))
    assert not any(name.startswith("cas_owner") for name, _ in steps(stale))


def explore(defect="", depth=12):
    initial = State()
    queue = deque([(initial, ())])
    seen = {initial}
    while queue:
        state, trace = queue.popleft()
        if problem := violation(state):
            return len(seen), problem, trace
        if len(trace) == depth:
            continue
        for event, successor in steps(state, defect):
            if successor not in seen:
                seen.add(successor)
                queue.append((successor, trace + (event,)))
    return len(seen), None, ()


def main():
    scenarios()
    for label, defect, depth in (
        ("composed lifecycle", "", 12),
        ("CAS omits selected-unit accounting", "cas_omits_unit_accounting", 7),
        ("disable omits ref fence", "disable_without_ref_fence", 9),
        ("trust stale branch cut", "trust_stale_branch_cut", 10),
        ("close omits admitted receipt recovery", "close_omits_recovery", 12),
    ):
        count, problem, trace = explore(defect, depth)
        if bool(problem) != bool(defect):
            raise SystemExit(f"{label}: unexpected {problem} after {count} states")
        print(f"{label}: {count} states through depth {depth}; {problem or 'no violation'}")
        if trace:
            print("  " + " -> ".join(trace))


if __name__ == "__main__":
    main()
