#!/usr/bin/env python3
"""Bounded transitive Hold and revision fence for a transported source unit.

Run: python3 models/research/flowing_lineage_policy.py

One unit starts on branch B, passes through two mixed outputs on C and D, and
then enters the trunk gate. The immutable source atom remains the unit's root;
the two mixed output ids are never substitutes for it. Every branch in its
transitive lineage contributes a current policy epoch and Hold bit at CAS.

This abstracts actual cut derivation, blob retention, durable ref transactions,
norm exclusion, and independent store locks. It is one FB-1/FB-3 premise, not
an activation proof or a Home-wide coverage claim.
"""

from collections import deque
from dataclasses import dataclass, replace


BRANCHES = ("B", "C", "D")


@dataclass(frozen=True)
class Certificate:
    source_atoms: tuple[str, ...]
    lineage: tuple[str, ...]
    policy_epochs: tuple[int, int, int]
    source_revision: int
    trunk_base: int
    candidate_cut: str


@dataclass(frozen=True)
class State:
    phase: int = 0  # B, C, D, accounted
    actual_lineage: tuple[str, ...] = ("B",)
    recorded_lineage: tuple[str, ...] = ("B",)
    source_atoms: tuple[str, ...] = ("u0:x",)
    output_cut: str = "cut-b"
    source_revision: int = 0
    trunk_base: int = 0
    policy_epochs: tuple[int, int, int] = (0, 0, 0)
    held: tuple[bool, bool, bool] = (False, False, False)
    hold_used: bool = False
    release_used: bool = False
    revision_used: bool = False
    policy_up: bool = True
    policy_outage_used: bool = False
    ref_up: bool = True
    ref_outage_used: bool = False
    certificate: Certificate | None = None


def at(values: tuple, index: int, value):
    changed = list(values)
    changed[index] = value
    return tuple(changed)


def current_policy(state: State, lineage: tuple[str, ...]) -> bool:
    return all(not state.held[BRANCHES.index(branch)] for branch in lineage)


def matching_epochs(state: State, certificate: Certificate,
                    lineage: tuple[str, ...]) -> bool:
    return all(
        certificate.policy_epochs[BRANCHES.index(branch)]
        == state.policy_epochs[BRANCHES.index(branch)]
        for branch in lineage
    )


def steps(state: State, defect: str = ""):
    if state.phase == 0:
        yield "transport_B_to_C", replace(
            state, phase=1, output_cut="mixed-c",
            actual_lineage=("B", "C"), recorded_lineage=("B", "C"),
        )
    if state.phase == 1:
        recorded = (("C", "D") if defect == "lose_origin_on_transport"
                    else ("B", "C", "D"))
        yield "transport_C_to_D", replace(
            state, phase=2, output_cut="mixed-d",
            actual_lineage=("B", "C", "D"), recorded_lineage=recorded,
        )
    if state.phase != 2:
        return

    if not state.hold_used:
        index = BRANCHES.index("B")
        yield "hold_B", replace(
            state, hold_used=True, held=at(state.held, index, True),
            policy_epochs=at(state.policy_epochs, index,
                             state.policy_epochs[index] + 1),
        )
    if state.held[0] and not state.release_used:
        yield "release_B", replace(
            state, release_used=True, held=at(state.held, 0, False),
            policy_epochs=at(state.policy_epochs, 0,
                             state.policy_epochs[0] + 1),
        )
    if not state.revision_used:
        # A controlled revision replaces the selected unit's substantive atom.
        # The new source revision must fence an already passed candidate.
        yield "revise_unit", replace(
            state, revision_used=True, source_revision=state.source_revision + 1,
            source_atoms=("u0:x:revised",), output_cut="mixed-d-revised",
        )
    if state.policy_up and not state.policy_outage_used:
        yield "policy_down", replace(state, policy_up=False,
                                     policy_outage_used=True)
    if not state.policy_up:
        yield "policy_up", replace(state, policy_up=True)
    if state.ref_up and not state.ref_outage_used:
        yield "ref_down", replace(state, ref_up=False, ref_outage_used=True)
    if not state.ref_up:
        yield "ref_up", replace(state, ref_up=True)

    if state.policy_up and state.ref_up and current_policy(
        state, state.recorded_lineage
    ):
        atoms = ((state.output_cut,) if defect == "output_id_as_source_atom"
                 else state.source_atoms)
        next_certificate = Certificate(
            source_atoms=atoms,
            lineage=state.recorded_lineage,
            policy_epochs=state.policy_epochs,
            source_revision=state.source_revision,
            trunk_base=state.trunk_base,
            candidate_cut=state.output_cut,
        )
        if next_certificate != state.certificate:
            yield "gate_pass", replace(state, certificate=next_certificate)

    cert = state.certificate
    if cert is None or not state.ref_up:
        return
    if not state.policy_up and defect != "policy_outage_as_clear":
        return
    checked_lineage = (("D",) if defect == "check_current_branch_only"
                       else cert.lineage)
    if not current_policy(state, checked_lineage):
        return
    if (defect != "ignore_policy_epoch" and
            not matching_epochs(state, cert, checked_lineage)):
        return
    if (defect != "trust_stale_revision" and
            (cert.source_revision != state.source_revision or
             cert.candidate_cut != state.output_cut)):
        return
    if (defect not in ("output_id_as_source_atom", "trust_stale_revision") and
            cert.source_atoms != state.source_atoms):
        return
    if cert.trunk_base == state.trunk_base:
        yield "trunk_CAS", replace(state, phase=3, trunk_base=state.trunk_base + 1)


def violation(state: State) -> str | None:
    if state.phase != 3:
        return None
    cert = state.certificate
    assert cert is not None
    if cert.lineage != state.actual_lineage:
        return "transport lost an origin branch from the admitted lineage"
    if cert.source_atoms != state.source_atoms:
        return "certificate substituted an output id or stale source atom"
    if not state.policy_up:
        return "policy outage was treated as a clear answer"
    if not current_policy(state, state.actual_lineage):
        return "origin Hold was bypassed at trunk CAS"
    if not matching_epochs(state, cert, state.actual_lineage):
        return "pre-Hold certificate was reused after policy changed"
    if cert.source_revision != state.source_revision or cert.candidate_cut != state.output_cut:
        return "revised source admitted under an old candidate"
    return None


def trace(events: tuple[str, ...], defect: str = "") -> State:
    state = State()
    for wanted in events:
        matches = [next_state for event, next_state in steps(state, defect)
                   if event == wanted]
        assert len(matches) == 1, (defect, wanted, state)
        state = matches[0]
    return state


def explore(defect: str = "", depth: int = 10):
    first = State()
    queue = deque([(first, ())])
    seen = {first}
    while queue:
        state, events = queue.popleft()
        if problem := violation(state):
            return len(seen), problem, events
        if len(events) == depth:
            continue
        for event, next_state in steps(state, defect):
            if next_state not in seen:
                seen.add(next_state)
                queue.append((next_state, events + (event,)))
    return len(seen), None, ()


def main():
    admitted = trace(("transport_B_to_C", "transport_C_to_D", "gate_pass", "trunk_CAS"))
    assert violation(admitted) is None
    assert admitted.certificate.lineage == ("B", "C", "D")
    assert admitted.certificate.source_atoms == ("u0:x",)
    held = trace(("transport_B_to_C", "transport_C_to_D", "gate_pass", "hold_B"))
    assert "trunk_CAS" not in dict(steps(held))
    released = trace(("transport_B_to_C", "transport_C_to_D", "gate_pass",
                      "hold_B", "release_B"))
    assert "trunk_CAS" not in dict(steps(released))
    fresh = trace(("transport_B_to_C", "transport_C_to_D", "gate_pass",
                   "hold_B", "release_B", "gate_pass", "trunk_CAS"))
    assert violation(fresh) is None
    revised = trace(("transport_B_to_C", "transport_C_to_D", "gate_pass", "revise_unit"))
    assert "trunk_CAS" not in dict(steps(revised))
    assert violation(trace(("transport_B_to_C", "transport_C_to_D", "gate_pass",
                            "revise_unit", "gate_pass", "trunk_CAS"))) is None
    unavailable = trace(("transport_B_to_C", "transport_C_to_D",
                         "gate_pass", "policy_down"))
    assert "trunk_CAS" not in dict(steps(unavailable))
    assert violation(trace(("transport_B_to_C", "transport_C_to_D",
                            "gate_pass", "policy_down", "policy_up", "trunk_CAS"))) is None
    ref_unavailable = trace(("transport_B_to_C", "transport_C_to_D",
                             "gate_pass", "ref_down"))
    assert "trunk_CAS" not in dict(steps(ref_unavailable))

    count, problem, _ = explore()
    assert problem is None, problem
    print(f"transitive lineage and policy: {count} safe states through depth 10")
    mutants = (
        ("lose_origin_on_transport", ("transport_B_to_C", "transport_C_to_D",
                                      "gate_pass", "trunk_CAS"),
         "transport lost an origin branch from the admitted lineage"),
        ("check_current_branch_only", ("transport_B_to_C", "transport_C_to_D",
                                       "gate_pass", "hold_B", "trunk_CAS"),
         "origin Hold was bypassed at trunk CAS"),
        ("ignore_policy_epoch", ("transport_B_to_C", "transport_C_to_D",
                                 "gate_pass", "hold_B", "release_B", "trunk_CAS"),
         "pre-Hold certificate was reused after policy changed"),
        ("output_id_as_source_atom", ("transport_B_to_C", "transport_C_to_D",
                                      "gate_pass", "trunk_CAS"),
         "certificate substituted an output id or stale source atom"),
        ("trust_stale_revision", ("transport_B_to_C", "transport_C_to_D",
                                   "gate_pass", "revise_unit", "trunk_CAS"),
         "certificate substituted an output id or stale source atom"),
        ("policy_outage_as_clear", ("transport_B_to_C", "transport_C_to_D",
                                      "gate_pass", "policy_down", "trunk_CAS"),
         "policy outage was treated as a clear answer"),
    )
    for defect, events, expected in mutants:
        reached = trace(events, defect)
        assert violation(reached) == expected, (defect, violation(reached))
        count, problem, found = explore(defect, depth=10)
        assert problem is not None, defect
        print(f"{defect}: {problem}; {count} states; " + " -> ".join(found))


if __name__ == "__main__":
    main()
