#!/usr/bin/env python3
"""Compose pinned source atoms, dependent basis, closure and norm/ref CAS.

Run: python3 models/research/flowing_full_seam.py
Two member twigs and source units, one candidate, two coordinators. Unit 1
depends on the version of unit 0 it read. When selected together, unit 1
neutralizes unit 0's x write but applies a y write. The exact source atoms,
their path effects, dependent read basis and per-unit outcomes must survive
that neutralization in the certificate and the ref admission. The ref CAS
also checks the digest of the precise candidate payload the gate verified;
a post-check swap cannot reuse its certificate. An equivalent no-op still
gets a checked admission and per-unit receipt. Independent norm/ref outages
block admission and require recovery of their own authority state; fail-open
mutants reach an admission with one unavailable. The model still abstracts
real cut contents, semantic edge discovery, certificate authenticity, physical
lock scheduling and cross-store crash transactions.
The mixed-source mode additionally carries one unit through B, C and D, and
checks each origin's Hold and policy epoch at the same norm/ref CAS. Transport
and policy storage are abstract here; the source atoms and receipt must still
be derived from real cuts in production.
"""

from collections import deque
from dataclasses import dataclass, field, replace
from hashlib import sha256
import json

import composed_admission as gate
import private_pin_closure as work


@dataclass(frozen=True)
class Atom:
    identity: str
    unit: int
    path: str
    before: int
    after: int


ATOMS = (
    Atom("u0:x", 0, "x", 0, 1),
    Atom("u1:x", 1, "x", 1, 0),
    Atom("u1:y", 1, "y", 0, 1),
)
BRANCHES = ("B", "C", "D")


def holder_kind(source_kind: str) -> str:
    return "branch" if source_kind == "mixed" else source_kind


def policy_clear(state, lineage: tuple[str, ...]) -> bool:
    return all(not state.held[BRANCHES.index(branch)] for branch in lineage)


def policy_current(state, candidate, lineage: tuple[str, ...]) -> bool:
    return all(candidate.policy_epochs[BRANCHES.index(branch)]
               == state.policy_epochs[BRANCHES.index(branch)]
               for branch in lineage)


@dataclass(frozen=True)
class Candidate:
    selected: tuple[int, ...]
    before: tuple[int, int]
    source_atoms: tuple[str, ...]
    certificate_atoms: tuple[str, ...]
    output_atoms: tuple[str, ...]
    dependent_read_basis: int | None
    after: tuple[int, int]
    outcomes: tuple[str, ...]
    output_change_id: str
    actual_lineage: tuple[str, ...]
    certificate_lineage: tuple[str, ...]
    policy_epochs: tuple[int, int, int]


def certificate_digest(candidate: Candidate) -> str:
    """Bind the candidate fields the gate verified and the ref must consume."""
    payload = {
        "selected": candidate.selected,
        "before": candidate.before,
        "source_atoms": candidate.certificate_atoms,
        "output_atoms": candidate.output_atoms,
        "dependent_read_basis": candidate.dependent_read_basis,
        "after": candidate.after,
        "outcomes": candidate.outcomes,
        "output_change_id": candidate.output_change_id,
        "lineage": candidate.certificate_lineage,
        "policy_epochs": candidate.policy_epochs,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return sha256(encoded).hexdigest()


def source_atoms(selected: tuple[int, ...]) -> tuple[str, ...]:
    return tuple(atom.identity for atom in ATOMS if atom.unit in selected)


def candidate_for(selected: tuple[int, ...], cut: int,
                  before: tuple[int, int], actual_lineage: tuple[str, ...],
                  recorded_lineage: tuple[str, ...],
                  policy_epochs: tuple[int, int, int], defect: str = "") -> Candidate:
    roots = source_atoms(selected)
    output_change_id = f"mixed-output:{cut}"
    certificate = ((output_change_id,) if defect == "output_id_as_witness"
                   else roots[1:] if defect == "omit_source_atom" else roots)
    output = roots[1:] if defect == "omit_predecessor_effect" else roots
    normal_outcomes = (
        ("equivalent" if before[0] == 1 else "neutralized", "applied")
        if selected == (0, 1) else
        ("equivalent" if before[0] == 1 else "applied",)
    )
    outcomes = (("applied", "applied") if defect == "misstate_neutralization"
                else normal_outcomes)
    return Candidate(
        selected, before, roots, certificate, output,
        (2 if defect == "stale_dependent_basis" else 1) if 1 in selected else None,
        (0, 1) if selected == (0, 1) else (1, before[1]),
        outcomes, output_change_id, actual_lineage, recorded_lineage,
        policy_epochs,
    )


def candidate_error(candidate: Candidate) -> str | None:
    expected = source_atoms(candidate.selected)
    if candidate.source_atoms != expected or candidate.certificate_atoms != expected:
        return "certificate omitted a selected source atom"
    if candidate.output_atoms != expected:
        return "candidate omitted a selected source effect"
    content = {"x": candidate.before[0], "y": candidate.before[1]}
    predecessor = None
    for identity in candidate.output_atoms:
        atom = next((item for item in ATOMS if item.identity == identity), None)
        if atom is None or atom.unit not in candidate.selected:
            return "candidate includes an unselected source atom"
        if atom.unit == 1 and predecessor is None:
            predecessor = content["x"]
        if content[atom.path] not in (atom.before, atom.after):
            return "candidate path effects do not compose"
        content[atom.path] = atom.after
    if candidate.dependent_read_basis is not None and (
        0 not in candidate.selected or candidate.dependent_read_basis != predecessor
    ):
        return "dependent read basis differs from realized predecessor"
    if (content["x"], content["y"]) != candidate.after:
        return "candidate cut differs from selected source effects"
    outcomes = (
        ("equivalent" if candidate.before[0] == 1 else "neutralized", "applied")
        if candidate.selected == (0, 1) else
        ("equivalent" if candidate.before[0] == 1 else "applied",)
    )
    if candidate.outcomes != outcomes:
        return "per-unit outcome misstates source realization"
    return None


@dataclass(frozen=True)
class State:
    source_kind: str = "branch"  # named branch, mixed transport, or direct twig
    trunk_content: tuple[int, int] = (0, 0)
    admission: gate.State = field(default_factory=gate.State)
    obligations: work.State = field(default_factory=work.State)
    candidate_source_cut: int = -1
    admitted_source_cut: int = -1
    candidate: Candidate | None = None
    candidate_certificate_digest: str | None = None
    candidate_swapped: bool = False
    admitted_candidate: Candidate | None = None
    admitted_certificate_digest: str | None = None
    admitted_trunk_before: tuple[int, int] | None = None
    source_attempt_pin: bool = False
    candidate_attempt_pin: bool = False
    source_available: bool = True
    candidate_available: bool = False
    frontier_reconciled: bool = False
    transport_stage: int = 0
    actual_lineage: tuple[str, ...] = ("D",)
    recorded_lineage: tuple[str, ...] = ("D",)
    policy_epochs: tuple[int, int, int] = (0, 0, 0)
    held: tuple[bool, bool, bool] = (False, False, False)
    hold_used: bool = False
    release_used: bool = False
    admitted_policy_epochs: tuple[int, int, int] | None = None
    admitted_held: tuple[bool, bool, bool] | None = None
    norm_up: bool = True
    norm_outage_used: bool = False
    ref_outage_used: bool = False
    admitted_norm_up: bool | None = None
    admitted_ref_up: bool | None = None


def steps(state: State, defect: str = ""):
    a, w = state.admission, state.obligations
    if not a.admission and not state.norm_outage_used:
        # A failed norm transaction loses its exclusion and validation; the
        # coordinator must recapture those premises after recovery.
        yield "norm_outage", replace(
            state, norm_up=False, norm_outage_used=True,
            admission=replace(a, ledger_locked_by=-1,
                              validated_revision=-1, validated_by=-1),
        )
    if not state.norm_up:
        yield "norm_restore", replace(state, norm_up=True)
    if not a.admission and not state.ref_outage_used:
        yield "ref_outage", replace(
            state, ref_outage_used=True,
            obligations=replace(w, ref_up=False),
        )
    if not w.ref_up:
        yield "ref_restore", replace(state, obligations=replace(w, ref_up=True))
    if state.source_kind == "mixed" and not a.admission:
        if state.transport_stage == 0 and w.units[0] == "branch":
            yield "transport_B_to_C", replace(
                state, transport_stage=1, actual_lineage=("B", "C"),
                recorded_lineage=("B", "C"),
            )
        if state.transport_stage == 1:
            yield "transport_C_to_D", replace(
                state, transport_stage=2, actual_lineage=("B", "C", "D"),
                recorded_lineage=(("C", "D") if defect == "lose_origin"
                                  else ("B", "C", "D")),
            )
    if state.source_kind == "mixed" and state.transport_stage == 2 and not a.admission:
        if not state.hold_used:
            yield "hold_B", replace(
                state, hold_used=True,
                held=(True, state.held[1], state.held[2]),
                policy_epochs=(state.policy_epochs[0] + 1,
                               state.policy_epochs[1], state.policy_epochs[2]),
            )
        if state.held[0] and not state.release_used:
            yield "release_B", replace(
                state, release_used=True,
                held=(False, state.held[1], state.held[2]),
                policy_epochs=(state.policy_epochs[0] + 1,
                               state.policy_epochs[1], state.policy_epochs[2]),
            )
    for event, next_a in gate.steps(a):
        if (not state.norm_up and defect != "fail_open_norm_outage" and
                (event in ("gate_pass", "revoke_original_grant", "precheck_without_lock")
                 or event.startswith("lock_and_validate"))):
            continue
        if (not w.ref_up and defect != "fail_open_ref_outage" and
                (event in ("hold", "takeover", "recover_receipt")
                 or event.startswith("cas_owner"))):
            continue
        if event == "gate_pass":
            if state.source_kind == "mixed" and state.transport_stage != 2:
                continue
            if state.source_kind != "twig":
                if w.units[0] != "branch" or not w.branch_pins[0]:
                    continue
                source_cut = w.branch_cut
            else:
                if w.units[0] != "twig" or not w.twig_pins[0]:
                    continue
                source_cut = w.twig_cuts[0]
            selections = ((0,),)
            if (state.source_kind == "branch" and
                    w.units[1] == "branch" and w.branch_pins[1]):
                selections += ((0, 1),)
            for selected in selections:
                candidate = candidate_for(selected, source_cut,
                                          state.trunk_content,
                                          state.actual_lineage,
                                          state.recorded_lineage,
                                          state.policy_epochs, defect)
                if not policy_clear(state, candidate.certificate_lineage):
                    continue
                if candidate_error(candidate) and defect not in (
                    "omit_source_atom", "omit_predecessor_effect",
                    "stale_dependent_basis", "misstate_neutralization",
                    "output_id_as_witness",
                ):
                    continue
                name = "gate_pass_both" if len(selected) == 2 else event
                yield name, replace(state, admission=next_a,
                                    candidate_source_cut=source_cut,
                                    candidate=candidate,
                                    candidate_certificate_digest=certificate_digest(candidate),
                                    source_attempt_pin=True,
                                    candidate_attempt_pin=(defect != "drop_candidate_pin"),
                                    candidate_available=True)
        elif event == "hold":
            # Close uses this ref-owned mutation below. A separate Hold has
            # the same eligibility effect and can race a candidate.
            yield event, replace(state, admission=next_a)
        elif event.startswith("cas_owner"):
            source_cut = (w.branch_cut if state.source_kind != "twig"
                          else w.twig_cuts[0])
            if ((not w.ref_up and defect != "fail_open_ref_outage") or
                    (source_cut != state.candidate_source_cut and
                     defect not in ("trust_stale_branch_cut",
                                    "cas_ignores_abandonment"))):
                continue
            if not state.source_available or not state.candidate_available:
                continue
            if state.candidate is None:
                continue
            if (certificate_digest(state.candidate) !=
                    state.candidate_certificate_digest and
                    defect != "skip_certificate_digest_check"):
                continue
            checked_lineage = (("D",) if defect == "current_branch_only"
                               else state.candidate.certificate_lineage)
            if not policy_clear(state, checked_lineage):
                continue
            if (defect != "ignore_origin_epoch" and
                    not policy_current(state, state.candidate, checked_lineage)):
                continue
            if defect == "disable_without_ref_fence" and not w.ref_enabled:
                yield event, replace(state, admission=next_a,
                                     admitted_source_cut=source_cut,
                                     admitted_policy_epochs=state.policy_epochs,
                                     admitted_held=state.held)
            elif (w.ref_enabled and state.candidate is not None and
                  (all(w.units[i] == holder_kind(state.source_kind)
                       for i in state.candidate.selected) or
                   (defect == "cas_ignores_abandonment" and
                    all(w.units[i] == "abandoned"
                        for i in state.candidate.selected)))):
                next_w = w
                if defect != "cas_omits_unit_accounting":
                    if state.source_kind != "twig":
                        if defect == "cas_ignores_abandonment":
                            next_w = replace(
                                next_w, units=tuple(
                                    "branch" if i in state.candidate.selected else status
                                    for i, status in enumerate(next_w.units)
                                ), branch_pins=tuple(
                                    True if i in state.candidate.selected else pinned
                                    for i, pinned in enumerate(next_w.branch_pins)
                                ),
                            )
                        for unit in state.candidate.selected:
                            # The mutant pretends an unavailable ref accepted
                            # the entry; retain the actual outage in the state.
                            next_w = work.admit(
                                replace(next_w, ref_up=True)
                                if defect == "fail_open_ref_outage" else next_w,
                                unit,
                            )
                            if not w.ref_up:
                                next_w = replace(next_w, ref_up=False)
                    else:
                        next_w = replace(
                            w, units=work.at(w.units, 0, "accounted"),
                            twig_pins=work.at(w.twig_pins, 0, False),
                            trunk_receipts=w.trunk_receipts + (0,),
                        )
                yield event, replace(state, admission=next_a,
                                     obligations=next_w,
                                     admitted_source_cut=source_cut,
                                     admitted_candidate=state.candidate,
                                     admitted_certificate_digest=state.candidate_certificate_digest,
                                     admitted_policy_epochs=state.policy_epochs,
                                     admitted_held=state.held,
                                     admitted_norm_up=state.norm_up,
                                     admitted_ref_up=w.ref_up,
                                     admitted_trunk_before=state.trunk_content,
                                     trunk_content=(state.trunk_content
                                                    if defect == "cas_omits_output"
                                                    else state.candidate.after))
        else:
            yield event, replace(state, admission=next_a)

    for event, next_w in work.steps(w):
        if event.startswith("admit"):
            continue  # Only the ref CAS above may account a unit.
        if state.source_kind == "twig" and (
            event.endswith("1") or event in ("request_close", "disable", "close") or
            event.startswith(("park", "resolve", "handoff"))
        ):
            continue  # A direct twig has no branch handoff or member closure.
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

    if state.candidate is not None:
        if not a.admission and not state.candidate_swapped:
            yield "swap_candidate_witness", replace(
                state, candidate=replace(
                    state.candidate,
                    output_change_id=state.candidate.output_change_id + ":replaced",
                ), candidate_swapped=True,
            )
        if not state.candidate_attempt_pin and state.candidate_available:
            yield "collect_candidate", replace(state, candidate_available=False)
        source_holder_pin = any(
            w.draft_pins[i] or w.twig_pins[i] or w.branch_pins[i] or
            w.parked_pins[i] for i in state.candidate.selected
        )
        if (not state.source_attempt_pin and not source_holder_pin and
                state.source_available):
            yield "collect_source", replace(state, source_available=False)
    if a.admission and not state.frontier_reconciled:
        yield "reconcile_frontier", replace(state, frontier_reconciled=True)
    if (a.admission and (a.receipt and state.frontier_reconciled or
                         defect == "release_before_reconciliation") and
            (state.source_attempt_pin or state.candidate_attempt_pin)):
        yield "release_attempt_pins", replace(
            state, source_attempt_pin=False, candidate_attempt_pin=False,
        )


def violation(state: State):
    a, w = state.admission, state.obligations
    if problem := gate.violation(a):
        return problem
    if problem := work.violation(w):
        return problem
    if state.candidate is not None and (
        not a.admission or not a.receipt or not state.frontier_reconciled
    ):
        if not state.source_available:
            return "selected source cut was collected before recovery finished"
        if not state.candidate_available:
            return "candidate cut was collected before recovery finished"
    if (a.trunk == 1) != bool(w.trunk_receipts):
        return "trunk CAS and selected-unit accounting split"
    if a.trunk and state.admitted_source_cut != state.candidate_source_cut:
        return "stale branch cut admitted"
    if a.trunk:
        if state.admitted_norm_up is not True:
            return "norm authority unavailable at trunk CAS"
        if state.admitted_ref_up is not True:
            return "ref authority unavailable at trunk CAS"
        candidate = state.admitted_candidate
        if candidate is None:
            return "trunk admission lacks its exact candidate"
        if certificate_digest(candidate) != state.admitted_certificate_digest:
            return "admitted candidate differs from verified certificate digest"
        if candidate.certificate_lineage != candidate.actual_lineage:
            return "transport omitted an origin from the certificate"
        if state.admitted_policy_epochs is None or state.admitted_held is None:
            return "trunk admission lacks its policy snapshot"
        if any(state.admitted_held[BRANCHES.index(branch)]
               for branch in candidate.actual_lineage):
            return "origin Hold was bypassed at trunk CAS"
        if any(candidate.policy_epochs[BRANCHES.index(branch)]
               != state.admitted_policy_epochs[BRANCHES.index(branch)]
               for branch in candidate.actual_lineage):
            return "stale origin policy epoch was admitted"
        if problem := candidate_error(candidate):
            return problem
        if candidate.before != state.admitted_trunk_before:
            return "candidate was checked against a different trunk base"
        if state.trunk_content != candidate.after:
            return "trunk CAS omitted the checked candidate content"
        if set(w.trunk_receipts) != set(candidate.selected):
            return "trunk receipt omitted a selected source unit"
    if w.close == "closed" and a.admission and not a.receipt:
        return "closure omitted recovery of the accepted admission"
    return None


def scenario(events, initial=None):
    state = State() if initial is None else initial
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

    recovered = scenario((
        "write0", "declare0", "handoff0", "cleanup0", "gate_pass",
        "crash_operator0", "takeover", "lock_and_validate_owner1",
        "cas_owner1", "reconcile_frontier", "recover_receipt",
        "release_attempt_pins", "collect_candidate", "collect_source",
    ))
    assert not recovered.candidate_available and not recovered.source_available
    assert recovered.admission.receipt and recovered.frontier_reconciled

    direct = scenario((
        "write0", "declare0", "gate_pass", "lock_and_validate_owner0",
        "cas_owner0", "recover_receipt",
    ), State(source_kind="twig"))
    assert direct.obligations.units == ("accounted", "none")
    assert direct.obligations.trunk_receipts == (0,)

    both = scenario((
        "write0", "declare0", "handoff0", "write1", "declare1",
        "handoff1", "gate_pass_both", "lock_and_validate_owner0",
        "cas_owner0", "recover_receipt",
    ))
    assert both.admitted_candidate is not None
    assert both.admitted_candidate.source_atoms == ("u0:x", "u1:x", "u1:y")
    assert both.admitted_candidate.outcomes == ("neutralized", "applied")
    assert both.admitted_candidate.after == (0, 1)
    assert both.trunk_content == (0, 1)
    assert both.obligations.trunk_receipts == (0, 1)

    abandoned = scenario((
        "write0", "declare0", "handoff0", "write1", "declare1",
        "handoff1", "gate_pass_both", "abandon_dependent_closure",
        "lock_and_validate_owner0",
    ))
    assert abandoned.obligations.abandonment_receipt == (0, 1)
    assert not any(name.startswith("cas_owner") for name, _ in steps(abandoned))
    broken_abandonment = State()
    for wanted in (
        "write0", "declare0", "handoff0", "write1", "declare1",
        "handoff1", "gate_pass_both", "abandon_dependent_closure",
        "lock_and_validate_owner0", "cas_owner0",
    ):
        matches = [after for name, after in
                   steps(broken_abandonment, "cas_ignores_abandonment")
                   if name == wanted]
        assert len(matches) == 1, (wanted, broken_abandonment)
        broken_abandonment = matches[0]
    assert violation(broken_abandonment) == (
        "source unit has both trunk and abandonment dispositions")

    equivalent = scenario((
        "write0", "declare0", "handoff0", "gate_pass",
        "lock_and_validate_owner0", "cas_owner0", "recover_receipt",
    ), State(trunk_content=(1, 0)))
    assert equivalent.admitted_candidate is not None
    assert equivalent.admitted_candidate.before == equivalent.admitted_candidate.after
    assert equivalent.admitted_candidate.outcomes == ("equivalent",)
    assert equivalent.trunk_content == (1, 0)
    assert equivalent.obligations.trunk_receipts == (0,)

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

    swapped = scenario(prefix + ("swap_candidate_witness",
                                 "lock_and_validate_owner0"))
    assert not any(name.startswith("cas_owner") for name, _ in steps(swapped))

    missing_norm = scenario(prefix + ("norm_outage",))
    assert not any(name.startswith("lock_and_validate")
                   for name, _ in steps(missing_norm))
    recovered_norm = scenario(prefix + (
        "norm_outage", "norm_restore", "lock_and_validate_owner0", "cas_owner0",
    ))
    assert recovered_norm.admitted_norm_up

    missing_ref = scenario(prefix + ("lock_and_validate_owner0", "ref_outage"))
    assert not any(name.startswith("cas_owner") for name, _ in steps(missing_ref))
    recovered_ref = scenario(prefix + (
        "lock_and_validate_owner0", "ref_outage", "release_ledger_owner0",
        "ref_restore", "lock_and_validate_owner0", "cas_owner0",
    ))
    assert recovered_ref.admitted_ref_up

    mixed_prefix = ("write0", "declare0", "handoff0",
                    "transport_B_to_C", "transport_C_to_D")
    mixed = scenario(mixed_prefix + ("gate_pass", "lock_and_validate_owner0",
                                     "cas_owner0", "recover_receipt"),
                     State(source_kind="mixed"))
    assert mixed.admitted_candidate.actual_lineage == ("B", "C", "D")
    assert mixed.admitted_candidate.source_atoms == ("u0:x",)
    held_origin = scenario(mixed_prefix + ("gate_pass", "hold_B",
                                           "lock_and_validate_owner0"),
                           State(source_kind="mixed"))
    assert not any(name.startswith("cas_owner") for name, _ in steps(held_origin))
    released_origin = scenario(mixed_prefix + ("hold_B", "release_B",
                                               "gate_pass", "lock_and_validate_owner0",
                                               "cas_owner0"),
                               State(source_kind="mixed"))
    assert released_origin.admitted_candidate.policy_epochs[0] == 2


def lineage_mutants():
    prefix = ("write0", "declare0", "handoff0",
              "transport_B_to_C", "transport_C_to_D", "gate_pass")
    for defect, tail, expected in (
        ("lose_origin", ("lock_and_validate_owner0", "cas_owner0"),
         "transport omitted an origin from the certificate"),
        ("current_branch_only", ("hold_B", "lock_and_validate_owner0", "cas_owner0"),
         "origin Hold was bypassed at trunk CAS"),
        ("ignore_origin_epoch", ("hold_B", "release_B",
                                  "lock_and_validate_owner0", "cas_owner0"),
         "stale origin policy epoch was admitted"),
    ):
        state = State(source_kind="mixed")
        for event in prefix + tail:
            matches = [successor for name, successor in steps(state, defect)
                       if name == event]
            assert len(matches) == 1, (defect, event, state)
            state = matches[0]
        assert violation(state) == expected, (defect, violation(state))
        print(f"{defect}: {expected}; " + " -> ".join(prefix + tail))


def witness_mutants():
    prefix = (
        "write0", "declare0", "handoff0", "write1", "declare1",
        "handoff1", "gate_pass_both", "lock_and_validate_owner0", "cas_owner0",
    )
    for defect, expected in (
        ("omit_source_atom", "certificate omitted a selected source atom"),
        ("output_id_as_witness", "certificate omitted a selected source atom"),
        ("omit_predecessor_effect", "candidate omitted a selected source effect"),
        ("stale_dependent_basis", "dependent read basis differs from realized predecessor"),
        ("misstate_neutralization", "per-unit outcome misstates source realization"),
    ):
        state = State()
        for event in prefix:
            matches = [successor for name, successor in steps(state, defect)
                       if name == event]
            assert len(matches) == 1, (defect, event, state)
            state = matches[0]
        assert violation(state) == expected, (defect, violation(state))
        print(f"{defect}: {expected}; " + " -> ".join(prefix))

    no_op = State(trunk_content=(1, 0))
    no_op_trace = (
        "write0", "declare0", "handoff0", "gate_pass",
        "lock_and_validate_owner0", "cas_owner0",
    )
    for event in no_op_trace:
        matches = [successor for name, successor in
                   steps(no_op, "cas_omits_unit_accounting") if name == event]
        assert len(matches) == 1, (event, no_op)
        no_op = matches[0]
    assert no_op.admitted_candidate is not None
    assert no_op.admitted_candidate.before == no_op.admitted_candidate.after
    assert violation(no_op) == "trunk CAS and selected-unit accounting split"
    print("no-op accounting mutant: equivalent cut lost its unit receipt; " +
          " -> ".join(no_op_trace))

    missed_output = State()
    output_trace = (
        "write0", "declare0", "handoff0", "gate_pass",
        "lock_and_validate_owner0", "cas_owner0",
    )
    for event in output_trace:
        matches = [successor for name, successor in
                   steps(missed_output, "cas_omits_output") if name == event]
        assert len(matches) == 1, (event, missed_output)
        missed_output = matches[0]
    assert violation(missed_output) == "trunk CAS omitted the checked candidate content"
    print("CAS output mutant: accounted units but omitted candidate content; " +
          " -> ".join(output_trace))

    swapped = State()
    swap_trace = (
        "write0", "declare0", "handoff0", "gate_pass",
        "swap_candidate_witness", "lock_and_validate_owner0", "cas_owner0",
    )
    for event in swap_trace:
        matches = [successor for name, successor in
                   steps(swapped, "skip_certificate_digest_check") if name == event]
        assert len(matches) == 1, (event, swapped)
        swapped = matches[0]
    assert violation(swapped) == "admitted candidate differs from verified certificate digest"
    print("certificate digest mutant: a post-check candidate swap reached CAS; " +
          " -> ".join(swap_trace))


    early_release = State()
    release_trace = (
        "write0", "declare0", "handoff0", "gate_pass",
        "lock_and_validate_owner0", "cas_owner0",
        "release_attempt_pins", "collect_candidate",
    )
    for event in release_trace:
        matches = [successor for name, successor in
                   steps(early_release, "release_before_reconciliation") if name == event]
        assert len(matches) == 1, (event, early_release)
        early_release = matches[0]
    assert violation(early_release) == "candidate cut was collected before recovery finished"
    print("early pin release mutant: candidate lost before receipt and reconciliation; " +
          " -> ".join(release_trace))

    missing_pin = State()
    missing_trace = ("write0", "declare0", "handoff0", "gate_pass", "collect_candidate")
    for event in missing_trace:
        matches = [successor for name, successor in
                   steps(missing_pin, "drop_candidate_pin") if name == event]
        assert len(matches) == 1, (event, missing_pin)
        missing_pin = matches[0]
    assert violation(missing_pin) == "candidate cut was collected before recovery finished"
    print("missing candidate pin mutant: gate work lost its cut; " +
          " -> ".join(missing_trace))


def authority_failure_mutants():
    prefix = ("write0", "declare0", "handoff0", "gate_pass")
    for defect, trace, expected in (
        ("fail_open_norm_outage",
         prefix + ("norm_outage", "lock_and_validate_owner0", "cas_owner0"),
         "norm authority unavailable at trunk CAS"),
        ("fail_open_ref_outage",
         prefix + ("lock_and_validate_owner0", "ref_outage", "cas_owner0"),
         "ref authority unavailable at trunk CAS"),
    ):
        state = State()
        for event in trace:
            matches = [successor for name, successor in steps(state, defect)
                       if name == event]
            assert len(matches) == 1, (defect, event, state)
            state = matches[0]
        assert violation(state) == expected, (defect, violation(state))
        print(f"{defect}: {expected}; " + " -> ".join(trace))


def explore(defect="", depth=12, source_kind="branch"):
    initial = State(source_kind=source_kind)
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
    witness_mutants()
    authority_failure_mutants()
    lineage_mutants()
    count, problem, _ = explore(depth=9, source_kind="twig")
    assert problem is None, problem
    print(f"direct twig lifecycle: {count} safe states through depth 9")
    count, problem, trace = explore("cas_omits_unit_accounting", 6, "twig")
    assert problem == "trunk CAS and selected-unit accounting split", problem
    print(f"direct twig accounting mutant: {problem}; " + " -> ".join(trace))
    count, problem, _ = explore(depth=12, source_kind="mixed")
    assert problem is None, problem
    print(f"mixed transport lifecycle: {count} safe states through depth 12")
    for label, defect, depth in (
        ("composed lifecycle", "", 12),
        ("CAS omits selected-unit accounting", "cas_omits_unit_accounting", 7),
        ("disable omits ref fence", "disable_without_ref_fence", 9),
        ("trust stale branch cut", "trust_stale_branch_cut", 10),
        ("CAS ignores abandonment", "cas_ignores_abandonment", 12),
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
