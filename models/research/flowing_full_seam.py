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
mutants reach an admission with one unavailable. A later tail retains its
selected prefix in source ancestry; abandonment or rewrite removes it, so only
the latter invalidate an already checked candidate. Immutable retained cut
records now supply the selected source atoms.

The ref CAS also checks an issuer-bound gate receipt: only the gate authority
mints one, so a caller-supplied candidate with a self-consistent digest is
refused. Cross-store mode splits admission into three durable writes: the norm
ledger's commit, the ref store's CAS and the review store's per-unit source
receipt. A coordinator can crash between any two. Recovery retakes the norm
exclusion and completes or aborts the durable commit, and replays the ref
entry into the source receipt; until then no closure, abandonment, park or
pin release may act on the admitted units. Mutants that skip either recovery
or accept an unauthenticated certificate reach forbidden histories.

The model still abstracts the real merge engine, semantic edge discovery,
the cryptography and key management behind receipt authentication, physical
lock scheduling, and the native and hosted store transactions themselves.
The mixed-source mode additionally carries one or two units through B, C and D, and
checks each origin's Hold and policy epoch at the same norm/ref CAS. Transport
and policy storage are abstract here; production must derive the same evidence
from its real cuts. The mixed mode also composes all three durable writes:
origin Hold and epoch are rechecked after a norm-commit crash, while a ref-CAS
crash retains the exact transported candidate until its unit receipt and
frontier reconciliation finish.
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


@dataclass(frozen=True)
class Cut:
    line: str
    identity: int
    parent: tuple[str, int] | None
    atoms: tuple[str, ...]


GENESIS_CUTS = (
    Cut("branch", 0, None, ()),
    Cut("twig0", 0, None, ()),
    Cut("twig1", 0, None, ()),
)


def exact_cut(cuts: tuple[Cut, ...], line: str, identity: int) -> Cut:
    found = [cut for cut in cuts if cut.line == line and cut.identity == identity]
    assert len(found) == 1, (line, identity, found)
    return found[0]


def append_cut(cuts: tuple[Cut, ...], cut: Cut) -> tuple[Cut, ...]:
    assert not any(existing.line == cut.line and existing.identity == cut.identity
                   for existing in cuts), "an immutable cut id was reused"
    if cut.parent is not None:
        parent = exact_cut(cuts, *cut.parent)
        assert cut.atoms[:len(parent.atoms)] == parent.atoms, "cut lost its parent changes"
    return cuts + (cut,)


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
    source_cut: Cut
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
        "source_cut": candidate.source_cut.__dict__,
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


GATE_ISSUER = "gate-authority"
CALLER_ISSUER = "embedding-caller"


@dataclass(frozen=True)
class GateReceipt:
    """An issuer-bound statement that the gate verified one candidate digest.

    Only gate_pass mints GATE_ISSUER. A caller can compute any digest, so a
    receipt whose issuer is not the gate authority is not evidence of a check,
    even when its digest equals the candidate it accompanies.
    """
    issuer: str
    digest: str


def receipt_authentic(receipt: GateReceipt | None, digest: str | None) -> bool:
    return (receipt is not None and digest is not None and
            receipt.issuer == GATE_ISSUER and receipt.digest == digest)


@dataclass(frozen=True)
class NormRecord:
    """The norm ledger's durable admission commit, written before ref CAS."""
    status: str  # committed or aborted; applied is read from the ref entry
    digest: str
    actor: int
    revision: int
    granted: bool
    principal: int
    norm_up: bool


def declared_atoms(selected: tuple[int, ...]) -> tuple[str, ...]:
    return tuple(atom.identity for atom in ATOMS if atom.unit in selected)


def source_atoms(source_cut: Cut, selected: tuple[int, ...]) -> tuple[str, ...]:
    by_identity = {atom.identity: atom for atom in ATOMS}
    return tuple(identity for identity in source_cut.atoms
                 if identity in by_identity and by_identity[identity].unit in selected)


def candidate_for(selected: tuple[int, ...], source_cut: Cut,
                  before: tuple[int, int], actual_lineage: tuple[str, ...],
                  recorded_lineage: tuple[str, ...],
                  policy_epochs: tuple[int, int, int], defect: str = "") -> Candidate:
    roots = source_atoms(source_cut, selected)
    output_change_id = f"mixed-output:{source_cut.identity}"
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
        selected, source_cut, before, roots, certificate, output,
        (2 if defect == "stale_dependent_basis" else 1) if 1 in selected else None,
        (0, 1) if selected == (0, 1) else (1, before[1]),
        outcomes, output_change_id, actual_lineage, recorded_lineage,
        policy_epochs,
    )


def candidate_error(candidate: Candidate) -> str | None:
    expected = declared_atoms(candidate.selected)
    known = {atom.identity for atom in ATOMS}
    if any(identity not in known
           for identity in candidate.source_cut.atoms):
        return "retained source cut contains an unclassified source change"
    if source_atoms(candidate.source_cut, candidate.selected) != expected:
        return "retained source cut omitted a selected declared change"
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


def source_cut_error(cuts: tuple[Cut, ...], candidate: Candidate) -> str | None:
    cut = candidate.source_cut
    if cut != exact_cut(cuts, cut.line, cut.identity):
        return "certificate names a different retained source cut"
    if cut.line == "D":
        for child_line, parent_line in (("D", "C"), ("C", "B")):
            child = exact_cut(cuts, child_line, cut.identity)
            if child.parent != (parent_line, cut.identity):
                return "mixed transport cut omitted its source ancestry"
            parent = exact_cut(cuts, parent_line, cut.identity)
            if child.atoms[:len(parent.atoms)] != parent.atoms:
                return "mixed transport cut omitted its source changes"
    return None


@dataclass(frozen=True)
class State:
    source_kind: str = "branch"  # named branch, mixed transport, or direct twig
    trunk_content: tuple[int, int] = (0, 0)
    cuts: tuple[Cut, ...] = GENESIS_CUTS
    admission: gate.State = field(default_factory=gate.State)
    obligations: work.State = field(default_factory=work.State)
    # Active-head ancestry, distinct from retained content bodies. A later
    # append extends it; a rewrite/abandonment starts a new chain.
    source_ancestry: tuple[int, ...] = (0,)
    source_rewrite_used: bool = False
    candidate_source_cut: int = -1
    admitted_source_cut: int = -1
    admitted_source_ancestry: tuple[int, ...] = ()
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
    transport_cut_id: int = -1
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
    gate_receipt: GateReceipt | None = None
    admitted_gate_receipt: GateReceipt | None = None
    # Cross-store mode splits the admission into three durable writes: the
    # norm ledger's commit, the ref store's CAS, and the review store's
    # per-unit source receipt. A coordinator can crash between any two.
    cross_store: bool = False
    norm_record: NormRecord | None = None
    source_receipt_owed: bool = False
    cas_by: int = -1
    cas_actor_lost: bool = False
    caller_certificate_used: bool = False


def source_head(state: State) -> int:
    return (state.obligations.twig_cuts[0] if state.source_kind == "twig"
            else state.obligations.branch_cut)


def norm_commit_pending(state: State) -> bool:
    return (state.norm_record is not None and
            state.norm_record.status == "committed" and
            not state.admission.trunk)


def coordinator_up(state: State, actor: int) -> bool:
    a = state.admission
    return a.operator0_up if actor == 0 else a.takeover_used


def account_units(state: State, w: work.State,
                  selected: tuple[int, ...]) -> work.State:
    """Write the review store's per-unit source receipt from a ref entry."""
    for unit in selected:
        pins = ({"twig_pins": work.at(w.twig_pins, unit, False)}
                if state.source_kind == "twig" else
                {"branch_pins": work.at(w.branch_pins, unit, False)})
        w = replace(w, units=work.at(w.units, unit, "accounted"),
                    trunk_receipts=w.trunk_receipts + (unit,), **pins)
    return w


def cross_store_steps(state: State, defect: str = ""):
    """Ref CAS, norm recovery and source-receipt recovery between stores."""
    a, w = state.admission, state.obligations
    record = state.norm_record
    if (state.candidate is not None and record is None and not a.admission and
            not state.caller_certificate_used):
        # The embedding supplies its own candidate with a self-consistent
        # digest. It omits a selected effect the gate would have refused.
        forged = replace(state.candidate, output_atoms=(),
                         after=state.candidate.before)
        digest = certificate_digest(forged)
        yield "submit_caller_certificate", replace(
            state, candidate=forged, candidate_certificate_digest=digest,
            gate_receipt=GateReceipt(CALLER_ISSUER, digest),
            caller_certificate_used=True,
        )
    if norm_commit_pending(state):
        for actor in (0, 1):
            if not coordinator_up(state, actor):
                continue
            if (a.ledger_locked_by == -1 and state.norm_up and
                    defect != "skip_norm_commit_recovery"):
                # Recovery retakes the norm exclusion and reads the durable
                # commit. It never revalidates or commits a second time.
                yield f"recover_norm_commit_owner{actor}", replace(
                    state, admission=replace(a, ledger_locked_by=actor))
            if a.ledger_locked_by != actor or a.owner != actor:
                continue
            if state.norm_up:
                yield f"abort_norm_commit_owner{actor}", replace(
                    state, norm_record=replace(record, status="aborted"),
                    admission=replace(a, ledger_locked_by=-1),
                )
            candidate = state.candidate
            if a.owner_fence != actor or a.held or a.branch_epoch != 0:
                continue
            if (not w.ref_up and defect != "fail_open_ref_outage") or not w.ref_enabled:
                continue
            if (candidate is None or not state.source_available or
                    not state.candidate_available or
                    state.candidate_source_cut not in state.source_ancestry):
                continue
            if (certificate_digest(candidate) != state.candidate_certificate_digest and
                    defect != "skip_certificate_digest_check"):
                continue
            if record.digest != state.candidate_certificate_digest:
                continue
            if (not receipt_authentic(state.gate_receipt, record.digest) and
                    defect != "accept_unauthenticated_certificate"):
                continue
            # A durable norm commit does not freeze the independent ref
            # authority's origin Hold/epoch vector. Recovery must recheck it.
            checked_lineage = (("D",) if defect == "current_branch_only"
                               else candidate.certificate_lineage)
            if not policy_clear(state, checked_lineage):
                continue
            if (defect != "ignore_origin_epoch" and
                    not policy_current(state, candidate, checked_lineage)):
                continue
            if not all(w.units[i] == holder_kind(state.source_kind)
                       for i in candidate.selected):
                continue
            # The ref store moves trunk and records the selected units in its
            # entry. The review store's per-unit receipt is a later write.
            yield f"ref_cas_owner{actor}", replace(
                state,
                admission=replace(
                    a, trunk=1, ledger_locked_by=-1,
                    admission=(record.revision, record.granted, a.held,
                               record.principal, a.branch_epoch, True,
                               actor, a.owner == actor),
                ),
                admitted_source_cut=state.candidate_source_cut,
                admitted_source_ancestry=state.source_ancestry,
                admitted_candidate=candidate,
                admitted_certificate_digest=state.candidate_certificate_digest,
                admitted_gate_receipt=state.gate_receipt,
                admitted_policy_epochs=state.policy_epochs,
                admitted_held=state.held,
                admitted_norm_up=record.norm_up,
                admitted_ref_up=w.ref_up,
                admitted_trunk_before=state.trunk_content,
                trunk_content=candidate.after,
                source_receipt_owed=True, cas_by=actor, cas_actor_lost=False,
            )
    if state.source_receipt_owed and state.admitted_candidate is not None:
        recovering = state.cas_actor_lost or not coordinator_up(state, state.cas_by)
        if (any(coordinator_up(state, actor) for actor in (0, 1)) and
                not (recovering and defect == "skip_source_receipt_recovery")):
            # Recovery replays the durable ref entry into the review store.
            yield "write_source_receipt", replace(
                state, source_receipt_owed=False,
                obligations=account_units(state, w,
                                          state.admitted_candidate.selected),
            )


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
            source = exact_cut(state.cuts, "B", w.branch_cut)
            yield "transport_B_to_C", replace(
                state, transport_stage=1, transport_cut_id=source.identity,
                actual_lineage=("B", "C"),
                recorded_lineage=("B", "C"),
                cuts=append_cut(state.cuts, Cut(
                    "C", source.identity, ("B", source.identity), source.atoms,
                )),
            )
        if state.transport_stage == 1:
            source = exact_cut(state.cuts, "C", state.transport_cut_id)
            transported = Cut("D", source.identity,
                              None if defect == "transport_forgets_parent"
                              else ("C", source.identity),
                              () if defect == "transport_omits_atom" else
                              tuple(atom for atom in source.atoms if atom != "u1:y")
                              if defect == "transport_omits_dependent_atom" else source.atoms)
            yield "transport_C_to_D", replace(
                state, transport_stage=2, actual_lineage=("B", "C", "D"),
                recorded_lineage=(("C", "D") if defect == "lose_origin"
                                  else ("B", "C", "D")),
                cuts=(state.cuts + (transported,)
                      if defect in ("transport_omits_atom", "transport_omits_dependent_atom") else
                      append_cut(state.cuts, transported)),
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
    if (state.candidate is not None and not a.admission and
            not state.source_rewrite_used and w.ref_up and w.ref_enabled and
            all(w.units[i] == holder_kind(state.source_kind)
                for i in state.candidate.selected)):
        # A ref-fenced rewrite or repair can retain the immutable old body
        # under an attempt pin while removing it from the active head's
        # ancestry. That is different from appending an unselected tail.
        next_cut = source_head(state) + 1
        rewritten = (replace(w, twig_cuts=work.at(w.twig_cuts, 0, next_cut),
                             epoch=w.epoch + 1)
                     if state.source_kind == "twig" else
                     replace(w, branch_cut=next_cut,
                             epoch=w.epoch + 1))
        rewritten_cuts = append_cut(state.cuts, Cut(
            "twig0" if state.source_kind == "twig" else "branch",
            next_cut, None,
            exact_cut(state.cuts,
                      "twig0" if state.source_kind == "twig" else "branch",
                      source_head(state)).atoms,
        ))
        if state.source_kind == "mixed":
            rewritten_cuts = append_cut(rewritten_cuts, Cut(
                "B", next_cut, None, exact_cut(state.cuts, "B", source_head(state)).atoms,
            ))
        yield "rewrite_selected_prefix", replace(
            state, obligations=rewritten,
            cuts=rewritten_cuts,
            source_ancestry=(next_cut,),
            source_rewrite_used=True,
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
        if (state.norm_record is not None and
                event.startswith(("lock_and_validate", "cas_owner"))):
            continue  # The durable norm commit is recovered, never redone.
        if event == "gate_pass":
            if state.source_kind == "mixed" and state.transport_stage != 2:
                continue
            if state.source_kind != "twig":
                if w.units[0] != "branch" or not w.branch_pins[0]:
                    continue
                source_cut = (state.transport_cut_id if state.source_kind == "mixed"
                              else w.branch_cut)
            else:
                if w.units[0] != "twig" or not w.twig_pins[0]:
                    continue
                source_cut = w.twig_cuts[0]
            source_evidence = exact_cut(
                state.cuts, ("twig0" if state.source_kind == "twig" else
                             "D" if state.source_kind == "mixed" else "branch"),
                source_cut,
            )
            selections = ((0,),)
            if (state.source_kind in ("branch", "mixed") and
                    w.units[1] == "branch" and w.branch_pins[1]):
                selections += ((0, 1),)
            for selected in selections:
                candidate = candidate_for(selected, source_evidence,
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
                    "handoff_omits_atom",
                    "handoff_invents_atom",
                    "transport_omits_atom",
                    "transport_omits_dependent_atom",
                ):
                    continue
                if source_cut_error(state.cuts, candidate) and defect not in (
                    "transport_forgets_parent", "transport_omits_atom",
                    "transport_omits_dependent_atom",
                ):
                    continue
                name = "gate_pass_both" if len(selected) == 2 else event
                yield name, replace(state, admission=next_a,
                                    candidate_source_cut=source_cut,
                                    candidate=candidate,
                                    candidate_certificate_digest=certificate_digest(candidate),
                                    gate_receipt=GateReceipt(
                                        GATE_ISSUER, certificate_digest(candidate)),
                                    source_attempt_pin=True,
                                    candidate_attempt_pin=(defect != "drop_candidate_pin"),
                                    candidate_available=True)
        elif event == "hold":
            # Close uses this ref-owned mutation below. A separate Hold has
            # the same eligibility effect and can race a candidate.
            yield event, replace(state, admission=next_a)
        elif event.startswith("cas_owner"):
            if ((not w.ref_up and defect != "fail_open_ref_outage") or
                    (state.candidate_source_cut not in state.source_ancestry and
                     defect != "trust_stale_branch_cut" and
                     not (defect == "cas_ignores_abandonment" and
                          w.abandonment_receipt))):
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
            if (not receipt_authentic(state.gate_receipt,
                                      state.candidate_certificate_digest) and
                    defect != "accept_unauthenticated_certificate"):
                continue
            if state.cross_store:
                # The norm ledger commits first, under its write exclusion,
                # binding the gate receipt's digest. Ref CAS follows below.
                if ((state.norm_up or defect == "fail_open_norm_outage") and
                        w.ref_enabled and
                        all(w.units[i] == holder_kind(state.source_kind)
                            for i in state.candidate.selected)):
                    actor = int(event.removeprefix("cas_owner"))
                    yield f"norm_commit_owner{actor}", replace(
                        state, norm_record=NormRecord(
                            "committed", state.candidate_certificate_digest,
                            actor, a.norm_revision, a.principal_granted,
                            a.validated_principal_identity, state.norm_up,
                        ),
                    )
                continue
            if defect == "disable_without_ref_fence" and not w.ref_enabled:
                yield event, replace(state, admission=next_a,
                                     admitted_source_cut=state.candidate_source_cut,
                                     admitted_source_ancestry=state.source_ancestry,
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
                                     admitted_source_cut=state.candidate_source_cut,
                                     admitted_source_ancestry=state.source_ancestry,
                                     admitted_candidate=state.candidate,
                                     admitted_certificate_digest=state.candidate_certificate_digest,
                                     admitted_gate_receipt=state.gate_receipt,
                                     admitted_policy_epochs=state.policy_epochs,
                                     admitted_held=state.held,
                                     admitted_norm_up=state.norm_up,
                                     admitted_ref_up=w.ref_up,
                                     admitted_trunk_before=state.trunk_content,
                                     trunk_content=(state.trunk_content
                                                    if defect == "cas_omits_output"
                                                    else state.candidate.after))
        elif event == "crash_operator0":
            # A crash loses the coordinator's volatile progress. Durable
            # records in the norm ledger, ref store and review store remain.
            yield event, replace(
                state, admission=next_a,
                cas_actor_lost=(state.cas_actor_lost or
                                (state.source_receipt_owed and state.cas_by == 0)),
            )
        else:
            yield event, replace(state, admission=next_a)

    if state.cross_store:
        yield from cross_store_steps(state, defect)

    owed_units = (state.admitted_candidate.selected
                  if state.source_receipt_owed and state.admitted_candidate
                  else ())
    for event, next_w in work.steps(w):
        if event.startswith("admit"):
            continue  # Only the ref CAS above may account a unit.
        if state.source_kind == "twig" and (
            event.endswith("1") or event in ("request_close", "disable", "close") or
            event.startswith(("park", "resolve", "handoff"))
        ):
            continue  # A direct twig has no branch handoff or member closure.
        if owed_units and defect != "skip_source_receipt_recovery" and (
            event in ("abandon_dependent_closure", "close") or
            any(event == f"park{unit}" for unit in owed_units)
        ):
            # The ref entry, not the review store, is authoritative for a
            # unit it admitted: no other disposition until its receipt lands.
            continue
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
            if (norm_commit_pending(state) and
                    defect != "skip_norm_commit_recovery"):
                continue
            if not a.admission or a.receipt or defect == "close_omits_recovery":
                yield event, replace(state, obligations=next_w)
        else:
            ancestry = state.source_ancestry
            cuts = state.cuts
            if event.startswith("write"):
                unit = int(event.removeprefix("write"))
                line = f"twig{unit}"
                parent = exact_cut(cuts, line, w.twig_cuts[unit])
                cuts = append_cut(cuts, Cut(
                    line, next_w.twig_cuts[unit], (line, parent.identity),
                    parent.atoms + declared_atoms((unit,)),
                ))
            elif event.startswith("handoff"):
                unit = int(event.removeprefix("handoff"))
                parent = exact_cut(cuts, "branch", w.branch_cut)
                twig = exact_cut(cuts, f"twig{unit}", w.twig_cuts[unit])
                moved = source_atoms(twig, (unit,))
                if defect == "handoff_omits_atom":
                    moved = ()
                elif defect == "handoff_invents_atom":
                    moved += (f"unclassified:{unit}",)
                cuts = append_cut(cuts, Cut(
                    "branch", next_w.branch_cut, ("branch", parent.identity),
                    parent.atoms + moved,
                ))
                if state.source_kind == "mixed":
                    cuts = append_cut(cuts, Cut(
                        "B", next_w.branch_cut,
                        ("B", w.branch_cut) if w.branch_cut else ("branch", w.branch_cut),
                        parent.atoms + moved,
                    ))
            elif event == "abandon_dependent_closure":
                cuts = append_cut(cuts, Cut("branch", next_w.branch_cut, None, ()))
                if state.source_kind == "mixed":
                    cuts = append_cut(cuts, Cut("B", next_w.branch_cut, None, ()))
            if state.source_kind == "twig":
                if next_w.twig_cuts[0] != w.twig_cuts[0]:
                    ancestry += (next_w.twig_cuts[0],)
            elif next_w.branch_cut != w.branch_cut:
                ancestry = ((next_w.branch_cut,)
                            if event == "abandon_dependent_closure" else
                            ancestry + (next_w.branch_cut,))
            yield event, replace(state, obligations=next_w,
                                 source_ancestry=ancestry, cuts=cuts)

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
    aborted = (state.norm_record is not None and
               state.norm_record.status == "aborted")
    if ((aborted or a.admission and not state.source_receipt_owed and
         (a.receipt and state.frontier_reconciled or
          defect == "release_before_reconciliation")) and
            (state.source_attempt_pin or state.candidate_attempt_pin)):
        yield "release_attempt_pins", replace(
            state, source_attempt_pin=False, candidate_attempt_pin=False,
        )


def violation(state: State):
    a, w = state.admission, state.obligations
    if not state.source_ancestry or state.source_ancestry[-1] != source_head(state):
        return "source head differs from its recorded ancestry"
    if problem := gate.violation(a):
        return problem
    if problem := work.violation(w):
        return problem
    aborted = (state.norm_record is not None and
               state.norm_record.status == "aborted")
    if state.candidate is not None and not aborted and (
        not a.admission or not a.receipt or not state.frontier_reconciled or
        state.source_receipt_owed
    ):
        if not state.source_available:
            return "selected source cut was collected before recovery finished"
        if not state.candidate_available:
            return "candidate cut was collected before recovery finished"
    if w.trunk_receipts and state.source_receipt_owed:
        return "source receipt and its owed marker disagree"
    if ((a.trunk == 1) != bool(w.trunk_receipts) and
            not (a.trunk and state.source_receipt_owed)):
        return "trunk CAS and selected-unit accounting split"
    if state.cross_store and a.trunk and (
        state.norm_record is None or state.norm_record.status != "committed" or
        state.norm_record.digest != state.admitted_certificate_digest
    ):
        return "ref CAS lacks its matching norm commit"
    if state.source_receipt_owed and state.admitted_candidate is not None:
        for unit in state.admitted_candidate.selected:
            if w.units[unit] not in ("twig", "branch"):
                return "ref-admitted unit received a conflicting disposition"
        if w.close == "closed":
            return "closure acknowledged before the source receipt was recovered"
    if w.close == "closed" and norm_commit_pending(state):
        return "closure left a norm commit unresolved"
    if a.trunk and state.admitted_source_cut not in state.admitted_source_ancestry:
        return "selected source prefix was absent from admitted head ancestry"
    if a.trunk:
        if state.admitted_norm_up is not True:
            return "norm authority unavailable at trunk CAS"
        if state.admitted_ref_up is not True:
            return "ref authority unavailable at trunk CAS"
        if not receipt_authentic(state.admitted_gate_receipt,
                                 state.admitted_certificate_digest):
            return "trunk admitted a certificate its gate authority did not issue"
        candidate = state.admitted_candidate
        if candidate is None:
            return "trunk admission lacks its exact candidate"
        if problem := source_cut_error(state.cuts, candidate):
            return problem
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
        if (not state.source_receipt_owed and
                set(w.trunk_receipts) != set(candidate.selected)):
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
    assert both.admitted_candidate.source_cut == Cut(
        "branch", 2, ("branch", 1), ("u0:x", "u1:x", "u1:y")
    )
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

    # A later member extends the same source ancestry. The selected prefix
    # stays immutable and eligible while the later unit remains owed.
    tailed = scenario(prefix + (
        "write1", "declare1", "handoff1", "lock_and_validate_owner0",
        "cas_owner0", "recover_receipt",
    ))
    assert tailed.admitted_source_cut == 1
    assert tailed.admitted_source_ancestry == (0, 1, 2)
    assert tailed.admitted_candidate.source_cut == Cut(
        "branch", 1, ("branch", 0), ("u0:x",)
    )
    assert exact_cut(tailed.cuts, "branch", 2).atoms == ("u0:x", "u1:x", "u1:y")
    assert tailed.obligations.units == ("accounted", "branch")
    assert tailed.obligations.trunk_receipts == (0,)
    tailed_after_lock = scenario(prefix + (
        "lock_and_validate_owner0", "write1", "declare1", "handoff1",
        "cas_owner0",
    ))
    assert tailed_after_lock.obligations.units == ("accounted", "branch")

    # A revision-fenced rewrite retains the old body under the attempt pin,
    # but removes it from the active head's ancestry. Its old gate cannot CAS.
    stale = scenario(prefix + (
        "rewrite_selected_prefix", "lock_and_validate_owner0",
    ))
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
    assert mixed.admitted_candidate.source_cut == Cut("D", 1, ("C", 1), ("u0:x",))
    assert exact_cut(mixed.cuts, "C", 1).parent == ("B", 1)
    assert exact_cut(mixed.cuts, "B", 1).parent == ("branch", 0)
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
        ("transport_omits_atom", ("lock_and_validate_owner0", "cas_owner0"),
         "mixed transport cut omitted its source changes"),
        ("transport_forgets_parent", ("lock_and_validate_owner0", "cas_owner0"),
         "mixed transport cut omitted its source ancestry"),
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
        ("handoff_omits_atom", "retained source cut omitted a selected declared change"),
        ("handoff_invents_atom", "retained source cut contains an unclassified source change"),
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

    # A cut id is immutable, and the certificate digest binds the exact cut
    # record. Replacing that record after gate work cannot borrow its verdict.
    try:
        append_cut(GENESIS_CUTS, Cut("branch", 0, None, ("u0:x",)))
    except AssertionError:
        pass
    else:
        raise AssertionError("a source cut id was reused with changed content")
    checked = scenario(("write0", "declare0", "handoff0", "gate_pass"))
    changed = replace(checked, candidate=replace(
        checked.candidate, source_cut=exact_cut(checked.cuts, "branch", 0)
    ))
    assert not any(name.startswith("cas_owner") for name, _ in steps(
        scenario(("lock_and_validate_owner0",), changed)
    ))
    allowed = scenario(("lock_and_validate_owner0",), changed)
    bypass = [next_state for name, next_state in
              steps(allowed, "skip_certificate_digest_check")
              if name == "cas_owner0"]
    assert len(bypass) == 1
    assert violation(bypass[0]) == "admitted candidate differs from verified certificate digest"

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


RECOVERY_PROGRESS = (
    "ref_cas", "abort_norm_commit", "recover_norm_commit", "write_source_receipt",
    "restart_operator0", "takeover", "norm_restore", "ref_restore",
    "release_ledger",
)


def unrecoverable(state: State, successors) -> str | None:
    """A crash may leave cross-store work owed, never without a way on."""
    if not (norm_commit_pending(state) or state.source_receipt_owed):
        return None
    if any(event.startswith(RECOVERY_PROGRESS) for event, _ in successors):
        return None
    return "cross-store crash left a commit with no recovery path"


def cross_store_trace(events, defect="", initial=None):
    """Follow a named trace; only its last state may violate an invariant."""
    state = State(cross_store=True) if initial is None else initial
    for index, wanted in enumerate(events):
        matches = [successor for event, successor in steps(state, defect)
                   if event == wanted]
        assert len(matches) == 1, (defect, wanted, state)
        state = matches[0]
        if index + 1 < len(events):
            assert violation(state) is None, (defect, wanted, violation(state))
    return state


def cross_store_scenarios():
    prefix = ("write0", "declare0", "handoff0", "gate_pass",
              "lock_and_validate_owner0", "norm_commit_owner0")
    applied = cross_store_trace(prefix + (
        "ref_cas_owner0", "write_source_receipt", "recover_receipt",
        "reconcile_frontier", "release_attempt_pins",
    ))
    assert violation(applied) is None
    assert applied.obligations.trunk_receipts == (0,)

    # Crash between the norm commit and ref CAS. A new owner retakes the
    # norm exclusion, reads the durable commit and completes the same CAS.
    pending = cross_store_trace(prefix + ("crash_operator0",))
    assert norm_commit_pending(pending)
    assert not any(name.startswith(("ref_cas", "norm_commit", "lock_and_validate"))
                   for name, _ in steps(pending))
    taken_over = cross_store_trace(prefix + (
        "crash_operator0", "takeover", "recover_norm_commit_owner1",
        "ref_cas_owner1", "write_source_receipt", "recover_receipt",
        "reconcile_frontier", "release_attempt_pins",
    ))
    assert violation(taken_over) is None
    assert taken_over.admission.admission[6] == 1
    restarted = cross_store_trace(prefix + (
        "crash_operator0", "revoke_original_grant", "restart_operator0",
        "recover_norm_commit_owner0", "ref_cas_owner0", "write_source_receipt",
    ))
    # The commit was ordered before the revocation; its premises stand.
    assert violation(restarted) is None
    assert restarted.admission.norm_revision == 1

    # A Hold that lands after the norm commit fences the ref CAS. Recovery
    # aborts the commit, and only then may the branch close.
    fenced = cross_store_trace(prefix + (
        "crash_operator0", "request_close", "disable", "restart_operator0",
        "recover_norm_commit_owner0",
    ))
    assert not any(name.startswith("ref_cas") for name, _ in steps(fenced))
    assert "close" not in {name for name, _ in steps(fenced)}
    closed = cross_store_trace((), initial=fenced)
    closed = cross_store_trace(("abort_norm_commit_owner0", "park0", "resolve1",
                                "close", "release_attempt_pins"), initial=closed)
    assert violation(closed) is None
    assert closed.norm_record.status == "aborted"
    assert closed.obligations.close == "closed" and not closed.admission.trunk

    # Crash between ref CAS and the review store's source receipt. Until
    # recovery replays the ref entry, no other disposition may take the units.
    both = ("write0", "declare0", "handoff0", "write1", "declare1",
            "handoff1", "gate_pass_both", "lock_and_validate_owner0",
            "norm_commit_owner0", "ref_cas_owner0", "crash_operator0")
    owed = cross_store_trace(both)
    assert owed.source_receipt_owed and owed.obligations.trunk_receipts == ()
    assert not any(name in ("abandon_dependent_closure", "release_attempt_pins")
                   for name, _ in steps(owed))
    recovered = cross_store_trace(both + (
        "takeover", "write_source_receipt", "recover_receipt",
        "reconcile_frontier", "release_attempt_pins",
    ))
    assert violation(recovered) is None
    assert recovered.obligations.trunk_receipts == (0, 1)
    assert recovered.obligations.units == ("accounted", "accounted")

    # An embedding-supplied certificate with a matching digest is refused.
    forged = cross_store_trace(("write0", "declare0", "handoff0", "gate_pass",
                                "submit_caller_certificate",
                                "lock_and_validate_owner0"))
    assert not any(name.startswith("norm_commit") for name, _ in steps(forged))
    print("cross-store recovery traces: norm-commit crash completed by takeover "
          "and by restart, Hold-fenced commit aborted before close, ref-CAS "
          "crash replayed into the source receipt, caller certificate refused")


def cross_store_mutants():
    prefix = ("write0", "declare0", "handoff0", "gate_pass",
              "lock_and_validate_owner0", "norm_commit_owner0")
    both = ("write0", "declare0", "handoff0", "write1", "declare1",
            "handoff1", "gate_pass_both", "lock_and_validate_owner0",
            "norm_commit_owner0", "ref_cas_owner0", "crash_operator0")
    for defect, trace, expected in (
        ("skip_norm_commit_recovery",
         prefix + ("crash_operator0", "request_close", "disable", "park0",
                   "resolve1", "close"),
         "closure left a norm commit unresolved"),
        ("skip_source_receipt_recovery",
         both + ("takeover", "abandon_dependent_closure"),
         "ref-admitted unit received a conflicting disposition"),
        ("accept_unauthenticated_certificate",
         ("write0", "declare0", "handoff0", "gate_pass",
          "submit_caller_certificate", "lock_and_validate_owner0",
          "norm_commit_owner0", "ref_cas_owner0"),
         "trunk admitted a certificate its gate authority did not issue"),
    ):
        state = cross_store_trace(trace, defect)
        assert violation(state) == expected, (defect, violation(state))
        print(f"{defect}: {expected}; " + " -> ".join(trace))


MIXED_PREFIX = ("write0", "declare0", "handoff0", "transport_B_to_C",
                "transport_C_to_D", "gate_pass", "lock_and_validate_owner0",
                "norm_commit_owner0")
MIXED_BOTH_READY = ("write0", "declare0", "handoff0", "write1", "declare1", "handoff1")
MIXED_BOTH_PREFIX = MIXED_BOTH_READY + ("transport_B_to_C", "transport_C_to_D",
                                     "gate_pass_both", "lock_and_validate_owner0",
                                     "norm_commit_owner0")


def mixed_crash_scenarios():
    """Compose retained B/C/D ancestry with all three durable writes."""
    initial = State(source_kind="mixed", cross_store=True)
    pending = cross_store_trace(MIXED_PREFIX + ("crash_operator0",), initial=initial)
    assert norm_commit_pending(pending)
    assert pending.candidate.actual_lineage == ("B", "C", "D")
    assert pending.candidate.source_atoms == ("u0:x",)
    assert pending.candidate.source_cut == Cut("D", 1, ("C", 1), ("u0:x",))
    assert exact_cut(pending.cuts, "C", 1).parent == ("B", 1)
    assert pending.source_attempt_pin and pending.candidate_attempt_pin
    assert not any(name.startswith(("ref_cas", "norm_commit", "lock_and_validate"))
                   for name, _ in steps(pending))

    # Norm authority's completed commit survives loss of the coordinator.
    # Takeover cannot borrow its volatile lock; it must retake exclusion.
    taken_over = cross_store_trace(MIXED_PREFIX + (
        "crash_operator0", "takeover", "recover_norm_commit_owner1",
        "ref_cas_owner1", "write_source_receipt", "recover_receipt",
        "reconcile_frontier", "release_attempt_pins",
    ), initial=initial)
    assert violation(taken_over) is None
    assert taken_over.norm_record == pending.norm_record
    assert taken_over.admission.admission[6] == 1
    assert taken_over.obligations.trunk_receipts == (0,)
    assert taken_over.admitted_candidate == pending.candidate
    assert taken_over.admitted_certificate_digest == pending.norm_record.digest

    # Norm revocation after its durable commit does not rewrite commit-time
    # authority. An independent origin Hold/epoch still fences the ref CAS.
    restarted = cross_store_trace(MIXED_PREFIX + (
        "crash_operator0", "revoke_original_grant", "restart_operator0",
        "recover_norm_commit_owner0", "ref_cas_owner0", "write_source_receipt",
    ), initial=initial)
    assert violation(restarted) is None
    assert restarted.norm_record == pending.norm_record
    assert restarted.admission.norm_revision == 1
    for tail in (("hold_B",), ("hold_B", "release_B")):
        fenced = cross_store_trace(MIXED_PREFIX + (
            "crash_operator0",
        ) + tail + (
            "takeover", "recover_norm_commit_owner1",
        ), initial=initial)
        assert not any(name.startswith("ref_cas") for name, _ in steps(fenced))
        assert fenced.obligations.trunk_receipts == ()
        assert fenced.trunk_content == (0, 0)
        aborted = cross_store_trace(("abort_norm_commit_owner1",), initial=fenced)
        assert violation(aborted) is None
        assert aborted.norm_record.status == "aborted"
        assert aborted.obligations.units[0] == "branch"
        assert aborted.obligations.branch_pins[0]

    # Once the ref wins, later origin policy cannot abandon an admitted unit.
    owed = cross_store_trace(MIXED_PREFIX + (
        "ref_cas_owner0", "crash_operator0",
    ), initial=initial)
    assert owed.source_receipt_owed and owed.obligations.trunk_receipts == ()
    assert not any(name in ("abandon_dependent_closure", "park0", "close",
                            "release_attempt_pins", "collect_candidate", "collect_source")
                   for name, _ in steps(owed))
    recovered = cross_store_trace((
        "takeover", "write_source_receipt", "recover_receipt",
        "reconcile_frontier", "release_attempt_pins",
    ), initial=owed)
    assert violation(recovered) is None
    assert recovered.obligations.trunk_receipts == (0,)
    assert recovered.obligations.units[0] == "accounted"
    assert recovered.admitted_candidate == owed.admitted_candidate
    assert recovered.admitted_gate_receipt == owed.admitted_gate_receipt
    assert recovered.trunk_content == (1, 0)
    # Reopening a reconciled result does not offer another CAS or receipt.
    assert not any(name.startswith(("ref_cas", "norm_commit")) or
                   name == "write_source_receipt" for name, _ in steps(recovered))
    print("mixed cross-store traces: exact B/C/D cut ancestry survives norm-commit "
          "crash/takeover and grant-revoked restart; origin Hold/release fences "
          "ref CAS; CAS crash retains pins and replays one unit receipt")


def mixed_crash_mutants():
    initial = State(source_kind="mixed", cross_store=True)
    for defect, trace, expected in (
        ("lose_origin", MIXED_PREFIX + ("ref_cas_owner0",),
         "transport omitted an origin from the certificate"),
        ("current_branch_only", MIXED_PREFIX + (
            "crash_operator0", "hold_B", "takeover", "recover_norm_commit_owner1",
            "ref_cas_owner1"), "origin Hold was bypassed at trunk CAS"),
        ("ignore_origin_epoch", MIXED_PREFIX + (
            "crash_operator0", "hold_B", "release_B", "takeover",
            "recover_norm_commit_owner1", "ref_cas_owner1"),
         "stale origin policy epoch was admitted"),
        ("transport_omits_atom", MIXED_PREFIX + ("ref_cas_owner0",),
         "mixed transport cut omitted its source changes"),
        ("transport_forgets_parent", MIXED_PREFIX + ("ref_cas_owner0",),
         "mixed transport cut omitted its source ancestry"),
        ("output_id_as_witness", MIXED_PREFIX + ("ref_cas_owner0",),
         "certificate omitted a selected source atom"),
        ("skip_certificate_digest_check", MIXED_PREFIX + (
            "crash_operator0", "swap_candidate_witness", "takeover",
            "recover_norm_commit_owner1", "ref_cas_owner1"),
         "admitted candidate differs from verified certificate digest"),
        ("skip_norm_commit_recovery", MIXED_PREFIX + (
            "crash_operator0", "request_close", "disable", "park0", "resolve1",
            "close"), "closure left a norm commit unresolved"),
        ("skip_source_receipt_recovery", MIXED_PREFIX + (
            "ref_cas_owner0", "crash_operator0", "takeover",
            "request_close", "disable", "park0"),
         "ref-admitted unit received a conflicting disposition"),
        ("release_before_reconciliation", MIXED_PREFIX + (
            "ref_cas_owner0", "crash_operator0", "takeover",
            "write_source_receipt", "release_attempt_pins", "collect_candidate"),
         "candidate cut was collected before recovery finished"),
    ):
        state = cross_store_trace(trace, defect, initial)
        assert violation(state) == expected, (defect, violation(state))
        print(f"mixed cross-store {defect}: {expected}; " + " -> ".join(trace))


def mixed_both_crash_scenarios():
    """The dependent neutralizes its predecessor without disposing its debt."""
    initial = State(source_kind="mixed", cross_store=True)
    pending = cross_store_trace(MIXED_BOTH_PREFIX + ("crash_operator0",), initial=initial)
    candidate = pending.candidate
    assert candidate.selected == (0, 1)
    assert candidate.source_atoms == ("u0:x", "u1:x", "u1:y")
    assert candidate.certificate_atoms == candidate.source_atoms
    assert candidate.source_cut == Cut("D", 2, ("C", 2), candidate.source_atoms)
    assert exact_cut(pending.cuts, "C", 2).parent == ("B", 2)
    assert exact_cut(pending.cuts, "B", 2).parent == ("B", 1)
    assert candidate.dependent_read_basis == 1
    assert candidate.after == (0, 1)
    assert candidate.outcomes == ("neutralized", "applied")
    assert pending.obligations.branch_pins == (True, True)
    for cut in ("norm", "ref"):
        trace = MIXED_BOTH_PREFIX + (
            () if cut == "norm" else ("ref_cas_owner0",)
        ) + ("crash_operator0", "takeover") + (
            ("recover_norm_commit_owner1", "ref_cas_owner1") if cut == "norm" else ()
        )
        owed = cross_store_trace(trace, initial=initial)
        assert violation(owed) is None
        assert owed.source_receipt_owed
        assert owed.obligations.trunk_receipts == ()
        assert owed.obligations.units == ("branch", "branch")
        assert owed.obligations.branch_pins == (True, True)
        assert not any(name in ("park0", "park1", "abandon_dependent_closure",
                                "release_attempt_pins", "collect_candidate")
                       for name, _ in steps(owed))
        completed = cross_store_trace(("write_source_receipt", "recover_receipt",
                                      "reconcile_frontier", "release_attempt_pins"),
                                     initial=owed)
        assert violation(completed) is None
        assert completed.norm_record == pending.norm_record
        assert completed.admitted_candidate == candidate
        assert completed.admitted_certificate_digest == pending.norm_record.digest
        assert completed.obligations.trunk_receipts == (0, 1)
        assert completed.obligations.units == ("accounted", "accounted")
        assert completed.trunk_content == (0, 1)
        assert not any(name.startswith(("norm_commit", "ref_cas")) or
                       name == "write_source_receipt" for name, _ in steps(completed))
    print("mixed two-unit crash traces: three retained source atoms, dependent read "
          "basis and neutralized/applied outcomes survive both crash windows; "
          "one exact selected-set receipt accounts both units")


def mixed_both_crash_mutants():
    initial = State(source_kind="mixed", cross_store=True)
    for defect, tail, expected in (
        ("transport_omits_dependent_atom", ("ref_cas_owner0",),
         "mixed transport cut omitted its source changes"),
        ("omit_source_atom", ("crash_operator0", "takeover",
                              "recover_norm_commit_owner1", "ref_cas_owner1"),
         "certificate omitted a selected source atom"),
        ("omit_predecessor_effect", ("ref_cas_owner0",),
         "candidate omitted a selected source effect"),
        ("stale_dependent_basis", ("ref_cas_owner0",),
         "dependent read basis differs from realized predecessor"),
        ("misstate_neutralization", ("ref_cas_owner0",),
         "per-unit outcome misstates source realization"),
        ("skip_source_receipt_recovery", ("ref_cas_owner0", "crash_operator0",
                                           "takeover", "abandon_dependent_closure"),
         "ref-admitted unit received a conflicting disposition"),
    ):
        trace = MIXED_BOTH_PREFIX + tail
        state = cross_store_trace(trace, defect, initial)
        assert violation(state) == expected, (defect, violation(state))
        print(f"mixed two-unit {defect}: {expected}; " + " -> ".join(trace))


def explore(defect="", depth=12, source_kind="branch", cross_store=False, initial=None):
    initial = (State(source_kind=source_kind, cross_store=cross_store)
               if initial is None else initial)
    queue = deque([(initial, ())])
    seen = {initial}
    while queue:
        state, trace = queue.popleft()
        if problem := violation(state):
            return len(seen), problem, trace
        successors = list(steps(state, defect))
        if state.cross_store and (problem := unrecoverable(state, successors)):
            return len(seen), problem, trace
        if len(trace) == depth:
            continue
        for event, successor in successors:
            if successor not in seen:
                seen.add(successor)
                queue.append((successor, trace + (event,)))
    return len(seen), None, ()


def main():
    scenarios()
    witness_mutants()
    authority_failure_mutants()
    lineage_mutants()
    cross_store_scenarios()
    cross_store_mutants()
    mixed_crash_scenarios()
    mixed_crash_mutants()
    mixed_both_crash_scenarios()
    mixed_both_crash_mutants()
    count, problem, trace = explore(depth=13, source_kind="mixed", cross_store=True)
    assert problem is None, (problem, trace)
    print(f"mixed cross-store lifecycle: {count} safe states through depth 13")
    ready = cross_store_trace(MIXED_BOTH_READY,
                             initial=State(source_kind="mixed", cross_store=True))
    count, problem, trace = explore(depth=13, initial=ready)
    assert problem is None, (problem, trace)
    print(f"mixed two-unit cross-store lifecycle: {count} safe states through "
          "13 transitions after both exact handoffs")
    for source_kind, depth in (("twig", 12), ("branch", 11)):
        count, problem, trace = explore(depth=depth, source_kind=source_kind,
                                        cross_store=True)
        assert problem is None, (problem, trace)
        print(f"cross-store {source_kind} lifecycle: {count} safe states "
              f"through depth {depth}")
    for label, defect, depth in (
        ("skip norm-commit recovery", "skip_norm_commit_recovery", 10),
        ("skip source-receipt recovery", "skip_source_receipt_recovery", 10),
        ("accept unauthenticated certificate",
         "accept_unauthenticated_certificate", 9),
    ):
        count, problem, trace = explore(defect, depth, cross_store=True)
        assert problem, label
        print(f"cross-store {label}: {count} states through depth {depth}; "
              f"{problem}\n  " + " -> ".join(trace))
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
