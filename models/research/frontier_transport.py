#!/usr/bin/env python3
"""Small executable probe of a repeatable branch admission frontier.

Run: python3 models/research/frontier_transport.py
This is a content-only abstraction; it does not implement VCS reconciliation.
"""

from dataclasses import dataclass, replace
from hashlib import sha256


@dataclass(frozen=True)
class Change:
    identity: str
    path: str
    before: int
    after: int


@dataclass(frozen=True)
class Submission:
    op: str
    intent: str
    source_cut: str
    selected: tuple[Change, ...]
    base: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class Receipt:
    submission: Submission
    accounted: tuple[str, ...]
    output_change_id: str
    after: tuple[tuple[str, int], ...]
    outcomes: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class State:
    changes: tuple[Change, ...] = ()
    branch_cut: str = "empty"
    trunk: tuple[tuple[str, int], ...] = ()
    receipts: tuple[Receipt, ...] = ()


@dataclass(frozen=True)
class DeclaredUnit:
    identity: str
    source_cut: str
    pin: str
    changes: tuple[Change, ...]


@dataclass(frozen=True)
class HandoffCandidate:
    target_branch: str
    parent_cut: str
    target_before: tuple[tuple[str, int], ...]
    target_after: tuple[tuple[str, int], ...]
    target_cut: str
    recorded_manifest_hash: str


@dataclass(frozen=True)
class HandoffReceipt:
    unit: str
    source_changes: tuple[str, ...]
    target_cut: str
    target_before: tuple[tuple[str, int], ...]
    target_after: tuple[tuple[str, int], ...]


def manifest_hash(entries: tuple[tuple[str, int], ...]) -> str:
    return sha256(repr(entries).encode()).hexdigest()


def candidate(before: tuple[tuple[str, int], ...],
              after: tuple[tuple[str, int], ...], cut: str) -> HandoffCandidate:
    return HandoffCandidate("branch", "branch-base", before, after, cut,
                            manifest_hash(after))


def handoff(
    unit: DeclaredUnit,
    candidate: HandoffCandidate,
    twig_changes: tuple[Change, ...],
    target_head: tuple[tuple[str, int], ...],
    defect: str = "",
) -> HandoffReceipt:
    """Check an exact source selection and its target content before transfer.

    The real planner must derive `unit.changes` from retained source provenance;
    a caller-provided list is not a valid production witness.
    """
    if target_head != candidate.target_before:
        raise ValueError("stale target")
    if (candidate.target_branch != "branch"
            or candidate.parent_cut != "branch-base"
            or candidate.recorded_manifest_hash != manifest_hash(candidate.target_after)):
        raise ValueError("target cut metadata mismatch")
    if not unit.changes or any(change not in twig_changes for change in unit.changes):
        raise ValueError("missing source identity")
    if len({change.identity for change in unit.changes}) != len(unit.changes):
        raise ValueError("duplicate source identity")
    if defect != "cut_metadata_only":
        by_path: dict[str, list[Change]] = {}
        for change in unit.changes:
            by_path.setdefault(change.path, []).append(change)
        expected = dict(candidate.target_before)
        for path, writes in by_path.items():
            before, after = writes[0].before, writes[-1].after
            if any(left.after != right.before for left, right in zip(writes, writes[1:])):
                raise ValueError("incoherent selected source path")
            current = expected.get(path, 0)
            if current == after:
                continue  # An equivalent result still needs its receipt.
            if current != before:
                raise ValueError("conflicting target")
            expected[path] = after
        if tuple(sorted(expected.items())) != candidate.target_after:
            raise ValueError("target cut omitted or changed selected content")
    return HandoffReceipt(
        unit.identity,
        tuple(change.identity for change in unit.changes),
        candidate.target_cut,
        candidate.target_before,
        candidate.target_after,
    )


def add(state: State, change: Change, cut: str) -> State:
    # A rewrite may carry an old identity, but may not quietly give it a
    # different source effect. Resolution with a changed effect needs a new id.
    for old in state.changes:
        if old.identity == change.identity and old != change:
            raise ValueError("same change identity has divergent content")
    previous = next((old.after for old in reversed(state.changes)
                     if old.path == change.path), 0)
    if change.before != previous:
        raise ValueError("incoherent source history on path")
    if any(old.identity == change.identity for old in state.changes):
        raise ValueError("duplicate source identity")
    return replace(state, changes=state.changes + (change,), branch_cut=cut)


def rewrite(state: State, cut: str) -> State:
    # Rebase rewrites the cut identity; source change identities survive.
    return replace(state, branch_cut=cut)


def accounted(state: State, defect: str = "") -> set[str]:
    if defect == "cut_as_frontier":
        return {
            identity
            for receipt in state.receipts
            if receipt.submission.source_cut == state.branch_cut
            for identity in receipt.accounted
        }
    return {identity for receipt in state.receipts for identity in receipt.accounted}


def submit(state: State, op: str, defect: str = "", intent: str = "task") -> Submission | None:
    pending = tuple(c for c in state.changes if c.identity not in accounted(state, defect))
    if not pending:
        return None
    return Submission(op, intent, state.branch_cut, pending, state.trunk)


def admit(state: State, submission: Submission, defect: str = "") -> tuple[State, Receipt]:
    for receipt in state.receipts:
        if receipt.submission.op == submission.op:
            if receipt.submission != submission:
                raise ValueError("same operation id has different submission meaning")
            return state, receipt  # Exact retry reads durable receipt.
    if state.trunk != submission.base:
        raise ValueError("stale trunk base requires a new candidate and gate")
    if not all(change in state.changes for change in submission.selected):
        raise ValueError("immutable source selection is missing")
    by_path: dict[str, list[Change]] = {}
    for change in submission.selected:
        by_path.setdefault(change.path, []).append(change)
    target = dict(state.trunk)
    outcomes = []
    for path, writes in sorted(by_path.items()):
        before, after = writes[0].before, writes[-1].after
        current = target.get(path, 0)
        if before == after:
            outcomes.append((path, "neutralized"))
        elif current == after:
            outcomes.append((path, "equivalent"))
        elif current == before:
            target[path] = after
            outcomes.append((path, "applied"))
        else:
            raise ValueError(f"conflict on {path}: expected {before}, found {current}")
    selected = tuple(c.identity for c in submission.selected)
    output_id = selected[0] if len(selected) == 1 else f"bundle:{submission.op}"
    receipt = Receipt(
        submission,
        (output_id,) if defect == "output_id_as_frontier" else selected,
        output_id, tuple(sorted(target.items())), tuple(outcomes),
    )
    return replace(state, trunk=receipt.after, receipts=state.receipts + (receipt,)), receipt


def invariant(state: State) -> str | None:
    seen: set[str] = set()
    for receipt in state.receipts:
        selected = tuple(c.identity for c in receipt.submission.selected)
        if receipt.accounted != selected:
            return "output identity lost the source identities it represented"
        for identity in selected:
            if identity in seen:
                return "source change was accounted for twice"
            seen.add(identity)
    return None


def scenarios():
    a = add(State(), Change("a", "x", 0, 1), "cut-a")
    ab = add(a, Change("b", "y", 0, 1), "cut-b")
    first_submission = submit(ab, "op1")
    assert first_submission is not None
    # The mutable branch may receive a tail while this immutable cut is gated.
    with_tail = add(ab, Change("c", "z", 0, 1), "cut-c")
    landed, first = admit(with_tail, first_submission)
    assert tuple(c.identity for c in first.submission.selected) == ("a", "b")
    assert first.output_change_id == "bundle:op1"
    assert landed.trunk == (("x", 1), ("y", 1))
    assert admit(landed, first_submission) == (landed, first)
    changed_meaning = replace(first_submission, source_cut="cut-c")
    try:
        admit(landed, changed_meaning)
    except ValueError as error:
        assert "different submission meaning" in str(error)
    else:
        raise AssertionError("operation id reuse with a changed cut must refuse")
    rebased = rewrite(landed, "cut-b-rebased")
    tail_submission = submit(rebased, "op2")
    assert tail_submission is not None
    assert tuple(c.identity for c in tail_submission.selected) == ("c",)
    tail_landed, second = admit(rebased, tail_submission)
    assert second.accounted == ("c",) and invariant(tail_landed) is None
    assert submit(tail_landed, "op3") is None

    undone_before = add(a, Change("undo-a", "x", 1, 0), "cut-undo")
    neutral, receipt = admit(undone_before, submit(undone_before, "op-neutral"))
    assert neutral.trunk == () and receipt.outcomes == (("x", "neutralized"),)
    one_landed, _ = admit(a, submit(a, "op-a"))
    undone_after = add(one_landed, Change("undo-a", "x", 1, 0), "cut-undo")
    reverted, receipt = admit(undone_after, submit(undone_after, "op-undo"))
    assert reverted.trunk == (("x", 0),) and receipt.accounted == ("undo-a",)

    equivalent_start = replace(a, trunk=(("x", 1),))
    equivalent, receipt = admit(equivalent_start,
                                submit(equivalent_start, "op-equivalent"))
    assert equivalent.trunk == (("x", 1),)
    assert receipt.outcomes == (("x", "equivalent"),)
    try:
        conflict_start = replace(a, trunk=(("x", 2),))
        admit(conflict_start, submit(conflict_start, "op-conflict"))
    except ValueError as error:
        assert "conflict" in str(error)
    else:
        raise AssertionError("conflicting target must refuse")
    try:
        add(a, Change("a", "x", 0, 2), "cut-divergent")
    except ValueError as error:
        assert "divergent" in str(error)
    else:
        raise AssertionError("same identity cannot silently change effect")
    try:
        add(a, Change("impossible", "x", 9, 2), "cut-impossible")
    except ValueError as error:
        assert "incoherent" in str(error)
    else:
        raise AssertionError("source path history must be continuous")

    broken_output, _ = admit(ab, submit(ab, "op1"), "output_id_as_frontier")
    assert invariant(broken_output) == "output identity lost the source identities it represented"
    print("output-id-only counterexample: mixed transport accounts bundle:op1, loses a and b")
    initial, _ = admit(ab, submit(ab, "op1"))
    broken_cut = rewrite(initial, "cut-b-rebased")
    replayed, _ = admit(broken_cut, submit(broken_cut, "op2", "cut_as_frontier"))
    assert invariant(replayed) == "source change was accounted for twice"
    print("raw-cut-id-only counterexample: rewrite selects a and b again")

    # Two declarations share one retained cut. Moving the first unit must
    # leave the second owed, even though the cut and pin are the same.
    unit_a = DeclaredUnit("u-a", "twig-cut-ab", "pin-ab", (ab.changes[0],))
    unit_b = DeclaredUnit("u-b", "twig-cut-ab", "pin-ab", (ab.changes[1],))
    candidate_a = candidate((), (("x", 1),), "branch-cut-a")
    receipt_a = handoff(unit_a, candidate_a, ab.changes, ())
    assert receipt_a.source_changes == ("a",)
    assert unit_b.identity != receipt_a.unit
    candidate_b = candidate(candidate_a.target_after,
                            (("x", 1), ("y", 1)), "branch-cut-b")
    assert handoff(unit_b, candidate_b, ab.changes, candidate_a.target_after).source_changes == ("b",)
    omitted = candidate((), (), "branch-cut-empty")
    assert omitted.recorded_manifest_hash == manifest_hash(omitted.target_after)
    try:
        handoff(unit_a, omitted, ab.changes, ())
    except ValueError as error:
        assert "omitted" in str(error)
    else:
        raise AssertionError("a cut with the right metadata cannot omit the unit")
    defective = handoff(unit_a, omitted, ab.changes, (), "cut_metadata_only")
    assert defective.target_after == () and defective.source_changes == ("a",)
    print("cut-metadata-only counterexample: handoff accounts a while target omits x")
    print("frontier scenarios: passed")


if __name__ == "__main__":
    scenarios()
