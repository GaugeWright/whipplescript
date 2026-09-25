#!/usr/bin/env python3
"""Small executable probe of a repeatable branch admission frontier.

Run: python3 models/research/frontier_transport.py
This is a content-only abstraction; it does not implement VCS reconciliation.
"""

from dataclasses import dataclass, replace


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
    print("frontier scenarios: passed")


if __name__ == "__main__":
    scenarios()
