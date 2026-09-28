"""Bounded twig-to-branch holder transfer probe; run this file directly.

One declared unit, its unselected later twig tail, two coordinators, and one
target ref are modeled. Content is a Boolean abstraction: a target candidate
either contains the exact selected effect or omits it. This cannot validate
the real merge engine, content authority, or hosted transaction.
"""

from collections import deque
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class Candidate:
    op: int
    base: int
    contains_unit: bool


@dataclass(frozen=True)
class Receipt:
    op: int
    base: int
    observed_head: int
    after: int
    contains_unit: bool


@dataclass(frozen=True)
class State:
    head: int = 0
    target_contains_unit: bool = False
    candidates: tuple[Candidate | None, Candidate | None] = (None, None)
    receipts: tuple[Receipt, ...] = ()
    handoff_heads: tuple[int, ...] = ()
    holder: str = "twig"
    source_pin: bool = True
    tail_written: bool = False
    tail_pin: bool = False
    delivered: bool = False
    crashed: bool = False
    crash_used: bool = False
    external_moved: bool = False


def violation(s: State) -> str | None:
    if s.holder == "twig" and not s.source_pin and not s.receipts:
        return "twig lost its last pin before transfer"
    if s.holder == "branch" and not s.receipts:
        return "branch claims the unit without a durable receipt"
    if s.tail_written and not s.tail_pin:
        return "unselected twig tail was dropped"
    if len(s.receipts) > 1:
        return "one unit was transferred twice"
    if any(not receipt.contains_unit for receipt in s.receipts):
        return "holder transferred while target omitted selected content"
    if any(receipt.base != receipt.observed_head for receipt in s.receipts):
        return "stale target basis was accepted"
    if any(head not in tuple(receipt.after for receipt in s.receipts)
           for head in s.handoff_heads):
        return "target head moved without its transfer receipt"
    if s.receipts and not s.target_contains_unit:
        return "receipt exists but target has no selected effect"
    return None


def steps(s: State, defect: str = ""):
    if s.crashed:
        yield "restart", replace(s, crashed=False)
        return
    if not s.crash_used:
        yield "crash", replace(s, crashed=True, crash_used=True)
    if not s.tail_written:
        yield "write unselected tail", replace(s, tail_written=True, tail_pin=True)
    if not s.external_moved:
        yield "external target advance", replace(
            s, head=s.head + 1, external_moved=True
        )
    for op in (0, 1):
        if s.candidates[op] is None and (not s.receipts or defect == "double_transfer"):
            for contains in (True, False):
                candidates = list(s.candidates)
                candidates[op] = Candidate(op, s.head, contains)
                label = "complete" if contains else "omitted"
                yield f"prepare {op} {label}", replace(s, candidates=tuple(candidates))
        candidate = s.candidates[op]
        if candidate is None:
            continue
        can_commit = (
            (not s.receipts or defect == "double_transfer")
            and (candidate.base == s.head or defect == "ignore_stale")
            and (candidate.contains_unit or defect == "metadata_only")
        )
        if can_commit:
            after = s.head + 1
            receipt = Receipt(op, candidate.base, s.head, after,
                              candidate.contains_unit)
            if defect == "head_before_receipt":
                yield f"commit {op}", replace(
                    s, head=after,
                    target_contains_unit=s.target_contains_unit or candidate.contains_unit,
                    handoff_heads=s.handoff_heads + (after,),
                )
            else:
                yield f"commit {op}", replace(
                    s, head=after,
                    target_contains_unit=s.target_contains_unit or candidate.contains_unit,
                    handoff_heads=s.handoff_heads + (after,),
                    receipts=s.receipts + (receipt,), holder="branch",
                    tail_pin=False if defect == "drop_tail" else s.tail_pin,
                )
    if s.receipts and not s.delivered:
        yield "deliver receipt", replace(s, delivered=True)
    if s.source_pin and (s.receipts or defect == "release_early"):
        yield "release source pin", replace(s, source_pin=False)


def explore(defect: str = "", depth: int = 8):
    start = State()
    queue = deque([(start, ())])
    seen = {start}
    while queue:
        state, path = queue.popleft()
        error = violation(state)
        if error:
            return len(seen), path, error
        if len(path) >= depth:
            continue
        for event, after in steps(state, defect):
            if after not in seen:
                seen.add(after)
                queue.append((after, path + (event,)))
    return len(seen), (), None


def scenario(events: tuple[str, ...]) -> State:
    state = State()
    for event in events:
        choices = dict(steps(state))
        assert event in choices, (event, state)
        state = choices[event]
        assert violation(state) is None, (event, violation(state))
    return state


def main():
    complete = scenario((
        "prepare 0 complete", "write unselected tail", "commit 0", "crash",
        "restart", "deliver receipt", "release source pin",
    ))
    assert complete.holder == "branch" and complete.tail_pin
    omitted = scenario(("prepare 0 omitted",))
    assert "commit 0" not in dict(steps(omitted))
    raced = scenario(("prepare 0 complete", "prepare 1 complete", "commit 0"))
    assert "commit 1" not in dict(steps(raced))
    stale = scenario(("prepare 0 complete", "external target advance"))
    assert "commit 0" not in dict(steps(stale))
    states, path, error = explore()
    assert error is None, (path, error)
    print(f"twig handoff: {states} safe states through eight steps; scenarios passed")
    for defect in (
        "metadata_only", "release_early", "head_before_receipt",
        "double_transfer", "ignore_stale", "drop_tail",
    ):
        states, path, error = explore(defect)
        assert error, (defect, states)
        print(f"  {defect}: {error} via {' -> '.join(path)}")


if __name__ == "__main__":
    main()
