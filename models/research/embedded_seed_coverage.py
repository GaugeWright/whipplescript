#!/usr/bin/env python3
"""Bounded RC-1 probe for embedded package seeding and retained-program use.

One host binary and one retained program suffice to expose the distinction
between manifest bytes embedded in an artifact and mutable runtime provider
rows. A complete seed pointer binds both the artifact and its installed row
meaning. This is a local seed-class model, not a Home-wide journal proof.
"""

from collections import deque
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class State:
    binary: int = 0
    rows: str = "v0"
    completed: tuple[int, ...] = (0,)
    pending: int | None = None
    target_written: bool = False
    classified_rows: bool = True
    retained_used: bool = False
    claim: bool = False
    used_sound: bool = True


def current_seed_is_exact(s: State) -> bool:
    return (
        s.rows == f"v{s.binary}"
        and s.binary in s.completed
        and s.pending is None
        and s.classified_rows
    )


def retained_use_is_exact(s: State) -> bool:
    # The retained program was accepted under artifact 0. This host has only
    # its current binary, so a later binary needs re-attestation or refusal.
    return (
        s.binary == 0
        and s.rows == "v0"
        and 0 in s.completed
        and s.pending is None
        and s.classified_rows
    )


def steps(s: State, defect: str = ""):
    if s.binary == 0:
        yield "upgrade binary", replace(s, binary=1, claim=False)

    if s.binary == 1 and 1 not in s.completed and s.pending is None:
        yield "register pending seed", replace(s, pending=1, claim=False)

    if s.pending == 1 and not s.target_written:
        yield "write seed rows", replace(
            s, rows="v1", target_written=True, classified_rows=True, claim=False
        )
    if s.pending == 1 and s.target_written:
        yield "complete exact pointer", replace(
            s, completed=s.completed + (1,), pending=None, target_written=False
        )

    if s.rows != "foreign":
        yield "other registration changes provider", replace(
            s, rows="foreign", classified_rows=False, claim=False
        )

    if not s.retained_used and retained_use_is_exact(s):
        yield "use retained program", replace(s, retained_used=True)
    if not s.claim and current_seed_is_exact(s):
        yield "claim current seed class", replace(s, claim=True)

    if defect == "unregistered_write" and s.binary == 1 and s.pending is None:
        yield "write without Home pointer", replace(s, rows="v1", claim=False)
    if defect == "unregistered_write" and s.rows == "v1" and 1 not in s.completed:
        yield "claim from target rows alone", replace(s, claim=True)
    if defect == "pending_use" and s.pending == 1 and s.target_written:
        yield "use pending seed", replace(s, claim=True)
    if defect == "binary_only_claim" and s.rows == "foreign":
        yield "claim from binary digest alone", replace(s, claim=True)
    if defect == "stale_retained_use" and s.binary == 1 and not s.retained_used:
        yield "use old pin under new binary", replace(
            s, retained_used=True, used_sound=retained_use_is_exact(s)
        )
    if defect == "unfenced_row_change" and s.claim and s.rows != "foreign":
        yield "change provider without invalidation", replace(
            s, rows="foreign", classified_rows=False
        )


def violation(s: State) -> str | None:
    if not s.used_sound:
        return "retained program used without its exact artifact and row premise"
    if s.claim and not current_seed_is_exact(s):
        return "complete seed claim lacks a completed pointer or current row meaning"
    return None


def explore(defect: str = "", depth: int = 9):
    initial = State()
    queue = deque([(initial, ())])
    seen = {initial}
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
        assert violation(state) is None, (wanted, violation(state))
    return state


def main():
    before = scenario(("use retained program", "claim current seed class"))
    assert before.retained_used and before.claim
    after = scenario((
        "upgrade binary", "register pending seed", "write seed rows",
        "complete exact pointer", "claim current seed class",
    ))
    assert after.rows == "v1" and after.completed == (0, 1)
    assert not retained_use_is_exact(after)
    count, error, _ = explore()
    assert error is None, error
    print(f"safe search: {count} states; retained use and claims stayed exact")
    for defect in (
        "unregistered_write", "pending_use", "binary_only_claim",
        "stale_retained_use", "unfenced_row_change",
    ):
        count, error, trace = explore(defect)
        assert error is not None, (defect, count)
        print(f"{defect}: {error} after {' -> '.join(trace)}")


if __name__ == "__main__":
    main()
