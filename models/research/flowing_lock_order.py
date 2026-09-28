#!/usr/bin/env python3
"""Bounded physical lock-order probe for a norm-to-ref admission.

Run: python3 models/research/flowing_lock_order.py

Two operations require both independent authorities. An admission holds norm
exclusion while it takes the ref lock and compares its candidate. Any other
operation needing both must use the same acquisition order. This models lock
ownership and an unavailable ref, not the authorities' actual transactions.
"""

from collections import deque
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class State:
    admission: str = "start"  # start, norm, both, done, aborted
    other: str = "start"  # start, norm, ref, both, done
    norm_owner: int = -1
    ref_owner: int = -1
    ref_up: bool = True
    outage_used: bool = False
    revoked: bool = False
    committed: bool = False


def steps(s: State, defect: str = ""):
    if s.admission == "start" and s.norm_owner == -1 and not s.revoked:
        yield "admission takes norm", replace(s, admission="norm", norm_owner=0)
    if s.admission == "norm" and s.ref_up and s.ref_owner == -1:
        yield "admission takes ref", replace(s, admission="both", ref_owner=0)
    if s.admission == "both" and s.ref_up:
        yield "admission commits", replace(
            s, admission="done", norm_owner=-1, ref_owner=-1, committed=True
        )

    if s.other == "start":
        if defect == "reverse_order" and s.ref_up and s.ref_owner == -1:
            yield "other takes ref first", replace(s, other="ref", ref_owner=1)
        elif defect != "reverse_order" and s.norm_owner == -1:
            yield "other takes norm", replace(s, other="norm", norm_owner=1)
    if s.other == "norm" and s.ref_up and s.ref_owner == -1:
        yield "other takes ref", replace(s, other="both", ref_owner=1)
    if s.other == "ref" and s.norm_owner == -1:
        yield "other takes norm second", replace(s, other="both", norm_owner=1)
    if s.other == "both" and s.ref_up:
        yield "other finishes", replace(s, other="done", norm_owner=-1, ref_owner=-1)

    if not s.outage_used and s.ref_up and s.ref_owner == -1:
        yield "ref unavailable", replace(s, ref_up=False, outage_used=True)
    if not s.ref_up:
        yield "ref recovers", replace(s, ref_up=True)
        if s.admission == "norm":
            yield "admission abandons on ref outage", replace(
                s, admission="aborted",
                norm_owner=0 if defect == "retain_norm_on_outage" else -1,
            )
    # A grant revocation needs norm exclusion but need not take the ref lock.
    # It can progress after an admission abandons a missing ref.
    if s.norm_owner == -1 and not s.revoked:
        yield "revoke grant", replace(s, revoked=True)


def violation(s: State):
    if s.admission == "norm" and s.other == "ref" and s.norm_owner == 0 and s.ref_owner == 1:
        return "norm/ref circular wait"
    if s.admission == "aborted" and s.norm_owner == 0:
        return "aborted admission stranded norm exclusion"
    if s.committed and s.admission != "done":
        return "commit without admission completion"
    if s.admission in ("done", "aborted") and s.ref_owner == 0:
        return "finished admission kept the ref lock"
    if s.other == "done" and (s.norm_owner == 1 or s.ref_owner == 1):
        return "finished operation kept a lock"
    return None


def explore(defect="", depth=8):
    start = State()
    queue = deque([(start, ())])
    seen = {start}
    while queue:
        state, trace = queue.popleft()
        error = violation(state)
        if error:
            return len(seen), error, trace
        if len(trace) == depth:
            continue
        for event, after in steps(state, defect):
            if after not in seen:
                seen.add(after)
                queue.append((after, trace + (event,)))
    return len(seen), None, ()


def scenario(events):
    state = State()
    for wanted in events:
        successors = [after for event, after in steps(state) if event == wanted]
        assert len(successors) == 1, (wanted, state)
        state = successors[0]
        assert violation(state) is None, (wanted, state)
    return state


def main():
    normal = scenario(("admission takes norm", "admission takes ref", "admission commits"))
    assert normal.committed and normal.norm_owner == normal.ref_owner == -1
    waiting = scenario(("admission takes norm",))
    assert "other takes norm" not in {event for event, _ in steps(waiting)}
    after_wait = scenario(("admission takes norm", "admission takes ref",
                           "admission commits", "other takes norm",
                           "other takes ref", "other finishes"))
    assert after_wait.other == "done"
    outage = scenario(("admission takes norm", "ref unavailable",
                       "admission abandons on ref outage", "revoke grant"))
    assert outage.revoked and not outage.committed
    shared_order = scenario(("other takes norm", "other takes ref", "other finishes",
                             "admission takes norm", "admission takes ref",
                             "admission commits"))
    assert shared_order.committed

    count, error, _ = explore()
    assert error is None, error
    print(f"norm-before-ref: {count} safe states through eight transitions")
    for defect in ("reverse_order", "retain_norm_on_outage"):
        count, error, trace = explore(defect)
        assert error, (defect, count)
        print(f"  {defect}: {error} via {' -> '.join(trace)}")


if __name__ == "__main__":
    main()
