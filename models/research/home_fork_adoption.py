#!/usr/bin/env python3
"""Bounded crash probe for a Home-governed cross-store chat fork/adoption.

The source pin, target program import, and fork handoff are separate durable
facts. The fork pointer is registered before any target write and completed
only after an exact seed and fork event. The target is unusable as an adopted
chat until that final pointer completes, even if its import already completed.
This abstracts immutable event evidence and the Home's epoch revalidation.
"""

from collections import deque
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class State:
    source_pin: bool = False
    source_incarnation: int = 0
    target_incarnation: int = 0
    fork: str = "absent"  # absent, pending, completed
    bound_source: int = -1
    bound_target: int = -1
    import_registered: bool = False
    import_completed: bool = False
    opened: bool = False
    seeded: bool = False
    fork_event: bool = False
    recovered: bool = False
    acknowledged: bool = False
    used: bool = False
    sealed: bool = False
    completed_at_seal: bool = False
    cut_includes_fork: bool = False


def steps(s: State, defect: str = ""):
    if not s.source_pin:
        yield "pin exact source", replace(s, source_pin=True)
    if s.source_pin and s.fork == "absent":
        yield "register fork", replace(
            s, fork="pending", bound_source=s.source_incarnation,
            bound_target=s.target_incarnation)
    if s.fork == "pending" and not s.import_registered:
        yield "register import", replace(s, import_registered=True)
    if s.import_registered and not s.import_completed:
        yield "complete import", replace(s, import_completed=True)
    if s.import_completed and not s.opened:
        yield "open target", replace(s, opened=True)
    if s.opened and not s.seeded:
        yield "seed exact snapshot", replace(s, seeded=True)
    if s.seeded and not s.fork_event:
        yield "record fork event", replace(s, fork_event=True)
    if s.fork == "pending" and s.seeded and s.fork_event:
        if (s.bound_source == s.source_incarnation and
                s.bound_target == s.target_incarnation):
            yield "complete fork pointer", replace(s, fork="completed")
        if defect == "complete_without_seed":
            yield "complete unchecked", replace(s, fork="completed", seeded=False)
    if s.fork == "completed":
        yield "ack fork", replace(s, acknowledged=True)
        yield "use target", replace(s, used=True)
    if s.opened and not s.recovered:
        # A crash may occur after any target step. Exact retry reuses the
        # registered identities and idempotent evidence, not another target.
        yield "crash and retry", replace(s, recovered=True)
        if defect == "lose_pending":
            yield "forget fork on crash", replace(s, fork="absent", recovered=True)
        if defect == "retry_new_target":
            yield "retry into replacement", replace(
                s, target_incarnation=1, recovered=True)
    if s.opened and s.fork != "completed" and defect == "open_is_use":
        yield "use opened target", replace(s, used=True)
    if s.import_completed and s.fork != "completed" and defect == "import_is_ack":
        yield "ack imported target", replace(s, acknowledged=True)
    if s.fork == "pending" and defect == "source_unpinned":
        yield "drop source pin", replace(s, source_pin=False)
    if not s.sealed:
        yield "seal", replace(
            s, sealed=True, completed_at_seal=s.fork == "completed", cut_includes_fork=(
                s.fork == "completed" or defect == "include_pending" and s.fork == "pending"))


def violation(s: State):
    if s.fork != "absent" and not s.source_pin:
        return "fork lost its exact source pin"
    if s.opened and s.fork == "absent":
        return "target exists without a pending Home fork"
    if s.opened and not s.import_completed:
        return "target opened before Home import completion"
    if s.fork == "completed" and not (s.seeded and s.fork_event):
        return "completed fork lacks seed and fork event"
    if s.fork == "completed" and (s.bound_source != s.source_incarnation or
                                  s.bound_target != s.target_incarnation):
        return "completed fork names a replaced source or target store"
    if (s.acknowledged or s.used) and s.fork != "completed":
        return "incomplete fork escaped the Home use door"
    if s.sealed and s.cut_includes_fork != s.completed_at_seal:
        return "sealed cut misstates fork completion"
    return None


def explore(defect="", depth=13):
    start = State()
    seen = {start}
    queue = deque([(start, ())])
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
        assert violation(state) is None, (wanted, state, violation(state))
    return state


def main():
    recovered = scenario((
        "pin exact source", "register fork", "register import",
        "complete import", "open target", "crash and retry",
        "seed exact snapshot", "record fork event", "complete fork pointer",
        "ack fork", "seal", "use target"))
    assert recovered.recovered and recovered.cut_includes_fork and recovered.used
    pending = scenario((
        "pin exact source", "register fork", "register import",
        "complete import", "open target", "seal", "crash and retry"))
    assert not pending.cut_includes_fork and not pending.used

    count, error, _ = explore()
    assert error is None, error
    print(f"Home fork/adoption: {count} safe states through 13 transitions")
    for defect in ("complete_without_seed", "lose_pending", "retry_new_target",
                   "open_is_use", "import_is_ack", "source_unpinned",
                   "include_pending"):
        count, error, trace = explore(defect)
        assert error is not None, (defect, count)
        print(f"  {defect}: {error} via {' -> '.join(trace)}")


if __name__ == "__main__":
    main()
