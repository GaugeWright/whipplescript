#!/usr/bin/env python3
"""Bounded retry and use-door probe for a Home-registered target operation.

One logical request has one stable operation ID and exact basis. A second
caller, or the first caller after a crash, must either find the same immutable
target operation or receive a conflict. A retained-version run reads its old
completed Home pointer; it does not register a new target operation merely
because it runs again. This abstracts store durability and the product's
request-key derivation; neither is proved by the search.
"""

from collections import deque
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class State:
    home: str = "absent"  # absent, pending, completed, refused
    basis: int = -1
    target: int = -1  # -1 absent, otherwise the basis of the immutable write
    epoch: int = 0
    registered_epoch: int = -1
    completed_epoch: int = -1
    rechecked: bool = False
    recovered: bool = False
    crashed: bool = False
    acknowledged: bool = False
    used: bool = False
    sealed: bool = False
    cut: bool = False


def steps(s: State, defect: str = ""):
    if s.home == "absent":
        yield "register exact request", replace(
            s, home="pending", basis=0, registered_epoch=s.epoch)
        if defect == "retained_bypass":
            yield "retained version bypasses Home", replace(s, used=True)
        if defect == "write_without_registration":
            yield "write before register", replace(s, target=0)
    if s.home == "pending":
        # Registering the same ID and meaning is a read of the same row. A
        # different meaning must conflict, so neither action changes state.
        if s.target == -1:
            yield "write exact target", replace(s, target=s.basis)
        else:
            yield "recover exact target", replace(s, recovered=True)
            if defect == "replace_on_duplicate":
                yield "replace duplicate target", replace(s, target=1)
        if not s.crashed:
            yield "crash", replace(
                s, crashed=True,
                home=("absent" if defect == "drop_on_crash" else s.home))
        if s.target != -1 and s.epoch > s.registered_epoch and not s.rechecked:
            yield "revalidate current basis", replace(s, rechecked=True)
        if s.target == s.basis and (s.epoch == s.registered_epoch or s.rechecked
                                      or defect == "late_complete_without_recheck"):
            completed_epoch = (s.registered_epoch if defect == "late_complete_without_recheck"
                               else s.epoch)
            yield "complete Home pointer", replace(
                s, home="completed", completed_epoch=completed_epoch)
        yield "terminal refusal", replace(s, home="refused")
        if defect == "early_ack" and s.target != -1:
            yield "ack pending target", replace(s, acknowledged=True)
    if s.home == "completed":
        yield "ack", replace(s, acknowledged=True)
        # A retained-version run uses this same historical pointer. It has no
        # new target write and owes no new pending registration.
        yield "retained version use", replace(s, used=True)
    if s.home == "refused" and defect == "use_refused":
        yield "use refused target", replace(s, used=True)
    if not s.sealed:
        yield "seal", replace(
            s, sealed=True, epoch=1,
            cut=(s.home == "completed" and s.completed_epoch == 0)
            or (defect == "include_pending_in_cut" and s.home == "pending"))


def violation(s: State):
    if s.target != -1 and s.home == "absent":
        return "target write has no durable Home registration"
    if s.target != -1 and s.basis != s.target:
        return "same operation ID names different target evidence"
    if s.home == "completed" and s.target == -1:
        return "completed pointer lacks target operation"
    if s.home == "completed" and s.completed_epoch != s.registered_epoch and not s.rechecked:
        return "post-seal completion skipped current-basis revalidation"
    if s.sealed and s.cut != (s.home == "completed" and s.completed_epoch == 0):
        return "sealed cut includes pending work or loses a completed operation"
    if (s.acknowledged or s.used) and s.home != "completed":
        return "pending or refused evidence escaped the Home use door"
    return None


def explore(defect="", depth=10):
    queue = deque([(State(), ())])
    seen = {State()}
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
        "register exact request", "write exact target", "crash",
        "recover exact target", "complete Home pointer", "ack", "seal",
        "retained version use"))
    assert recovered.cut and recovered.recovered and recovered.used
    deferred = scenario((
        "register exact request", "write exact target", "seal",
        "recover exact target", "revalidate current basis",
        "complete Home pointer", "ack"))
    assert not deferred.cut and deferred.completed_epoch == 1
    refused = scenario(("register exact request", "seal", "terminal refusal"))
    assert refused.home == "refused" and not refused.cut

    count, error, _ = explore()
    assert error is None, error
    print(f"Home operation retry: {count} safe states through ten transitions")
    for defect in (
        "retained_bypass", "write_without_registration", "replace_on_duplicate",
        "drop_on_crash", "late_complete_without_recheck", "early_ack",
        "use_refused", "include_pending_in_cut",
    ):
        count, error, trace = explore(defect)
        assert error is not None, (defect, count)
        print(f"  {defect}: {error} via {' -> '.join(trace)}")


if __name__ == "__main__":
    main()
