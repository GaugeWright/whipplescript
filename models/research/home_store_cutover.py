#!/usr/bin/env python3
"""Bounded Home target-store cutover probe for the accepted operation journal.

Two possible runtime stores are enough to expose a late create or restore. The
candidate protocol stops old writers before inventory, records each existing
store as legacy-unknown, and requires a Home pending pointer before a new
store incarnation or re-attestation writes target evidence. Only completed
exact evidence can discharge unknown coverage. This models an authoritative
writer exclusion as a premise; GaugeDesk does not yet implement or prove it.
"""

from collections import deque
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class Target:
    physical: bool = False
    incarnation: int = 0
    catalogued: int = 0
    legacy_unknown: bool = False
    operation: str = "absent"  # absent, pending, written, completed
    installed: bool = False
    used_exact: bool = False
    used_legacy: bool = False
    legacy_use_sound: bool = True


@dataclass(frozen=True)
class State:
    targets: tuple[Target, Target] = (Target(True, 1, installed=True), Target())
    old_writers_stopped: bool = False
    cutover_closed: bool = False
    claimed_complete: bool = False
    claim_sound: bool = True


def change(s: State, index: int, target: Target, **rest):
    targets = list(s.targets)
    targets[index] = target
    return replace(s, targets=tuple(targets), **rest)


def truly_complete(s: State):
    return s.cutover_closed and s.old_writers_stopped and all(
        not t.physical or (
            t.catalogued == t.incarnation
            and t.operation == "completed"
            and t.installed
            and not t.legacy_unknown
        )
        for t in s.targets
    )


def steps(s: State, defect: str = ""):
    if not s.old_writers_stopped:
        yield "stop old writers", replace(s, old_writers_stopped=True)
        if not s.cutover_closed:
            for index, t in enumerate(s.targets):
                if not t.physical:
                    yield f"old writer creates {index}", change(
                        s, index, replace(t, physical=True, incarnation=1, installed=True))
    if not s.cutover_closed and (s.old_writers_stopped or defect == "inventory_without_exclusion"):
        targets = tuple(
            replace(t, catalogued=t.incarnation, legacy_unknown=True)
            if t.physical else t for t in s.targets
        )
        yield "close legacy inventory", replace(s, targets=targets, cutover_closed=True)

    if not s.cutover_closed:
        return

    for index, t in enumerate(s.targets):
        if not t.physical and t.operation == "absent":
            yield f"register new {index}", change(
                s, index, replace(t, incarnation=t.incarnation + 1,
                                  catalogued=t.incarnation + 1, operation="pending"))
        if t.physical and t.operation == "absent" and t.legacy_unknown:
            yield f"register legacy recheck {index}", change(
                s, index, replace(t, operation="pending"))
        if t.physical and t.operation == "completed":
            yield f"register restore {index}", change(
                s, index, replace(t, incarnation=t.incarnation + 1,
                                  catalogued=t.incarnation + 1, operation="pending",
                                  installed=False, used_exact=False))
        if t.operation == "pending":
            yield f"write target {index}", change(
                s, index, replace(t, physical=True, installed=True, operation="written"))
        if t.operation == "written":
            yield f"complete pointer {index}", change(
                s, index, replace(t, operation="completed", legacy_unknown=False))
        if t.operation == "completed" and t.installed:
            yield f"use exact {index}", change(s, index, replace(t, used_exact=True))
        if t.legacy_unknown and t.physical and t.catalogued == t.incarnation:
            yield f"continue unknown {index}", change(
                s, index, replace(t, used_legacy=True,
                                  legacy_use_sound=t.legacy_use_sound and t.legacy_unknown))

        if defect == "write_before_register" and not t.physical:
            yield f"write unregistered {index}", change(
                s, index, replace(t, physical=True, incarnation=t.incarnation + 1,
                                  installed=True))
        if defect == "restore_without_generation" and t.physical and t.operation == "completed":
            yield f"restore without fence {index}", change(
                s, index, replace(t, incarnation=t.incarnation + 1, installed=True))
        if defect == "use_pending" and t.operation in ("pending", "written"):
            yield f"use pending {index}", change(s, index, replace(t, used_exact=True))

    if defect == "inventory_without_exclusion" and not s.old_writers_stopped:
        for index, t in enumerate(s.targets):
            if not t.physical:
                yield f"late old writer creates {index}", change(
                    s, index, replace(t, physical=True, incarnation=1, installed=True))

    if not s.claimed_complete and (
        truly_complete(s) or defect == "unknown_as_complete"
    ):
        yield "claim complete", replace(
            s, claimed_complete=True, claim_sound=truly_complete(s))


def violation(s: State):
    for t in s.targets:
        if s.cutover_closed and t.physical and t.catalogued != t.incarnation:
            return "physical store incarnation escaped the Home catalogue"
        if t.used_exact and (t.operation != "completed" or not t.installed):
            return "runtime used pending or missing target evidence"
        if not t.legacy_use_sound:
            return "legacy use lost its explicit unknown classification"
    if s.claimed_complete and not s.claim_sound:
        return "Home claimed complete despite an unknown store or operation"
    return None


def explore(defect="", depth=11):
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
    old = scenario(("stop old writers", "close legacy inventory", "continue unknown 0"))
    assert old.targets[0].used_legacy and not truly_complete(old)
    certified = scenario((
        "stop old writers", "close legacy inventory", "register legacy recheck 0",
        "write target 0", "complete pointer 0", "register new 1",
        "write target 1", "complete pointer 1", "claim complete",
    ))
    assert certified.claimed_complete and certified.claim_sound
    restored = scenario((
        "stop old writers", "close legacy inventory", "register legacy recheck 0",
        "write target 0", "complete pointer 0", "register restore 0",
        "write target 0", "complete pointer 0", "use exact 0",
    ))
    assert restored.targets[0].incarnation == 2 and restored.targets[0].used_exact

    count, error, _ = explore()
    assert error is None, error
    print(f"Home store cutover: {count} safe states through eleven transitions")
    for defect in (
        "inventory_without_exclusion", "write_before_register",
        "restore_without_generation", "use_pending", "unknown_as_complete",
    ):
        count, error, trace = explore(defect)
        assert error is not None, (defect, count)
        print(f"  {defect}: {error} via {' -> '.join(trace)}")


if __name__ == "__main__":
    main()
