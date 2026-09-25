"""Bounded probe of owner routing and audited dependency pin movement.

Run: python3 models/research/dependency_update.py

One external dependency has an immutable proposed source revision. Repository
A uses it, B uses A, and a graph edit discovers C. A response stands for an
owner migration or an evidence-bearing compatibility answer; the model does
not inspect the migration's content. See README.md for assumptions.
"""

from collections import deque
from dataclasses import dataclass, replace


OWNERS = ("a", "b", "c")


@dataclass(frozen=True)
class Receipt:
    source: int
    graph: int
    owners: tuple[str, ...]
    resolved: tuple[tuple[str, int], ...]
    audit_source: int | None
    gate_source: int | None
    gate_graph: int | None


@dataclass(frozen=True)
class State:
    source: int = 1
    graph: int = 0
    routed: tuple[tuple[str, int, int], ...] = ()
    answered: tuple[tuple[str, int, int], ...] = ()
    blocked: tuple[tuple[str, int, int], ...] = ()
    audit: tuple[int, str] | None = None
    gate: tuple[int, int] | None = None
    pin: int = 0
    receipt: Receipt | None = None
    accounted: bool = False
    crashed: bool = False
    crash_used: bool = False


def affected(s: State) -> tuple[str, ...]:
    return OWNERS[: 2 + s.graph]


def key(owner: str, s: State) -> tuple[str, int, int]:
    return owner, s.source, s.graph


def owner_answers_current(s: State) -> bool:
    return all(key(owner, s) in s.answered for owner in affected(s))


def steps(s: State, defect: str = ""):
    if s.crashed:
        yield "restart", replace(s, crashed=False)
        return
    if not s.crash_used:
        yield "crash", replace(s, crashed=True, crash_used=True)
    if s.receipt is not None:
        if not s.accounted:
            yield "finish accounting", replace(s, accounted=True)
        return

    if s.source == 1:
        yield "replace source", replace(s, source=2)
    if s.graph == 0:
        yield "discover c", replace(s, graph=1)

    for owner in affected(s):
        current = key(owner, s)
        if current not in s.routed:
            yield f"route {owner}", replace(s, routed=s.routed + (current,))
        elif current not in s.answered and current not in s.blocked:
            yield f"answer {owner}", replace(s, answered=s.answered + (current,))
            yield f"block {owner}", replace(s, blocked=s.blocked + (current,))

    if s.audit is None or s.audit[0] != s.source:
        yield "audit pass", replace(s, audit=(s.source, "passed"))
        yield "audit reject", replace(s, audit=(s.source, "rejected"))

    can_gate = owner_answers_current(s)
    if defect == "skip_owner":
        can_gate = True
    if defect == "stale_owner":
        can_gate = all(any(a[0] == owner for a in s.answered)
                       for owner in affected(s))
    if can_gate and s.gate != (s.source, s.graph):
        yield "gate pass", replace(s, gate=(s.source, s.graph))

    audit_ok = s.audit == (s.source, "passed")
    owners_ok = owner_answers_current(s)
    gate_ok = s.gate == (s.source, s.graph)
    if defect == "skip_audit":
        audit_ok = True
    if defect == "stale_audit":
        audit_ok = s.audit is not None and s.audit[1] == "passed"
    if defect == "skip_owner":
        owners_ok = True
    if defect == "stale_owner":
        owners_ok = all(any(a[0] == owner for a in s.answered)
                        for owner in affected(s))
    if defect == "skip_gate":
        gate_ok = True
    if defect == "stale_gate":
        gate_ok = s.gate is not None

    if audit_ok and owners_ok and gate_ok:
        resolved = tuple((owner, s.source) for owner in affected(s))
        if defect == "partial_cut":
            resolved = resolved[:-1]
        receipt = Receipt(
            s.source, s.graph, affected(s), resolved,
            s.audit[0] if s.audit and s.audit[1] == "passed" else None,
            s.gate[0] if s.gate else None,
            s.gate[1] if s.gate else None,
        )
        yield "advance pin", replace(s, pin=s.source, receipt=receipt)


def violation(s: State) -> str | None:
    if s.pin != 0 and s.receipt is None:
        return "pin moved without an exact admission receipt"
    if s.accounted and s.receipt is None:
        return "request accounted without a receipt"
    r = s.receipt
    if r is None:
        return None
    if s.pin != r.source or r.owners != OWNERS[: 2 + r.graph]:
        return "receipt does not describe the accepted cut"
    if r.resolved != tuple((owner, r.source) for owner in r.owners):
        return "accepted cut has missing or conflicting dependency resolutions"
    if not all((owner, r.source, r.graph) in s.answered for owner in r.owners):
        return "affected owner was not resolved on the accepted basis"
    if r.audit_source != r.source:
        return "external pin moved without an audit of that source"
    if (r.gate_source, r.gate_graph) != (r.source, r.graph):
        return "pin moved without a gate on the exact candidate"
    return None


def explore(defect: str = "", depth: int = 8):
    start = State()
    queue = deque([(start, ())])
    seen = {start}
    while queue:
        state, path = queue.popleft()
        error = violation(state)
        if error:
            return len(seen), path, error
        if len(path) == depth:
            continue
        for event, after in steps(state, defect):
            if after not in seen:
                seen.add(after)
                queue.append((after, path + (event,)))
    return len(seen), (), None


def scenario(events: tuple[str, ...], defect: str = "",
             expect_violation: bool = False) -> State:
    state = State()
    for index, event in enumerate(events):
        choices = dict(steps(state, defect))
        assert event in choices, (event, state)
        state = choices[event]
        if index == len(events) - 1 and expect_violation:
            assert violation(state) is not None, (event, state)
        else:
            assert violation(state) is None, (event, violation(state))
    return state


def main():
    happy = scenario((
        "route a", "answer a", "route b", "answer b", "audit pass",
        "gate pass", "advance pin", "crash", "restart",
        "finish accounting",
    ))
    assert happy.pin == 1 and happy.accounted
    expanded = scenario((
        "route a", "answer a", "route b", "answer b", "audit pass",
        "gate pass", "discover c", "route a", "answer a", "route b",
        "answer b", "route c", "answer c", "gate pass", "advance pin",
    ))
    assert expanded.receipt and expanded.receipt.owners == OWNERS
    rejected = scenario(("audit reject", "route a", "answer a",
                         "route b", "answer b", "gate pass"))
    assert "advance pin" not in dict(steps(rejected)) and rejected.pin == 0
    blocked = scenario(("route a", "block a", "route b", "answer b",
                        "audit pass"))
    assert "gate pass" not in dict(steps(blocked)) and blocked.pin == 0
    stale = scenario(("audit pass", "replace source"))
    assert "advance pin" not in dict(steps(stale))
    states, path, error = explore()
    assert error is None, (path, error)
    print(f"dependency update: {states} safe states through 8 steps; scenarios passed")
    for defect in ("skip_owner", "stale_owner", "skip_audit", "stale_audit",
                   "skip_gate", "partial_cut"):
        states, path, error = explore(defect)
        assert error, (defect, states)
        print(f"  {defect}: {error} via {' -> '.join(path)}")
    stale_gate = scenario((
        "route a", "answer a", "route b", "answer b", "gate pass",
        "replace source", "route a", "answer a", "route b", "answer b",
        "audit pass", "advance pin",
    ), defect="stale_gate", expect_violation=True)
    print(f"  stale_gate: {violation(stale_gate)} via explicit scenario")


if __name__ == "__main__":
    main()
