#!/usr/bin/env python3
"""Bounded private-draft and member-twig closure probe.

Run: python3 models/research/private_pin_closure.py

The ref CAS itself is covered by flowing_recovery.py. Here the unit of
observation is a durable pin or handoff receipt. Physical content, dependency
repair, and target settlement are deliberately abstracted.
"""

from collections import deque
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class Handoff:
    unit: int
    twig_cut: int
    branch_cut: int


@dataclass(frozen=True)
class State:
    # Each twig has one private draft and may declare one durable unit.
    drafts: tuple[str, str] = ("none", "none")  # none, private, released, parked
    draft_pins: tuple[bool, bool] = (False, False)
    ever_written: tuple[bool, bool] = (False, False)
    units: tuple[str, str] = ("none", "none")  # none, twig, branch, parked, accounted
    ever_declared: tuple[bool, bool] = (False, False)
    twig_pins: tuple[bool, bool] = (False, False)
    branch_pins: tuple[bool, bool] = (False, False)
    parked_pins: tuple[bool, bool] = (False, False)
    receipts: tuple[Handoff, ...] = ()
    trunk_receipts: tuple[int, ...] = ()
    twig_cuts: tuple[int, int] = (0, 0)
    branch_cut: int = 0
    members: tuple[str, str] = ("open", "open")  # open, resolved, parked
    close: str = "open"  # open, closing, closed
    ref_enabled: bool = True
    epoch: int = 0
    close_report: tuple[str, ...] = ()
    ref_up: bool = True
    topology_up: bool = True


def at(pair: tuple, i: int, value):
    result = list(pair)
    result[i] = value
    return tuple(result)


def write_private(s: State, i: int) -> State:
    if s.close != "open" or s.members[i] != "open" or s.drafts[i] != "none":
        raise ValueError("private write needs open member and empty draft")
    return replace(s, drafts=at(s.drafts, i, "private"),
                   draft_pins=at(s.draft_pins, i, True),
                   ever_written=at(s.ever_written, i, True),
                   twig_cuts=at(s.twig_cuts, i, s.twig_cuts[i] + 1))


def end_session(s: State, i: int, defect: str = "") -> State:
    # A process or chat ending has no release authority.
    if defect == "session_drops_pin":
        return replace(s, draft_pins=at(s.draft_pins, i, False))
    return s


def release_private(s: State, i: int) -> State:
    if s.drafts[i] != "private" or s.units[i] != "none":
        raise ValueError("only an undeclared private draft may be released")
    return replace(s, drafts=at(s.drafts, i, "released"),
                   draft_pins=at(s.draft_pins, i, False))


def declare(s: State, i: int) -> State:
    if s.close != "open" or s.drafts[i] != "private" or not s.draft_pins[i]:
        raise ValueError("declaration needs a retained exact twig cut")
    if s.units[i] != "none":
        raise ValueError("twig already declared its unit")
    return replace(s, drafts=at(s.drafts, i, "none"),
                   draft_pins=at(s.draft_pins, i, False),
                   units=at(s.units, i, "twig"),
                   twig_pins=at(s.twig_pins, i, True),
                   ever_declared=at(s.ever_declared, i, True))


def handoff(s: State, i: int, conflict: bool = False,
            defect: str = "") -> State:
    if not s.topology_up or s.close != "open" or s.units[i] != "twig":
        raise ValueError("handoff needs open topology and a declared twig unit")
    if conflict:
        if defect == "conflict_drops_unit":
            return replace(s, units=at(s.units, i, "none"),
                           twig_pins=at(s.twig_pins, i, False))
        return s  # refusal names repair basis; twig remains accountable
    receipt = Handoff(i, s.twig_cuts[i], s.branch_cut + 1)
    return replace(s, units=at(s.units, i, "branch"),
                   branch_pins=at(s.branch_pins, i, defect != "missing_branch_pin"),
                   branch_cut=s.branch_cut + 1,
                   receipts=s.receipts + (() if defect == "missing_receipt" else (receipt,)))


def cleanup_twig_pin(s: State, i: int) -> State:
    if s.units[i] != "branch" or not s.branch_pins[i]:
        raise ValueError("new accountable holder has no pin")
    if not any(r.unit == i for r in s.receipts):
        raise ValueError("no exact transfer receipt")
    return replace(s, twig_pins=at(s.twig_pins, i, False))


def admit(s: State, i: int) -> State:
    # Abstract exact passed gate and durable ref entry; flowing_recovery.py
    # checks those premises. Closure must report an admission that won first.
    if not s.ref_up or not s.ref_enabled or s.units[i] != "branch":
        raise ValueError("no eligible shared unit")
    return replace(s, units=at(s.units, i, "accounted"),
                   trunk_receipts=s.trunk_receipts + (i,),
                   branch_pins=at(s.branch_pins, i, False))


def request_close(s: State) -> State:
    if not s.topology_up or s.close != "open":
        raise ValueError("close request needs open topology")
    return replace(s, close="closing")


def disable_admission(s: State) -> State:
    if not s.ref_up or s.close != "closing" or not s.ref_enabled:
        raise ValueError("ref authority has not acknowledged disable")
    return replace(s, ref_enabled=False, epoch=s.epoch + 1)


def park(s: State, i: int) -> State:
    if not s.topology_up or s.close != "closing" or s.ref_enabled:
        raise ValueError("parking for closure needs a ref-fenced close")
    if s.drafts[i] == "private":
        return replace(s, drafts=at(s.drafts, i, "parked"),
                       members=at(s.members, i, "parked"))
    if s.units[i] in ("twig", "branch"):
        return replace(s, units=at(s.units, i, "parked"),
                       parked_pins=at(s.parked_pins, i, True),
                       members=at(s.members, i, "parked"))
    raise ValueError("nothing outstanding to park")


def resolve_member(s: State, i: int) -> State:
    if s.close != "closing" or s.ref_enabled:
        raise ValueError("member resolution needs disabled admission")
    if s.drafts[i] == "private" or s.units[i] in ("twig", "branch"):
        raise ValueError("member has unowned outstanding work")
    return replace(s, members=at(s.members, i, "resolved"))


def acknowledge_close(s: State, defect: str = "") -> State:
    if not s.topology_up or s.close != "closing":
        raise ValueError("no pending close")
    if s.ref_enabled and defect != "close_before_disable":
        raise ValueError("admission still enabled")
    if any(m == "open" for m in s.members) and defect != "close_with_member":
        raise ValueError("member twig remains unresolved")
    if any(u in ("twig", "branch") for u in s.units) and defect != "close_drops_unit":
        raise ValueError("unit remains with closing branch or member")
    report = tuple(f"twig{i}: {s.drafts[i]}/{s.units[i]}" for i in (0, 1)
                   if s.drafts[i] == "parked" or s.units[i] == "parked")
    if defect == "close_omits_parked":
        report = ()
    result = replace(s, close="closed", close_report=report)
    if defect == "close_drops_unit":
        for i in (0, 1):
            if result.units[i] in ("twig", "branch"):
                result = replace(result, units=at(result.units, i, "none"),
                                 twig_pins=at(result.twig_pins, i, False),
                                 branch_pins=at(result.branch_pins, i, False))
    return result


def violation(s: State) -> str | None:
    for i in (0, 1):
        if s.drafts[i] == "private" and not s.draft_pins[i]:
            return "private draft lost its retained pin"
        if s.drafts[i] == "parked" and not s.draft_pins[i]:
            return "parked private draft lost its pin"
        if s.ever_declared[i] and s.units[i] == "none":
            return "declared unit lost its accountable holder"
        if s.units[i] == "twig" and not s.twig_pins[i]:
            return "twig unit lost its pin"
        if s.units[i] == "branch":
            if not s.branch_pins[i]:
                return "branch unit lost its pin"
            if not any(r.unit == i and r.twig_cut == s.twig_cuts[i]
                       for r in s.receipts):
                return "branch assumed unit without exact handoff receipt"
        if s.units[i] == "parked" and not s.parked_pins[i]:
            return "parked unit lost its pin"
        if s.units[i] == "accounted" and i not in s.trunk_receipts:
            return "accounted unit lacks durable trunk receipt"
    if s.close == "closed":
        if s.ref_enabled:
            return "closure acknowledged before ref disable"
        if "open" in s.members:
            return "closure acknowledged with unresolved member"
        if any(u in ("twig", "branch") for u in s.units):
            return "closure acknowledged with outstanding source unit"
        reported = {int(item.split(":", 1)[0].removeprefix("twig"))
                    for item in s.close_report}
        actual = {i for i in (0, 1) if s.drafts[i] == "parked" or s.units[i] == "parked"}
        if reported != actual:
            return "close receipt omitted parked obligations"
    return None


def scenarios() -> None:
    s = write_private(State(), 0)
    s = end_session(s, 0)
    assert s.draft_pins[0]
    s = declare(s, 0)
    assert handoff(s, 0, conflict=True) == s
    s = handoff(s, 0)
    assert s.twig_pins[0] and s.branch_pins[0]  # overlap during cleanup
    s = cleanup_twig_pin(s, 0)
    s = write_private(s, 1)
    s = request_close(s)
    try:
        acknowledge_close(s)
    except ValueError:
        pass
    else:
        raise AssertionError("closure ignored live ref admission")
    s = admit(s, 0)  # CAS wins before ref disable and must survive close
    s = disable_admission(s)
    s = resolve_member(s, 0)
    s = park(s, 1)
    s = acknowledge_close(s)
    assert s.close_report == ("twig1: parked/none",)
    assert s.units[0] == "accounted" and violation(s) is None

    # A shared unit can be parked instead of admitted; the close receipt
    # reports the continuing owner and does not call it integrated.
    parked = handoff(declare(write_private(State(), 0), 0), 0)
    parked = disable_admission(request_close(parked))
    parked = park(parked, 0)
    parked = resolve_member(parked, 1)
    parked = acknowledge_close(parked)
    assert parked.units[0] == "parked"
    assert parked.close_report == ("twig0: none/parked",)
    assert violation(parked) is None

    # Closure with an independently unavailable ref or topology remains
    # pending; neither absence is permission to discard pins.
    closing = request_close(write_private(State(), 0))
    for unavailable, action in ((replace(closing, ref_up=False), disable_admission),
                                (replace(closing, topology_up=False), acknowledge_close)):
        try:
            action(unavailable)
        except ValueError:
            pass
        else:
            raise AssertionError("outage acknowledged closure")


def mutants() -> None:
    private = write_private(State(), 0)
    assert violation(end_session(private, 0, "session_drops_pin")) == (
        "private draft lost its retained pin")
    declared = declare(private, 0)
    assert violation(handoff(declared, 0, True, "conflict_drops_unit")) == (
        "declared unit lost its accountable holder")
    assert violation(handoff(declared, 0, defect="missing_branch_pin")) == (
        "branch unit lost its pin")
    assert violation(handoff(declared, 0, defect="missing_receipt")) == (
        "branch assumed unit without exact handoff receipt")
    closing = request_close(State())
    resolved = replace(closing, members=("resolved", "resolved"))
    assert violation(acknowledge_close(resolved, "close_before_disable")) == (
        "closure acknowledged before ref disable")
    disabled = disable_admission(closing)
    assert violation(acknowledge_close(disabled, "close_with_member")) == (
        "closure acknowledged with unresolved member")
    outstanding = disable_admission(request_close(handoff(declared, 0)))
    outstanding = replace(outstanding, members=("resolved", "resolved"))
    assert violation(acknowledge_close(outstanding, "close_drops_unit")) == (
        "declared unit lost its accountable holder")
    parked = park(disable_admission(request_close(private)), 0)
    parked = resolve_member(parked, 1)
    assert violation(acknowledge_close(parked, "close_omits_parked")) == (
        "close receipt omitted parked obligations")


def steps(s: State):
    if s.close == "open":
        for i in (0, 1):
            if s.drafts[i] == "none" and not s.ever_written[i]:
                yield f"write{i}", write_private(s, i)
            if s.drafts[i] == "private":
                yield f"declare{i}", declare(s, i)
                yield f"release{i}", release_private(s, i)
            if s.units[i] == "twig":
                yield f"handoff{i}", handoff(s, i)
    for i in (0, 1):
        if s.units[i] == "branch" and s.twig_pins[i]:
            yield f"cleanup{i}", cleanup_twig_pin(s, i)
        if s.units[i] == "branch" and s.ref_enabled:
            yield f"admit{i}", admit(s, i)
    if s.close == "open":
        yield "request_close", request_close(s)
    if s.close == "closing":
        if s.ref_enabled:
            yield "disable", disable_admission(s)
        else:
            for i in (0, 1):
                if s.drafts[i] == "private" or s.units[i] in ("twig", "branch"):
                    yield f"park{i}", park(s, i)
                if s.members[i] == "open" and s.drafts[i] != "private" and s.units[i] not in ("twig", "branch"):
                    yield f"resolve{i}", resolve_member(s, i)
            if "open" not in s.members and not any(u in ("twig", "branch") for u in s.units):
                yield "close", acknowledge_close(s)


def explore(depth: int = 10) -> int:
    start = State()
    queue = deque([(start, 0)])
    seen = {start}
    while queue:
        state, distance = queue.popleft()
        assert violation(state) is None, (state, violation(state))
        if distance >= depth:
            continue
        for _, next_state in steps(state):
            if next_state not in seen:
                seen.add(next_state)
                queue.append((next_state, distance + 1))
    return len(seen)


def main() -> None:
    scenarios()
    mutants()
    count = explore()
    print(f"private pin closure: {count} safe states through ten transitions")
    print("two member twigs, pinned handoff and closure, and eight mutants passed")


if __name__ == "__main__":
    main()
