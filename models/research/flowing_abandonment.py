#!/usr/bin/env python3
"""Bounded ref-owned abandonment and dependent-unit conservation probe.

Run: python3 models/research/flowing_abandonment.py

Unit 0 writes x=1. Unit 1 read x=1 and writes y=1. Authorized abandonment
of unit 0 therefore either settles unit 1 in the same exact source-head
transition or must refuse; this model chooses the settle-both path. A prepared
replacement cut stays pinned through crash and a competing head move. The ref
transaction owns the head CAS, both per-unit dispositions, and one receipt.
This abstracts authorization, real content derivation, lock scheduling and
cross-store persistence; it tests the ordering those implementations owe.
"""

from collections import deque
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class State:
    head_revision: int = 0
    head_x: int = 1
    head_y: int = 1
    head_tail: int = 0
    tail_written: bool = False
    units: tuple[str, str] = ("owed", "owed")
    dependent_read_x: int = 1
    trunk_admitted: bool = False
    attempt: str = "none"  # none, prepared, stale, committed
    expected_revision: int = -1
    prepared_tail: int = -1
    prepared_cut_exists: bool = False
    prepared_cut_pin: bool = False
    coordinator_up: bool = True
    crashed_once: bool = False
    ref_up: bool = True
    outage_used: bool = False
    receipt_units: tuple[int, ...] = ()
    receipt_count: int = 0


def steps(s: State, defect: str = ""):
    if not s.outage_used:
        yield "ref_outage", replace(s, ref_up=False, outage_used=True)
    if not s.ref_up:
        yield "ref_restore", replace(s, ref_up=True)

    if not s.tail_written and s.units == ("owed", "owed"):
        # Another writer changes the source after a candidate was prepared.
        yield "append_unselected_tail", replace(
            s, head_revision=s.head_revision + 1, head_tail=1,
            tail_written=True,
        )
    if not s.trunk_admitted and s.ref_up and s.units == ("owed", "owed"):
        # The competing trunk CAS accounts both dependent units at once.
        yield "trunk_cas", replace(
            s, trunk_admitted=True, units=("accounted", "accounted"),
        )

    if (s.coordinator_up and s.attempt in ("none", "stale") and
            (s.units == ("owed", "owed") or defect == "abandon_after_trunk")):
        yield "prepare_abandonment", replace(
            s, attempt="prepared", expected_revision=s.head_revision,
            prepared_tail=s.head_tail, prepared_cut_exists=True,
            prepared_cut_pin=(defect != "drop_prepared_pin"),
        )
    if s.attempt == "prepared" and not s.crashed_once:
        yield "crash", replace(s, coordinator_up=False, crashed_once=True)
    if not s.coordinator_up:
        yield "recover", replace(s, coordinator_up=True)
    if s.prepared_cut_exists and not s.prepared_cut_pin and s.attempt != "committed":
        yield "collect_unpinned_cut", replace(s, prepared_cut_exists=False)

    if s.coordinator_up and s.attempt == "prepared" and s.ref_up:
        if s.head_revision != s.expected_revision and defect != "skip_revision_fence":
            yield "stale_refusal", replace(
                s, attempt="stale", prepared_cut_pin=False,
            )
        elif s.units != ("owed", "owed") and defect != "abandon_after_trunk":
            yield "already_admitted_refusal", replace(
                s, attempt="stale", prepared_cut_pin=False,
            )
        elif (s.units == ("owed", "owed") or defect == "abandon_after_trunk"):
            if s.prepared_cut_exists:
                abandoned = (("abandoned", "owed") if defect == "omit_dependent"
                             else ("abandoned", "abandoned"))
                receipt = (() if defect == "cut_without_receipt"
                           else (0,) if defect == "omit_dependent" else (0, 1))
                # This is one ref transaction: no observer can see a new head
                # without the exact dispositions and receipt, or vice versa.
                yield "commit_abandonment", replace(
                    s, attempt="committed", units=abandoned,
                    head_revision=s.head_revision + 1,
                    head_x=(s.head_x if defect == "receipt_without_cut" else 0),
                    head_y=(s.head_y if defect == "receipt_without_cut" else 0),
                    head_tail=(s.head_tail if defect == "receipt_without_cut"
                               else s.prepared_tail),
                    receipt_units=receipt, receipt_count=1 if receipt else 0,
                    prepared_cut_pin=True,
                )
    if s.attempt == "committed" and s.coordinator_up and s.ref_up:
        yield "retry_same_op", replace(
            s, receipt_count=(s.receipt_count + 1
                             if defect == "duplicate_retry" else s.receipt_count),
        )


def violation(s: State) -> str | None:
    if s.attempt == "prepared" and (
        not s.prepared_cut_pin or not s.prepared_cut_exists
    ):
        return "prepared replacement cut lost its retained body"
    if s.receipt_count > 1:
        return "one operation id produced duplicate disposition receipts"
    if s.units[0] == "abandoned":
        if s.head_x != 0:
            return "abandonment receipt left effective unit content on source"
        if s.units[1] != "abandoned" or s.head_y != 0:
            return "dependent unit was not resolved with abandoned predecessor"
        if s.receipt_units != (0, 1) or s.receipt_count != 1:
            return "source head moved without exact per-unit disposition receipt"
    if s.units[1] == "owed" and s.dependent_read_x != s.head_x:
        return "owed dependent lost its declared read basis"
    if s.receipt_count and s.units != ("abandoned", "abandoned"):
        return "disposition receipt is not bound to both source units"
    if s.trunk_admitted and "abandoned" in s.units:
        return "already admitted content was retrospectively abandoned"
    if s.tail_written and s.head_tail != 1:
        return "stale abandonment overwrote an unselected source tail"
    if s.attempt == "committed" and not s.prepared_cut_exists:
        return "ref entry named a collected replacement cut"
    return None


def explore(defect: str = "", depth: int = 12):
    initial = State()
    queue = deque([(initial, ())])
    seen = {initial}
    while queue:
        state, trace = queue.popleft()
        if problem := violation(state):
            return len(seen), problem, trace
        if len(trace) >= depth:
            continue
        for event, after in steps(state, defect):
            if after not in seen:
                seen.add(after)
                queue.append((after, trace + (event,)))
    return len(seen), None, ()


def scenario(events: tuple[str, ...]):
    state = State()
    for wanted in events:
        options = [after for event, after in steps(state) if event == wanted]
        assert len(options) == 1, (wanted, state)
        state = options[0]
        assert violation(state) is None, (wanted, violation(state))
    return state


def main():
    recovered = scenario((
        "prepare_abandonment", "crash", "recover",
        "commit_abandonment", "retry_same_op",
    ))
    assert recovered.units == ("abandoned", "abandoned")
    assert recovered.receipt_units == (0, 1) and recovered.receipt_count == 1
    stale = scenario((
        "prepare_abandonment", "append_unselected_tail", "stale_refusal",
        "prepare_abandonment", "commit_abandonment",
    ))
    assert stale.head_tail == 1 and stale.units == ("abandoned", "abandoned")
    cas_first = scenario(("trunk_cas",))
    assert not any(event == "prepare_abandonment" for event, _ in steps(cas_first))
    cas_during_prepare = scenario((
        "prepare_abandonment", "trunk_cas", "already_admitted_refusal",
    ))
    assert cas_during_prepare.units == ("accounted", "accounted")
    offline = scenario(("prepare_abandonment", "ref_outage", "crash", "recover"))
    assert not any(event == "commit_abandonment" for event, _ in steps(offline))
    assert any(event == "commit_abandonment"
               for event, _ in steps(scenario((
                   "prepare_abandonment", "ref_outage", "ref_restore",
               ))))

    count, problem, _ = explore()
    assert problem is None, problem
    print(f"flowing abandonment: {count} safe states through 12 transitions")
    for defect in (
        "omit_dependent", "receipt_without_cut", "cut_without_receipt",
        "skip_revision_fence", "drop_prepared_pin", "abandon_after_trunk",
        "duplicate_retry",
    ):
        count, problem, trace = explore(defect)
        assert problem is not None, (defect, count)
        print(f"  {defect}: {problem} via {' -> '.join(trace)}")


if __name__ == "__main__":
    main()
