#!/usr/bin/env python3
"""Bounded final close of a flowing source with a member and a live gate attempt.

Run: python3 models/research/flowing_final_close.py

Topology first marks close pending and stops joins/imports. The ref authority
then orders admission CAS against admission disable, and later orders unit
parking and final close. An attempt prepared before the request may still win
before disable, or be refused by the disabled fence. A member and a private
draft pin remain separate work to resolve. This model abstracts receipt bytes,
dependency proofs, storage APIs, and the separate abandonment proof.
"""

from collections import deque
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class State:
    topology_open: bool = True
    admission_enabled: bool = True
    close_started: bool = False
    ref_disabled: bool = False
    eligibility_epoch: int = 0
    closed: bool = False
    source_unit: str = "owed"  # owed, parked, admitted, lost
    member_unit: str = "owed"  # owed, parked, lost
    source_park_receipt: bool = False
    member_park_receipt: bool = False
    member: str = "active"  # active, resolved
    member_resolution_receipt: bool = False
    private_pin: bool = True
    private_pin_release_receipt: bool = False
    attempt: str = "idle"  # idle, checking, admitted, failed
    attempt_pin: bool = False
    candidate_available: bool = False
    admission_receipts: int = 0
    admitted_while_pending: bool = False
    close_receipts: int = 0
    close_ack: bool = False
    admitted_after_disable: bool = False
    joined_after_fence: bool = False
    coordinator_up: bool = True
    crashed_once: bool = False
    recovered_before_close: bool = False
    recovered_before_disable: bool = False


def steps(s: State, defect: str = ""):
    if s.coordinator_up and s.admission_enabled and s.source_unit == "owed" and s.attempt == "idle":
        yield "prepare_attempt", replace(
            s, attempt="checking", attempt_pin=True, candidate_available=True
        )

    # This CAS may be made by an already running gate while close's coordinator
    # is down. It competes with begin-close at the same ref authority.
    if s.attempt == "checking" and s.source_unit == "owed" and (
        s.admission_enabled or defect == "admit_after_disable"
    ):
        yield "admission_cas", replace(
            s, source_unit="admitted", attempt="admitted", admission_receipts=1,
            admitted_after_disable=not s.admission_enabled,
            admitted_while_pending=s.close_started and not s.ref_disabled,
        )

    if s.coordinator_up and not s.close_started:
        yield "request_close", replace(
            s, close_started=True,
            topology_open=defect == "skip_topology_fence",
        )
    if s.coordinator_up and s.close_started and not s.ref_disabled:
        yield "disable_admission", replace(
            s, ref_disabled=True,
            admission_enabled=defect == "skip_disable",
            eligibility_epoch=s.eligibility_epoch + 1,
        )
    if s.close_started and defect == "join_after_topology_fence":
        yield "late_member_join", replace(s, joined_after_fence=True)

    if s.coordinator_up and s.attempt == "checking" and not s.admission_enabled:
        yield "finish_refused_attempt", replace(s, attempt="failed")
    if s.coordinator_up and s.attempt_pin and s.attempt in ("admitted", "failed"):
        yield "release_attempt_pin", replace(s, attempt_pin=False)
    if s.attempt == "checking" and defect == "drop_live_attempt_pin":
        yield "drop_live_attempt_pin", replace(s, attempt_pin=False)
    if s.candidate_available and not s.attempt_pin and s.attempt == "checking":
        yield "collect_candidate", replace(s, candidate_available=False)

    if s.coordinator_up and s.ref_disabled and s.source_unit == "owed":
        yield "park_source_unit", replace(
            s, source_unit="parked",
            source_park_receipt=defect != "skip_park_receipt",
        )
    if s.coordinator_up and s.ref_disabled and s.member_unit == "owed":
        yield "park_member_unit", replace(s, member_unit="parked",
            member_park_receipt=True)
    if s.ref_disabled and defect == "drop_owed_unit" and s.source_unit == "owed":
        yield "drop_owed_unit", replace(s, source_unit="lost")
    if s.coordinator_up and s.ref_disabled and s.private_pin and s.member_unit != "owed":
        yield "release_private_pin", replace(
            s, private_pin=False,
            private_pin_release_receipt=defect != "skip_pin_release_receipt",
        )
    if s.coordinator_up and s.ref_disabled and s.member == "active" and (
        (s.member_unit != "owed" and (
            not s.private_pin or defect == "ignore_private_pin"
        )) or defect == "skip_member_resolution"
    ):
        yield "resolve_member", replace(
            s, member="resolved",
            member_resolution_receipt=defect != "skip_member_receipt",
        )

    if s.coordinator_up and s.ref_disabled and not s.closed:
        base_ready = (
            not s.topology_open
            and not s.admission_enabled
            and s.eligibility_epoch == 1
            and s.source_unit in ("parked", "admitted")
            and s.member_unit == "parked"
            and s.member == "resolved"
        )
        attempt_ready = s.attempt != "checking" and not s.attempt_pin
        private_ready = not s.private_pin
        ready = (
            defect == "skip_close_inventory"
            or base_ready and (
                (attempt_ready or defect == "ignore_live_attempt")
                and (private_ready or defect == "ignore_private_pin")
            )
        )
        if ready:
            yield "final_close", replace(
                s, closed=True,
                close_receipts=(0 if defect == "close_without_receipt" else 1),
            )
    if s.coordinator_up and s.closed:
        yield "retry_close", replace(
            s, close_receipts=s.close_receipts
            + (1 if defect == "duplicate_close_receipt" else 0),
        )
        if not s.close_ack:
            yield "ack_close", replace(s, close_ack=True)
    if s.coordinator_up and s.close_started and not s.closed and defect == "ack_before_close":
        yield "ack_close_early", replace(s, close_ack=True)

    if s.coordinator_up and not s.crashed_once:
        yield "crash", replace(s, coordinator_up=False, crashed_once=True)
    if not s.coordinator_up:
        yield "recover", replace(
            s, coordinator_up=True,
            recovered_before_close=s.recovered_before_close or not s.closed,
            recovered_before_disable=s.recovered_before_disable or (
                s.close_started and not s.ref_disabled
            ),
        )


def violation(s: State):
    if s.close_started and s.topology_open:
        return "close request left topology open"
    if s.ref_disabled and (s.admission_enabled or s.eligibility_epoch != 1):
        return "ref disable did not fence admission and advance the epoch"
    if s.admitted_after_disable:
        return "an old gate admitted after ref disable"
    if s.joined_after_fence:
        return "a member joined after the topology fence"
    if s.source_unit == "lost" or s.member_unit == "lost":
        return "an owed unit disappeared"
    if s.attempt == "checking" and (not s.attempt_pin or not s.candidate_available):
        return "a live attempt lost its candidate retention"
    if s.admission_receipts > 1 or s.close_receipts > 1:
        return "retry duplicated a receipt"
    if s.source_unit == "admitted" and s.admission_receipts != 1:
        return "an admission has no exact receipt"
    if s.source_unit == "parked" and not s.source_park_receipt:
        return "source parking has no durable receipt"
    if s.member_unit == "parked" and not s.member_park_receipt:
        return "member parking has no durable receipt"
    if not s.private_pin and not s.private_pin_release_receipt:
        return "private pin release has no durable receipt"
    if s.member == "resolved" and (s.member_unit == "owed" or s.private_pin):
        return "member resolution left owed work or a private pin"
    if s.member == "resolved" and not s.member_resolution_receipt:
        return "member resolution has no durable receipt"
    if s.closed and (
        s.topology_open
        or not s.ref_disabled
        or s.admission_enabled
        or s.eligibility_epoch != 1
        or s.source_unit not in ("parked", "admitted")
        or s.member_unit != "parked"
        or s.member != "resolved"
        or s.private_pin
        or s.attempt == "checking"
        or s.attempt_pin
        or s.close_receipts != 1
    ):
        return "close acknowledged an unresolved roster or omitted its receipt"
    if s.close_ack and (not s.closed or s.close_receipts != 1):
        return "close was acknowledged without its terminal receipt"
    return None


def explore(defect: str = ""):
    start = State()
    queue = deque([(start, ())])
    seen = {start}
    witnesses = {}
    while queue:
        state, trace = queue.popleft()
        problem = violation(state)
        if problem:
            return len(seen), problem, trace, witnesses
        if state.closed:
            if state.source_unit == "admitted":
                witnesses.setdefault("admission_won_before_close", trace)
            if state.admitted_while_pending:
                witnesses.setdefault("admission_won_during_pending_close", trace)
            if state.source_unit == "parked" and state.attempt == "failed":
                witnesses.setdefault("close_fenced_prepared_attempt", trace)
            if state.recovered_before_close:
                witnesses.setdefault("closed_after_recovery", trace)
            if state.recovered_before_disable:
                witnesses.setdefault("pending_close_recovered_before_disable", trace)
        for name, next_state in steps(state, defect):
            if next_state not in seen:
                seen.add(next_state)
                queue.append((next_state, trace + (name,)))
    return len(seen), None, (), witnesses


if __name__ == "__main__":
    count, problem, _, witnesses = explore()
    assert problem is None, problem
    assert len(witnesses) == 5, f"missing legal close race: {witnesses}"
    print(f"flowing final close: {count} safe states")
    for name, trace in witnesses.items():
        print(f"  {name}: {' -> '.join(trace)}")
    defects = (
        "skip_topology_fence", "skip_disable", "admit_after_disable",
        "join_after_topology_fence",
        "drop_live_attempt_pin", "drop_owed_unit", "skip_member_resolution",
        "skip_close_inventory", "ignore_live_attempt", "ignore_private_pin",
        "skip_park_receipt", "skip_pin_release_receipt", "skip_member_receipt",
        "close_without_receipt", "duplicate_close_receipt", "ack_before_close",
    )
    for defect in defects:
        _, problem, trace, _ = explore(defect)
        assert problem, f"mutation {defect} was not detected"
        print(f"  {defect}: {problem} via {' -> '.join(trace)}")
