#!/usr/bin/env python3
"""Bounded race between unit parking, trunk admission and later resumption.

Run: python3 models/research/flowing_parking_race.py

One unit is held by a branch. A gate certificate and a park request may both
observe that holder. The ref authority serializes their final CAS operations:
the winner records its exact receipt, and the loser reads that outcome or
refuses. A parked unit stays owed to a named holder. Resumption increments the
unit's generation so a certificate prepared before parking cannot revive.
This abstracts authentication, dependency closure, content pins, branch
closure and cross-store persistence; it tests the common ref ordering only.
"""

from collections import deque
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class State:
    holder: str = "branch"  # branch, park:owner, admitted, lost
    generation: int = 0
    candidate_generation: int = -1
    candidate_refreshed: bool = False
    park_expected_generation: int = -1
    park_prepared: bool = False
    parked_once: bool = False
    resumed_once: bool = False
    admission_receipt: bool = False
    park_receipt: bool = False
    park_receipt_count: int = 0
    admission_receipt_count: int = 0
    admission_from_prepark_candidate: bool = False
    park_ack: bool = False
    admission_ack: bool = False
    park_saw_admission: bool = False
    admission_saw_park: bool = False
    coordinator_up: bool = True
    crashed_once: bool = False
    ref_up: bool = True
    outage_used: bool = False


def steps(s: State, defect: str = ""):
    if not s.outage_used:
        yield "ref_outage", replace(s, ref_up=False, outage_used=True)
    if not s.ref_up:
        yield "ref_restore", replace(s, ref_up=True)

    if s.coordinator_up and s.holder == "branch" and s.candidate_generation < 0:
        yield "prepare_candidate", replace(s, candidate_generation=s.generation)
    if (s.coordinator_up and s.holder == "branch" and s.resumed_once
            and s.candidate_generation >= 0
            and s.candidate_generation != s.generation
            and not s.candidate_refreshed):
        yield "refresh_candidate", replace(
            s, candidate_generation=s.generation, candidate_refreshed=True,
        )
    if s.coordinator_up and s.holder == "branch" and not s.park_prepared:
        yield "prepare_park", replace(
            s, park_prepared=True, park_expected_generation=s.generation,
        )
    if not s.crashed_once and (s.park_prepared or s.candidate_generation >= 0):
        yield "crash", replace(
            s, coordinator_up=False, crashed_once=True,
            holder=("lost" if defect == "lose_holder_on_crash" else s.holder),
        )
    if not s.coordinator_up:
        yield "recover", replace(s, coordinator_up=True)

    if s.coordinator_up and s.park_prepared and not s.park_receipt:
        if s.holder == "admitted" and s.ref_up and defect != "park_after_admission":
            yield "park_reads_admission", replace(s, park_saw_admission=True)
        elif (s.ref_up and s.holder in ("branch", "admitted")
              and s.generation == s.park_expected_generation):
            yield "park_cas", replace(
                s, holder="park:owner",
                parked_once=True,
                park_receipt=(defect != "park_without_receipt"),
                park_receipt_count=(0 if defect == "park_without_receipt" else 1),
            )
    if s.coordinator_up and s.ref_up and s.park_receipt:
        yield "retry_park", replace(
            s, park_receipt_count=s.park_receipt_count
            + (1 if defect == "duplicate_park_retry" else 0),
        )
        if not s.park_ack:
            yield "ack_park", replace(s, park_ack=True)
    elif (s.coordinator_up and s.park_prepared and not s.park_ack
          and defect == "ack_before_park_cas"):
        yield "ack_park_early", replace(s, park_ack=True)

    if (s.coordinator_up and s.ref_up and s.holder == "park:owner"
            and s.park_receipt and not s.resumed_once):
        yield "resume", replace(
            s, holder="branch", resumed_once=True,
            generation=s.generation
            + (0 if defect == "resume_without_generation" else 1),
        )

    if s.coordinator_up and s.ref_up and s.candidate_generation >= 0:
        if s.holder == "park:owner" and defect != "admit_parked":
            yield "admission_reads_park", replace(s, admission_saw_park=True)
        elif s.holder == "branch" or (s.holder == "park:owner" and defect == "admit_parked"):
            if (s.generation == s.candidate_generation
                    or defect == "skip_admission_generation"):
                if not s.admission_receipt:
                    yield "trunk_cas", replace(
                        s, holder="admitted", admission_receipt=True,
                        admission_receipt_count=1,
                        admission_from_prepark_candidate=(
                            s.resumed_once and s.candidate_generation == 0
                        ),
                    )
            elif not s.admission_receipt:
                yield "stale_candidate_refusal", s
    if s.coordinator_up and s.ref_up and s.admission_receipt:
        yield "retry_admission", replace(
            s, admission_receipt_count=s.admission_receipt_count
            + (1 if defect == "duplicate_admission_retry" else 0),
        )
        if not s.admission_ack:
            yield "ack_admission", replace(s, admission_ack=True)


def violation(s: State) -> str | None:
    if s.holder == "lost":
        return "crash dropped the accountable holder"
    if s.holder == "park:owner" and not s.park_receipt:
        return "parked holder exists without its durable transfer receipt"
    if s.holder == "admitted" and not s.admission_receipt:
        return "trunk result exists without an admission receipt"
    if s.admission_receipt and s.holder != "admitted":
        return "park CAS displaced an already admitted unit"
    if s.park_receipt and s.holder == "admitted" and not s.resumed_once:
        return "trunk CAS admitted a still-parked unit"
    if s.admission_from_prepark_candidate:
        return "resumption revived a certificate prepared before parking"
    if s.park_ack and not s.park_receipt:
        return "parking acknowledged before durable transfer"
    if s.admission_ack and not s.admission_receipt:
        return "admission acknowledged before durable receipt"
    if s.park_receipt_count > 1 or s.admission_receipt_count > 1:
        return "exact retry produced a second terminal receipt"
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
    parked = scenario((
        "prepare_candidate", "prepare_park", "park_cas",
        "admission_reads_park", "retry_park", "ack_park",
    ))
    assert (parked.holder == "park:owner" and parked.admission_saw_park
            and not parked.admission_receipt)
    admitted = scenario((
        "prepare_candidate", "prepare_park", "trunk_cas",
        "park_reads_admission", "retry_admission", "ack_admission",
    ))
    assert (admitted.holder == "admitted" and admitted.park_saw_admission
            and not admitted.park_receipt)
    resumed = scenario((
        "prepare_candidate", "prepare_park", "park_cas",
        "resume", "stale_candidate_refusal",
    ))
    assert resumed.holder == "branch" and resumed.generation == 1
    renewed = scenario((
        "prepare_candidate", "prepare_park", "park_cas", "resume",
        "stale_candidate_refusal", "refresh_candidate", "trunk_cas",
    ))
    assert renewed.holder == "admitted" and renewed.admission_receipt
    recovered = scenario((
        "prepare_park", "crash", "recover", "park_cas", "retry_park",
    ))
    assert recovered.park_receipt_count == 1
    offline = scenario(("prepare_park", "ref_outage"))
    assert not any(event == "park_cas" for event, _ in steps(offline))

    count, problem, _ = explore()
    assert problem is None, problem
    print(f"flowing parking race: {count} safe states through 12 transitions")
    for defect in (
        "park_after_admission", "park_without_receipt", "ack_before_park_cas",
        "admit_parked", "skip_admission_generation",
        "resume_without_generation", "duplicate_park_retry",
        "duplicate_admission_retry",
        "lose_holder_on_crash",
    ):
        count, problem, trace = explore(defect)
        assert problem is not None, (defect, count)
        print(f"  {defect}: {problem} via {' -> '.join(trace)}")


if __name__ == "__main__":
    main()
