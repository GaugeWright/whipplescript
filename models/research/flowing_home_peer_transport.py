#!/usr/bin/env python3
"""Bounded Home/hosted-peer cut transport probe (DR-0139, FB-6).

Run: python3 models/research/flowing_home_peer_transport.py

Home and peer have different local cut IDs. The Home ships content; receipt
records no peer ref. A separate atomic seed creates a peer-local cut, twig and
receipt before peer execution. A peer result returns as a pinned candidate.
Only the Home's gate and exact ref CAS can admit it. This model abstracts the
real bundle codec, signatures, owner authentication and unit dependency proof;
those remain implementation obligations.
"""

from collections import deque
from dataclasses import dataclass, replace


HOME_SOURCE_ID = "home-cut-1"
SOURCE_CONTENT = "sha256:source"
PEER_SOURCE_ID = "peer-cut-7"
PEER_TWIG_ID = "peer-twig-1"
PEER_RESULT_ID = "peer-cut-8"
HOME_CANDIDATE_ID = "home-cut-2"
RESULT_CONTENT = "sha256:result"
OTHER_CONTENT = "sha256:other"


@dataclass(frozen=True)
class State:
    home_trunk: str = "sha256:trunk-base"
    source_owed: bool = True
    source_pinned: bool = True
    shipped: bool = False
    peer_carriage_content: str = ""
    peer_source_id: str = ""
    peer_source_content: str = ""
    peer_twig_id: str = ""
    seed_receipt_id: str = ""
    seed_receipt_base: str = ""
    seed_receipt_count: int = 0
    peer_ref: str = ""
    peer_result_id: str = ""
    peer_result_parent: str = ""
    peer_result_content: str = ""
    returned_content: str = ""
    home_candidate_id: str = ""
    home_candidate_content: str = ""
    candidate_pinned: bool = False
    gate_base: str = ""
    gate_candidate: str = ""
    admitted: bool = False
    admission_before: str = ""
    receipt_count: int = 0
    home_up: bool = True
    peer_up: bool = True
    home_crashed: bool = False
    peer_crashed: bool = False
    competitor_moved: bool = False


def steps(s: State, defect: str = ""):
    if s.home_up and not s.home_crashed:
        yield "home_crash", replace(
            s, home_up=False, home_crashed=True,
            candidate_pinned=(False if defect == "drop_candidate_pin" else s.candidate_pinned),
        )
    if not s.home_up:
        yield "home_recover", replace(s, home_up=True)
    if s.peer_up and not s.peer_crashed:
        yield "peer_crash", replace(s, peer_up=False, peer_crashed=True)
    if not s.peer_up:
        yield "peer_recover", replace(s, peer_up=True)

    if s.home_up and not s.shipped and s.source_owed and s.source_pinned:
        yield "ship_source_bundle", replace(s, shipped=True)
    if s.peer_up and s.shipped and not s.peer_carriage_content:
        yield "verify_and_import_bundle", replace(
            s,
            peer_carriage_content=(OTHER_CONTENT if defect == "skip_bundle_digest" else SOURCE_CONTENT),
            peer_ref=(PEER_SOURCE_ID if defect == "import_moves_peer_ref" else s.peer_ref),
        )
    if s.peer_up and s.peer_carriage_content and not s.peer_source_id:
        local_cut = HOME_SOURCE_ID if defect == "reuse_home_cut_id" else PEER_SOURCE_ID
        yield "seed_peer_twig", replace(
            s,
            peer_source_id=local_cut,
            peer_source_content=(OTHER_CONTENT if defect == "seed_wrong_base" else s.peer_carriage_content),
            peer_twig_id=("" if defect == "receipt_without_twig" else PEER_TWIG_ID),
            peer_ref=("" if defect == "receipt_without_twig" else local_cut),
            seed_receipt_id=("" if defect == "seed_without_receipt" else local_cut),
            seed_receipt_base=s.peer_carriage_content,
            seed_receipt_count=1,
        )
    if s.peer_up and s.seed_receipt_count and not s.peer_result_id:
        yield "retry_seed", replace(
            s,
            seed_receipt_count=s.seed_receipt_count + (defect == "duplicate_seed_retry"),
        )
    if s.peer_up and s.peer_twig_id and s.seed_receipt_id and not s.peer_result_id:
        yield "write_on_peer", replace(
            s,
            peer_result_id=PEER_RESULT_ID,
            peer_result_parent=(OTHER_CONTENT if defect == "forget_parent" else s.peer_source_content),
            peer_result_content=RESULT_CONTENT,
            peer_ref=PEER_RESULT_ID,
        )
    if s.peer_up and s.peer_result_id and not s.returned_content:
        yield "return_candidate_bundle", replace(
            s, returned_content=(OTHER_CONTENT if defect == "skip_return_digest" else s.peer_result_content),
            home_trunk=(RESULT_CONTENT if defect == "peer_moves_home_ref" else s.home_trunk),
        )
    if s.home_up and s.returned_content and not s.home_candidate_content:
        if (s.peer_source_content == SOURCE_CONTENT
                and s.peer_result_parent == SOURCE_CONTENT
                and (s.returned_content == s.peer_result_content or defect == "skip_return_digest")):
            yield "verify_and_record_candidate", replace(
                s,
                home_candidate_id=(PEER_RESULT_ID if defect == "reuse_peer_result_id" else HOME_CANDIDATE_ID),
                home_candidate_content=s.returned_content,
                candidate_pinned=True,
            )
    if s.home_up and s.home_candidate_content and not s.gate_candidate:
        yield "gate_exact_candidate", replace(
            s, gate_base=s.home_trunk, gate_candidate=s.home_candidate_content,
        )
    if s.home_up and not s.competitor_moved and not s.admitted:
        yield "competing_home_admission", replace(
            s, home_trunk=OTHER_CONTENT, competitor_moved=True,
        )
    if s.home_up and s.home_candidate_content and not s.admitted and s.source_owed:
        gate_ready = (
            s.gate_candidate == s.home_candidate_content
            and (s.gate_base == s.home_trunk or defect == "skip_home_cas")
        )
        if s.source_pinned and s.candidate_pinned and (
            gate_ready or defect == "skip_gate"
        ):
            yield "home_trunk_cas", replace(
                s, home_trunk=s.home_candidate_content, source_owed=False,
                admitted=True, admission_before=s.home_trunk, receipt_count=1,
            )
    if s.home_up and s.admitted:
        yield "retry_admission", replace(
            s, receipt_count=s.receipt_count + (defect == "duplicate_retry"),
        )


def violation(s: State) -> str | None:
    if s.peer_carriage_content and s.peer_carriage_content != SOURCE_CONTENT:
        return "peer recorded a bundle with the wrong content digest"
    if s.peer_ref == PEER_SOURCE_ID and not s.peer_source_id:
        return "Home bundle import wrote a peer ref"
    if s.peer_source_id == HOME_SOURCE_ID:
        return "peer reused the Home's local cut ID"
    if s.peer_source_id and s.peer_source_content != SOURCE_CONTENT:
        return "peer twig seed did not hold the carried content"
    if s.peer_source_id and (
        s.peer_twig_id != PEER_TWIG_ID
        or s.seed_receipt_id != s.peer_source_id
        or s.seed_receipt_base != s.peer_carriage_content
        or s.seed_receipt_count != 1
    ):
        return "peer twig, local cut and seed receipt did not commit together"
    if s.peer_source_id and not s.peer_result_id and s.peer_ref != s.peer_source_id:
        return "seeded twig does not point at its local cut"
    if s.peer_result_id and s.peer_result_parent != SOURCE_CONTENT:
        return "peer result lost the imported source parent"
    if s.home_candidate_content and s.home_candidate_content != s.peer_result_content:
        return "Home recorded a returned bundle whose content differed from the peer result"
    if s.home_candidate_id == s.peer_result_id and s.home_candidate_id:
        return "Home reused the peer's local result cut ID"
    if s.home_trunk == RESULT_CONTENT and not s.admitted:
        return "peer return moved the Home trunk without admission"
    if s.home_candidate_content and not s.admitted and not s.candidate_pinned:
        return "unadmitted candidate lost its content pin"
    if s.shipped and s.source_owed and not s.source_pinned:
        return "owed Home source lost its content pin"
    if s.receipt_count > 1:
        return "exact retry duplicated the admission receipt"
    if s.admitted:
        if s.gate_candidate != s.home_candidate_content or not s.gate_candidate:
            return "Home admitted a candidate without its exact gate"
        if s.admission_before != s.gate_base:
            return "Home admitted against a trunk base that changed after the gate"
        if s.home_trunk != s.home_candidate_content or s.source_owed or s.receipt_count != 1:
            return "Home CAS did not atomically move the ref and account the source"
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
        choices = [after for event, after in steps(state) if event == wanted]
        assert len(choices) == 1, (wanted, state)
        state = choices[0]
        assert violation(state) is None, (wanted, violation(state))
    return state


def main():
    accepted = scenario((
        "ship_source_bundle", "verify_and_import_bundle", "peer_crash",
        "peer_recover", "seed_peer_twig", "retry_seed", "write_on_peer", "return_candidate_bundle",
        "verify_and_record_candidate", "home_crash", "home_recover",
        "gate_exact_candidate", "home_trunk_cas", "retry_admission",
    ))
    assert accepted.home_trunk == RESULT_CONTENT and accepted.receipt_count == 1
    assert accepted.peer_source_id != HOME_SOURCE_ID
    seeded = scenario((
        "ship_source_bundle", "verify_and_import_bundle", "seed_peer_twig",
        "peer_crash", "peer_recover", "retry_seed", "write_on_peer",
    ))
    assert seeded.peer_twig_id == PEER_TWIG_ID
    assert seeded.seed_receipt_id == PEER_SOURCE_ID and seeded.seed_receipt_count == 1
    stale = scenario((
        "ship_source_bundle", "verify_and_import_bundle", "seed_peer_twig", "write_on_peer",
        "return_candidate_bundle", "verify_and_record_candidate",
        "gate_exact_candidate", "competing_home_admission",
    ))
    assert not any(event == "home_trunk_cas" for event, _ in steps(stale))

    count, problem, _ = explore(depth=15)
    assert problem is None, problem
    print(f"Home/peer transport: {count} safe states through 15 transitions")
    for defect in (
        "reuse_home_cut_id", "skip_bundle_digest", "import_moves_peer_ref",
        "seed_wrong_base", "seed_without_receipt", "receipt_without_twig",
        "duplicate_seed_retry",
        "forget_parent", "skip_return_digest", "reuse_peer_result_id",
        "peer_moves_home_ref",
        "drop_candidate_pin", "skip_gate",
        "skip_home_cas", "duplicate_retry",
    ):
        _, problem, trace = explore(defect, depth=15)
        assert problem is not None, defect
        print(f"  {defect}: {problem} via {' -> '.join(trace)}")


if __name__ == "__main__":
    main()
