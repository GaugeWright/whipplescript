#!/usr/bin/env python3
"""Bounded lifecycle seam for a ref-owned branch admission policy.

Run: python3 models/research/lifecycle_seam.py
Research only: one branch, one old candidate, one close, and one new branch.
"""

from collections import deque
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class State:
    # Topology owns branch lifecycle; the ref authority owns admission policy.
    top_phase: str = "active"  # active, closing, closed, opening
    incarnation: int = 0
    ref_phase: str = "flowing"  # flowing, disabled
    ref_incarnation: int = 0
    ref_epoch: int = 0
    trunk: int = 0
    old_candidate_passed: bool = False
    admission: tuple[int, int, int, str] | None = None
    admission_receipt: bool = False
    close_acknowledged: bool = False
    top_available: bool = True
    ref_available: bool = True
    top_failed_once: bool = False
    ref_failed_once: bool = False


def steps(s: State, defect: str = ""):
    if not s.old_candidate_passed:
        yield "gate_old_candidate", replace(s, old_candidate_passed=True)
    if s.top_available and not s.top_failed_once:
        yield "topology_outage", replace(s, top_available=False, top_failed_once=True)
    if not s.top_available:
        yield "topology_recovers", replace(s, top_available=True)
    if s.ref_available and not s.ref_failed_once:
        yield "ref_outage", replace(s, ref_available=False, ref_failed_once=True)
    if not s.ref_available:
        yield "ref_recovers", replace(s, ref_available=True)

    if s.top_available and s.top_phase == "active" and s.incarnation == 0:
        yield "request_close", replace(s, top_phase="closing")
    if s.ref_available and s.top_phase == "closing" and s.ref_phase == "flowing":
        # Ref policy mutation and a competing CAS serialize at this authority.
        yield "disable_admission", replace(s, ref_phase="disabled",
                                            ref_epoch=s.ref_epoch + 1)
    if s.top_available and s.top_phase == "closing":
        if (s.ref_phase == "disabled" or defect == "close_before_disable") and (
            not s.admission or s.admission_receipt
        ):
            yield "ack_close", replace(s, top_phase="closed",
                                       close_acknowledged=True)
    if s.top_available and s.top_phase == "closed" and s.ref_phase == "disabled":
        yield "request_new_branch", replace(s, top_phase="opening",
                                             incarnation=s.incarnation + 1)
    if s.ref_available and s.top_phase == "opening" and s.ref_phase == "disabled":
        # New branch identity is minted from topology. It must never be an
        # alias of the archived branch's identity/certificate generation.
        new_generation = 0 if defect == "reuse_old_identity" else s.incarnation
        yield "install_new_policy", replace(s, ref_phase="flowing",
                                            ref_incarnation=new_generation,
                                            ref_epoch=0)
    if (s.top_available and s.top_phase == "opening" and
            s.ref_phase == "flowing"):
        yield "ack_new_branch", replace(s, top_phase="active")

    if s.ref_available and s.old_candidate_passed and s.trunk == 0:
        # The old certificate binds incarnation 0, policy epoch 0, and trunk 0.
        if s.ref_phase == "flowing" and s.ref_incarnation == 0 and s.ref_epoch == 0:
            yield "cas_old_candidate", replace(
                s, trunk=1,
                admission=(0, s.incarnation, s.ref_epoch, s.top_phase),
            )
    if s.admission and not s.admission_receipt and s.top_available:
        yield "recover_admission_receipt", replace(s, admission_receipt=True)


def violation(s: State):
    if s.trunk != int(s.admission is not None):
        return "ref and durable admission disagree"
    if s.admission:
        cert_generation, true_generation, epoch, phase = s.admission
        if cert_generation != true_generation:
            return "an old branch certificate admitted a new incarnation"
        if phase == "closed":
            return "admission occurred after closure was acknowledged"
        if epoch != 0:
            return "a revoked policy epoch admitted"
    if s.top_phase == "closed" and s.ref_phase != "disabled":
        return "closure was acknowledged while admission remained enabled"
    if s.admission_receipt and not s.admission:
        return "admission receipt without a durable CAS"
    if s.close_acknowledged and s.admission and not s.admission_receipt:
        return "closure omitted the accepted admission receipt"
    return None


def explore(defect="", depth=10):
    initial = State()
    queue = deque([(initial, ())])
    visited = {initial}
    while queue:
        state, trace = queue.popleft()
        error = violation(state)
        if error:
            return len(visited), error, trace
        if len(trace) == depth:
            continue
        for event, successor in steps(state, defect):
            if successor not in visited:
                visited.add(successor)
                queue.append((successor, trace + (event,)))
    return len(visited), None, ()


def scenario(events):
    state = State()
    for wanted in events:
        matches = [successor for event, successor in steps(state) if event == wanted]
        assert len(matches) == 1, (wanted, state)
        state = matches[0]
        assert violation(state) is None, (wanted, state)
    return state


def scenarios():
    # A close request is pending, not a promise that an in-flight CAS lost.
    before_disable = scenario(("gate_old_candidate", "request_close",
                               "cas_old_candidate", "disable_admission",
                               "recover_admission_receipt", "ack_close"))
    assert before_disable.close_acknowledged and before_disable.trunk == 1
    after_disable = scenario(("gate_old_candidate", "request_close",
                              "disable_admission", "ack_close"))
    assert "cas_old_candidate" not in {e for e, _ in steps(after_disable)}

    # A ref outage keeps closure pending; recovery can finish the disable.
    outage = scenario(("gate_old_candidate", "request_close", "ref_outage"))
    assert "ack_close" not in {e for e, _ in steps(outage)}
    recovered = scenario(("request_close", "ref_outage", "ref_recovers",
                          "disable_admission", "topology_outage",
                          "topology_recovers", "ack_close"))
    assert recovered.top_phase == "closed"

    new_branch = scenario(("request_close", "disable_admission", "ack_close",
                           "request_new_branch", "install_new_policy",
                           "ack_new_branch", "gate_old_candidate"))
    assert "cas_old_candidate" not in {e for e, _ in steps(new_branch)}


def main():
    scenarios()
    for label, defect, depth in (
        ("safe lifecycle", "", 10),
        ("ack closure before disable", "close_before_disable", 5),
        ("reuse archived identity", "reuse_old_identity", 10),
    ):
        count, error, trace = explore(defect, depth)
        if bool(error) != bool(defect):
            raise SystemExit(f"{label}: unexpected {error} after {count} states")
        print(f"{label}: {count} states through depth {depth}; {error or 'no violation'}")
        if trace:
            print("  " + " -> ".join(trace))


if __name__ == "__main__":
    main()
