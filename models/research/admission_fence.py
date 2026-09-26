#!/usr/bin/env python3
"""Bounded comparison of two possible branch-to-trunk admission fences.

Run: python3 models/research/admission_fence.py
These are research protocols, not a product implementation or a proof.
"""

from collections import deque
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class RefPolicy:
    # Policy, owner fence, and trunk ref live in ONE authority.
    epoch: int = 0
    held: bool = False
    hold_used: bool = False
    release_used: bool = False
    owner: int = 0
    owner_epoch: int = 0
    takeover_used: bool = False
    gate_passed: bool = False
    trunk: int = 0
    admission: tuple[int, int, int, bool] | None = None
    receipt: bool = False
    actor0_up: bool = True
    actor0_crashed: bool = False


def ref_policy_steps(s: RefPolicy, defect: str = ""):
    if not s.gate_passed:
        yield "gate_pass", replace(s, gate_passed=True)
    if not s.hold_used:
        yield "hold", replace(s, held=True, epoch=s.epoch + 1, hold_used=True)
    if s.held and not s.release_used:
        yield "release", replace(s, held=False, epoch=s.epoch + 1,
                                 release_used=True)
    if not s.takeover_used:
        yield "takeover", replace(s, owner=1, owner_epoch=s.owner_epoch + 1,
                                  takeover_used=True)
    if s.actor0_up and not s.actor0_crashed:
        yield "crash_owner0", replace(s, actor0_up=False, actor0_crashed=True)
    if not s.actor0_up:
        yield "restart_owner0", replace(s, actor0_up=True)
    if s.admission is not None and not s.receipt:
        yield "recover_receipt", replace(s, receipt=True)
    if not s.gate_passed or s.trunk != 0:
        return
    for actor in (0, 1):
        if actor == 0 and not s.actor0_up:
            continue
        if actor == 1 and not s.takeover_used:
            continue
        submitted_epoch = 0  # Both actors hold the original certificate.
        actor_fence = actor  # Owner 0 has token 0; takeover mints token 1.
        if (s.held or s.epoch != submitted_epoch) and defect != "stale_policy_read":
            continue
        if (s.owner != actor or s.owner_epoch != actor_fence) and defect != "stale_owner":
            continue
        yield f"cas_owner{actor}", replace(
            s, trunk=1,
            admission=(actor, s.epoch, s.owner_epoch, s.held),
        )


def ref_policy_violation(s: RefPolicy):
    if s.trunk != int(s.admission is not None):
        return "trunk and admission history disagree"
    if s.admission is not None:
        actor, epoch, fence, held = s.admission
        if held or epoch != 0:
            return "a stale or held policy admitted the candidate"
        if actor != fence:
            return "a former owner admitted after takeover"
    if s.receipt and s.admission is None:
        return "receipt without durable admission"
    return None


@dataclass(frozen=True)
class Reservation:
    # Topology authority: Hold and reservation; ref authority: token fence
    # and trunk. Actor-held tokens survive crash and former-owner restart.
    top_token: int = 0
    top_owner: int = -1
    held: bool = False
    hold_requested: bool = False
    takeover_requested: bool = False
    takeover_used: bool = False
    ref_active: int = 0
    ref_fence: int = 0
    ref_revoke_attempted: int = 0
    trunk: int = 0
    accepted_token: int = 0
    accepted_after_hold: bool = False
    accepted_by_former_owner: bool = False
    gate_passed: bool = False
    receipt: bool = False
    actor_tokens: tuple[int, int] = (0, 0)
    actor0_up: bool = True
    actor0_crashed: bool = False


def reservation_steps(s: Reservation, defect: str = ""):
    if not s.gate_passed:
        yield "gate_pass", replace(s, gate_passed=True)
    if s.top_token == 0 and not s.held and s.accepted_token == 0:
        yield "reserve_owner0", replace(s, top_token=1, top_owner=0,
                                        actor_tokens=(1, 0))
    if s.top_token and not s.hold_requested and not s.held:
        yield "request_hold", replace(s, hold_requested=True)
    if s.top_token and not s.takeover_requested and not s.takeover_used:
        yield "request_takeover", replace(s, takeover_requested=True)
    if s.actor0_up and not s.actor0_crashed:
        yield "crash_owner0", replace(s, actor0_up=False, actor0_crashed=True)
    if not s.actor0_up:
        yield "restart_owner0", replace(s, actor0_up=True)
    if s.accepted_token and not s.receipt:
        yield "recover_receipt", replace(s, receipt=True)

    # Any live actor may deliver an already minted token late. A tombstone in
    # the ref authority must reject it even if the active slot is empty.
    for actor, token in enumerate(s.actor_tokens):
        if not token or (actor == 0 and not s.actor0_up):
            continue
        if not s.ref_active and not s.accepted_token and token > s.ref_fence:
            yield f"grant_token{token}", replace(s, ref_active=token)
        if (s.gate_passed and s.ref_active == token and s.trunk == 0):
            yield f"cas_token{token}", replace(
                s, trunk=1, accepted_token=token, ref_active=0,
                ref_fence=max(s.ref_fence, token),
                accepted_after_hold=s.held,
                accepted_by_former_owner=(actor != s.top_owner),
            )

    # Revocation and CAS serialize at the ref authority. The revocation of
    # an absent permit still persists a tombstone, fencing a late grant.
    if s.top_token and (s.hold_requested or s.takeover_requested):
        token = s.top_token
        if s.ref_fence < token and not s.accepted_token:
            yield f"revoke_token{token}", replace(
                s, ref_active=0 if s.ref_active == token else s.ref_active,
                ref_fence=s.ref_fence if defect == "no_tombstone" else token,
                ref_revoke_attempted=max(s.ref_revoke_attempted, token),
            )

    if s.hold_requested and not s.held:
        fenced = s.ref_fence >= s.top_token
        if fenced or (defect == "ack_hold_early") or (
            defect == "no_tombstone" and s.ref_revoke_attempted >= s.top_token
            and s.ref_active == 0
        ):
            yield "ack_hold", replace(s, held=True, top_token=0, top_owner=-1,
                                      hold_requested=False, takeover_requested=False)

    if s.takeover_requested and not s.takeover_used and not s.held:
        fenced = s.ref_fence >= s.top_token
        if (fenced or defect == "takeover_early") and not s.accepted_token:
            new_token = s.top_token + 1
            yield "ack_takeover", replace(
                s, top_token=new_token, top_owner=1, takeover_requested=False,
                takeover_used=True, actor_tokens=(s.actor_tokens[0], new_token),
            )


def reservation_violation(s: Reservation):
    if s.trunk != int(bool(s.accepted_token)):
        return "trunk and admission history disagree"
    if s.accepted_after_hold:
        return "Hold was acknowledged before admission"
    if s.accepted_by_former_owner:
        return "a former owner admitted after takeover"
    if s.receipt and not s.accepted_token:
        return "receipt without durable admission"
    return None


def explore(initial, steps, invariant, defect="", depth=8):
    queue = deque([(initial, ())])
    visited = {initial}
    while queue:
        state, trace = queue.popleft()
        error = invariant(state)
        if error:
            return len(visited), error, trace
        if len(trace) == depth:
            continue
        for event, successor in steps(state, defect):
            if successor not in visited:
                visited.add(successor)
                queue.append((successor, trace + (event,)))
    return len(visited), None, ()


def scenario(initial, steps, events):
    state = initial
    for event in events:
        matches = [successor for name, successor in steps(state) if name == event]
        assert len(matches) == 1, (event, state)
        state = matches[0]
    return state


def scenarios():
    # A ref-owned Hold or takeover fences a restarted holder of an old view.
    ref_held = scenario(RefPolicy(), ref_policy_steps, (
        "gate_pass", "crash_owner0", "hold", "restart_owner0",
    ))
    assert "cas_owner0" not in {event for event, _ in ref_policy_steps(ref_held)}
    ref_taken = scenario(RefPolicy(), ref_policy_steps, (
        "gate_pass", "crash_owner0", "takeover", "restart_owner0",
    ))
    assert "cas_owner0" not in {event for event, _ in ref_policy_steps(ref_taken)}
    ref_landed = scenario(RefPolicy(), ref_policy_steps, (
        "gate_pass", "cas_owner0", "crash_owner0", "recover_receipt",
    ))
    assert ref_landed.trunk == 1 and ref_landed.receipt

    # CAS wins: Hold can be acknowledged afterward and recovery proves it.
    landed = scenario(Reservation(), reservation_steps, (
        "reserve_owner0", "grant_token1", "gate_pass", "request_hold",
        "cas_token1", "ack_hold", "recover_receipt",
    ))
    assert landed.accepted_token == 1 and landed.held and landed.receipt
    crashed_after_cas = scenario(Reservation(), reservation_steps, (
        "reserve_owner0", "grant_token1", "gate_pass", "cas_token1",
        "crash_owner0", "recover_receipt", "restart_owner0",
    ))
    assert crashed_after_cas.trunk == 1 and crashed_after_cas.receipt
    assert "cas_token1" not in {
        event for event, _ in reservation_steps(crashed_after_cas)
    }

    # Hold wins: revoke-before-ack fences even a restarted former owner.
    held = scenario(Reservation(), reservation_steps, (
        "reserve_owner0", "grant_token1", "gate_pass", "crash_owner0",
        "request_hold", "revoke_token1", "ack_hold", "restart_owner0",
    ))
    assert "cas_token1" not in {event for event, _ in reservation_steps(held)}

    # A revoke before a delayed grant must leave a durable tombstone.
    late = scenario(Reservation(), reservation_steps, (
        "reserve_owner0", "request_hold", "revoke_token1", "ack_hold",
    ))
    assert "grant_token1" not in {event for event, _ in reservation_steps(late)}

    # A takeover cannot acknowledge a new owner while the old token can CAS.
    taken = scenario(Reservation(), reservation_steps, (
        "reserve_owner0", "grant_token1", "request_takeover",
        "revoke_token1", "ack_takeover", "grant_token2", "gate_pass",
    ))
    assert "cas_token1" not in {event for event, _ in reservation_steps(taken)}
    assert "cas_token2" in {event for event, _ in reservation_steps(taken)}


def main():
    scenarios()
    checks = (
        ("ref-owned policy and fence", RefPolicy(), ref_policy_steps,
         ref_policy_violation, "", 8),
        ("ref-owned stale policy read", RefPolicy(), ref_policy_steps,
         ref_policy_violation, "stale_policy_read", 5),
        ("ref-owned stale owner", RefPolicy(), ref_policy_steps,
         ref_policy_violation, "stale_owner", 5),
        ("split reservation with ref token", Reservation(), reservation_steps,
         reservation_violation, "", 8),
        ("split Hold acknowledged early", Reservation(), reservation_steps,
         reservation_violation, "ack_hold_early", 7),
        ("split takeover acknowledged early", Reservation(), reservation_steps,
         reservation_violation, "takeover_early", 7),
        ("split revoke without tombstone", Reservation(), reservation_steps,
         reservation_violation, "no_tombstone", 8),
    )
    for label, initial, steps, invariant, defect, depth in checks:
        count, error, trace = explore(initial, steps, invariant, defect, depth)
        if bool(error) != bool(defect):
            raise SystemExit(f"{label}: unexpected {error} after {count} states")
        print(f"{label}: {count} states through depth {depth}; {error or 'no violation'}")
        if trace:
            print("  " + " -> ".join(trace))


if __name__ == "__main__":
    main()
