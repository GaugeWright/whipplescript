#!/usr/bin/env python3
"""Compose the norm-ledger exclusion with ref-owned Hold and owner fencing.

Run: python3 models/research/composed_admission.py
One prepared candidate; operator takeover retains its original principal.
"""

from collections import deque
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class State:
    # Immutable submission: principal p0, intent i0, norm revision 0,
    # branch policy epoch 0, and trunk base 0. Operators are custodians.
    gate_passed: bool = False
    norm_revision: int = 0
    principal_granted: bool = True
    operator1_principal_granted: bool = True  # Does not authorize p0's submission.
    ledger_locked_by: int = -1
    prechecked_revision: int = -1
    prechecked_granted: bool = False
    validated_revision: int = -1
    validated_by: int = -1
    validated_principal: bool = False
    validated_principal_identity: int = 0
    branch_epoch: int = 0
    held: bool = False
    owner: int = 0
    owner_fence: int = 0
    trunk: int = 0
    admission: tuple[int, bool, bool, int, int, bool, int, bool] | None = None
    receipt: bool = False
    operator0_up: bool = True
    crashed_once: bool = False
    takeover_used: bool = False
    hold_used: bool = False
    norm_changed: bool = False


def steps(s: State, defect: str = ""):
    if not s.gate_passed:
        yield "gate_pass", replace(s, gate_passed=True)
    if not s.norm_changed and s.ledger_locked_by == -1:
        yield "revoke_original_grant", replace(
            s, norm_revision=s.norm_revision + 1,
            principal_granted=False, norm_changed=True,
        )
    if not s.hold_used:
        yield "hold", replace(s, held=True, branch_epoch=s.branch_epoch + 1,
                              hold_used=True)
    if not s.takeover_used:
        yield "takeover", replace(s, owner=1, owner_fence=s.owner_fence + 1,
                                  takeover_used=True)
    if s.operator0_up and not s.crashed_once:
        yield "crash_operator0", replace(s, operator0_up=False, crashed_once=True,
                                         ledger_locked_by=(-1 if s.ledger_locked_by == 0
                                                           else s.ledger_locked_by),
                                         validated_revision=(-1 if s.validated_by == 0
                                                             else s.validated_revision),
                                         validated_by=(-1 if s.validated_by == 0
                                                       else s.validated_by))
    if not s.operator0_up:
        yield "restart_operator0", replace(s, operator0_up=True)
    if s.admission and not s.receipt:
        yield "recover_receipt", replace(s, receipt=True)

    if not s.gate_passed or s.trunk:
        return
    if s.prechecked_revision == -1:
        yield "precheck_without_lock", replace(
            s, prechecked_revision=s.norm_revision,
            prechecked_granted=s.principal_granted,
        )
    for actor in (0, 1):
        if actor == 0 and not s.operator0_up:
            continue
        if actor == 1 and not s.takeover_used:
            continue
        if s.ledger_locked_by == -1:
            # Norm-plane §5: exclusion THEN re-capture every ledger premise.
            # The protected grant is that of the ORIGINAL submission's p0.
            rebinding = defect == "rebind_principal" and actor == 1
            revision = (s.prechecked_revision if defect == "trust_precheck"
                        else s.norm_revision)
            granted = (s.prechecked_granted if defect == "trust_precheck"
                       else s.operator1_principal_granted if rebinding
                       else s.principal_granted)
            if (revision == 0 or rebinding) and granted:
                yield f"lock_and_validate_owner{actor}", replace(
                    s, ledger_locked_by=actor, validated_revision=revision,
                    validated_by=actor,
                    validated_principal=granted,
                    validated_principal_identity=1 if rebinding else 0,
                )
        if s.ledger_locked_by == actor:
            yield f"release_ledger_owner{actor}", replace(s, ledger_locked_by=-1)
        if (s.ledger_locked_by != actor and
                not (defect == "release_before_cas" and s.validated_revision == 0)):
            continue
        if s.validated_by != actor:
            continue
        if (s.validated_revision != 0 and defect != "rebind_principal") or not s.validated_principal:
            continue
        if (s.held or s.branch_epoch != 0) and defect != "trust_old_hold":
            continue
        if (s.owner != actor or s.owner_fence != actor) and defect != "trust_old_owner":
            continue
        # This is the ref store CAS, guarded by the standing mainline lease.
        # Record the premises observed at the actual commit, for invariants.
        yield f"cas_owner{actor}", replace(
            s, trunk=1,
            admission=(s.norm_revision, s.principal_granted, s.held,
                       s.validated_principal_identity,
                       s.branch_epoch, s.ledger_locked_by == actor,
                       actor, s.owner == actor),
            ledger_locked_by=-1,
        )


def violation(s: State):
    if s.trunk != int(s.admission is not None):
        return "trunk and admission history disagree"
    if s.receipt and not s.admission:
        return "receipt lacks durable admission"
    if s.admission:
        revision, granted, held, principal, branch_epoch, locked, actor, current_owner = s.admission
        if principal != 0:
            return "takeover substituted a different principal for the submission"
        if revision != 0 or not granted:
            return "norm ledger changed or original principal was revoked"
        if not locked:
            return "CAS ran without norm-ledger write exclusion"
        if held or branch_epoch != 0:
            return "Hold or branch policy changed before CAS"
        if not current_owner:
            return "former owner performed CAS after takeover"
        if actor not in (0, 1):
            return "unknown coordinator"
    return None


def explore(defect="", depth=8):
    queue = deque([(State(), ())])
    visited = {State()}
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
    passed = scenario(("gate_pass", "lock_and_validate_owner0", "cas_owner0",
                       "recover_receipt"))
    assert passed.trunk == 1 and passed.receipt

    revoked = scenario(("gate_pass", "revoke_original_grant"))
    assert not any(e.startswith("lock_and_validate") for e, _ in steps(revoked))

    locked = scenario(("gate_pass", "lock_and_validate_owner0"))
    assert "revoke_original_grant" not in {e for e, _ in steps(locked)}
    held = scenario(("gate_pass", "lock_and_validate_owner0", "hold"))
    assert "cas_owner0" not in {e for e, _ in steps(held)}

    takeover = scenario(("gate_pass", "crash_operator0", "takeover",
                         "lock_and_validate_owner1", "cas_owner1"))
    assert takeover.admission[1]  # p0's original grant, not owner1's grant.
    crashed = scenario(("gate_pass", "lock_and_validate_owner0",
                        "crash_operator0", "takeover"))
    assert "cas_owner0" not in {e for e, _ in steps(crashed)}


def main():
    scenarios()
    for label, defect, depth in (
        ("composed admission", "", 8),
        ("trust pre-lock read", "trust_precheck", 6),
        ("release exclusion before CAS", "release_before_cas", 6),
        ("trust old Hold", "trust_old_hold", 5),
        ("trust former owner", "trust_old_owner", 5),
        ("rebind original principal on takeover", "rebind_principal", 7),
    ):
        count, error, trace = explore(defect, depth)
        if bool(error) != bool(defect):
            raise SystemExit(f"{label}: unexpected {error} after {count} states")
        print(f"{label}: {count} states through depth {depth}; {error or 'no violation'}")
        if trace:
            print("  " + " -> ".join(trace))


if __name__ == "__main__":
    main()
