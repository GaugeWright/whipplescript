#!/usr/bin/env python3
"""Bounded boundary between one collaboration trunk and two native targets.

Run: python3 models/research/target_settlement.py
This restates GaugeDesk's existing receipt ordering as a research seam probe.
"""

from collections import deque
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class Target:
    status: str = "not_started"  # submitted, unknown, success, failed
    effects: int = 0
    receipt: bool = False


@dataclass(frozen=True)
class State:
    mode: str = "later"  # later settlement, or combined admit-and-settle
    collaboration_accepted: bool = False
    all_preflight_passed: bool = False
    preflight_failed: bool = False
    targets: tuple[Target, Target] = (Target(), Target())
    report: str = "pending"  # partial, settled
    started_without_preflight: bool = False


def target_at(s: State, i: int, target: Target) -> State:
    targets = list(s.targets)
    targets[i] = target
    return replace(s, targets=tuple(targets))


def steps(s: State, defect: str = ""):
    if (not s.collaboration_accepted and not s.preflight_failed and
            (s.mode == "later" or s.all_preflight_passed or
             defect == "combined_skip_preflight")):
        yield "admit_collaboration", replace(s, collaboration_accepted=True)
    if not s.all_preflight_passed and not s.preflight_failed and (
        s.mode == "combined" or s.collaboration_accepted
    ):
        yield "preflight_all_targets", replace(s, all_preflight_passed=True)
        if s.mode == "combined":
            yield "preflight_refuses", replace(s, preflight_failed=True)
    for i, target in enumerate(s.targets):
        if target.status == "not_started" and s.collaboration_accepted and (
            s.all_preflight_passed or defect == "skip_preflight"
        ):
            yield f"start_{i}", target_at(
                replace(s, started_without_preflight=(s.started_without_preflight or
                        not s.all_preflight_passed)), i,
                replace(target, status="submitted"),
            )
        if target.status == "submitted":
            yield f"success_{i}", target_at(
                s, i, replace(target, status="success", effects=1, receipt=True)
            )
            yield f"failure_{i}", target_at(s, i, replace(target, status="failed"))
            yield f"lost_reply_after_effect_{i}", target_at(
                s, i, replace(target, status="unknown", effects=1)
            )
            yield f"lost_reply_before_effect_{i}", target_at(
                s, i, replace(target, status="unknown")
            )
        if target.status == "unknown":
            if target.effects:
                yield f"query_proves_success_{i}", target_at(
                    s, i, replace(target, status="success", receipt=True)
                )
            else:
                yield f"query_proves_no_effect_{i}", target_at(
                    s, i, replace(target, status="failed")
                )
            if defect == "retry_unknown":
                yield f"blind_retry_{i}", target_at(
                    s, i, replace(target, effects=target.effects + 1)
                )
    if s.report == "pending":
        if defect == "collaboration_is_settlement" and s.collaboration_accepted:
            yield "claim_settled", replace(s, report="settled")
        if all(t.status == "success" and t.receipt for t in s.targets):
            yield "report_settled", replace(s, report="settled")
        if defect == "unknown_is_success" and all(
            t.status in ("success", "unknown") for t in s.targets
        ):
            yield "claim_unknown_settled", replace(s, report="settled")
        if any(t.status == "success" for t in s.targets) and any(
            t.status == "failed" for t in s.targets
        ):
            yield "report_partial", replace(s, report="partial")


def violation(s: State):
    if s.mode == "combined" and s.collaboration_accepted and not s.all_preflight_passed:
        return "combined request advanced collaboration before target preflight"
    if s.preflight_failed and (s.collaboration_accepted or any(
        t.status != "not_started" for t in s.targets
    )):
        return "combined preflight refusal still started an effect"
    if s.started_without_preflight:
        return "a target started before all-target preflight"
    if any(t.effects > 1 for t in s.targets):
        return "an unknown external effect was blindly replayed"
    if s.report == "settled" and not (
        s.collaboration_accepted and all(t.receipt for t in s.targets)
    ):
        return "collaboration or unknown target outcome was called settled"
    if s.report == "partial" and not (
        any(t.status == "success" for t in s.targets) and
        any(t.status == "failed" for t in s.targets)
    ):
        return "partial report lacks mixed target results"
    return None


def explore(defect="", depth=9, mode="later"):
    initial = State(mode=mode)
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


def scenario(events, mode="later"):
    state = State(mode=mode)
    for wanted in events:
        matches = [successor for event, successor in steps(state) if event == wanted]
        assert len(matches) == 1, (wanted, state)
        state = matches[0]
        assert violation(state) is None, (wanted, state)
    return state


def scenarios():
    partial = scenario(("admit_collaboration", "preflight_all_targets",
                        "start_0", "start_1", "success_0", "failure_1",
                        "report_partial"))
    assert partial.report == "partial" and partial.collaboration_accepted
    unknown = scenario(("admit_collaboration", "preflight_all_targets",
                        "start_0", "start_1", "lost_reply_after_effect_0",
                        "success_1"))
    assert "report_settled" not in {e for e, _ in steps(unknown)}
    recovered = scenario(("admit_collaboration", "preflight_all_targets",
                          "start_0", "start_1", "lost_reply_after_effect_0",
                          "success_1", "query_proves_success_0", "report_settled"))
    assert recovered.report == "settled"
    combined = scenario(("preflight_all_targets", "admit_collaboration",
                         "start_0", "start_1", "success_0", "success_1",
                         "report_settled"), mode="combined")
    assert combined.report == "settled"
    refused = scenario(("preflight_refuses",), mode="combined")
    assert "admit_collaboration" not in {e for e, _ in steps(refused)}


def main():
    scenarios()
    for label, defect, depth, mode in (
        ("later settlement", "", 9, "later"),
        ("combined admit and settle", "", 9, "combined"),
        ("local admission called settlement", "collaboration_is_settlement", 3, "later"),
        ("unknown called success", "unknown_is_success", 8, "later"),
        ("unknown blindly retried", "retry_unknown", 6, "later"),
        ("skip all-target preflight", "skip_preflight", 3, "later"),
        ("combined advance before preflight", "combined_skip_preflight", 3, "combined"),
    ):
        count, error, trace = explore(defect, depth, mode)
        if bool(error) != bool(defect):
            raise SystemExit(f"{label}: unexpected {error} after {count} states")
        print(f"{label}: {count} states through depth {depth}; {error or 'no violation'}")
        if trace:
            print("  " + " -> ".join(trace))


if __name__ == "__main__":
    main()
