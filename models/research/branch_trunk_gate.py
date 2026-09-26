#!/usr/bin/env python3
"""Bounded control-plane model for the proposed branch-to-trunk gate.

Run: python3 models/research/branch_trunk_gate.py

This is research, not the product protocol. Every transition is atomic. In
particular, commit represents a policy-fenced trunk CAS, whose implementation
across today's separate authorities remains an open design question.
"""

from collections import deque
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class Submission:
    op: int
    branch: int
    prefix: tuple[str, ...]
    delta: tuple[str, ...]
    base: int
    epoch: int
    candidate: tuple
    gate: str = "waiting"
    landed: bool = False


@dataclass(frozen=True)
class Branch:
    authored: tuple[str, ...] = ()
    head: tuple[str, ...] = ()
    frontier: tuple[str, ...] = ()
    epoch: int = 0
    held: bool = False
    submission: Submission | None = None


@dataclass(frozen=True)
class Admission:
    op: int
    branch: int
    prefix: tuple[str, ...]
    delta: tuple[str, ...]
    base: int
    epoch: int
    observed_epoch: int
    observed_hold: bool
    gate: str
    candidate: tuple


@dataclass(frozen=True)
class State:
    branches: tuple[Branch, Branch] = (Branch(), Branch())
    trunk: tuple[str, ...] = ()
    admissions: tuple[Admission, ...] = ()
    next_op: int = 1
    external_done: bool = False
    up: bool = True


def branch_at(state: State, index: int, value: Branch) -> State:
    branches = list(state.branches)
    branches[index] = value
    return replace(state, branches=tuple(branches))


def transitions(state: State, defect: str = ""):
    """Yield (event, successor); only the named defect changes the protocol."""
    for i, branch in enumerate(state.branches):
        # Each of two twigs contributes once, at a completed turn boundary.
        for twig in range(2):
            change = f"b{i}t{twig}"
            if change not in branch.authored:
                authored = branch.authored + (change,)
                yield f"contribute {change}", branch_at(
                    state, i, replace(branch, authored=authored, head=authored)
                )

        if not branch.held:
            yield f"hold b{i}", branch_at(
                state, i, replace(branch, held=True, epoch=branch.epoch + 1)
            )
        else:
            yield f"release b{i}", branch_at(
                state, i, replace(branch, held=False, epoch=branch.epoch + 1)
            )

        submission = branch.submission
        if not state.up:
            continue
        if submission is None and not branch.held and len(branch.head) > len(branch.frontier):
            assert branch.head[: len(branch.frontier)] == branch.frontier
            delta = branch.head[len(branch.frontier) :]
            op = state.next_op
            candidate = (len(state.admissions), state.trunk, branch.head, delta, branch.epoch, op)
            proposal = Submission(
                op, i, branch.head, delta, len(state.admissions), branch.epoch, candidate
            )
            yield f"submit b{i} op{op}", replace(
                branch_at(state, i, replace(branch, submission=proposal)), next_op=op + 1
            )
        if submission is None:
            continue
        if not submission.landed and submission.gate == "waiting":
            for verdict in ("passed", "failed", "unrun"):
                yield f"gate_{verdict} op{submission.op}", branch_at(
                    state, i, replace(branch, submission=replace(submission, gate=verdict))
                )
        if not submission.landed and submission.gate in ("failed", "unrun"):
            yield f"supersede op{submission.op}", branch_at(
                state, i, replace(branch, submission=None)
            )
        if not submission.landed:
            yield f"cancel op{submission.op}", branch_at(
                state, i, replace(branch, submission=None)
            )
        if submission.landed:
            # Receipt/frontier recording is a separate, fallible step. The
            # CAS already happened, so this step may not redo it.
            yield f"finish op{submission.op}", branch_at(
                state, i, replace(branch, frontier=submission.prefix, submission=None)
            )
            continue
        # This step must be ONE authority operation: recheck policy, the exact
        # candidate certificate, and expected trunk; then CAS with op identity.
        if submission.gate != "passed" and defect != "skip_gate":
            continue
        if (branch.held or branch.epoch != submission.epoch) and defect != "ignore_hold":
            continue
        if submission.base != len(state.admissions) and defect != "stale_base":
            continue
        if any(entry.op == submission.op for entry in state.admissions):
            continue
        entry = Admission(
            submission.op,
            i,
            submission.prefix,
            submission.delta,
            submission.base,
            submission.epoch,
            branch.epoch,
            branch.held,
            submission.gate,
            submission.candidate,
        )
        admitted = replace(
            branch_at(state, i, replace(branch, submission=replace(submission, landed=True))),
            trunk=state.trunk + submission.delta,
            admissions=state.admissions + (entry,),
        )
        if defect == "drop_tail":
            admitted = branch_at(
                admitted, i, replace(admitted.branches[i], head=submission.prefix)
            )
        yield f"commit_submission op{submission.op}", admitted

    if state.up:
        yield "crash", replace(state, up=False)
    else:
        recovered = replace(state, up=True)
        for i, branch in enumerate(recovered.branches):
            submission = branch.submission
            if submission is None:
                continue
            landed = any(entry.op == submission.op for entry in recovered.admissions)
            if landed:
                if defect == "replay_after_crash":
                    # Incorrectly treating an absent local receipt as failed
                    # repeats the effect under a newly minted operation id.
                    replay = Admission(
                        recovered.next_op, i, submission.prefix, submission.delta,
                        len(recovered.admissions), branch.epoch, branch.epoch,
                        branch.held, "passed",
                        (len(recovered.admissions), recovered.trunk,
                         submission.prefix, submission.delta, branch.epoch,
                         recovered.next_op),
                    )
                    recovered = replace(
                        recovered,
                        trunk=recovered.trunk + submission.delta,
                        admissions=recovered.admissions + (replay,),
                        next_op=recovered.next_op + 1,
                    )
                recovered = branch_at(
                    recovered, i,
                    replace(recovered.branches[i], frontier=submission.prefix, submission=None),
                )
        yield "recover", recovered

    if not state.external_done:
        # A competing trunk authority has already gated its own result. This
        # environment step intentionally says nothing about its checks.
        yield "trunk_advance external", replace(
            state,
            trunk=state.trunk + ("external",),
            admissions=state.admissions + (
                Admission(0, -1, (), ("external",), len(state.admissions), 0, 0,
                          False, "passed", ("external",)),
            ),
            external_done=True,
        )


def violation(state: State) -> str | None:
    for branch in state.branches:
        if branch.head != branch.authored:
            return "a completed twig contribution was lost from the branch head"
        if branch.head[: len(branch.frontier)] != branch.frontier:
            return "the integrated frontier is not a prefix of the branch"
    seen: set[str] = set()
    operations: set[int] = set()
    trunk: tuple[str, ...] = ()
    for position, entry in enumerate(state.admissions):
        if entry.base != position:
            return "a stale trunk base was admitted"
        if entry.op in operations:
            return "an operation id was admitted twice"
        operations.add(entry.op)
        if entry.branch >= 0:
            if entry.gate != "passed":
                return "a submission was admitted without a passing gate"
            if entry.observed_hold or entry.epoch != entry.observed_epoch:
                return "Hold or a newer policy epoch preceded admission"
            if entry.candidate != (
                entry.base, trunk, entry.prefix, entry.delta, entry.epoch, entry.op
            ):
                return "the admitted certificate changed identity"
        for change in entry.delta:
            if change in seen:
                return "a branch change reached trunk twice"
            seen.add(change)
        trunk += entry.delta
    if trunk != state.trunk:
        return "trunk differs from the durable admission log"
    return None


def explore(defect: str = "", depth: int = 9):
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
        for event, next_state in transitions(state, defect):
            if next_state not in visited:
                visited.add(next_state)
                queue.append((next_state, trace + (event,)))
    return len(visited), None, ()


def scenario(events: tuple[str, ...]) -> State:
    state = State()
    for wanted in events:
        matches = [next_state for event, next_state in transitions(state) if event == wanted]
        assert len(matches) == 1, (wanted, events, state)
        state = matches[0]
        assert violation(state) is None, (wanted, state)
    return state


def assert_scenarios():
    def cannot(state: State, event: str):
        assert event not in {name for name, _ in transitions(state)}, event

    prefix = ("contribute b0t0", "submit b0 op1", "gate_passed op1")
    tail = scenario(prefix + ("contribute b0t1", "commit_submission op1", "finish op1",
                              "submit b0 op2"))
    assert tail.branches[0].submission.delta == ("b0t1",)

    stale = scenario(prefix + ("trunk_advance external",))
    cannot(stale, "commit_submission op1")
    rebased = scenario(prefix + ("trunk_advance external", "cancel op1",
                                 "submit b0 op2", "gate_passed op2",
                                 "commit_submission op2"))
    assert rebased.trunk == ("external", "b0t0")

    held = scenario(prefix + ("hold b0", "release b0"))
    cannot(held, "commit_submission op1")
    scenario(prefix + ("hold b0", "release b0", "cancel op1", "submit b0 op2",
                       "gate_passed op2", "commit_submission op2"))

    repaired = scenario(("contribute b0t0", "submit b0 op1", "gate_failed op1",
                         "contribute b0t1", "supersede op1", "submit b0 op2",
                         "gate_passed op2", "commit_submission op2"))
    assert repaired.trunk == ("b0t0", "b0t1")

    competing = scenario(("contribute b0t0", "contribute b1t0", "submit b0 op1",
                          "submit b1 op2", "gate_passed op1", "gate_passed op2",
                          "commit_submission op1"))
    cannot(competing, "commit_submission op2")

    pre_cas = scenario(prefix + ("crash", "recover", "commit_submission op1"))
    assert pre_cas.trunk == ("b0t0",)
    post_cas = scenario(prefix + ("commit_submission op1", "crash", "recover"))
    cannot(post_cas, "commit_submission op1")
    assert post_cas.branches[0].frontier == ("b0t0",)
    post_receipt = scenario(prefix + ("commit_submission op1", "finish op1",
                                      "crash", "recover"))
    assert post_receipt.trunk == ("b0t0",)
    print("adversarial scenarios: passed")


def main():
    assert_scenarios()
    checks = (
        ("correct", "", 9),
        ("no gate check", "skip_gate", 5),
        ("no policy fence", "ignore_hold", 6),
        ("no trunk CAS", "stale_base", 7),
        ("drop branch tail", "drop_tail", 6),
        ("replay after crash", "replay_after_crash", 6),
    )
    for label, defect, depth in checks:
        count, error, trace = explore(defect, depth)
        if bool(error) != bool(defect):
            raise SystemExit(f"{label}: unexpected result after {count} states: {error}")
        print(f"{label}: {count} states through depth {depth}; {error or 'no violation'}")
        if trace:
            print("  " + " -> ".join(trace))


if __name__ == "__main__":
    main()
