"""Bounded probe of contribution conservation across the branch lifecycle.

Run: python3 models/research/contribution_lifecycle.py

This abstracts one branch, two contributions (u1 depends on u0), one revision,
one Hold, gate attempts, crash/recovery, and closure. It does not model cuts or
the physical ref/ledger stores. See models/research/README.md for limits.
"""

from collections import deque
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class Attempt:
    op: int
    selected: tuple[int, ...]
    epoch: int
    version0: int
    basis1: int
    base: int
    verdict: str = "waiting"
    committed: bool = False


@dataclass(frozen=True)
class Admission:
    op: int
    selected: tuple[int, ...]
    submitted_epoch: int
    commit_epoch: int
    submitted_version0: int
    commit_version0: int
    commit_basis1: int
    prior_accounted: tuple[int, ...]
    selected_holders: tuple[str, ...]
    held: bool
    ref_enabled: bool


@dataclass(frozen=True)
class State:
    holders: tuple[str, str] = ("none", "none")
    ever_written: tuple[bool, bool] = (False, False)
    version0: int = 0
    basis1: int = 0
    epoch: int = 0
    held: bool = False
    hold_used: bool = False
    revision_used: bool = False
    ref_enabled: bool = True
    close: str = "open"  # open, closing, closed
    attempt: Attempt | None = None
    admissions: tuple[Admission, ...] = ()
    next_op: int = 1
    external: str = "none"  # none, branch, release, settled
    crashed: bool = False
    crash_used: bool = False


def unit_at(s: State, unit: int, holder: str) -> State:
    holders = list(s.holders)
    holders[unit] = holder
    return replace(s, holders=tuple(holders))


def written_at(s: State, unit: int) -> State:
    written = list(s.ever_written)
    written[unit] = True
    return replace(s, ever_written=tuple(written))


def accounted(s: State) -> tuple[int, ...]:
    return tuple(i for i in (0, 1) if s.holders[i] == "accounted")


def selections(s: State, defect: str) -> tuple[tuple[int, ...], ...]:
    selected = []
    if s.holders[0] == "branch":
        selected.append((0,))
        if s.holders[1] == "branch" and (
            s.basis1 == s.version0 or defect == "skip_rebase"
        ):
            selected.append((0, 1))
    elif s.holders[0] == "accounted" and s.holders[1] == "branch" and (
        s.basis1 == s.version0 or defect == "skip_rebase"
    ):
        selected.append((1,))
    if defect == "skip_dependency" and s.holders == ("branch", "branch"):
        selected.append((1,))
    return tuple(selected)


def steps(s: State, defect: str = ""):
    if s.crashed:
        yield "restart", replace(s, crashed=False)
        return

    if not s.crash_used:
        yield "crash", replace(s, crashed=True, crash_used=True)

    if s.close == "open":
        for i in (0, 1):
            if s.holders[i] == "none" and (i == 0 or s.ever_written[0]):
                written = written_at(unit_at(s, i, "twig"), i)
                if i == 1:
                    # Reads during a revision still see the old completed
                    # basis; writing after repair sees the new version.
                    basis = s.version0 - 1 if s.holders[0] == "revising" else s.version0
                    written = replace(written, basis1=basis)
                yield f"write u{i}", written
            if s.holders[i] == "twig":
                yield f"ready u{i}", unit_at(s, i, "twig_ready")
            if s.holders[i] == "twig_ready" and (
                i == 0 or (s.holders[0] in ("branch", "accounted") and
                           s.basis1 == s.version0)
            ):
                yield f"share u{i}", unit_at(s, i, "branch")

    if (s.holders[1] in ("twig", "twig_ready", "branch") and
            s.holders[0] in ("branch", "accounted") and
            s.basis1 != s.version0):
        # Rebinding a shared dependent changes the meaning of a candidate.
        bump = 1 if s.holders[1] == "branch" else 0
        yield "rebase u1", replace(s, basis1=s.version0, epoch=s.epoch + bump)

    if s.holders[0] == "branch" and not s.revision_used:
        yield "revise u0", replace(
            unit_at(s, 0, "revising"), version0=s.version0 + 1,
            epoch=s.epoch + 1, revision_used=True,
        )
    if s.holders[0] == "revising":
        # A real repair has its own identity and derivation receipt; this
        # probe collapses it to a new version of u0.
        yield "finish repair u0", unit_at(s, 0, "branch")

    if not s.hold_used and s.close == "open":
        yield "hold", replace(s, held=True, hold_used=True, epoch=s.epoch + 1)
    if s.held and s.close == "open":
        yield "release Hold", replace(s, held=False, epoch=s.epoch + 1)

    attempt = s.attempt
    if attempt is None and s.ref_enabled and not s.held and s.next_op <= 2:
        for chosen in selections(s, defect):
            yield f"submit {chosen}", replace(
                s, attempt=Attempt(s.next_op, chosen, s.epoch, s.version0,
                                   s.basis1, len(s.admissions)),
                next_op=s.next_op + 1,
            )
    if attempt is not None:
        if not attempt.committed and attempt.verdict == "waiting":
            for verdict in ("passed", "failed", "unrun"):
                yield f"gate {verdict}", replace(
                    s, attempt=replace(attempt, verdict=verdict)
                )
        if not attempt.committed:
            cancelled = replace(s, attempt=None)
            if defect == "drop_on_cancel":
                for i in attempt.selected:
                    cancelled = unit_at(cancelled, i, "lost")
            yield "cancel attempt", cancelled
        if attempt.verdict == "passed" and not attempt.committed:
            eligible = (
                s.ref_enabled and not s.held and
                attempt.epoch == s.epoch and
                attempt.base == len(s.admissions) and
                all(s.holders[i] == "branch" for i in attempt.selected) and
                (0 not in attempt.selected or attempt.version0 == s.version0) and
                (1 not in attempt.selected or s.basis1 == s.version0) and
                (1 not in attempt.selected or 0 in attempt.selected or
                 s.holders[0] == "accounted")
            )
            if defect == "trust_stale_revision":
                eligible = (
                    s.ref_enabled and not s.held and
                    attempt.base == len(s.admissions)
                )
            if defect == "skip_dependency":
                eligible = (
                    s.ref_enabled and not s.held and
                    attempt.epoch == s.epoch and
                    attempt.base == len(s.admissions) and
                    all(s.holders[i] == "branch" for i in attempt.selected)
                )
            if defect == "skip_rebase":
                eligible = (
                    s.ref_enabled and not s.held and
                    attempt.epoch == s.epoch and
                    attempt.base == len(s.admissions) and
                    all(s.holders[i] == "branch" for i in attempt.selected)
                )
            if eligible:
                entry = Admission(
                    attempt.op, attempt.selected, attempt.epoch, s.epoch,
                    attempt.version0, s.version0, s.basis1, accounted(s),
                    tuple(s.holders[i] for i in attempt.selected),
                    s.held, s.ref_enabled,
                )
                yield "commit", replace(
                    s, admissions=s.admissions + (entry,),
                    attempt=replace(attempt, committed=True),
                )
        if attempt.committed:
            finished = s
            for i in attempt.selected:
                finished = unit_at(finished, i, "accounted")
            yield "finish accounting", replace(finished, attempt=None)

    if s.close == "open":
        yield "request close", replace(s, close="closing")
    if s.admissions and s.external == "none":
        # A later request against an accepted trunk cut cannot give a closed
        # source branch a new obligation. The release lane owns it directly.
        owner = "release" if s.close == "closed" else "branch"
        yield "request external settlement", replace(s, external=owner)
    if s.external == "branch":
        yield "transfer external settlement", replace(s, external="release")
        yield "settle external", replace(s, external="settled")
    if s.close == "closing" and defect == "close_before_disable":
        yield "ack close early", replace(s, close="closed")
    if s.close == "closing" and s.ref_enabled:
        yield "disable admission", replace(s, ref_enabled=False, epoch=s.epoch + 1)
    if s.close == "closing" and not s.ref_enabled:
        admitted = {i for entry in s.admissions for i in entry.selected}
        for i in (0, 1):
            if s.holders[i] in ("twig", "twig_ready", "branch", "revising") and i not in admitted:
                yield f"park u{i}", unit_at(s, i, "parked")
        if (all(h in ("none", "accounted", "parked") for h in s.holders)
                and attempt is None and
                (s.external != "branch" or defect == "drop_external_on_close")):
            yield "ack close", replace(s, close="closed")


def violation(s: State) -> str | None:
    for i in (0, 1):
        if s.ever_written[i] and s.holders[i] in ("none", "lost"):
            return f"u{i} was written and lost"
        if s.holders[i] == "accounted" and not any(
            i in entry.selected for entry in s.admissions
        ):
            return f"u{i} was marked accounted without a receipt"
    prior = set()
    seen_ops = set()
    for entry in s.admissions:
        if entry.op in seen_ops or any(i in prior for i in entry.selected):
            return "an effect or operation was admitted twice"
        seen_ops.add(entry.op)
        if entry.held or not entry.ref_enabled or entry.submitted_epoch != entry.commit_epoch:
            return "admission crossed Hold, lifecycle, or revision fence"
        if any(h != "branch" for h in entry.selected_holders):
            return "admission used a unit no longer ready on the branch"
        if 0 in entry.selected and entry.submitted_version0 != entry.commit_version0:
            return "admission used a pre-revision candidate"
        if 1 in entry.selected and entry.commit_basis1 != entry.commit_version0:
            return "dependent unit used a stale basis"
        if 1 in entry.selected and 0 not in entry.selected and 0 not in prior:
            return "dependent unit landed without its predecessor"
        prior.update(entry.selected)
    if s.close == "closed" and (
        s.ref_enabled or s.attempt is not None or
        any(h not in ("none", "accounted", "parked") for h in s.holders) or
        s.external == "branch"
    ):
        return "closure acknowledged with live admission or unowned work"
    return None


def explore(defect: str = "", depth: int = 12):
    start = State()
    queue = deque([(start, ())])
    seen = {start}
    while queue:
        state, path = queue.popleft()
        error = violation(state)
        if error:
            return len(seen), path, error
        if len(path) >= depth:
            continue
        for event, after in steps(state, defect):
            if after not in seen:
                seen.add(after)
                queue.append((after, path + (event,)))
    return len(seen), (), None


def scenario(events: tuple[str, ...], defect: str = "") -> State:
    state = State()
    for event in events:
        next_states = dict(steps(state, defect))
        assert event in next_states, (event, state)
        state = next_states[event]
        assert violation(state) is None, (event, violation(state))
    return state


def main():
    scenarios = (
        ("write u0", "ready u0", "share u0", "submit (0,)",
         "gate passed", "cancel attempt", "submit (0,)", "gate passed",
         "commit", "finish accounting"),
        ("write u0", "ready u0", "share u0", "submit (0,)",
         "gate passed", "revise u0", "finish repair u0", "cancel attempt",
         "submit (0,)", "gate passed", "commit"),
        ("write u0", "ready u0", "share u0", "submit (0,)",
         "gate failed", "revise u0", "finish repair u0", "cancel attempt",
         "submit (0,)", "gate passed", "commit"),
        ("write u0", "ready u0", "share u0", "write u1", "ready u1",
         "share u1", "revise u0", "finish repair u0", "rebase u1",
         "submit (0, 1)", "gate passed", "commit"),
        ("write u0", "ready u0", "share u0", "submit (0,)",
         "gate passed", "commit", "crash", "restart", "finish accounting"),
        ("write u0", "ready u0", "share u0", "write u1",
         "request close", "disable admission", "park u0", "park u1",
         "ack close"),
        ("write u0", "ready u0", "share u0", "submit (0,)",
         "gate passed", "commit", "finish accounting",
         "request external settlement", "request close", "disable admission",
         "transfer external settlement", "ack close"),
        ("write u0", "ready u0", "share u0", "submit (0,)",
         "gate passed", "commit", "finish accounting", "request close",
         "disable admission", "ack close", "request external settlement"),
    )
    for events in scenarios:
        scenario(events)
    held = scenario(("write u0", "ready u0", "share u0", "submit (0,)",
                     "gate passed", "hold", "release Hold"))
    assert "commit" not in dict(steps(held))
    assert scenario(scenarios[-1]).external == "release"
    states, path, error = explore()
    assert error is None, (path, error)
    print(f"lifecycle: {states} safe states through 12 steps; scenarios passed")
    for defect in (
        "drop_on_cancel", "skip_dependency", "trust_stale_revision",
        "skip_rebase", "close_before_disable", "drop_external_on_close",
    ):
        states, path, error = explore(defect, depth=12)
        assert error, (defect, states)
        print(f"  {defect}: {error} via {' -> '.join(path)}")


if __name__ == "__main__":
    main()
