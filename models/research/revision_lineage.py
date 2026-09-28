#!/usr/bin/env python3
"""Bounded source-mutation fence and transitive Hold-lineage probe.

Run: python3 models/research/revision_lineage.py

The ref CAS cannot atomically consult a topology-owned head. Every mutation
that changes the selected unit's meaning must advance its ref-owned epoch
before acknowledging the new head. An unrelated tail may leave the selected
prefix intact. This model abstracts real merge content and store transactions.
"""

from collections import deque
from dataclasses import dataclass, replace


# The operations currently capable of changing a source head, represented as
# semantic classes. Production implementation must inventory every call site;
# listing a door here alone does not prove that it takes the fence.
MUTATION_DOORS = (
    "direct_write", "rebase", "selective_transport", "selective_undo",
    "conflict_repair", "import", "revision_request", "head_retarget",
)


@dataclass(frozen=True)
class Attempt:
    source_id: str
    substance: int
    selected_cut: int
    trunk_basis: int
    policy_epochs: tuple[int, int]
    lineage: tuple[str, ...]
    door: str = "scheduled"
    gate: str = "waiting"


@dataclass(frozen=True)
class Admission:
    source_id: str
    submitted_substance: int
    current_substance: int
    submitted_cut: int
    current_cut: int
    selected_lineage: tuple[str, ...]
    true_lineage: tuple[str, ...]
    held_at_commit: tuple[bool, bool]
    epoch_at_commit: tuple[int, int]
    gate: str
    trunk_before: int
    trunk_after: int


@dataclass(frozen=True)
class State:
    # A single still-owed unit starts on A. The selected source cut is
    # distinct from A's moving head, so an unrelated tail need not stale it.
    source_id: str = "u"
    substance: int = 1
    selected_cut: int = 1
    head_cut: int = 1
    holder: str = "A"
    true_lineage: tuple[str, ...] = ("A",)
    visible_lineage: tuple[str, ...] = ("A",)
    epochs: tuple[int, int] = (0, 0)
    held: tuple[bool, bool] = (False, False)
    trunk_version: int = 0
    attempt: Attempt | None = None
    admission: Admission | None = None
    ref_up: bool = True
    topology_up: bool = True
    tail_written: bool = False
    transport_used: bool = False
    mutation_used: bool = False
    mutation_door: str = ""
    mutation_fenced: bool = True
    mixed_output_id: str = ""


def index(branch: str) -> int:
    return ("A", "B").index(branch)


def bump(pair: tuple[int, int], branch: str) -> tuple[int, int]:
    values = list(pair)
    values[index(branch)] += 1
    return tuple(values)


def submit(s: State, door: str = "scheduled") -> State:
    if s.attempt or s.admission or not s.topology_up or not s.ref_up:
        raise ValueError("no available source selection")
    if not set(s.visible_lineage) <= {"A", "B"}:
        raise ValueError("unknown lineage")
    if any(s.held[index(branch)] for branch in s.visible_lineage):
        raise ValueError("source lineage is held")
    attempt = Attempt(s.source_id, s.substance, s.selected_cut,
                      s.trunk_version, s.epochs, s.visible_lineage,
                      door=door)
    return replace(s, attempt=attempt)


def gate_pass(s: State) -> State:
    if not s.attempt or s.attempt.gate != "waiting":
        raise ValueError("no waiting gate")
    return replace(s, attempt=replace(s.attempt, gate="passed"))


def hold(s: State, branch: str) -> State:
    if not s.ref_up:
        raise ValueError("Hold cannot be acknowledged without ref authority")
    i = index(branch)
    held = list(s.held)
    held[i] = True
    return replace(s, held=tuple(held), epochs=bump(s.epochs, branch))


def release_hold(s: State, branch: str) -> State:
    if not s.ref_up or not s.held[index(branch)]:
        raise ValueError("no acknowledged Hold")
    held = list(s.held)
    held[index(branch)] = False
    return replace(s, held=tuple(held), epochs=bump(s.epochs, branch))


def tail_write(s: State) -> State:
    if not s.topology_up or s.tail_written or s.admission:
        raise ValueError("no unrelated tail write")
    # It cannot rewrite the exact prefix represented by selected_cut.
    return replace(s, head_cut=s.head_cut + 1, tail_written=True)


def mutate(s: State, door: str, defect: str = "") -> State:
    if door not in MUTATION_DOORS or s.mutation_used or s.admission:
        raise ValueError("unknown or repeated selected-unit mutation")
    if not s.topology_up or not s.ref_up:
        raise ValueError("no mutation acknowledgement without both authorities")
    fenced = defect != "skip_fence"
    return replace(s, epochs=bump(s.epochs, s.holder) if fenced else s.epochs,
                   substance=s.substance + 1,
                   selected_cut=s.selected_cut + 1,
                   head_cut=s.head_cut + 1,
                   mutation_used=True, mutation_door=door,
                   mutation_fenced=fenced)


def mixed_transport(s: State, defect: str = "") -> State:
    if s.transport_used or s.holder != "A" or s.admission:
        raise ValueError("source has already moved")
    if not s.ref_up or not s.topology_up:
        raise ValueError("transport acknowledgement needs both authorities")
    # The new output id is not the source unit id. B's certificate must retain
    # A in the source-unit lineage even though B now holds the unit.
    return replace(s, holder="B", true_lineage=("A", "B"),
                   visible_lineage=("B",) if defect == "output_only" else ("A", "B"),
                   epochs=bump(s.epochs, "A"), transport_used=True,
                   mixed_output_id="mixed-output")


def cas(s: State, defect: str = "") -> State:
    a = s.attempt
    if not a or a.gate != "passed" or s.admission or not s.ref_up:
        raise ValueError("no passed live candidate")
    if a.trunk_basis != s.trunk_version:
        raise ValueError("stale trunk basis")
    # The ref authority knows epochs and Holds, but not the topology head.
    # A mutation must fence before acknowledging that head change.
    if any(s.held[index(branch)] for branch in a.lineage):
        if defect != "ignore_hold":
            raise ValueError("source lineage is held")
    if any(a.policy_epochs[index(branch)] != s.epochs[index(branch)]
           for branch in a.lineage):
        if defect not in ("ignore_epoch", "ignore_hold"):
            raise ValueError("source lineage epoch changed")
    entry = Admission(a.source_id, a.substance, s.substance,
                      a.selected_cut, s.selected_cut, a.lineage,
                      s.true_lineage, s.held, s.epochs, a.gate,
                      s.trunk_version, s.trunk_version + 1)
    return replace(s, admission=entry, trunk_version=s.trunk_version + 1)


def undo_accounted_trunk(s: State) -> int:
    # An undo of content already admitted to trunk is a new trunk obligation.
    # Its old source branch cannot retroactively Hold the accepted receipt.
    if not s.admission or not s.ref_up:
        raise ValueError("no accounted trunk result")
    return s.trunk_version + 1


def violation(s: State) -> str | None:
    if s.mutation_used and not s.mutation_fenced:
        # A mutation not yet followed by admission is already a protocol
        # violation: it acknowledged changed selected meaning without a ref
        # fence, even if no old coordinator happens to race it.
        return f"{s.mutation_door} acknowledged without revision fence"
    if s.visible_lineage != s.true_lineage:
        return "mixed transport dropped transitive source lineage"
    if s.admission:
        entry = s.admission
        if entry.submitted_substance != entry.current_substance or entry.submitted_cut != entry.current_cut:
            return "stale selected meaning reached trunk"
        if entry.selected_lineage != entry.true_lineage:
            return "admission omitted transitive source lineage"
        if any(entry.held_at_commit[index(branch)] for branch in entry.true_lineage):
            return "Hold was bypassed through a governed door"
        if entry.gate != "passed" or entry.trunk_after != entry.trunk_before + 1:
            return "admission lacked exact gate or ref history"
    return None


def scenarios() -> None:
    # An unrelated tail can arrive while the prefix is checked; its exact
    # selected cut and substance remain valid.
    tail = gate_pass(submit(State()))
    tail = tail_write(tail)
    assert tail.head_cut != tail.selected_cut
    assert violation(cas(tail)) is None

    # Every mutation class fences a passed certificate before acknowledging
    # changed source meaning. A failed ref read cannot authorize the write.
    for door in MUTATION_DOORS:
        pending = gate_pass(submit(State()))
        changed = mutate(pending, door)
        try:
            cas(changed)
        except ValueError as error:
            assert "epoch changed" in str(error), (door, error)
        else:
            raise AssertionError(f"{door} admitted its old certificate")
        try:
            mutate(replace(pending, ref_up=False), door)
        except ValueError as error:
            assert "authorities" in str(error)
        else:
            raise AssertionError(f"{door} acknowledged without ref authority")

    moved = mixed_transport(State())
    assert moved.source_id == "u" and moved.mixed_output_id != moved.source_id
    try:
        submit(hold(moved, "A"), door="manual")
    except ValueError as error:
        assert "held" in str(error)
    else:
        raise AssertionError("origin Hold did not reach readiness selection")
    pending = gate_pass(submit(moved, door="manual"))
    held = hold(pending, "A")
    try:
        cas(held)
    except ValueError as error:
        assert "held" in str(error)
    else:
        raise AssertionError("manual transport bypassed origin Hold")

    # A branch Hold does not retroactively revoke an already admitted trunk
    # unit; a later trunk undo is governed as a fresh trunk mutation.
    admitted = cas(gate_pass(submit(moved)))
    admitted = hold(admitted, "A")
    assert undo_accounted_trunk(admitted) == admitted.trunk_version + 1


def mutants() -> None:
    for door in MUTATION_DOORS:
        pending = gate_pass(submit(State()))
        broken = mutate(pending, door, "skip_fence")
        landed = cas(broken)
        assert violation(landed) == f"{door} acknowledged without revision fence"
        assert landed.admission.submitted_substance != landed.admission.current_substance

    broken_lineage = hold(mixed_transport(State(), "output_only"), "A")
    broken_lineage = gate_pass(submit(broken_lineage, door="manual"))
    landed = cas(broken_lineage)
    assert violation(landed) == "mixed transport dropped transitive source lineage"
    assert landed.admission.held_at_commit[index("A")]

    held = hold(gate_pass(submit(State(), door="manual")), "A")
    assert violation(cas(held, "ignore_hold")) == "Hold was bypassed through a governed door"
    changed = mutate(gate_pass(submit(State())), "rebase")
    assert violation(cas(changed, "ignore_epoch")) == "stale selected meaning reached trunk"


def steps(s: State):
    if not s.attempt and not s.admission:
        try:
            yield "submit", submit(s)
        except ValueError:
            pass
    if s.attempt and s.attempt.gate == "waiting":
        yield "gate", gate_pass(s)
    if s.attempt and s.attempt.gate == "passed":
        try:
            yield "cas", cas(s)
        except ValueError:
            pass
    if not s.held[0]:
        yield "hold_A", hold(s, "A")
    if not s.held[1]:
        yield "hold_B", hold(s, "B")
    if not s.transport_used and not s.admission:
        yield "mixed_transport", mixed_transport(s)
    if not s.tail_written and not s.admission:
        yield "tail", tail_write(s)
    if not s.mutation_used and not s.admission:
        yield "rebase", mutate(s, "rebase")


def explore(depth: int = 8) -> int:
    start = State()
    queue = deque([(start, 0)])
    seen = {start}
    while queue:
        state, distance = queue.popleft()
        assert violation(state) is None, (state, violation(state))
        if distance >= depth:
            continue
        for _, successor in steps(state):
            if successor not in seen:
                seen.add(successor)
                queue.append((successor, distance + 1))
    return len(seen)


def main() -> None:
    scenarios()
    mutants()
    count = explore()
    print(f"revision lineage: {count} safe states through eight transitions")
    print(f"{len(MUTATION_DOORS)} mutation doors, transitive Hold, tail, and mutants passed")


if __name__ == "__main__":
    main()
