#!/usr/bin/env python3
"""Bounded crash probe for committing a derived flowing cut (FB-2).

Run: python3 models/research/flowing_derived_cut_commit.py

The model starts with two declared source units on a retained twig cut. It
tests every crash boundary around publishing an immutable candidate and
committing a mixed transport to a branch. It abstracts content hashes, the actual merge
algorithm, SQL locking, and the later branch-to-trunk gate. Its claim is only
about which durable facts must be visible together for a derived head to be
recoverable and for the two source obligations to remain accounted for.
"""

from dataclasses import dataclass, replace


UNITS = frozenset({"unit-a", "unit-b"})


@dataclass(frozen=True)
class State:
    # The retained twig cut and its constituent bodies exist before the work.
    source_retained: bool = True
    source_owed: frozenset[str] = UNITS
    candidate_bodies: bool = False
    candidate_cut: bool = False
    lineage: frozenset[str] = frozenset()
    receipts: frozenset[str] = frozenset()
    branch_head: bool = False
    # A successful ref entry retains both source and candidate closures after
    # the attempt pin and the twig's original holder are released.
    attempt_pin: bool = False
    ref_retained: bool = False


def invariant(s: State) -> None:
    if s.branch_head:
        assert s.candidate_bodies and s.candidate_cut, "head has no readable cut"
        assert s.lineage == UNITS, "head cannot prove its source constituents"
        assert s.receipts == UNITS, "head moved without every unit receipt"
        assert s.ref_retained, "head has no durable retention holder"
    assert s.source_retained or not s.source_owed, "owed source lost its basis"
    assert not s.receipts or s.branch_head, "receipt transferred work without a head"
    assert s.source_owed | s.receipts == UNITS, "source work disappeared"
    assert not (s.source_owed & s.receipts), "source work has two holders"


def prepare(s: State) -> State:
    # Candidate bodies, cut and complete derivation may be published before
    # the ref transaction if immutable and retained. A crash here leaves an
    # orphan candidate, never a head or a transferred source obligation.
    return replace(s, candidate_bodies=True, candidate_cut=True,
                   lineage=UNITS, attempt_pin=True)


def commit(s: State) -> State:
    assert (s.candidate_bodies and s.candidate_cut and s.lineage == UNITS
            and s.attempt_pin and s.source_retained)
    # One ref-authority transaction validates the source, expected target
    # head, current policy/fence, exact unit set, persisted cut/lineage and
    # candidate content proof. Receipts, head and ref retention become visible
    # together. A crash yields either the old or the new State.
    return replace(s, receipts=UNITS, source_owed=frozenset(), branch_head=True,
                   ref_retained=True)


def finish(s: State) -> State:
    assert s.branch_head and s.ref_retained
    # Delivery/acknowledgment and attempt-pin cleanup are post-commit work.
    return replace(s, attempt_pin=False, source_retained=False)


def crash(s: State) -> State:
    # Reopen keeps durable bytes and metadata, but process-owned pins vanish.
    # The source holder or committed ref entry must still own the closure.
    return replace(s, attempt_pin=False)


def atomic_scenarios() -> None:
    start = State()
    prepared = prepare(start)
    committed = commit(prepared)
    for boundary in (start, prepared, committed, finish(committed)):
        invariant(boundary)
        invariant(crash(boundary))
    assert not crash(prepared).branch_head
    assert crash(committed).branch_head
    assert crash(committed).receipts == UNITS


def split_write_mutants() -> None:
    prepared = prepare(State())
    mutants = {
        # The existing legacy transport sequence has the first shape: the
        # ref can advance before record_cut. Flowing admission must refuse it.
        "head before cut": replace(prepared, candidate_cut=False,
                                   branch_head=True),
        "cut and head before lineage": replace(
            prepared, lineage=frozenset(), branch_head=True,
            ref_retained=True),
        "head and lineage before receipts": replace(
            prepared, branch_head=True, ref_retained=True),
        "receipt before head": replace(
            prepared, receipts=UNITS, source_owed=frozenset()),
        "partial mixed receipt": replace(
            prepared, receipts=frozenset({"unit-a"}),
            source_owed=frozenset({"unit-b"}), branch_head=True,
            ref_retained=True),
        "publish bodies after head": replace(
            prepared, candidate_bodies=False, receipts=UNITS,
            source_owed=frozenset(),
            branch_head=True, ref_retained=True),
        "drop attempt pin before ref retention": replace(
            prepared, receipts=UNITS, source_owed=frozenset(), branch_head=True,
            attempt_pin=False, ref_retained=False),
    }
    for label, broken in mutants.items():
        try:
            invariant(crash(broken))
        except AssertionError:
            print(f"{label}: crash exposes an invalid durable state")
        else:
            raise AssertionError(f"mutant survived: {label}")


if __name__ == "__main__":
    atomic_scenarios()
    split_write_mutants()
    print("derived cut commit crash scenarios: passed")
