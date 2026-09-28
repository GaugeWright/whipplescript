"""Bounded RC-1 probe: a norm reference population is a roster of admissions.

Run: python3 models/research/norm_reference_population.py

The authoritative roster and its closure are explicit premises here. Replaying
the events one store happens to hold is not itself proof that its Home admitted
no other events. A content revision and a later activation of that content are
separate interpreting acts even when the content id stays the same.
"""

from dataclasses import dataclass
from hashlib import sha256


@dataclass(frozen=True)
class Admission:
    event: str
    record: str
    content: str
    charter: str
    vocabulary: str
    provider: str


@dataclass(frozen=True)
class Basis:
    frontier: int
    roster: int
    registry: int


@dataclass(frozen=True)
class Witness:
    basis: Basis
    roster_digest: str
    examined: frozenset[str]
    edges: frozenset[tuple[str, str, str]]
    state: str
    gaps: tuple[str, ...]


def digest(events: frozenset[str]) -> str:
    return sha256(repr(tuple(sorted(events))).encode()).hexdigest()


def capture(
    authoritative: frozenset[Admission],
    observed: frozenset[Admission],
    examined: frozenset[str],
    classes: frozenset[tuple[str, str]],
    basis: Basis,
    *,
    roster_closed: bool,
) -> Witness:
    roster = frozenset(act.event for act in authoritative)
    observed_ids = frozenset(act.event for act in observed)
    gaps = []
    if not roster_closed:
        gaps.append("the Home admission roster is not closed")
    if observed_ids != roster:
        gaps.append("observed acts differ from the authoritative roster")
    if examined != observed_ids:
        gaps.append("not every observed interpreting act was examined")
    edges = set()
    for act in observed:
        if (act.charter, act.vocabulary) not in classes:
            gaps.append("an accepting charter and vocabulary have no class basis")
        elif act.event in examined:
            edges.add((act.event, act.record, act.provider))
    return Witness(
        basis,
        digest(roster),
        examined,
        frozenset(edges),
        "unknown" if gaps else "complete",
        tuple(sorted(set(gaps))),
    )


def valid(witness: Witness, current: Basis, roster: frozenset[str]) -> bool:
    return (
        witness.state == "complete"
        and witness.basis == current
        and witness.roster_digest == digest(roster)
    )


def probe() -> None:
    created = Admission("create", "record-r", "content-a", "charter-1", "note@1", "provider-x")
    edited = Admission("edit", "record-r", "content-b", "charter-1", "note@1", "provider-y")
    migrated = Admission("activate", "record-r", "content-b", "charter-2", "note@2", "provider-z")
    retired = Admission("retire", "record-s", "content-c", "charter-1", "note@1", "provider-r")
    roster = frozenset((created, edited, migrated, retired))
    ids = frozenset(act.event for act in roster)
    classes = frozenset((("charter-1", "note@1"), ("charter-2", "note@2")))
    basis = Basis(frontier=4, roster=4, registry=2)
    complete = capture(roster, roster, ids, classes, basis, roster_closed=True)
    assert complete.state == "complete" and len(complete.edges) == 4
    assert valid(complete, basis, ids)

    # Activation changes interpretation without creating a new content id.
    assert edited.content == migrated.content
    assert edited.event != migrated.event
    omitted = frozenset((created, edited, retired))
    assert capture(roster, omitted, frozenset(act.event for act in omitted), classes,
                   basis, roster_closed=True).state == "unknown"
    # Defect: deduplicating by content id treats the activation as already seen.
    assert {act.content for act in roster} == {act.content for act in omitted}

    assert capture(roster, roster, ids, classes - {("charter-1", "note@1")},
                   basis, roster_closed=True).state == "unknown"
    assert capture(roster, roster, ids, classes, basis,
                   roster_closed=False).state == "unknown"
    # Defect: an observed-only roster can claim completeness after dropping an
    # admitted event, or after importing a partial history as a whole Home.
    assert capture(omitted, omitted, frozenset(act.event for act in omitted),
                   classes, basis, roster_closed=True).state == "complete"

    later = Admission("later", "record-s", "content-c", "charter-2", "note@2", "provider-q")
    later_roster = ids | {later.event}
    assert not valid(complete, Basis(frontier=5, roster=5, registry=2), later_roster)
    assert not valid(complete, basis, later_roster)
    print("norm reference population: create, edit, migration and retirement are distinct")
    print("  omitted act, old charter class, open roster and changed cut remain unknown")


if __name__ == "__main__":
    probe()
