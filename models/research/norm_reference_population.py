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


@dataclass(frozen=True)
class HomeCut:
    """A host-issued snapshot, never inferred from a successful replay.

    `source` stands for the Home capability supplied by the host, not by an
    imported event or a caller. `operations` includes interpreting acts even
    when several acts refer to the same content revision.
    """

    source: str
    operations: tuple[str, ...]
    registry: int


def capture_home_cut(source: str, operations: tuple[str, ...], registry: int) -> HomeCut:
    if source != "home":
        raise ValueError("a peer replay cannot close the Home admission roster")
    if len(operations) != len(set(operations)):
        raise ValueError("an operation may appear only once in a Home cut")
    return HomeCut(source, operations, registry)


def commit_at_home(cut: HomeCut, current_operations: tuple[str, ...], current_registry: int) -> bool:
    """The gate's final comparison while holding Home ledger write exclusion.

    The caller must keep exclusion through the governed ref CAS. A comparison
    before acquiring it is insufficient: another admission can land afterward.
    """

    return (
        cut.source == "home"
        and cut.operations == current_operations
        and cut.registry == current_registry
    )


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

    # A replay on a peer may be internally complete while the Home has an
    # independent concurrent act. Only a Home-issued cut closes that roster.
    try:
        capture_home_cut("peer", ("create", "edit", "activate"), 2)
    except ValueError:
        pass
    else:
        raise AssertionError("peer replay was mistaken for Home authority")

    cut = capture_home_cut("home", ("create", "edit", "activate", "retire"), 2)
    assert commit_at_home(cut, cut.operations, 2)
    # Capturing and extracting before another act is fine, but committing
    # against the old cut after that act must refuse and re-prepare.
    assert not commit_at_home(cut, cut.operations + ("later",), 2)
    assert not commit_at_home(cut, cut.operations, 3)
    # An observed-only replay cannot detect an omitted concurrent act even if
    # its own frontier and record rows are self-consistent.
    peer_operations = ("create", "edit", "activate")
    assert peer_operations == cut.operations[:3]
    assert not commit_at_home(cut, peer_operations, 2)
    print("norm reference population: create, edit, migration and retirement are distinct")
    print("  omitted act, old charter class, open roster and changed cut remain unknown")
    print("  Home-issued roster and final under-exclusion recheck fence concurrent acts")


if __name__ == "__main__":
    probe()
