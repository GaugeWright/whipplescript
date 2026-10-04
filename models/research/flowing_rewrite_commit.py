#!/usr/bin/env python3
"""Bounded proof shape for a disjoint flowing-source rebase (FB-1/2).

Run: python3 models/research/flowing_rewrite_commit.py

This models a complete source head with two owed units. It checks exact
content replay onto a new parent, immutable rewrite provenance, a short
source-ref transaction, crashes, and stale heads. It deliberately refuses
overlapping repair: changing a unit's effect needs a new identity and an
explicit disposition of the old obligation. Real merge algorithms, durable
SQL, content hashes, and norm/ref lock ownership are outside this model.
"""

from dataclasses import dataclass, replace
from hashlib import sha256


Manifest = tuple[tuple[str, int], ...]
OLD_PARENT: Manifest = ()
NEW_PARENT: Manifest = (("z", 3),)
OLD_SOURCE: Manifest = (("x", 1), ("y", 2))
ATOMS = (("atom-a", "unit-a", "x", 0, 1),
         ("atom-b", "unit-b", "y", 0, 2))
UNITS = frozenset({"unit-a", "unit-b"})


@dataclass(frozen=True)
class Candidate:
    old_cut: str
    new_cut: str
    parent_cut: str
    old_manifest: Manifest
    parent_manifest: Manifest
    new_manifest: Manifest
    roots: tuple[str, ...]
    digest: str


@dataclass(frozen=True)
class State:
    source_head: str = "old-cut"
    source_manifest: Manifest = OLD_SOURCE
    branch_point: str = "old-parent"
    branch_point_manifest: Manifest = OLD_PARENT
    parent_head: str = "new-parent"
    parent_manifest: Manifest = NEW_PARENT
    head_revision: int = 0
    owed: frozenset[str] = UNITS
    old_retained: bool = True
    candidate: Candidate | None = None
    candidate_bodies_published: bool = False
    candidate_cut_published: bool = False
    edge_published: bool = False
    attempt_pin: bool = False
    ref_retained: bool = False


def apply(base: Manifest, atoms=ATOMS) -> Manifest:
    result = dict(base)
    seen = set()
    for identity, _unit, path, before, after in atoms:
        if identity in seen:
            raise ValueError("duplicate source identity")
        seen.add(identity)
        if result.get(path, 0) != before:
            raise ValueError("source effect changed on the new parent")
        result[path] = after
    return tuple(sorted(result.items()))


def digest(candidate: Candidate) -> str:
    basis = (candidate.old_cut, candidate.new_cut, candidate.parent_cut,
             candidate.old_manifest, candidate.parent_manifest,
             candidate.new_manifest, candidate.roots)
    return sha256(repr(basis).encode()).hexdigest()


def prepare(state: State, new_parent: Manifest = NEW_PARENT,
            atoms=ATOMS) -> State:
    if state.source_head != "old-cut" or state.parent_head != "new-parent":
        raise ValueError("stale source or parent head")
    if state.candidate is not None:
        raise ValueError("candidate already prepared")
    if set(atom[1] for atom in atoms) != state.owed:
        raise ValueError("source unit roster is incomplete")
    old = apply(OLD_PARENT, atoms)
    new = apply(new_parent, atoms)
    if old != state.source_manifest:
        raise ValueError("old source content changed")
    roots = tuple(atom[0] for atom in atoms)
    candidate = Candidate("old-cut", "rebased-cut", "new-parent", old,
                          new_parent, new, roots, "")
    candidate = replace(candidate, digest=digest(candidate))
    # Cut, edge and bodies can publish before the ref move. All are complete
    # under a temporary holder here; none transfers an obligation yet.
    return replace(state, candidate=candidate,
                   candidate_bodies_published=True,
                   candidate_cut_published=True, edge_published=True,
                   attempt_pin=True)


def commit(state: State, expected_revision: int = 0) -> State:
    candidate = state.candidate
    if (candidate is None or not state.candidate_bodies_published
            or not state.candidate_cut_published or not state.edge_published):
        raise ValueError("rewrite evidence is incomplete")
    if (state.source_head != candidate.old_cut
            or state.source_manifest != candidate.old_manifest
            or state.parent_head != candidate.parent_cut
            or state.parent_manifest != candidate.parent_manifest
            or state.head_revision != expected_revision):
        raise ValueError("source, parent or head revision moved")
    if not state.old_retained or not state.attempt_pin:
        raise ValueError("source or candidate lost retention")
    if state.owed != UNITS:
        raise ValueError("source obligations changed")
    if candidate.digest != digest(candidate):
        raise ValueError("rewrite evidence changed")
    if candidate.old_manifest != apply(OLD_PARENT):
        raise ValueError("old source content changed")
    if candidate.parent_manifest != NEW_PARENT or candidate.new_manifest != apply(NEW_PARENT):
        raise ValueError("rebased content differs from the source roots")
    if candidate.roots != tuple(atom[0] for atom in ATOMS):
        raise ValueError("rewrite edge omitted a source atom")
    # The real source-ref authority must commit head, point, head revision and
    # continuing retention as one entry; a crash sees either whole state.
    return replace(state, source_head=candidate.new_cut,
                   source_manifest=candidate.new_manifest,
                   branch_point=candidate.parent_cut,
                   branch_point_manifest=candidate.parent_manifest,
                   head_revision=state.head_revision + 1,
                   ref_retained=True)


def crash(state: State) -> State:
    return replace(state, attempt_pin=False)


def invariant(state: State) -> None:
    assert state.owed == UNITS, "rewrite silently settled a source obligation"
    if state.source_head == "old-cut":
        assert state.branch_point == "old-parent", "point moved without head"
        assert state.source_manifest == OLD_SOURCE, "old head content changed"
        assert state.branch_point_manifest == OLD_PARENT, "point basis moved without head"
        assert state.old_retained, "owed old cut lost retention"
        return
    candidate = state.candidate
    assert candidate is not None and state.candidate_cut_published, "head has no cut"
    assert state.candidate_bodies_published, "head has no readable bodies"
    assert state.edge_published and candidate.roots == tuple(atom[0] for atom in ATOMS), \
        "head lost constituent lineage"
    assert candidate.digest == digest(candidate), "head has changed rewrite evidence"
    assert candidate.new_manifest == apply(NEW_PARENT), "head content differs from roots"
    assert state.source_manifest == candidate.new_manifest, "head manifest differs from cut"
    assert state.branch_point == candidate.parent_cut, "head and branch point disagree"
    assert state.branch_point_manifest == candidate.parent_manifest, \
        "head and branch point basis disagree"
    assert state.ref_retained and state.old_retained, "owed lineage lost retention"


def scenarios() -> None:
    start = State()
    prepared = prepare(start)
    committed = commit(prepared)
    for boundary in (start, prepared, committed, crash(prepared), crash(committed)):
        invariant(boundary)
    assert crash(prepared).source_head == "old-cut"
    assert crash(committed).source_head == "rebased-cut"
    assert crash(committed).owed == UNITS
    for changed in (replace(prepared, source_head="tail-cut"),
                    replace(prepared, parent_head="later-parent"),
                    replace(prepared, head_revision=1)):
        try:
            commit(changed)
        except ValueError as error:
            assert "moved" in str(error)
        else:
            raise AssertionError("stale rewrite committed")
    try:
        commit(replace(prepared, owed=frozenset({"unit-a"})))
    except ValueError as error:
        assert "obligations changed" in str(error)
    else:
        raise AssertionError("rewrite committed after a unit moved")
    try:
        prepare(start, (("x", 9),))
    except ValueError as error:
        assert "effect changed" in str(error)
    else:
        raise AssertionError("overlapping rebase reused an old atom identity")
    changed_atom = ("atom-a", "unit-a", "x", 0, 4)
    try:
        prepare(start, atoms=(changed_atom, ATOMS[1]))
    except ValueError as error:
        assert "old source content changed" in str(error)
    else:
        raise AssertionError("same atom identity acquired changed content")
    try:
        prepare(start, atoms=ATOMS[:1])
    except ValueError as error:
        assert "roster is incomplete" in str(error)
    else:
        raise AssertionError("rewrite omitted an owed unit")
    # A changed effect can be authored under a new atom/unit identity, but
    # that alone does not discharge the old unit-a obligation.
    repaired = ("atom-a-repair", "unit-a-repair", "x", 9, 1)
    assert apply((("x", 9),), (repaired,)) == (("x", 1),)
    assert "unit-a" in start.owed


def mutants() -> None:
    prepared = prepare(State())
    committed = commit(prepared)
    assert committed.candidate is not None
    omitted_root = replace(committed.candidate, roots=("atom-a",))
    omitted_root = replace(omitted_root, digest=digest(omitted_root))
    changed_output = replace(committed.candidate,
                             new_manifest=(("x", 1), ("z", 3)))
    changed_output = replace(changed_output, digest=digest(changed_output))
    broken = {
        "head before cut": replace(committed, candidate_cut_published=False),
        "head before bodies": replace(committed, candidate_bodies_published=False),
        "head before edge": replace(committed, edge_published=False),
        "omitted root": replace(committed, candidate=omitted_root),
        "changed output": replace(committed, candidate=changed_output),
        "point before head": replace(prepared, branch_point="new-parent"),
        "head manifest mismatch": replace(committed, source_manifest=OLD_SOURCE),
        "point basis mismatch": replace(committed, branch_point_manifest=OLD_PARENT),
        "lost old pin": replace(committed, old_retained=False),
        "dropped unit": replace(committed, owed=frozenset({"unit-a"})),
    }
    for label, state in broken.items():
        try:
            invariant(crash(state))
        except AssertionError:
            print(f"{label}: invalid durable state detected")
        else:
            raise AssertionError(f"mutant survived: {label}")


if __name__ == "__main__":
    scenarios()
    mutants()
    print("flowing rewrite commit scenarios: passed")
