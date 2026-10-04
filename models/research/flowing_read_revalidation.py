#!/usr/bin/env python3
"""Bounded read/dependency proof needed after a flowing-source rewrite.

Run: python3 models/research/flowing_read_revalidation.py

Content-disjoint replay preserves write atoms, but it cannot prove that an old
unit read the same facts. This probe gives each unit exact positive/negative
reads and declared unit/external dependencies. It checks those facts at the
new predecessor, then binds the result to the parent, source and policy epochs
at the ref entry. Unknown reads refuse. This is a proof-shape model, not an
extractor of real Home or norm observations.
"""

from dataclasses import dataclass, replace


Manifest = tuple[tuple[str, int], ...]
Versions = tuple[tuple[str, int], ...]


def value(manifest: Manifest, path: str) -> int | None:
    return dict(manifest).get(path)


@dataclass(frozen=True)
class Unit:
    identity: str
    reads: tuple[tuple[str, int | None], ...]
    unknown_read: bool
    predecessors: tuple[str, ...]
    external: tuple[tuple[str, int], ...]
    write: tuple[str, int | None, int | None]


@dataclass(frozen=True)
class State:
    parent: Manifest = (("z", 1),)
    parent_revision: int = 1
    source_revision: int = 1
    policy_epoch: int = 1
    held: bool = False
    external_versions: Versions = (("package", 1),)
    owed: frozenset[str] = frozenset({"u1", "u2"})
    # An unbound later tail is outside the selected cut and does not decide it.
    later_tail: tuple[str, ...] = ()


@dataclass(frozen=True)
class Certificate:
    selected: tuple[str, ...]
    unit_facts: tuple[Unit, ...]
    parent: Manifest
    parent_revision: int
    source_revision: int
    policy_epoch: int
    external_versions: Versions
    result: Manifest


def prepare(state: State, units: tuple[Unit, ...],
            defect: str = "") -> Certificate:
    if state.held or not units:
        raise ValueError("source is held or selection empty")
    selected = tuple(unit.identity for unit in units)
    if len(selected) != len(set(selected)) or not set(selected) <= state.owed:
        raise ValueError("selected identities are not uniquely owed")
    current = dict(state.parent)
    completed = set()
    for unit in units:
        if defect != "skip_unit_dependencies" and not set(unit.predecessors) <= completed:
            raise ValueError("predecessor unit is missing from selected prefix")
        if unit.unknown_read and defect != "unknown_as_empty":
            raise ValueError("read coverage is unknown")
        for path, observed in unit.reads:
            if defect == "skip_reads":
                continue
            if defect == "skip_negative_reads" and observed is None:
                continue
            if current.get(path) != observed:
                raise ValueError("recorded read changed on new predecessor")
        for identity, pinned in unit.external:
            if defect != "skip_external_dependencies" and (
                dict(state.external_versions).get(identity) != pinned
            ):
                raise ValueError("external dependency pin changed")
        path, before, after = unit.write
        if current.get(path) != before:
            raise ValueError("source effect changed on new predecessor")
        if after is None:
            current.pop(path, None)
        else:
            current[path] = after
        completed.add(unit.identity)
    return Certificate(selected, units, state.parent, state.parent_revision,
                       state.source_revision, state.policy_epoch,
                       state.external_versions, tuple(sorted(current.items())))


def admit(state: State, certificate: Certificate, defect: str = "") -> State:
    if state.held:
        raise ValueError("source held")
    if defect != "stale_parent" and (
        certificate.parent != state.parent
        or certificate.parent_revision != state.parent_revision
    ):
        raise ValueError("parent moved after proof")
    if defect != "stale_source" and certificate.source_revision != state.source_revision:
        raise ValueError("selected source meaning changed after proof")
    if defect != "stale_policy" and certificate.policy_epoch != state.policy_epoch:
        raise ValueError("policy changed after proof")
    if defect != "stale_external" and certificate.external_versions != state.external_versions:
        raise ValueError("external pin changed after proof")
    if not set(certificate.selected) <= state.owed:
        raise ValueError("selected unit no longer owed")
    # The actual ref entry also checks the exact candidate cut and gate result;
    # those are established by the separate admission and candidate models.
    return replace(state, owed=state.owed - set(certificate.selected))


U1 = Unit("u1", (("x", None),), False, (), (("package", 1),),
          ("x", None, 1))
U2 = Unit("u2", (("z", 1),), False, ("u1",), (("package", 1),),
          ("y", None, 2))


def refuses(action, message: str) -> None:
    try:
        action()
    except ValueError as error:
        assert message in str(error), error
    else:
        raise AssertionError(f"expected refusal: {message}")


def scenarios() -> None:
    safe = State(later_tail=("unbound-later-write",))
    proof = prepare(safe, (U1, U2))
    assert proof.result == (("x", 1), ("y", 2), ("z", 1))
    assert admit(safe, proof).owed == frozenset()

    # Disjoint writes are not disjoint reads, including a read of absence.
    changed_read = replace(safe, parent=(("z", 1), ("q", 7)))
    reads_q = replace(U1, reads=(("q", None),))
    refuses(lambda: prepare(changed_read, (reads_q, U2)), "recorded read changed")
    assert prepare(changed_read, (reads_q, U2), "skip_negative_reads")
    assert prepare(changed_read, (reads_q, U2), "skip_reads")

    positive_read = replace(U1, reads=(("z", 1),))
    changed_z = replace(safe, parent=(("z", 2),))
    refuses(lambda: prepare(changed_z, (positive_read, U2)), "recorded read changed")
    assert prepare(changed_z, (positive_read, U2), "skip_reads")

    refuses(lambda: prepare(safe, (replace(U1, unknown_read=True), U2)),
            "read coverage is unknown")
    assert prepare(safe, (replace(U1, unknown_read=True), U2), "unknown_as_empty")
    refuses(lambda: prepare(safe, (U2,)), "predecessor unit is missing")
    assert prepare(safe, (U2,), "skip_unit_dependencies")

    external_moved = replace(safe, external_versions=(("package", 2),))
    refuses(lambda: prepare(external_moved, (U1, U2)), "external dependency pin changed")
    assert prepare(external_moved, (U1, U2), "skip_external_dependencies")

    for label, changed, defect, reason in (
        ("parent", replace(safe, parent=(("z", 2),), parent_revision=2),
         "stale_parent", "parent moved"),
        ("source", replace(safe, source_revision=2),
         "stale_source", "source meaning changed"),
        ("policy", replace(safe, policy_epoch=2),
         "stale_policy", "policy changed"),
        ("external", replace(safe, external_versions=(("package", 2),)),
         "stale_external", "external pin changed"),
    ):
        refuses(lambda changed=changed: admit(changed, proof), reason)
        assert admit(changed, proof, defect).owed == frozenset(), label

    print("safe read/dependency cases and nine defective bypasses checked")


if __name__ == "__main__":
    scenarios()
