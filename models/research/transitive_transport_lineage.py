#!/usr/bin/env python3
"""Bounded source-identity probe for mixed and transitive transport (FB-1/2).

Run: python3 models/research/transitive_transport_lineage.py

This models immutable source atoms, a content-checked derivation edge, a
second transport of that output, and ref-owned accounting. It does not model
the real stores, locks, content hashes, or a general merge algorithm.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Atom:
    identity: str
    unit: str
    path: str
    before: int
    after: int


@dataclass(frozen=True)
class Derived:
    cut: str
    output_change: str
    parents: tuple[str, ...]
    roots: tuple[str, ...]
    before: tuple[tuple[str, int], ...]
    after: tuple[tuple[str, int], ...]


class Lineage:
    def __init__(self, atoms: tuple[Atom, ...]):
        if len({atom.identity for atom in atoms}) != len(atoms):
            raise ValueError("source atom identity reused")
        self.atoms = {atom.identity: atom for atom in atoms}
        self.order = tuple(atom.identity for atom in atoms)
        self.derived: dict[str, Derived] = {}

    def roots(self, node: str, visiting: frozenset[str] = frozenset()) -> tuple[str, ...]:
        if node in self.atoms:
            return (node,)
        if node in visiting:
            raise ValueError("lineage cycle")
        edge = self.derived.get(node)
        if edge is None:
            raise ValueError(f"missing lineage for {node}")
        found = tuple(root for parent in edge.parents
                      for root in self.roots(parent, visiting | {node}))
        if len(found) != len(set(found)) or set(found) != set(edge.roots):
            raise ValueError("derivation edge lost or duplicated a source atom")
        return tuple(root for root in self.order if root in found)

    def derive(self, cut: str, output_change: str, parents: tuple[str, ...],
               selected: tuple[str, ...], before: tuple[tuple[str, int], ...],
               after: tuple[tuple[str, int], ...]) -> Derived:
        if cut in self.atoms or cut in self.derived:
            raise ValueError("cut identity reused")
        if not parents or not selected or len(selected) != len(set(selected)):
            raise ValueError("empty or duplicate source selection")
        inherited = tuple(root for parent in parents for root in self.roots(parent))
        if len(inherited) != len(set(inherited)) or set(inherited) != set(selected):
            raise ValueError("selected source atoms differ from derivation inputs")
        ordered = tuple(root for root in self.order if root in selected)
        by_path: dict[str, list[Atom]] = {}
        for root in ordered:
            atom = self.atoms[root]
            by_path.setdefault(atom.path, []).append(atom)
        expected = dict(before)
        for path, writes in by_path.items():
            # The endpoints cannot hide an unselected middle write. A single
            # later write is fine when the target has its exact precondition.
            source_path = [self.atoms[root] for root in self.order
                           if self.atoms[root].path == path]
            first = source_path.index(writes[0])
            last = source_path.index(writes[-1])
            if source_path[first:last + 1] != writes:
                raise ValueError("selected path has an unselected middle write")
            if any(left.after != right.before for left, right in zip(writes, writes[1:])):
                raise ValueError("incoherent source path")
            old, new = writes[0].before, writes[-1].after
            current = expected.get(path, 0)
            if current != old and current != new:
                raise ValueError("target conflicts with selected source")
            if current != new:
                expected[path] = new
        if tuple(sorted(expected.items())) != after:
            raise ValueError("target output differs from selected source effects")
        edge = Derived(cut, output_change, parents, ordered, before, after)
        self.derived[cut] = edge
        return edge


def admit(graph: Lineage, cut: str, selected_units: tuple[str, ...],
          held_units: frozenset[str], accounted: frozenset[str],
          defect: str = "") -> frozenset[str]:
    roots = graph.roots(cut)
    units = frozenset(graph.atoms[root].unit for root in roots)
    if units != frozenset(selected_units):
        raise ValueError("candidate lineage differs from selected units")
    if units & held_units:
        raise ValueError("transitive Hold blocks source admission")
    if units & accounted:
        raise ValueError("source unit already accounted")
    if defect == "output_as_unit":
        return accounted | {graph.derived[cut].output_change}
    return accounted | units


def scenarios() -> None:
    atoms = (
        Atom("a", "unit-a", "x", 0, 1),
        Atom("middle", "unit-middle", "z", 0, 1),
        Atom("b", "unit-b", "y", 0, 2),
    )
    graph = Lineage(atoms)
    branch = graph.derive("branch-cut", "mixed-output", ("a", "b"),
                          ("a", "b"), (), (("x", 1), ("y", 2)))
    assert branch.roots == ("a", "b")
    trunk = graph.derive("trunk-cut", "rebased-output", ("branch-cut",),
                         ("a", "b"), (), (("x", 1), ("y", 2)))
    assert trunk.roots == ("a", "b")
    try:
        admit(graph, "trunk-cut", ("unit-a", "unit-b"),
              frozenset({"unit-a"}), frozenset())
    except ValueError as error:
        assert "Hold" in str(error)
    else:
        raise AssertionError("a Hold must follow source lineage through two transports")
    assert admit(graph, "trunk-cut", ("unit-a", "unit-b"),
                 frozenset(), frozenset()) == frozenset({"unit-a", "unit-b"})
    try:
        admit(graph, "trunk-cut", ("unit-a", "unit-b"),
              frozenset(), frozenset({"unit-a", "unit-b"}))
    except ValueError as error:
        assert "already accounted" in str(error)
    else:
        raise AssertionError("one output cannot settle its roots twice")

    broken = admit(graph, "trunk-cut", ("unit-a", "unit-b"),
                   frozenset(), frozenset(), "output_as_unit")
    assert broken == frozenset({"rebased-output"})
    assert broken != frozenset({"unit-a", "unit-b"})
    print("output-id mutant: one rebased output loses two source-unit obligations")

    graph.derived["trunk-cut"] = Derived("trunk-cut", "rebased-output",
                                          ("branch-cut",), ("a",), (),
                                          (("x", 1), ("y", 2)))
    try:
        graph.roots("trunk-cut")
    except ValueError as error:
        assert "lost or duplicated" in str(error)
    else:
        raise AssertionError("a derivation edge cannot omit a source atom")
    print("missing-lineage mutant: a transitive edge drops unit-b")

    # A single output change ID does not imply one root. A later tail that was
    # never selected remains separate from this candidate.
    assert "middle" not in branch.roots
    repeated = Lineage((
        Atom("p1", "unit-1", "p", 0, 1),
        Atom("p2", "unit-2", "p", 1, 2),
        Atom("p3", "unit-3", "p", 2, 3),
    ))
    try:
        repeated.derive("gap", "mixed", ("p1", "p3"), ("p1", "p3"),
                        (), (("p", 3),))
    except ValueError as error:
        assert "unselected middle" in str(error)
    else:
        raise AssertionError("endpoints cannot conceal a skipped source write")
    assert repeated.derive("suffix", "mixed", ("p2", "p3"),
                           ("p2", "p3"), (("p", 1),),
                           (("p", 3),)).roots == ("p2", "p3")
    try:
        Lineage((Atom("p1", "unit-1", "p", 0, 1),
                 Atom("p1", "unit-1", "p", 0, 2)))
    except ValueError as error:
        assert "identity reused" in str(error)
    else:
        raise AssertionError("changed substance cannot reuse a source identity")
    print("path-gap mutant: endpoints hide an unselected middle write")
    print("transitive lineage scenarios: passed")


if __name__ == "__main__":
    scenarios()
