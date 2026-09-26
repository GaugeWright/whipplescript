"""Bounded probe of conservative reverse-dependency discovery.

Run: python3 models/research/edge_discovery.py

This models a complete repository roster, two graph cuts, known edges, and
unresolved edge classes with an enforced upper envelope. It checks routing
coverage, not the trustworthiness of the extractors or owner responses.
"""

from dataclasses import dataclass
from itertools import product


ROOT = "x"  # dependency proposed for update
ROSTER = frozenset(("a", "b", "c"))


@dataclass(frozen=True)
class Edge:
    consumer: str
    provider: str
    kind: str


# Finite universe for the probe, not a second product dependency registry.
UNIVERSE = (
    Edge("a", "x", "build"),
    Edge("b", "a", "build"),
    Edge("c", "b", "semantic"),
    Edge("c", "x", "semantic"),
    Edge("a", "c", "semantic"),
)


def reverse_closure(edges: frozenset[Edge], root: str,
                    roster: frozenset[str] = ROSTER) -> frozenset[str]:
    reached = {root}
    pending = [root]
    while pending:
        provider = pending.pop()
        for edge in edges:
            if edge.provider == provider and edge.consumer in roster:
                if edge.consumer not in reached:
                    reached.add(edge.consumer)
                    pending.append(edge.consumer)
    return frozenset(reached - {root})


def envelope(known: frozenset[Edge],
             incomplete: frozenset[tuple[str, str]],
             universe: tuple[Edge, ...] = UNIVERSE) -> frozenset[Edge]:
    """Unknown owner/kind coverage widens to its enforced possible edges.

    In a real system, the possible-provider set must come from an authority
    that constrains references, or widen to every provider the owner can see.
    The model checks that actual edges fit inside that set.
    """
    possible = set(known)
    for edge in universe:
        if (edge.consumer, edge.kind) in incomplete:
            possible.add(edge)
    return frozenset(possible)


def route(current_known: frozenset[Edge], proposed_known: frozenset[Edge],
          current_incomplete: frozenset[tuple[str, str]],
          proposed_incomplete: frozenset[tuple[str, str]],
          roster: frozenset[str] = ROSTER) -> frozenset[str]:
    current_possible = envelope(current_known, current_incomplete)
    proposed_possible = envelope(proposed_known, proposed_incomplete)
    return reverse_closure(current_possible | proposed_possible, ROOT, roster)


def route_after_capture(query_succeeded: bool,
                        current_known: frozenset[Edge],
                        proposed_known: frozenset[Edge],
                        current_incomplete: frozenset[tuple[str, str]],
                        proposed_incomplete: frozenset[tuple[str, str]]
                        ) -> frozenset[str] | None:
    # A failed analysis supplies no graph witness. In particular, its lack of
    # returned edges is not a complete, empty graph.
    if not query_succeeded:
        return None
    return route(current_known, proposed_known, current_incomplete,
                 proposed_incomplete)


def states():
    # For each edge: absent, present and observed, or present but unresolved.
    for choices in product((0, 1, 2), repeat=len(UNIVERSE)):
        actual = frozenset(edge for edge, choice in zip(UNIVERSE, choices)
                           if choice != 0)
        known = frozenset(edge for edge, choice in zip(UNIVERSE, choices)
                          if choice == 1)
        incomplete = frozenset((edge.consumer, edge.kind)
                               for edge, choice in zip(UNIVERSE, choices)
                               if choice == 2)
        yield actual, known, incomplete


def expect_miss(label: str, actual: frozenset[Edge], routed: frozenset[str]):
    missed = reverse_closure(actual, ROOT) - routed
    assert missed, label
    return f"{label}: missed {','.join(sorted(missed))}"


def main():
    graph_states = tuple(states())
    checked = 0
    widened = 0
    for current, current_known, current_incomplete in graph_states:
        for proposed, proposed_known, proposed_incomplete in graph_states:
            affected = reverse_closure(current | proposed, ROOT)
            assert current <= envelope(current_known, current_incomplete)
            assert proposed <= envelope(proposed_known, proposed_incomplete)
            routed = route(current_known, proposed_known, current_incomplete,
                           proposed_incomplete)
            assert affected <= routed, (current, proposed, affected, routed)
            checked += 1
            widened += routed != affected

    ax, ba, cb, cx, ac = UNIVERSE
    hidden = frozenset((ax, ba, cb))
    known = frozenset((ax, ba))
    incomplete = frozenset((("c", "semantic"),))
    assert route(known, known, incomplete, incomplete) == ROSTER
    negatives = [expect_miss(
        "known edges only", hidden, reverse_closure(known, ROOT)
    )]

    current = frozenset((ax, ba))
    proposed = frozenset((ax, ba, cb))
    negatives.append(expect_miss(
        "current graph only", current | proposed,
        reverse_closure(current, ROOT)
    ))
    negatives.append(expect_miss(
        "direct consumers only", hidden, frozenset(("a",))
    ))
    negatives.append(expect_miss(
        "omitted repository", hidden,
        route(hidden, hidden, frozenset(), frozenset(),
              frozenset(("a", "b")))
    ))
    assert route_after_capture(False, known, known, incomplete,
                               incomplete) is None
    negatives.append(expect_miss(
        "failed query treated as empty", hidden,
        reverse_closure(frozenset(), ROOT)
    ))

    # An added edge after capture invalidates its graph-epoch certificate.
    captured_epoch = 4
    current_epoch = 5
    captured_route = reverse_closure(current, ROOT)
    assert captured_route != reverse_closure(proposed, ROOT)
    assert captured_epoch != current_epoch  # safe admission refuses/replans
    negatives.append(expect_miss(
        "stale graph epoch", proposed, captured_route
    ))

    # The visited set terminates even when a migration introduces a cycle.
    cycle = frozenset((ax, ba, cb, ac))
    assert reverse_closure(cycle, ROOT) == ROSTER
    print(f"edge discovery: {checked} graph pairs; {widened} conservative routes")
    for result in negatives:
        print(f"  {result}")
    print("  cycle closure and graph-epoch fence scenarios passed")


if __name__ == "__main__":
    main()
