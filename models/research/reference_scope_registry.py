"""Bounded RC-1 probe: required scopes come from the admitted boundary.

Run: python3 models/research/reference_scope_registry.py

This model treats a schema/construct/provider registry and its accepting
operations as one versioned authority. It does not prove that production
parsers have been routed through that authority yet.
"""

from dataclasses import dataclass
from hashlib import sha256
from itertools import combinations


MEANINGS = frozenset(("plain", "live", "historical", "provenance",
                      "authority", "content"))
REF_MEANINGS = MEANINGS - {"plain"}


@dataclass(frozen=True)
class Declaration:
    field: str
    scope: str
    meaning: str | None


@dataclass(frozen=True)
class AcceptedRef:
    consumer: str
    field: str
    provider: str
    admitted_registry: int = 1


@dataclass(frozen=True)
class Basis:
    registry: int
    roster: int
    cut: int
    graph: int


@dataclass(frozen=True)
class Witness:
    basis: Basis
    required: frozenset[tuple[str, str]]
    examined: frozenset[str]
    edges: frozenset[tuple[str, str, str, str]]
    edge_digest: str
    state: str
    gaps: tuple[str, ...]


def required_scopes(declarations: tuple[Declaration, ...]):
    """None means a new interpreting field has no classification."""
    if any(d.meaning not in MEANINGS for d in declarations):
        return None
    if len({d.field for d in declarations}) != len(declarations):
        return None
    return frozenset((d.scope, d.meaning) for d in declarations
                     if d.meaning in REF_MEANINGS)


def digest(edges: frozenset[tuple[str, str, str, str]]) -> str:
    body = repr(tuple(sorted(edges))).encode()
    return sha256(body).hexdigest()


def capture(declarations: tuple[Declaration, ...],
            population: frozenset[str], examined: frozenset[str],
            accepted: frozenset[AcceptedRef], basis: Basis,
            *, population_closed: bool = True,
            boundary_enforced: bool = True) -> Witness:
    required = required_scopes(declarations)
    gaps = []
    if required is None:
        gaps.append("unclassified or duplicate declaration")
        required = frozenset()
    if not population_closed:
        gaps.append("consumer population is open")
    if examined != population:
        gaps.append("consumer population not fully examined")
    if not boundary_enforced:
        gaps.append("undeclared interpreting path may accept references")
    by_field = {d.field: d for d in declarations}
    edges = set()
    for ref in accepted:
        declaration = by_field.get(ref.field)
        if ref.admitted_registry != basis.registry:
            gaps.append("accepted reference from an earlier registry needs its own witness")
        elif ref.consumer not in population:
            gaps.append("accepted reference outside roster")
        elif declaration is None or declaration.meaning not in REF_MEANINGS:
            gaps.append("accepted reference lacks declared meaning")
        elif ref.consumer not in examined:
            gaps.append("accepted reference outside examined set")
        else:
            edges.add((ref.consumer, ref.provider, declaration.scope,
                       declaration.meaning))
    edges = frozenset(edges)
    return Witness(basis, required, examined, edges, digest(edges),
                   "unknown" if gaps else "complete", tuple(sorted(set(gaps))))


def admit(witness: Witness, current: Basis) -> bool:
    return witness.state == "complete" and witness.basis == current


def live_consumers(witness: Witness, provider: str) -> frozenset[str]:
    assert witness.state == "complete"
    return frozenset(consumer for consumer, destination, _, meaning
                     in witness.edges
                     if destination == provider and meaning == "live")


def probe():
    basis = Basis(registry=1, roster=1, cut=1, graph=1)
    declarations = (
        Declaration("program.use", "program-import", "live"),
        Declaration("norm.derived_from", "norm-reference", "provenance"),
        Declaration("instance.pin", "instance-reference", "historical"),
        Declaration("provider.binding", "provider-reference", "live"),
        Declaration("content.handle", "content-reference", "content"),
        Declaration("legacy.payload", "legacy-reference", "authority"),
    )
    population = frozenset(("program-a", "program-b"))
    accepted = frozenset((
        AcceptedRef("program-a", "program.use", "package-x"),
        AcceptedRef("program-a", "norm.derived_from", "package-x"),
        AcceptedRef("program-b", "instance.pin", "package-x"),
    ))
    complete = capture(declarations, population, population, accepted, basis)
    assert complete.state == "complete" and not complete.gaps
    assert len(complete.required) == len(declarations)
    assert complete.edge_digest == digest(complete.edges)
    assert admit(complete, basis)
    assert live_consumers(complete, "package-x") == frozenset(("program-a",))

    # Every subset of the two-consumer population is tried. A complete claim
    # exists exactly when the authoritative population was fully examined.
    checked = 0
    for length in range(len(population) + 1):
        for members in combinations(sorted(population), length):
            witness = capture(declarations, population, frozenset(members),
                              accepted, basis)
            assert (witness.state == "complete") == (len(members) == 2)
            checked += 1

    added = declarations + (Declaration("new.dynamic", "norm-reference", None),)
    unknown_field = capture(added, population, population, accepted, basis)
    assert unknown_field.state == "unknown"
    assert not admit(unknown_field, basis)
    # Defect: a missing registration is treated as plain text. It produces a
    # false complete result even though the new path can interpret a provider.
    guessed_plain = added[:-1] + (Declaration("new.dynamic", "norm-reference", "plain"),)
    assert capture(guessed_plain, population, population, accepted, basis).state == "complete"

    omitted = capture(declarations, population, frozenset(("program-a",)),
                      frozenset(ref for ref in accepted
                                if ref.consumer == "program-a"), basis)
    assert omitted.state == "unknown"
    # Defect: use the extractor's observed set as the authoritative roster.
    assert capture(declarations, frozenset(("program-a",)),
                   frozenset(("program-a",)), frozenset(ref for ref in accepted
                   if ref.consumer == "program-a"), basis).state == "complete"

    opaque = capture(declarations, population, population,
                     accepted | {AcceptedRef("program-b", "opaque.string", "package-x")},
                     basis)
    assert opaque.state == "unknown"
    # Defect: query only declared typed edges, silently drop an accepted
    # opaque reference, and falsely claim complete coverage.
    assert capture(declarations, population, population, accepted, basis).state == "complete"

    earlier = accepted | {AcceptedRef("program-b", "norm.derived_from",
                                      "package-x", admitted_registry=0)}
    assert capture(declarations, population, population, earlier, basis).state == "unknown"
    # Defect: the current registry's declarations are used for an admitted
    # reference whose earlier accepting registry is absent from this witness.
    assert capture(declarations, population, population, accepted, basis).state == "complete"

    unenforced = capture(declarations, population, population, accepted, basis,
                         boundary_enforced=False)
    assert unenforced.state == "unknown"
    # Defect: a read-only crawler is mistaken for a closed accepting boundary.
    assert capture(declarations, population, population, accepted, basis,
                   boundary_enforced=True).state == "complete"

    assert not admit(complete, Basis(1, 1, 1, 2))  # edge added after capture
    assert not admit(complete, Basis(2, 1, 1, 1))  # new reference class
    assert not admit(complete, Basis(1, 2, 1, 1))  # new consumer
    assert not admit(complete, Basis(1, 1, 2, 1))  # source changed
    # Defect: accepting only the captured graph's successful query ignores
    # all four exact-basis changes and would admit stale evidence.
    assert complete.state == "complete"

    assert live_consumers(complete, "package-x") == frozenset(("program-a",))
    # Defect: treating every typed reference as a live dependency routes
    # provenance and historical recipients as migrations.
    all_typed = frozenset(consumer for consumer, destination, _, _
                          in complete.edges if destination == "package-x")
    assert all_typed == population
    print(f"reference scope registry: {checked} population subsets; "
          f"{len(complete.required)} required scopes")
    print("  unclassified field, omitted consumer, opaque path, earlier registry, and open boundary refuse")
    print("  graph/registry/roster/cut changes invalidate; provenance and pins stay non-live")
    print("  seven weakened variants give false completeness, staleness, or live routing")


if __name__ == "__main__":
    probe()
