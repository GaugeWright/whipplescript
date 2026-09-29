"""RC-3 probe: a declaration witness needs a checked source-to-IR inventory.

The current production `IrProgram.construct_uses()` sees rule-effect metadata,
not registered top-level declarations. A declaration list reconstructed only
from lowered IR can be empty when lowering dropped a source occurrence. This
model checks an independently enumerated inventory of the selected,
pattern-expanded compiler AST against tagged IR declarations before resolving
the registration. It assumes the AST inventory and tags are honest and bound
to exact source bytes and expansion basis; it does not prove that boundary.
"""

from dataclasses import dataclass, replace
from hashlib import sha256


def digest(value: object) -> str:
    return sha256(repr(value).encode()).hexdigest()


@dataclass(frozen=True)
class Occurrence:
    identity: str  # source site plus expansion path, not a declaration name
    keyword: str
    family: str
    lowering: str


@dataclass(frozen=True)
class Registration:
    identity: str
    library: str
    version: str
    keyword: str
    family: str
    lowering: str
    source_digest: str

    def matches(self, occurrence: Occurrence) -> bool:
        return (self.keyword, self.family, self.lowering) == (
            occurrence.keyword, occurrence.family, occurrence.lowering)


@dataclass(frozen=True)
class Edge:
    occurrence: str
    registration: str
    library: str
    version: str
    provider_source: str


@dataclass(frozen=True)
class Witness:
    scope: str
    source_digest: str
    examined: tuple[str, ...]
    edges: tuple[Edge, ...]
    edge_digest: str


def ir_only_capture(lowered: tuple[Occurrence, ...]) -> tuple[str, ...]:
    """Defective candidate: an empty IR list falsely looks examined-empty."""
    return tuple(item.identity for item in lowered)


def capture(parsed: tuple[Occurrence, ...], lowered: tuple[Occurrence, ...],
            registry: tuple[Registration, ...], imported: frozenset[str],
            source_digest: str) -> Witness | None:
    parsed_by_id = {item.identity: item for item in parsed}
    lowered_by_id = {item.identity: item for item in lowered}
    if (len(parsed_by_id) != len(parsed) or len(lowered_by_id) != len(lowered)
            or parsed_by_id != lowered_by_id):
        return None
    edges = []
    for occurrence in parsed:
        matches = tuple(row for row in registry if row.matches(occurrence))
        if len(matches) != 1 or matches[0].library not in imported:
            return None
        row = matches[0]
        edges.append(Edge(occurrence.identity, row.identity, row.library,
                          row.version, row.source_digest))
    retained = tuple(edges)
    return Witness("registered_declaration", source_digest,
                   tuple(item.identity for item in parsed), retained,
                   digest(retained))


def current(witness: Witness, parsed: tuple[Occurrence, ...],
            lowered: tuple[Occurrence, ...], registry: tuple[Registration, ...],
            imported: frozenset[str], source_digest: str) -> bool:
    fresh = capture(parsed, lowered, registry, imported, source_digest)
    return fresh is not None and witness == fresh


def probe() -> None:
    lease = Occurrence("source:12", "lease", "declaration_block", "metadata_only")
    source = Occurrence("source:41", "source", "source_declaration", "signal_source")
    parsed = (lease, source)
    rows = (
        Registration("coord.lease", "std.coord", "1", "lease",
                     "declaration_block", "metadata_only", "coord-bytes-a"),
        Registration("ingress.source", "std.ingress", "1", "source",
                     "source_declaration", "signal_source", "ingress-bytes-a"),
    )
    imported = frozenset(("std.coord", "std.ingress"))
    witness = capture(parsed, parsed, rows, imported, "program-bytes-a")
    assert witness is not None
    assert witness.examined == ("source:12", "source:41")
    assert current(witness, parsed, parsed, rows, imported, "program-bytes-a")

    # An IR-only inventory claims complete(empty) after losing BOTH source
    # declarations. With the source inventory, each loss refuses.
    assert ir_only_capture(()) == ()
    assert capture(parsed, (), rows, imported, "program-bytes-a") is None
    assert capture(parsed, (lease,), rows, imported, "program-bytes-a") is None
    assert capture(parsed, (source,), rows, imported, "program-bytes-a") is None
    assert capture(parsed, parsed + (lease,), rows, imported, "program-bytes-a") is None
    assert capture(parsed, parsed + (Occurrence("source:99", "lease",
                   "declaration_block", "metadata_only"),), rows, imported,
                   "program-bytes-a") is None
    repeated = (replace(lease, identity="source:12/apply:a"),
                replace(lease, identity="source:12/apply:b"))
    assert capture(repeated, repeated, rows, imported, "program-bytes-a") is not None
    assert capture(repeated, repeated[:1], rows, imported, "program-bytes-a") is None
    # A caller that forges BOTH inventories can still claim a subset. The
    # AST inventory must come from exact selected/expanded source, not a caller.
    assert capture((lease,), (lease,), rows, imported, "program-bytes-a") is not None

    # Matching by name or list length would miss a changed lowering shape.
    wrong_shape = (lease, replace(source, lowering="clock_source"))
    assert capture(parsed, wrong_shape, rows, imported, "program-bytes-a") is None
    competitor = replace(rows[0], identity="other.lease", library="other.coord")
    assert capture(parsed, parsed, rows + (competitor,), imported | {"other.coord"},
                   "program-bytes-a") is None
    assert capture(parsed, parsed, rows, frozenset(("std.coord",)),
                   "program-bytes-a") is None

    # Exact source and registration bytes remain part of revalidation.
    assert not current(witness, parsed, parsed, rows, imported, "program-bytes-b")
    moved = (replace(rows[0], source_digest="coord-bytes-b"), rows[1])
    assert not current(witness, parsed, parsed, moved, imported, "program-bytes-a")

    print("declaration construct inventory: source and IR occurrences correspond")
    print("  omitted, duplicate, extra, or changed-shape lowering refuses")
    print("  IR-only examined-empty can conceal source declarations")
    print("  forged source and IR subsets remain possible without compiler provenance")


if __name__ == "__main__":
    probe()
