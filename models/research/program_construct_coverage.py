"""Bounded RC-3 probe for construct edges at checked-program admission.

The accepted unit is an operation, even when two operations reuse a program
version. A construct use resolves to exactly one registration from the checked
registry. The witness binds that choice, its source bytes, program source,
lock, and running compiler. This is an executable design probe, not an
implementation of the compiler, Home roster, or admitting transaction.
"""

from dataclasses import dataclass, replace
from hashlib import sha256
from itertools import combinations


def digest(value: object) -> str:
    return sha256(repr(value).encode()).hexdigest()


@dataclass(frozen=True)
class Use:
    occurrence: int
    keyword: str
    scope: str
    family: str
    lowering: str
    capability: str


@dataclass(frozen=True)
class Registration:
    identity: str
    library: str
    version: str
    keyword: str
    scope: str
    family: str
    lowering: str
    capability: str
    source_digest: str

    def matches(self, use: Use) -> bool:
        return (self.keyword, self.scope, self.family, self.lowering,
                self.capability) == (use.keyword, use.scope, use.family,
                                     use.lowering, use.capability)


@dataclass(frozen=True)
class Program:
    version: str
    source_digest: str
    imported_libraries: frozenset[str]
    uses: tuple[Use, ...]


@dataclass(frozen=True)
class Edge:
    occurrence: int
    registration: str
    library: str
    version: str
    source_digest: str
    meaning: str = "live_dependency"


@dataclass(frozen=True)
class Witness:
    version: str
    program_source: str
    lock_revision: str
    compiler_artifact: str
    examined: tuple[int, ...]
    edges: tuple[Edge, ...]
    edge_digest: str


def capture(program: Program, registry: tuple[Registration, ...],
            lock_revision: str, compiler_artifact: str,
            *, omit: frozenset[int] = frozenset(),
            choose_first: bool = False) -> Witness | None:
    """Every IR occurrence must resolve uniquely under the checked registry."""
    occurrences = tuple(use.occurrence for use in program.uses)
    if len(set(occurrences)) != len(occurrences) or omit:
        return None
    edges = []
    for use in program.uses:
        matches = tuple(registration for registration in registry
                        if registration.matches(use))
        if not matches or (len(matches) != 1 and not choose_first):
            return None
        selected = matches[0]
        if selected.library not in program.imported_libraries:
            return None
        edges.append(Edge(use.occurrence, selected.identity, selected.library,
                          selected.version, selected.source_digest))
    ordered = tuple(sorted(edges, key=lambda edge: edge.occurrence))
    return Witness(program.version, program.source_digest, lock_revision,
                   compiler_artifact, tuple(sorted(occurrences)), ordered,
                   digest(ordered))


def current(witness: Witness, program: Program,
            registry: tuple[Registration, ...], lock_revision: str,
            compiler_artifact: str) -> bool:
    fresh = capture(program, registry, lock_revision, compiler_artifact)
    return fresh is not None and witness == fresh


@dataclass
class Home:
    # Each call to an accepting door has its own entry. A version is not an
    # operation: the same version can be accepted again with another basis.
    operations: dict[str, tuple[Program, Witness | None]]
    population_closed: bool = True

    def admit(self, operation: str, program: Program,
              registry: tuple[Registration, ...], lock: str,
              compiler: str) -> bool:
        assert operation not in self.operations
        witness = capture(program, registry, lock, compiler)
        if witness is None:
            return False
        self.operations[operation] = (program, witness)
        return True

    def admit_unwitnessed(self, operation: str, program: Program) -> None:
        assert operation not in self.operations
        self.operations[operation] = (program, None)

    def coverage(self, bases: dict[str, tuple[tuple[Registration, ...], str, str]]) -> str:
        if not self.population_closed:
            return "unknown"
        for operation, (program, witness) in self.operations.items():
            basis = bases.get(operation)
            if witness is None or basis is None or not current(witness, program, *basis):
                return "unknown"
        return "complete"


def probe() -> None:
    send = Use(0, "send", "rule_body", "effect_operation", "capability.call",
               "messaging.send")
    recall = Use(1, "recall", "rule_body", "effect_operation", "capability.call",
                 "memory.recall")
    messaging = Registration("messaging.send", "std.messaging", "1", "send",
                             "rule_body", "effect_operation", "capability.call",
                             "messaging.send", "embedded-compiler-a")
    memory = Registration("memory.recall", "local.memory", "1", "recall",
                          "rule_body", "effect_operation", "capability.call",
                          "memory.recall", "package-source-a")
    registry = (messaging, memory)
    program = Program("program-version-a", "program-source-a",
                      frozenset(("std.messaging", "local.memory")), (send, recall))
    lock = "lock-a"
    compiler = "compiler-a"
    witness = capture(program, registry, lock, compiler)
    assert witness is not None
    assert witness.examined == (0, 1)
    assert tuple(edge.registration for edge in witness.edges) == (
        "messaging.send", "memory.recall")
    assert all(edge.meaning == "live_dependency" for edge in witness.edges)
    assert current(witness, program, registry, lock, compiler)

    home = Home({})
    assert home.admit("first", program, registry, lock, compiler)
    assert home.coverage({"first": (registry, lock, compiler)}) == "complete"
    home.population_closed = False
    assert home.coverage({"first": (registry, lock, compiler)}) == "unknown"
    home.population_closed = True
    home.admit_unwitnessed("same-version-later", program)
    assert home.coverage({"first": (registry, lock, compiler),
                          "same-version-later": (registry, lock, compiler)}) == "unknown"
    # A version-keyed join would hide the later unwitnessed accepting call.
    by_version = {item.version: captured for item, captured in home.operations.values()
                  if captured is not None}
    assert by_version == {program.version: witness}

    # All subsets of two uses are examined. Only the full set can witness the
    # program; a missing registration or owning import refuses it as well.
    subsets = 0
    for size in range(3):
        for retained in combinations((0, 1), size):
            omitted = frozenset((0, 1)) - frozenset(retained)
            assert (capture(program, registry, lock, compiler, omit=omitted)
                    is not None) == (size == 2)
            subsets += 1
    assert capture(program, (messaging,), lock, compiler) is None
    assert capture(replace(program, imported_libraries=frozenset(("std.messaging",))),
                   registry, lock, compiler) is None
    omitted_use = capture(replace(program, uses=(send,)), registry, lock, compiler)
    assert omitted_use is not None
    assert not current(omitted_use, program, registry, lock, compiler)

    # A registration's shape is not a unique identity. If two packages claim
    # the same use, selecting the first by iteration order cannot certify it.
    competitor = replace(memory, identity="other.recall", library="other.memory")
    ambiguous_program = replace(
        program, imported_libraries=program.imported_libraries | {"other.memory"})
    assert capture(ambiguous_program, registry + (competitor,), lock, compiler) is None
    false_witness = capture(ambiguous_program, registry + (competitor,), lock,
                            compiler, choose_first=True)
    assert false_witness is not None
    assert not current(false_witness, ambiguous_program,
                       registry + (competitor,), lock, compiler)

    # The v0 lock can stay byte-identical when package source bytes move.
    changed_source = (messaging, replace(memory, source_digest="package-source-b"))
    assert not current(witness, program, changed_source, lock, compiler)
    assert not current(witness, program, registry, lock, "compiler-b")
    assert not current(witness, replace(program, source_digest="program-source-b"),
                       registry, lock, compiler)
    assert not current(witness, program, registry, "lock-b", compiler)
    truncated = witness.edges[:1]
    forged_subset = replace(witness, examined=(0,), edges=truncated,
                            edge_digest=digest(truncated))
    assert not current(forged_subset, program, registry, lock, compiler)

    checked = Home({})
    assert checked.admit("first", program, registry, lock, compiler)
    assert checked.admit("same-version-later", program, registry, lock, compiler)
    assert checked.coverage({"first": (registry, lock, compiler),
                             "same-version-later": (registry, lock, compiler)}) == "complete"

    print(f"program construct coverage: {subsets} examined subsets")
    print("  exact checked uses resolve once and bind their registration sources")
    print("  ambiguous, omitted, unimported, or changed uses cannot certify a program")
    print("  a version witness cannot cover a later unwitnessed accepting operation")


if __name__ == "__main__":
    probe()
