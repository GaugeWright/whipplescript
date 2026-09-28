"""Bounded RC-2 probe: one accepted program's local package imports.

Run: python3 models/research/program_import_coverage.py

This models the accepting operation as atomic with import extraction. It does
not show that every production program-admission path uses that operation.
"""

from dataclasses import dataclass
from hashlib import sha256
from itertools import combinations


def digest(*parts: object) -> str:
    return sha256(repr(parts).encode()).hexdigest()


@dataclass(frozen=True)
class Package:
    identity: str
    version: str
    source_path: str
    manifest_digest: str
    source_digest: str


@dataclass(frozen=True)
class Lock:
    # source_digest in each resolved Package is read from the current package
    # source. The on-disk v0 lock revision below excludes it.
    packages: tuple[tuple[str, Package], ...]

    @property
    def revision(self) -> str:
        # v0 whip.lock pins the manifest and path, not every package source
        # byte. The witness must detect a changed source under the same lock.
        return digest(tuple((name, package.identity, package.version,
                             package.source_path, package.manifest_digest)
                            for name, package in self.packages))

    def resolve(self, name: str) -> Package | None:
        return dict(self.packages).get(name)


@dataclass(frozen=True)
class Program:
    identity: str
    source_digest: str
    uses: tuple[str, ...]

    @property
    def applicable(self) -> frozenset[str]:
        return frozenset(name for name in self.uses if not name.startswith("std."))


@dataclass(frozen=True)
class Witness:
    program: str
    source_digest: str
    lock_revision: str
    compiler_revision: str
    examined: frozenset[str]
    edges: frozenset[tuple[str, str, str, str]]
    edge_digest: str


def capture(program: Program, lock: Lock, compiler_revision: str,
            *, omit: frozenset[str] = frozenset()) -> Witness | None:
    """The accepting boundary must refuse incomplete or unresolved capture."""
    examined = program.applicable - omit
    if examined != program.applicable:
        return None
    edges = set()
    for name in examined:
        package = lock.resolve(name)
        if package is None:
            return None
        edges.add((name, package.identity, package.version, package.source_digest))
    frozen = frozenset(edges)
    return Witness(program.identity, program.source_digest, lock.revision,
                   compiler_revision, examined, frozen,
                   digest(tuple(sorted(frozen))))


def current(witness: Witness, program: Program, lock: Lock,
            compiler_revision: str) -> bool:
    recaptured = capture(program, lock, compiler_revision)
    return (witness.program == program.identity
            and witness.source_digest == program.source_digest
            and witness.lock_revision == lock.revision
            and witness.compiler_revision == compiler_revision
            and witness.examined == program.applicable
            and witness.edge_digest == digest(tuple(sorted(witness.edges)))
            and recaptured is not None
            and witness.edges == recaptured.edges)


@dataclass
class Home:
    admitted: dict[str, Program]
    witnesses: dict[str, Witness]
    population_closed: bool = True

    def admit(self, program: Program, lock: Lock, compiler_revision: str) -> bool:
        witness = capture(program, lock, compiler_revision)
        if witness is None:
            return False
        self.admitted[program.identity] = program
        self.witnesses[program.identity] = witness
        return True

    def import_coverage(self, locks: dict[str, Lock],
                        compiler_revision: str) -> str:
        if not self.population_closed:
            return "unknown"
        for identity, program in self.admitted.items():
            lock = locks.get(identity)
            witness = self.witnesses.get(identity)
            if lock is None or witness is None or not current(
                    witness, program, lock, compiler_revision):
                return "unknown"
        return "complete"


def probe() -> None:
    old = Package("package-x", "1", "packages/x/manifest.json", "manifest-x", "source-a")
    lock = Lock((("x", old),))
    a = Program("a", "program-a-v1", ("std.time", "x"))
    b = Program("b", "program-b-v1", ("x",))
    home = Home({}, {})
    assert home.admit(a, lock, "compiler-1")
    witness = home.witnesses["a"]
    assert witness.examined == frozenset(("x",))
    assert witness.edges == frozenset((("x", "package-x", "1", "source-a"),))
    assert home.import_coverage({"a": lock}, "compiler-1") == "complete"
    home.population_closed = False
    assert home.import_coverage({"a": lock}, "compiler-1") == "unknown"
    home.population_closed = True

    # The narrow witness says nothing about a second program that was accepted
    # through an older path without capture. Treating a successful graph query
    # for a as Home-wide evidence gives a false complete claim.
    home.admitted["b"] = b
    assert home.import_coverage({"a": lock, "b": lock}, "compiler-1") == "unknown"
    assert current(witness, a, lock, "compiler-1")
    assert home.admit(b, lock, "compiler-1")
    assert home.import_coverage({"a": lock, "b": lock}, "compiler-1") == "complete"

    # Same package spelling and version, different source: the edge is stale.
    moved = Lock((("x", Package("package-x", "1", "packages/x/manifest.json",
                                  "manifest-x", "source-b")),))
    assert moved.revision == lock.revision  # the v0 lock did not move
    assert not current(witness, a, moved, "compiler-1")
    assert home.import_coverage({"a": moved, "b": lock}, "compiler-1") == "unknown"
    assert not current(witness, Program("a", "program-a-v2", a.uses), lock,
                       "compiler-1")
    assert not current(witness, a, lock, "compiler-2")

    # Check every subset of a two-import program. Only examining both may
    # yield a witness; a resolver failure also refuses the narrow admission.
    both = Program("c", "program-c", ("x", "y"))
    two = Lock((("x", old), ("y", Package("package-y", "2",
                                          "packages/y/manifest.json", "manifest-y",
                                          "source-y"))))
    checked = 0
    for length in range(3):
        for members in combinations(sorted(both.applicable), length):
            omitted = both.applicable - frozenset(members)
            result = capture(both, two, "compiler-1", omit=omitted)
            assert (result is not None) == (length == 2)
            checked += 1
    assert capture(both, lock, "compiler-1") is None
    assert not Home({}, {}).admit(both, lock, "compiler-1")

    # Defective extractor: it silently skips y, then mistakes its examined
    # subset for the applicable set. The edge digest alone cannot expose y.
    skipped_y = Program("c", both.source_digest, ("x",))
    defective = capture(skipped_y, lock, "compiler-1")
    assert defective is not None
    assert not current(defective, both, two, "compiler-1")

    print(f"program import coverage: {checked} examined subsets")
    print("  one program is complete only at its source, lock, and compiler revision")
    print("  missing program, unresolved import, and omitted import cannot close Home")


if __name__ == "__main__":
    probe()
