"""Bounded RC-2 probe: one accepted program's local package imports.

Run: python3 models/research/program_import_coverage.py

This models the accepting operation as atomic with import extraction and
assumes an authoritative roster of accepting operations. It does not show
that production records every operation or captures its import witness.
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
    # An accepting operation has its own identity even when it reuses a
    # program-version row. A version-keyed roster loses later admissions.
    admissions: dict[str, tuple[Program, Witness | None]]
    population_closed: bool = True

    def admit(self, operation: str, program: Program, lock: Lock,
              compiler_revision: str) -> bool:
        assert operation not in self.admissions
        witness = capture(program, lock, compiler_revision)
        if witness is None:
            return False
        self.admissions[operation] = (program, witness)
        return True

    def admit_without_capture(self, operation: str, program: Program) -> None:
        assert operation not in self.admissions
        self.admissions[operation] = (program, None)

    def import_coverage(self, locks: dict[str, Lock],
                        compiler_revision: str) -> str:
        if not self.population_closed:
            return "unknown"
        for operation, (program, witness) in self.admissions.items():
            lock = locks.get(operation)
            if lock is None or witness is None or not current(
                    witness, program, lock, compiler_revision):
                return "unknown"
        return "complete"


def probe() -> None:
    old = Package("package-x", "1", "packages/x/manifest.json", "manifest-x", "source-a")
    lock = Lock((("x", old),))
    a = Program("a", "program-a-v1", ("std.time", "x"))
    b = Program("b", "program-b-v1", ("x",))
    home = Home({})
    assert home.admit("admit-a", a, lock, "compiler-1")
    witness = home.admissions["admit-a"][1]
    assert witness is not None
    assert witness.examined == frozenset(("x",))
    assert witness.edges == frozenset((("x", "package-x", "1", "source-a"),))
    assert home.import_coverage({"admit-a": lock}, "compiler-1") == "complete"
    home.population_closed = False
    assert home.import_coverage({"admit-a": lock}, "compiler-1") == "unknown"
    home.population_closed = True

    # The narrow witness says nothing about a second program that was accepted
    # through an older path without capture. Treating a successful graph query
    # for a as Home-wide evidence gives a false complete claim.
    home.admit_without_capture("admit-b", b)
    assert home.import_coverage({"admit-a": lock, "admit-b": lock},
                                "compiler-1") == "unknown"
    assert current(witness, a, lock, "compiler-1")
    # A later checked admission does not repair an earlier operation whose
    # basis and witness were never retained.
    assert home.admit("admit-b-checked", b, lock, "compiler-1")
    assert home.import_coverage({"admit-a": lock, "admit-b": lock,
                                 "admit-b-checked": lock}, "compiler-1") == "unknown"

    # More subtly, an older path can accept the *same version* after its
    # first checked admission. A version roster still finds a valid witness
    # for a, but has silently dropped the later unwitnessed operation.
    reused = Home({})
    assert reused.admit("first", a, lock, "compiler-1")
    reused.admit_without_capture("later", a)
    assert current(witness, a, lock, "compiler-1")
    assert reused.import_coverage({"first": lock, "later": lock},
                                  "compiler-1") == "unknown"
    # Version-keyed projection would collapse both operations to one row.
    by_version = {program.identity: recorded for program, recorded
                  in reused.admissions.values() if recorded is not None}
    assert by_version == {"a": witness}
    assert all(current(recorded, a, lock, "compiler-1")
               for recorded in by_version.values())  # false complete

    checked = Home({})
    assert checked.admit("a", a, lock, "compiler-1")
    assert checked.admit("b", b, lock, "compiler-1")
    assert checked.import_coverage({"a": lock, "b": lock}, "compiler-1") == "complete"

    # Same package spelling and version, different source: the edge is stale.
    moved = Lock((("x", Package("package-x", "1", "packages/x/manifest.json",
                                  "manifest-x", "source-b")),))
    assert moved.revision == lock.revision  # the v0 lock did not move
    assert not current(witness, a, moved, "compiler-1")
    assert checked.import_coverage({"a": moved, "b": lock},
                                   "compiler-1") == "unknown"
    assert not current(witness, Program("a", "program-a-v2", a.uses), lock,
                       "compiler-1")
    assert not current(witness, a, lock, "compiler-2")

    # Check every subset of a two-import program. Only examining both may
    # yield a witness; a resolver failure also refuses the narrow admission.
    both = Program("c", "program-c", ("x", "y"))
    two = Lock((("x", old), ("y", Package("package-y", "2",
                                          "packages/y/manifest.json", "manifest-y",
                                          "source-y"))))
    subsets = 0
    for length in range(3):
        for members in combinations(sorted(both.applicable), length):
            omitted = both.applicable - frozenset(members)
            result = capture(both, two, "compiler-1", omit=omitted)
            assert (result is not None) == (length == 2)
            subsets += 1
    assert capture(both, lock, "compiler-1") is None
    assert not Home({}).admit("c", both, lock, "compiler-1")

    # Defective extractor: it silently skips y, then mistakes its examined
    # subset for the applicable set. The edge digest alone cannot expose y.
    skipped_y = Program("c", both.source_digest, ("x",))
    defective = capture(skipped_y, lock, "compiler-1")
    assert defective is not None
    assert not current(defective, both, two, "compiler-1")

    print(f"program import coverage: {subsets} examined subsets")
    print("  one program is complete only at its source, lock, and compiler revision")
    print("  missing operation, unresolved import, and omitted import cannot close Home")
    print("  a witness for one version cannot cover its later unwitnessed admission")


if __name__ == "__main__":
    probe()
