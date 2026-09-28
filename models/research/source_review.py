"""Bounded reviewed-contribution admission probe.

Run: python3 models/research/source_review.py

One destination ref, two contributions, two candidate revisions and one gate
attempt at a time. Candidate construction is a token: this probes review and
admission binding, not Git merge correctness or durable store transactions.
Each weakened guard must produce an observable forbidden receipt.
"""

from dataclasses import dataclass, field
from hashlib import sha256


def candidate(base: str, kind: str, cut: str) -> str:
    return sha256(f"{base}\0{kind}\0{cut}".encode()).hexdigest()[:16]


@dataclass
class Contribution:
    identity: str
    source_kind: str
    revisions: list[str]
    predecessors: tuple[str, ...] = ()
    source_head: str = ""
    owed: bool = True
    admitted: bool = False

    @property
    def revision(self) -> int:
        return len(self.revisions) - 1


@dataclass
class Attempt:
    operation: str
    contribution: str
    source_kind: str
    revision: int
    source_cut: str
    base: str
    policy: int
    candidate: str
    verdict: str = "unrun"
    gate_evidence: tuple[str, str, int, str, str, int, str] | None = None
    cancelled: bool = False

    def binding(self) -> tuple[str, str, int, str, str, int, str]:
        return (self.contribution, self.source_kind, self.revision,
                self.source_cut, self.base, self.policy, self.candidate)


@dataclass
class Entry:
    operation: str
    contribution: str
    revision: int
    source_cut: str
    expected_base: str
    actual_base: str
    expected_policy: int
    actual_policy: int
    verdict: str
    gate_bound: bool
    cancelled: bool
    predecessors_admitted: bool
    held: bool
    candidate: str


@dataclass
class Model:
    trunk: str = "T0"
    policy: int = 0
    held: bool = False
    contributions: dict[str, Contribution] = field(default_factory=dict)
    attempts: dict[str, Attempt] = field(default_factory=dict)
    entries: list[Entry] = field(default_factory=list)
    delivered: set[str] = field(default_factory=set)

    def declare(self, identity: str, kind: str, cut: str,
                predecessors: tuple[str, ...] = ()) -> None:
        assert kind in ("git", "flowing-prefix")
        assert identity not in self.contributions
        self.contributions[identity] = Contribution(
            identity, kind, [cut], predecessors, cut)

    def revise(self, identity: str, cut: str) -> None:
        contribution = self.contributions[identity]
        assert contribution.owed and cut != contribution.revisions[-1]
        contribution.revisions.append(cut)
        contribution.source_head = cut

    def advance_source_tail(self, identity: str, cut: str) -> None:
        contribution = self.contributions[identity]
        assert contribution.source_kind == "flowing-prefix"
        contribution.source_head = cut
        # The selected immutable revision stays exactly where it was.

    def schedule(self, identity: str, operation: str) -> None:
        contribution = self.contributions[identity]
        assert contribution.owed and operation not in self.attempts
        cut = contribution.revisions[-1]
        self.attempts[operation] = Attempt(
            operation, identity, contribution.source_kind, contribution.revision,
            cut, self.trunk, self.policy,
            candidate(self.trunk, contribution.source_kind, cut))

    def gate(self, operation: str, verdict: str) -> None:
        assert verdict in ("passed", "failed", "unrun")
        attempt = self.attempts[operation]
        attempt.verdict = verdict
        attempt.gate_evidence = attempt.binding()

    def cancel(self, operation: str) -> None:
        self.attempts[operation].cancelled = True

    def move_trunk(self) -> None:
        self.trunk = f"external({self.trunk})"

    def change_policy(self) -> None:
        self.policy += 1

    def hold(self) -> None:
        self.held = True
        self.change_policy()

    def admit(self, operation: str, defect: str = "") -> bool:
        attempt = self.attempts[operation]
        contribution = self.contributions[attempt.contribution]
        predecessors_ok = all(
            self.contributions[p].admitted for p in contribution.predecessors)
        checks = {
            "owed": contribution.owed,
            "cancel": not attempt.cancelled,
            "revision": attempt.revision == contribution.revision,
            "base": attempt.base == self.trunk,
            "policy": attempt.policy == self.policy,
            "hold": not (self.held and contribution.source_kind == "flowing-prefix"),
            "dependencies": predecessors_ok,
            "gate": attempt.verdict == "passed",
            "gate_binding": attempt.gate_evidence == attempt.binding(),
            "candidate": attempt.candidate == candidate(
                attempt.base, attempt.source_kind, attempt.source_cut),
        }
        if not all(value for name, value in checks.items() if name != defect):
            return False
        entry = Entry(
            operation, attempt.contribution, attempt.revision, attempt.source_cut,
            attempt.base, self.trunk, attempt.policy, self.policy,
            attempt.verdict, attempt.gate_evidence == attempt.binding(),
            attempt.cancelled, predecessors_ok, self.held, attempt.candidate)
        self.entries.append(entry)
        self.trunk = attempt.candidate
        contribution.owed = False
        contribution.admitted = True
        return True

    def recover(self, operation: str, defect: str = "") -> None:
        entries = [entry for entry in self.entries if entry.operation == operation]
        assert entries
        if defect == "repeat_cas":
            self.entries.append(entries[-1])
        self.delivered.add(operation)

    def violation(self) -> str | None:
        seen = set()
        admitted_contributions = set()
        for entry in self.entries:
            if entry.operation in seen:
                return "one operation advanced twice"
            seen.add(entry.operation)
            if entry.contribution in admitted_contributions:
                return "one contribution admitted twice"
            admitted_contributions.add(entry.contribution)
            contribution = self.contributions[entry.contribution]
            if entry.verdict != "passed":
                return "unpassed gate admitted"
            if not entry.gate_bound:
                return "gate evidence for another candidate admitted"
            if entry.cancelled:
                return "cancelled attempt admitted"
            if entry.expected_base != entry.actual_base:
                return "old base admitted"
            if entry.expected_policy != entry.actual_policy:
                return "old policy admitted"
            if entry.revision != contribution.revision:
                return "superseded revision admitted"
            if not entry.predecessors_admitted:
                return "dependent contribution admitted early"
            if entry.held and contribution.source_kind == "flowing-prefix":
                return "held branch admitted"
            if entry.candidate != candidate(
                    entry.expected_base, contribution.source_kind, entry.source_cut):
                return "unbound candidate admitted"
        if any(not c.admitted and not c.owed for c in self.contributions.values()):
            return "unadmitted contribution lost"
        return None


def guarded_scenarios() -> None:
    for kind in ("git", "flowing-prefix"):
        m = Model()
        m.declare("a", kind, "A1")
        m.schedule("a", "op-a")
        if kind == "flowing-prefix":
            m.advance_source_tail("a", "A2-tail")
            assert m.attempts["op-a"].source_cut == "A1"
        m.gate("op-a", "passed")
        assert m.admit("op-a")
        assert "op-a" not in m.delivered  # crash after durable ref entry
        m.recover("op-a")
        m.recover("op-a")
        assert len(m.entries) == 1 and m.violation() is None

    m = Model()
    m.declare("a", "git", "A1")
    m.declare("b", "git", "B1", ("a",))
    m.schedule("b", "op-b")
    m.gate("op-b", "passed")
    assert not m.admit("op-b")  # predecessor absent
    m.schedule("a", "op-a")
    m.gate("op-a", "passed")
    assert m.admit("op-a")
    assert not m.admit("op-b")  # its base is now stale
    m.schedule("b", "op-b-current")
    m.gate("op-b-current", "passed")
    assert m.admit("op-b-current") and m.violation() is None

    for event in ("cancel", "revise", "move_trunk", "change_policy", "hold"):
        m = Model()
        m.declare("a", "flowing-prefix", "A1")
        m.schedule("a", "op-a")
        m.gate("op-a", "passed")
        if event == "cancel":
            m.cancel("op-a")
        elif event == "revise":
            m.revise("a", "A2")
        else:
            getattr(m, event)()
        assert not m.admit("op-a") and m.contributions["a"].owed
        assert m.violation() is None


def mutant_scenarios() -> None:
    for defect, mutation in (
        ("gate", lambda m: None),
        ("base", lambda m: m.move_trunk()),
        ("policy", lambda m: m.change_policy()),
        ("revision", lambda m: m.revise("a", "A2")),
        ("hold", lambda m: setattr(m, "held", True)),
        ("dependencies", lambda m: None),
        ("cancel", lambda m: m.cancel("op-a")),
        ("gate_binding", lambda m: (
            setattr(m.attempts["op-a"], "source_cut", "A2"),
            setattr(m.attempts["op-a"], "candidate",
                    candidate("T0", "flowing-prefix", "A2")))),
    ):
        m = Model()
        m.declare("a", "flowing-prefix", "A1", ("b",) if defect == "dependencies" else ())
        if defect == "dependencies":
            m.declare("b", "git", "B1")
        m.schedule("a", "op-a")
        m.gate("op-a", "unrun" if defect == "gate" else "passed")
        mutation(m)
        assert m.admit("op-a", defect), defect
        assert m.violation() is not None, defect

    m = Model()
    m.declare("a", "git", "A1")
    m.schedule("a", "op-a")
    m.gate("op-a", "passed")
    assert m.admit("op-a")
    m.recover("op-a", "repeat_cas")
    assert m.violation() == "one operation advanced twice"

    # A second coordinator may present a fresh, passing candidate for a unit
    # already accounted by the first. The ref authority still refuses it.
    m = Model()
    m.declare("a", "flowing-prefix", "A1")
    m.schedule("a", "op-a")
    m.gate("op-a", "passed")
    assert m.admit("op-a")
    m.attempts["op-b"] = Attempt(
        "op-b", "a", "flowing-prefix", 0, "A1", m.trunk, m.policy,
        candidate(m.trunk, "flowing-prefix", "A1"))
    m.gate("op-b", "passed")
    assert not m.admit("op-b")
    assert m.admit("op-b", "owed")
    assert m.violation() == "one contribution admitted twice"


if __name__ == "__main__":
    guarded_scenarios()
    mutant_scenarios()
    print("source review: guarded scenarios pass; ten weakened guards are detected")
