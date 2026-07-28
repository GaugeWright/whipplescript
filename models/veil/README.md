# Veil / Lean Models

Veil is not on the v0 critical path.

Use it later when the kernel has stabilized and we know which invariants deserve
theorem-level assurance.

Candidate future targets:

```text
effect dependency safety
idempotent recovery
trace conformance
capability enforcement facts
```

Reason for deferral:

- the Veil docs describe a powerful Lean-embedded transition-system framework
  with model checking, SMT-style automation, and interactive proof support
- that power is useful after the model settles
- while the language and runtime contract are still moving, Maude and TLA+ give
  faster design feedback
