# Branch-to-trunk gate research models

`branch_trunk_gate.py` is a dependency-free bounded state explorer for the
control plane sketched in [the research note](../../spec/branch-trunk-gate-research-note.md).
Run it with:

```sh
python3 models/research/branch_trunk_gate.py
```

It explores all distinct states reachable in at most nine transitions from an
empty trunk, two flowing branches, and two one-time twig contributions per
branch. It also runs explicit adversarial scenarios and five defective
protocols. Each defect must reach a safety violation. This is an executable
design probe, not an exhaustive proof or a product conformance test.

The model gives every submission a newly minted operation id and freezes its
branch prefix, delta, expected trunk, policy epoch, and candidate identity.
The gate verdict attaches to that immutable submission. A successful trunk
CAS writes a durable admission entry; finishing the branch frontier is a
separate step that can be interrupted and recovered. Hold and release bump the
branch policy epoch. An external trunk advance represents another authority's
already gated result. The model treats the policy check and trunk CAS as one
atomic admission step; making that true in the actual split authorities is
still a design problem.

Its abstractions are intentionally narrow:

- Change identities are unique opaque tokens in a linear branch sequence.
  There is no content merge, rebase, selective undo, independent equivalent
  change, or conflict calculation. A sequence prefix stands in for an
  integrated frontier; this cannot validate the real frontier representation.
- All required checks collapse to one `passed`, `failed`, or `unrun` result.
  Rule revision, target scope, peer pins, cache keys, check freshness, and
  host trust are not represented.
- The external trunk step is assumed already authorized. External target
  effects, sparse materialization, and partial/unknown settlement are absent.
- Steps are atomic and the state is durable except for receipt/frontier
  completion. There are no independent policy and ref stores, lease owners,
  fencing tokens, message loss, or fairness assumptions.

The admission-fence comparison below takes up the first missing authority
question. Later models still need durable change identity under rewriting and
an external target after the single-ref invariants remain sound.

## Admission-fence comparison

`admission_fence.py` compares two ways to implement the atomic step assumed by
the first probe:

```sh
python3 models/research/admission_fence.py
```

The first keeps the admission policy epoch, Hold state, owner fence, and trunk
ref in one authority. Hold, takeover, and CAS serialize there. The second
keeps Hold and the reservation in topology, with a token registry and monotone
revocation fence in the ref authority. A CAS accepts only the active token.
Topology may acknowledge Hold or a new owner only after the old token is
consumed or durably revoked at the ref authority. Revocation of an as-yet
ungranted token still writes a tombstone, so a delayed grant cannot revive it.

The explorer bounds one candidate, one Hold, and one owner takeover. It checks
both safe variants through eight steps, runs crash and ordering scenarios, and
requires five defective variants to find counterexamples. It does not model
concurrent databases failing independently, lost replies, a lease clock,
membership/closure, candidate construction, or policy grants beyond Hold. Its
`recover_receipt` reads a durable admission fact; the actual evidence lookup
and indeterminate outcome still need design. The split protocol's token
registry is a *new required ref-authority capability*, not something the
current DR-0078 boundary reservation already provides.
