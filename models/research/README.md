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

The next model should compare a policy epoch stored in the trunk ref authority
with a durable cross-authority admission reservation, including crash and
former-owner fencing. It should replace linear prefix transport with durable
change identity under rewriting and add an external target only after the
single-ref invariants remain sound.
