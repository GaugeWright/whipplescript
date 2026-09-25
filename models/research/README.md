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
question. The subsequent probes cover change identity under rewriting and
two external targets, within the limits stated for each model.

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

## Lifecycle and existing gate composition

`lifecycle_seam.py` models branch closure across topology and a ref-owned
admission policy. A close request is pending until the ref authority disables
admission and increments its epoch; only then may topology acknowledge closure.
A CAS that wins before disable remains an accepted admission and must be
reported during close. A new branch gets a new incarnation identity. The
model includes independent topology/ref outages and counterexamples for
acknowledging close before disable and for reusing an archived identity.

`composed_admission.py` composes the preferred branch fence with the **existing**
norm-plane §5 gate. The native gate takes the norm ledger's write exclusion,
re-captures its premises, then performs the ref CAS while still holding that
exclusion. The ref CAS checks the branch Hold epoch, current owner fence, and
base. A takeover changes the coordinator, not the original submission's
principal or intent; the original principal's grant is checked again. The
model includes negative fixtures for an unlocked precheck, early ledger
release, stale Hold, former-owner CAS, and principal substitution. It assumes
the replacement coordinator has an authenticated grant to take custody; it
checks the original submission's grant at admission, not the grant to take
over. That separate authorization and its revocation still need a fixture.

```sh
python3 models/research/lifecycle_seam.py
python3 models/research/composed_admission.py
```

Both models hold one candidate and abstract the durable ref admission entry as
an atomic CAS record. They do not prove lock scheduling, database failure
semantics, or a ref history implementation. Native gate code currently holds
the ledger exclusion across branch-store CAS, but its gated-head API does not
atomically record a submission id and certificate handle with that CAS; the
future flowing-admission operation needs such a ref-authority record for
post-CAS recovery.

## Transport frontier under rewriting

`frontier_transport.py` probes a content-only admission receipt. An immutable
source cut selects stable source change identities; the receipt records those
identities, exact target before/after, and per-path applied, equivalent, or
neutralized outcomes. A mixed transport may mint a new output change id, and a
rebase may rewrite the source cut, but neither substitutes for the source ids
the receipt accounted for. Retrying one operation reads its receipt. Later
admission selects source identities not already accounted for.

```sh
python3 models/research/frontier_transport.py
```

Its scenarios cover a mixed transport, rewrite after admission, a later tail,
undo before and after admission, independent equivalent content, conflict, and
divergent content under the same identity. Negative fixtures show that using
only the output change id loses constituents, while using raw cut-ID equality
alone selects them again after rebase. This is a probe of receipt meaning,
not proof that the current `change_id` and change-unit index can reconstruct
every source unit. In particular, the probe assumes canonical source change
identities and a linear per-path effect history; actual merge, selective undo,
partial transport, and cross-target receipts need a broader model.

## Collaboration versus native target settlement

`target_settlement.py` adds two independent external targets. It models both
a later settlement request against an already accepted collaboration cut and
a combined admit-and-settle request, which preflights every target **before**
the collaboration advance. It restates GaugeDesk DR-0151's existing boundary:
all requested targets preflight before effects; each effect needs an
authenticated success receipt or authoritative recovery query; unknown is not
success and is never blindly retried. Partial application is an honest report,
not a rollback of the collaboration cut.

```sh
python3 models/research/target_settlement.py
```

The bounded safe variants explore 41 and 42 states through nine steps. Five
defective variants call local admission settlement, call unknown success,
retry an unknown external effect, start a target before all-target preflight,
or advance collaboration before preflight in the combined case; each finds a
counterexample. The model abstracts stable operation identity, native basis,
capability, digest, target lane, and receipt authentication as trusted inputs.
It checks status and receipt ordering, not those inputs' enforcement. It adds
no new target-settlement policy; a flowing branch changes the frequency of
local candidate admission, not the authority of an external Git repo or folder.

## Contribution and branch lifecycle

`contribution_lifecycle.py` probes one branch with two declared contributions,
where `u1` depends on `u0`. It separates the durable holder of each unit from
a disposable gate attempt. Ready declaration, twig-to-branch sharing, bounded
attempt selection, Hold, revision, dependent rebase, failed/unrun gate,
ref-fenced commit, crash before accounting, close, parking, and transfer of an
external settlement obligation are separate transitions.

```sh
python3 models/research/contribution_lifecycle.py
```

The correct variant explores 8,752 states through twelve steps without violating
its conservation, dependency, fence, or closure checks. Explicit scenarios
exercise cancellation followed by resubmission, revision of a passed and a
failed attempt, dependent rebase, recovery after CAS, parking of an in-flight
twig, and transfer of an unsettled external act. Six defective variants each
reach a forbidden history: cancellation drops the selected unit, a dependent
lands without its predecessor, an old candidate lands after revision, a
dependent lands on a stale basis, closure acknowledges before the ref is
disabled, or closure drops the continuing owner of an external act.

This is a state-shape probe, not a proof of the full lifecycle. A repair is
collapsed to a new version of `u0`; the model has no actual content merge,
cut-rewrite lineage, semantic dependency discovery, equivalence/no-op
accounting receipt, independently failing topology/ref stores, or release
gate. `parked` stands for a durable named holder without modeling its pin or
receipt. It assumes that revision and cancellation fence the ref in one
atomic transition and that the trunk CAS durably records its source units.
The real host contracts and merge engine must supply those facts or refuse
the operation. The [research note](../../spec/branch-trunk-gate-research-note.md)
§11 states the intended lifecycle and its remaining design obligations.
