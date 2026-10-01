# Branch-to-trunk gate research models

## Forge source-review boundary

`source_review.py` is a bounded transition probe for the reviewed-contribution
contract in [source review](../../spec/source-review.md):

```sh
python3 models/research/source_review.py
```

It exercises Git and flowing-prefix sources through the same review and
admission state, stable review identity across immutable revisions, a source
tail arriving behind a selected prefix, dependent contributions, stale base
and policy, Hold, cancellation, and receipt delivery after a durable ref
entry. Ten deliberately weakened guards must produce an observable forbidden
history, including a repeated post-crash advance. It assumes the candidate
constructor really computes the proposed result, that its token names the
checked tree, and that one ref entry can atomically record admission. It does
not prove the Git/WhippleScript merge engine, authentication, durable storage,
independent failures, or cross-repository atomicity. Those are running-host
and restore obligations in the source-review tracker.

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

The same probe now checks twig-to-branch handoff of two distinct declared
units sharing one retained source cut. It transfers one unit while the other
remains owed, and refuses a target cut that omits the selected content even
when that cut's branch, parent and manifest metadata are internally valid.
A deliberately defective metadata-only check accounts the omitted unit and
prints the counterexample. The positive check still assumes that a trusted
planner derived each unit's exact constituent changes from immutable source
provenance. Production must supply that derivation and bind it to the
declaration; accepting an arbitrary caller-provided change list would move
the same defect one layer earlier.

`transitive_transport_lineage.py` checks the content and identity shape a
durable transport derivation must carry through two outputs:

```sh
python3 models/research/transitive_transport_lineage.py
```

It derives a mixed branch output from two source atoms, then transports that
output again while retaining both original units. A Hold on either unit still
blocks admission; accounting uses the roots rather than either output change
id. Its counterexamples lose a constituent from a derivation edge, settle the
output id in place of the units, or hide an unselected middle write behind
matching path endpoints. It also refuses changed substance under one atom id.
This is an explicit-scenario content abstraction: a trusted selection supplies
the source atoms, and no native or hosted store yet persists these derivation
edges with a ref move. It does not close FB-1 or FB-2.

`flowing_derived_cut_commit.py` checks the separate crash boundary for making
that derived output visible:

```sh
python3 models/research/flowing_derived_cut_commit.py
```

Two selected units share one mixed output. The immutable candidate bodies,
cut and complete source edge publish under an attempt pin before the ref move;
one ref-authority transaction verifies them and commits both unit receipts,
target head and continuing retention. Crashes before or after this transaction
leave a recoverable state. Seven split-write mutants
expose a head without a cut, lineage or receipts; a premature receipt; a partial
mixed receipt; unpublished bodies; or retention released before the ref entry
takes over. This is a bounded metadata and lifetime model, not a proof of SQL
transaction scope, real blob publication, content reconciliation, or hosted
implementation. The existing legacy transport advances the target head before
recording its cut, and flowing transport remains refused.

`revision_lineage.py` probes the other half of that boundary: every
acknowledged mutation of a selected unit's meaning must advance the ref-owned
source epoch before the topology head changes. It models eight mutation
classes, a later unrelated tail, and mixed transport from branch A through B
with A retained in the unit's source lineage:

```sh
python3 models/research/revision_lineage.py
```

Its explorer reaches 328 safe states through eight transitions. An old passed
candidate is refused after each mutation class; a tail leaves its exact prefix
eligible. A Hold on A blocks a later manual admission through B, while an undo
of already-accounted trunk content is a new trunk obligation. Weakening each
mutation fence, dropping A from mixed-output lineage, or ignoring Hold/epoch
lets a forbidden history land. This model treats the ref's epoch as the
atomic guard because the ref CAS cannot atomically read a topology-owned
head. It does not prove that the real store takes that guard on every path.
The production inventory must cover `commit_write_with_evidence`,
`advance_head`, `rebase_branch`, and `retarget_branch` in both branch stores,
plus the VCS transport, undo, import, repair, and future revision doors that
can reach them. Terminal v1 promotion of a flowing incarnation must refuse.

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

`private_pin_closure.py` probes the conservation boundary before and during
branch closure for two member twigs:

```sh
python3 models/research/private_pin_closure.py
```

Its explorer reaches 450 safe states through ten transitions. Positive traces
retain a private draft across session end, leave a conflicting handoff on the
twig, overlap twig and branch pins during a successful handoff, report a CAS
that wins before ref disable, and close with either an admitted or named
parked obligation. Nine weakened variants lose a private pin or declared
unit, transfer without a durable pin or exact handoff receipt, acknowledge
closure before ref disable or member resolution, drop a branch unit, omit a
parked obligation from the close receipt, or omit the joint abandonment
receipt. The gate and CAS are abstracted;
`flowing_recovery.py` covers their immediate recovery seam. This model does
not prove real cut retention, rehome mechanics, abandonment content, dependency
repair, external settlement, or native and hosted storage transactions.

`flowing_abandonment.py` isolates the explicit abandonment transaction before
that operation is composed into the full admission model:

```sh
python3 models/research/flowing_abandonment.py
```

It explores 126 safe states through twelve transitions. A prepared replacement
cut remains pinned across crash and retry; a competing source-tail write makes
the old preparation stale, while a fresh preparation preserves the tail. A
competing trunk CAS accounts the selected units first and prevents their
retrospective abandonment. Seven weakenings expose omitted dependent
resolution, a receipt without content removal, content removal without a
receipt, stale-head overwrite, lost prepared content, abandonment after trunk
admission, and duplicate receipts under one operation id. Authorization, real
cut derivation, physical lock order, and native/hosted atomic persistence remain
outside this bounded model.

`flowing_full_seam.py` synchronizes the private-pin model's selected-unit
accounting with the norm/ref model's trunk CAS, and synchronizes closure's
disable with the ref-owned Hold epoch:

```sh
python3 models/research/flowing_full_seam.py
```

It explores 109,723 safe branch states and 67,591 safe abstract mixed-transport
states through twelve transitions, plus 3,477 direct-twig states through nine.
Scenarios show a CAS winning before close disable, a second member's unit
parked at close, and disable blocking a passed candidate. A later member
handoff extends active source ancestry without invalidating the selected
immutable prefix, so that prefix can still enter trunk while the new tail
remains owed. A ref-fenced rewrite removes the selected prefix from active
ancestry and blocks its old candidate. An explicit abandonment of both
dependent units does the same; a weakening admits
the same unit under both trunk and abandonment receipts. The combined
candidate now binds three fixed source atoms to two
selected units, replays their path effects, checks the dependent's read basis
at the realized predecessor, and accounts both units even when the dependent
neutralizes the predecessor's write. An equivalent no-op keeps its source atom
and receives a checked unit receipt. Five witness weakenings admit a missing
atom, an output id substituted for roots, omitted candidate content, stale
dependent basis or false neutralized outcome; a separate no-op weakening drops
its unit receipt, and a CAS weakening records unit receipts without moving the
checked output content. Durable attempt pins now keep the source and candidate
available through a coordinator crash, ref CAS, receipt recovery and frontier
reconciliation; collection follows release. Dropping the candidate pin during
gate work or releasing it before recovery lets collection lose a still-needed
cut. The gate binds a digest of the selected units, source-atom witness,
candidate content and outcome, lineage and policy bases; the ref CAS compares
that exact digest. A post-check candidate swap is refused, while removing the
comparison admits the swapped witness. This models equality of a canonical
payload, not the authenticity of a production certificate or the actual
encoding and storage of its digest. Independent norm and ref outages now
interleave with the same lifecycle: a norm outage loses its captured validation,
a ref outage blocks CAS and close disable, and a restored authority can retry
while the selected units and pins remain owed. Fail-open weakenings admit a
candidate with the norm or ref authority unavailable. These are availability
states, not a physical cross-store crash or lock implementation. Four earlier
weakenings admit a CAS without unit accounting, omit the ref fence at disable,
trust a rewritten source prefix, or close before recovering an accepted receipt.
The mixed mode carries one selected unit's atom through B→C→D beside the same
norm/ref CAS, pin and accounting state. It checks every recorded origin's
current Hold and policy epoch there. A Hold blocks a passed candidate, and a
release needs a fresh certificate. Three weakenings lose B on transport,
check only D at CAS, or reuse the pre-Hold epoch; each reaches a forbidden
admission. The transport events do not derive real output cuts or persist
lineage, and the fixed atom is the only transported unit in this mode.
The source atoms and read relation are fixed model inputs: actual cut-to-atom
derivation, actual blob-closure and collector transactions, semantic edge
discovery, failed/cancelled attempt pin release, source revisions through all
mutation doors, certificate authenticity at the ref authority, physical
lock scheduling and independently failing store transactions remain open.
The model does not prove the native or hosted transactions implement these
synchronized transitions.

`flowing_lineage_policy.py` isolates a missing part of that composition: one
unit moves from branch B through mixed outputs on C and D, retaining its
original source atom and all three policy ancestors. The gate captures their
epochs; the ref CAS checks every ancestor's current Hold and epoch, the exact
source revision, and the source atom rather than a mixed output id:

```sh
python3 models/research/flowing_lineage_policy.py
```

The bounded search finds 179 safe states through ten transitions. Positive
traces admit the transported unit, block an origin Hold, require a fresh gate
after release or revision, and refuse during policy or ref outage. Six mutants
admit lost origin lineage, a check of only the current branch, a pre-Hold
certificate reused after release, an output id in place of the source atom,
an old candidate after revision, or an outage treated as a clear policy answer.
The derivation graph and cut contents are fixed abstractions here; the model
does not prove transport persistence, every head mutation, certificate
authenticity, independent store locks or native/hosted implementation.

`flowing_attempt_pins.py` probes the failed/cancelled attempt lifetime with
two coordinators selecting the same still-owed unit:

```sh
python3 models/research/flowing_attempt_pins.py
```

It explores 1,468 safe states through nine transitions. One attempt may fail,
crash, and release its own durable pins while the other admits; a cancelled
attempt may release its candidate, let a collector reclaim it, and leave the
source available for a fresh attempt. A ref outage cannot acknowledge
cancellation. At CAS, the unit holder's source pin transfers to ref-owned
source and candidate pins atomically; those ref pins remain through receipt
recovery and frontier reconciliation. Two weakenings collect an owed source
after its holder pin is dropped, or collect a live candidate when another
attempt releases pins it does not own. Cuts are abstract booleans and the
model does not establish real blob closure, cross-store atomicity, exact
cancellation identity, production collector behavior, or implementation
conformance.

`contribution_lifecycle.py` probes one branch with two declared contributions,
where `u1` depends on `u0`. It separates the durable holder of each unit from
a disposable gate attempt. Ready declaration, twig-to-branch sharing, bounded
attempt selection, Hold, revision, dependent rebase, failed/unrun gate,
ref-fenced commit, crash before accounting, close, parking, and transfer of an
external settlement obligation are separate transitions.

```sh
python3 models/research/contribution_lifecycle.py
```

The correct variant explores 11,105 states through twelve steps without violating
its conservation, dependency, fence, or closure checks. Explicit scenarios
exercise cancellation followed by resubmission, revision of a passed and a
failed attempt, dependent rebase, recovery after CAS, parking of an in-flight
twig and an empty member twig, and transfer of an unsettled external act.
Seven defective variants each
reach a forbidden history: cancellation drops the selected unit, a dependent
lands without its predecessor, an old candidate lands after revision, a
dependent lands on a stale basis, closure acknowledges before the ref is
disabled, closure drops the continuing owner of an external act, or closure
leaves a member twig active.

This is a state-shape probe, not a proof of the full lifecycle. A repair is
collapsed to a new version of `u0`; the model has no actual content merge,
cut-rewrite lineage, semantic dependency discovery, equivalence/no-op
accounting receipt, independently failing topology/ref stores, or release
gate. `parked` stands for a durable named holder without modeling its pin or
receipt. Member parking is separate from contribution parking; even an empty
member must park before close is acknowledged. The probe assumes that revision
and cancellation fence the ref in one
atomic transition and that the trunk CAS durably records its source units.
The real host contracts and merge engine must supply those facts or refuse
the operation. The [research note](../../spec/branch-trunk-gate-research-note.md)
§11 states the intended lifecycle and its remaining design obligations.

`flowing_recovery.py` composes the ref-owned source fence, norm-ledger
exclusion, exact trunk basis, source-unit accounting, and lagging frontier
projection for a branch or direct twig:

```sh
python3 models/research/flowing_recovery.py
```

Its bounded explorer finds 8,040 safe states through nine transitions. Explicit
traces cover a metadata-only admission that accounts two selected units, a
coordinator crash after CAS, replacement-coordinator selection before frontier
recovery, cancellation before and after CAS, resubmission after cancellation,
former-owner cancellation after takeover, Hold, source rewrite, grant
revocation, and independent ref, norm, and topology outages. Eight defective
variants admit a mixed-output alias,
ungated no-op, manual Hold bypass, CAS after releasing norm exclusion,
duplicate admission by a replacement coordinator that trusts the lagging
frontier, operation-id reuse, stale reference coverage, or CAS after a
queue-only cancellation acknowledgement. This probes the CAS-to-frontier seam under
the actual norm/ref lock order. It still abstracts private draft retention,
source lineage derivation, revision across all real mutation doors, branch
closure with member twigs and parked work, the complete gate plan, and
production lock scheduling. A cancellation tombstone is an abstract ref fact;
the model does not prove its native or hosted SQL transaction. Those remain open in FB-1 and its implementation
items; this model alone does not qualify host activation.

`flowing_lock_order.py` probes the physical acquisition order that the recovery
model assumes:

```sh
python3 models/research/flowing_lock_order.py
```

It finds 67 safe states through eight transitions when both operations take
norm exclusion before the ref lock. A reversed acquisition reaches a circular
wait; retaining norm exclusion after a ref outage strands revocation. Positive
traces commit an admission, release on outage and let revocation proceed, and
let a second operation finish before admission. This is a lock schedule model,
not a measurement of the actual store APIs; FB-3 must enforce the same order
at every production path that needs both authorities.

`flowing_home_lock_order.py` updates the final schedule for the accepted Home
journal and epoch seal, ahead of the norm ledger and ref authority:

```sh
python3 models/research/flowing_home_lock_order.py
```

It reaches 5,922 safe states through ten transitions. Positive traces let a
later unrelated Home entry proceed, let a competing writer finish under the
same Home → norm → ref order, and release exclusion after independent Home,
norm or ref outages. Eight weakenings expose reversed lock acquisition,
stale affected-premise recapture, early Home or norm release, Hold bypass,
fail-open Home outage, stranded exclusion and a trunk CAS without its selected
unit receipt. The selected prefix and Home seal are abstract inputs; this
schedule does not establish actual lock ownership, full source-content
derivation, path coverage or cross-store crash recovery in a host.

`home_cut_authorities.py` extends that question to the native runtime admission
roster, which is in a different SQLite file from the norm ledger and ref:

```sh
python3 models/research/home_cut_authorities.py
```

It explores 2,436 safe states through ten transitions for one linked operation,
one gate, two independent writes and a second operation needing both stores.
The modeled protocol records a durable pending marker with the linked
operation's first component, keeps it across a crash, and clears it only after
the second component lands. The gate prepares exact norm/runtime revisions,
then takes norm, runtime and ref exclusion in that order, rechecks both
revisions and the marker, and holds all three through CAS. Positive traces
include completion after a crash, a stale gate interleaved with recovery, and
release after a ref outage. Six weakened variants expose false completeness
after a partial operation, stale preparation, early lock release and a
norm/runtime circular wait. The pending marker is one candidate recovery
mechanism, not a chosen production schema. The probe assumes its first write
is atomic, each revision is monotone, and every linked accepting operation
participates. It does not establish Home identity, enumerate production
accepting paths, implement the locks, or prove a hosted single-writer cut.

`twig_handoff.py` isolates the holder transfer that the larger lifecycle
probe treats as one step:

```sh
python3 models/research/twig_handoff.py
```

Its bounded explorer finds 720 safe states through eight steps. Positive
traces keep an unselected twig tail through a content-backed target cut,
atomic holder receipt, crash, receipt delivery and source-pin release. An
omitted target effect, second coordinator using the same unit, and stale
target base refuse. Six mutants expose a metadata-only transfer, early pin
release, target head movement before receipt, duplicate transfer, stale-base
commit and dropped tail. Source content is a Boolean in this probe; actual
manifest comparison, selected-unit lineage, content retention, SQL rollback,
and independent authority failures still need native and hosted evidence.

## Dependency update, owner routing, and external audit

`dependency_update.py` adds a bounded probe for one external dependency and
three repository owners. A depends directly on it, B depends transitively
through A, and a graph edit discovers C. The update request keeps one proposed
immutable source revision; replacing that revision changes its exact basis.
Owners receive versioned routes and answer with a migration or compatibility
claim. A separate audit approves or rejects the external source, and a gate
passes the exact candidate. Only an admission receipt can advance the logical
pin and account for the request.

```sh
python3 models/research/dependency_update.py
```

The safe variant explores 82,614 distinct states through eight transitions.
Explicit scenarios cover graph expansion and rerouting, audit rejection,
owner refusal, stale source approval, and recovery after the pin-moving receipt.
Six bounded mutants and one longer explicit mutant expose missing owner
resolution, stale owner basis, absent or stale audit, absent or stale gate,
and a cut that moves the pin without resolving every affected repository.
The model assumes the impact graph is correct, owner and auditor identities
are authenticated, audit verdicts are trustworthy, and the logical cut plus
receipt is atomic. It does not prove supply-chain inspection quality, migration
correctness, discovery of missing semantic edges, independent Git-main
settlement, historical bark-chip resolution, or delivery of a request through
real queues. The
[research note](../../spec/branch-trunk-gate-research-note.md) §12 describes
those design obligations.

## Edge discovery and coverage

`edge_discovery.py` isolates the dependency-update probe's graph assumption.
It gives a complete repository roster, a current and proposed graph, known
build/semantic edges, and a per-owner/edge-kind signal for incomplete
coverage. An incomplete class widens to an enforced possible-provider
envelope. Routing uses reverse transitive reachability over both cuts and
deduplicates cycles.

```sh
python3 models/research/edge_discovery.py
```

All 59,049 pairs of bounded graph states route every actually affected
repository under those assumptions; 765 routes deliberately include an
unaffected owner because coverage is incomplete. Negative scenarios miss an
owner when routing uses known edges only, the current graph only, direct
consumers only, an incomplete roster, a failed query treated as an empty
answer, or a graph captured before its epoch changed. A cycle scenario
terminates with the expected closure.

The model's finite edge universe stands for a trusted, enforced possible
provider set. Its coverage signal is an input independent of the hidden edges;
the explorer verifies that every actual edge lies within the envelope. This
does **not** show that a real extractor can certify completeness, that a
dynamic reference obeys its declared ceiling, or that the roster includes
every restricted repository. A false completeness claim or missing repository
is precisely the failure the protocol must prevent. The
[research note](../../spec/branch-trunk-gate-research-note.md) §12.3 maps the
candidate edge authorities and the unresolved evidence needed before a DR.
Section 12.4 records a focused read of the current VMR, Buck graph, and
WhippleScript package/construct contracts, including a real all-cell query
failure. The probe now makes that failure a blocked capture rather than an
empty route.

## Required reference scopes

`reference_scope_registry.py` probes the other half of RC-1: deriving the
required class/scope set from one admitted, versioned declaration registry
and checking every member of the authoritative consumer population. It
separates live dependencies from provenance, historical pins, authority and
content references. A complete witness binds registry, roster, source cut
and graph revisions, the examined set and an edge digest.

```sh
python3 models/research/reference_scope_registry.py
```

It checks all subsets of a two-consumer population and gives negative
fixtures for an unclassified field, omitted consumer, opaque reference,
unenforced accepting boundary, stale basis and provenance treated as live.
The model assumes production parsers and accepting operations cannot bypass
the registry; that is the central implementation obligation, not a property
this Python probe establishes. The current admitted fields, constructs and
provider bindings still need a real exact-cut inventory before RC-1 closes.

## Checked-program import coverage

`program_import_coverage.py` probes RC-2's narrow local-package claim:

```sh
python3 models/research/program_import_coverage.py
```

An admission captures every non-`std.` `use`, resolves each against the exact
local lock, and binds its edge set to the program source, lock and compiler
revisions. The probe checks every examined subset of two imports and shows
that an unresolved or omitted import refuses admission. A second admitted
program without a witness, a changed package source under the same name, or
an unclosed Home population makes broader coverage unknown. It also admits
the same version twice, first with a witness and then through an unwitnessed
path: a version-keyed roster sees the first witness and hides the second
operation. The model therefore assumes an authoritative **operation** roster
and atomic witness capture for each acceptance. Neither property follows from
an on-demand `whip compile` report or the current version and witness tables.

`program_construct_coverage.py` probes the companion RC-3 construct class:

```sh
python3 models/research/program_construct_coverage.py
```

Each IR construct occurrence resolves to exactly one registration in the
checked registry, owned by an imported library. The candidate witness binds
the selected registration identity/version and the bytes that supplied it to
the program source, lock and compiler artifact. It refuses an omitted,
unresolved, unimported or ambiguous use. A later unwitnessed accepting call
remains unknown even when it reuses the same program-version row. A changed
package source under an unchanged v0 lock, changed compiler, forged edge
subset, and first-match selection from two registrations all invalidate the
claim. The model assumes the compiler's IR use list is complete, the registry
was built from the same immutable package snapshot as the admission, and a
Home operation roster is authoritative. Native admission now retains the
rule-effect slice, but the model does not establish those assumptions or
completeness of other construct forms.

`declaration_construct_inventory.py` probes the next source-to-IR gap:

```sh
python3 models/research/declaration_construct_inventory.py
```

The rule-effect IR accessor does not walk declarations. Seven registered std
declaration rows (`lease`, `ledger`, `counter`, `file store`, `signal`, `source`,
`tracker`) lower into separate IR lists. A capture reconstructed only from
those lists can report examined-empty even when source declarations were lost
during lowering. The probe compares compiler-owned occurrence
handles from the selected, pattern-expanded AST with tagged lowered
declarations before resolving each against one imported registration.
Omission, duplicate output, extra output, changed lowering shape and ambiguous
registration refuse. Forging the same
subset on both sides still passes, exposing the need for compiler provenance.
Two applications of one pattern need distinct occurrence handles. The compiler
now emits a scoped declaration-construct inventory from its selected,
pattern-expanded AST and checks each named lowering step against its IR
payload. Older IR lacks that inventory and remains unknown. Production still
needs registration resolution against the exact package snapshot, explicit
authorization of source variants, a construct admission witness and a closed
Home operation roster. The current rule-effect witness remains separate.

`home_operation_roster.py` probes how one Home could close that operation
population when its runtime evidence lives in multiple SQLite stores:

```sh
python3 models/research/home_operation_roster.py
```

The candidate protocol durably registers a pending Home pointer before a
runtime shard accepts a program, records the immutable shard operation and
witness, completes the Home pointer, then acknowledges the acceptance. A
Home-issued cut enumerates completed pointers and treats pending ones as
unknown. Final admission rechecks the journal revision under Home write
exclusion held through ref CAS. Its 141 safe states through ten transitions
include crashes before and after the shard write, repair, stale capture and
ref outage. Six weakened variants expose a missed newly created shard,
missing or ignored pending state, early acknowledgment, stale final comparison
and early lock release. This is one recovery candidate, not a selected Home
schema. It assumes all accepting paths use the Home door, completed pointers
resolve to immutable evidence, and the issuer has a host-bound Home identity.
It does not establish current source/lock/compiler revalidation, norm-ledger
composition, product migration, or the authority of existing Home commands.
The model has no liveness claim: its gate waits for a Home-wide absence of
pending operations and requires an unchanged global journal revision. Under
continuous admissions either condition can starve the gate. A usable design
needs a sealed cut and an explicit rule for admissions after that cut, including
their dependency and historical-pin obligations.

`home_epoch_cut.py` probes one way to remove that global quiescence condition:

```sh
python3 models/research/home_epoch_cut.py
```

The Home atomically seals the set of already accepted operations in an epoch.
Unfinished registrations retain their original epoch and are recognized as
next-epoch work at completion; a shard write from before the seal needs
revalidation before Home completion. New operations
also enter the next epoch, while a run on an older exact version records a
temporal pin obligation. The gate checks the immutable candidate cut and ref
base, so later journal writes do not by themselves invalidate its work. The
probe reaches 1,023 safe states through ten transitions and exposes six
shortcuts: dropping a pending operation, allowing one to enter the sealed cut,
skipping its recheck, omitting an already accepted operation, losing an old
pin, and trusting a changed ref base. It models one seal and two operations.
It assumes the Home alone controls when shard evidence becomes usable, that
the epoch marker and accepted-set snapshot seal atomically, and that completed
evidence cannot mutate. It does not prove exact dependency routing, what
revalidation checks, migration/retention for old pins, policy revocation,
norm-ledger composition, recovery from independent storage failures, or
implementation cost. The founder selected the Home journal and epoch seal in
[DR-0150](../../spec/decision-records/0150-home-operation-journal-and-sealed-epoch-cuts.md);
the model does not discharge those remaining product and gate obligations.

`project_home_coverage.py` checks the later project Home boundary with two
projects running on one host:

```sh
python3 models/research/project_home_coverage.py
```

It reaches 228 safe states through eleven transitions. An operation can be
registered, completed and used only in its project's Home; each epoch and
seal advances independently, and the gate for project 0 consumes only that
Home's cut even after project 1 changes. Five weakenings admit a wrong journal,
a host-wide union roster, cross-project use, a borrowed seal or a shared
epoch. This is an identity-isolation probe, not a coverage proof: it abstracts
target-store incarnations and recovery, accepting-path inventory, gate
content, key separation and actual per-project product storage.

`home_store_cutover.py` probes a prerequisite for making that Home roster
authoritative across older and newly created runtime stores:

```sh
python3 models/research/home_store_cutover.py
```

An old writer is excluded before the Home inventories existing stores as
`legacy_unknown`. A new store or restored incarnation first gets a Home
catalogue entry and pending operation; exact target evidence and Home
completion precede use. Historical unknown use may continue in the model but
cannot support a complete coverage claim. Its 325 safe states through eleven
transitions and five weakened paths expose a late old writer, target write
before registration, restore without a new incarnation fence, pending use,
and a false complete claim. It treats the writer exclusion, exact target
evidence, re-attestation, and item-to-operation use pin as atomic premises.
GaugeDesk's in-process Workbench mutex and a filesystem directory scan do not
establish those premises across processes or restores. The probe supplies a
necessary cutover shape, not a product migration or Home-wide proof.

`embedded_seed_coverage.py` isolates the embedded-standard-package seed from
the program import operation:

```sh
python3 models/research/embedded_seed_coverage.py
```

It explores 24 safe states with one binary upgrade and one retained program.
Five weakened paths expose a seed write without a Home pointer, pending use,
binary-only coverage over mutable provider rows, stale retained use, and an
unfenced provider mutation. This assumes exact effective-row readback and a
use door; it does not prove either or choose between a journaled seed
acceptance and exclusively owned artifact materialization. The [research
note](../../spec/branch-trunk-gate-research-note.md#1210-embedded-package-bytes-are-not-the-live-provider-registry-2026-09-30-probe)
records the two implementation shapes and their remaining obligations.
