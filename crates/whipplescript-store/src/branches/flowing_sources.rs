//! Durable source facts for flowing admission (DR-0130, FB-2).
//!
//! A private cut is retained without an expiry. A declaration reserves a new
//! source-unit identity against that exact cut, original principal, intent,
//! read/dependency basis and scope. A later one-time binding records the
//! content-derived source atoms and makes duplicate atom ownership impossible.
//! An unbound declaration remains owed on its twig. A content-verified handoff
//! moves one bound unit to its parent branch with the target ref and receipt in
//! one transaction. A mixed cut can prepublish a content derivation while
//! every unit remains owed. A complete same-twig prefix can then prove source
//! order and move the head with every unit receipt in one transaction. Mixed
//! cross-source dependencies and branch-to-trunk admission remain open.
//! The calling host authenticates and authorizes the principal on pin,
//! declaration and release; the store binds those claims and prevents their
//! later reinterpretation.

#[cfg(feature = "native")]
mod native;

pub const SCHEMA: [&str; 11] = [
    "CREATE TABLE IF NOT EXISTS flowing_private_pins (
        pin_id TEXT PRIMARY KEY,
        twig_branch_id TEXT NOT NULL,
        cut_id TEXT NOT NULL,
        manifest_hash TEXT NOT NULL,
        principal TEXT NOT NULL,
        retained_at TEXT NOT NULL,
        released_at TEXT,
        released_by TEXT,
        release_reason TEXT
    )",
    "CREATE INDEX IF NOT EXISTS flowing_private_pins_cut_idx
        ON flowing_private_pins(cut_id) WHERE released_at IS NULL",
    "CREATE TABLE IF NOT EXISTS flowing_contributions (
        unit_id TEXT PRIMARY KEY,
        pin_id TEXT NOT NULL,
        source_branch_id TEXT NOT NULL,
        source_cut_id TEXT NOT NULL,
        source_manifest_hash TEXT NOT NULL,
        principal TEXT NOT NULL,
        intent TEXT NOT NULL,
        read_basis_digest TEXT NOT NULL,
        dependency_basis_digest TEXT NOT NULL,
        scope_digest TEXT NOT NULL,
        declared_at TEXT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS flowing_contributions_pin_idx
        ON flowing_contributions(pin_id)",
    "CREATE TABLE IF NOT EXISTS flowing_contribution_basis (
        unit_id TEXT PRIMARY KEY,
        basis_digest TEXT NOT NULL,
        atoms_json TEXT NOT NULL,
        bound_at TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS flowing_source_atom_owners (
        source_branch_id TEXT NOT NULL,
        source_cut_id TEXT NOT NULL,
        path TEXT NOT NULL,
        unit_id TEXT NOT NULL,
        PRIMARY KEY (source_branch_id, source_cut_id, path)
    )",
    "CREATE TABLE IF NOT EXISTS flowing_handoffs (
        op_id TEXT PRIMARY KEY,
        unit_id TEXT NOT NULL UNIQUE,
        source_branch_id TEXT NOT NULL,
        source_cut_id TEXT NOT NULL,
        source_manifest_hash TEXT NOT NULL,
        source_basis_digest TEXT NOT NULL,
        target_branch_id TEXT NOT NULL,
        target_before_cut_id TEXT,
        target_after_cut_id TEXT NOT NULL,
        target_after_manifest_hash TEXT NOT NULL,
        effects_json TEXT NOT NULL,
        original_principal TEXT NOT NULL,
        actor TEXT NOT NULL,
        recorded_at TEXT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS flowing_handoffs_target_idx
        ON flowing_handoffs(target_branch_id, recorded_at)",
    "CREATE TABLE IF NOT EXISTS flowing_derived_cuts (
        derivation_id TEXT PRIMARY KEY,
        target_after_cut_id TEXT NOT NULL UNIQUE,
        target_branch_id TEXT NOT NULL,
        target_before_cut_id TEXT,
        target_after_manifest_hash TEXT NOT NULL,
        witness_json TEXT NOT NULL,
        witness_digest TEXT NOT NULL,
        actor TEXT NOT NULL,
        recorded_at TEXT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS flowing_derived_cuts_branch_idx
        ON flowing_derived_cuts(target_branch_id, target_after_cut_id)",
    "CREATE TABLE IF NOT EXISTS flowing_handoff_batches (
        derivation_id TEXT PRIMARY KEY,
        target_after_cut_id TEXT NOT NULL UNIQUE,
        receipt_json TEXT NOT NULL,
        receipt_digest TEXT NOT NULL
    )",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinPrivateCut<'a> {
    pub pin_id: &'a str,
    pub twig_branch_id: &'a str,
    pub cut_id: &'a str,
    pub manifest_hash: &'a str,
    pub principal: &'a str,
    pub retained_at: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateCutPin {
    pub pin_id: String,
    pub twig_branch_id: String,
    pub cut_id: String,
    pub manifest_hash: String,
    pub principal: String,
    pub retained_at: String,
    pub released_at: Option<String>,
    pub released_by: Option<String>,
    pub release_reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PinPrivateCutOutcome {
    Pinned,
    Existing,
    Released,
    IdentityMismatch,
    BranchMissing,
    BranchNotActive,
    CutMissing,
    CutMismatch,
    Invalid { field: &'static str },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeclareContribution<'a> {
    pub unit_id: &'a str,
    pub pin_id: &'a str,
    pub principal: &'a str,
    pub intent: &'a str,
    pub read_basis_digest: &'a str,
    pub dependency_basis_digest: &'a str,
    pub scope_digest: &'a str,
    pub declared_at: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContributionDeclaration {
    pub unit_id: String,
    pub pin_id: String,
    pub source_branch_id: String,
    pub source_cut_id: String,
    pub source_manifest_hash: String,
    pub principal: String,
    pub intent: String,
    pub read_basis_digest: String,
    pub dependency_basis_digest: String,
    pub scope_digest: String,
    pub declared_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeclareContributionOutcome {
    Declared,
    Existing,
    IdentityMismatch,
    PinMissing,
    PinReleased,
    PrincipalMismatch,
    Invalid { field: &'static str },
}

/// An unbound declaration is still owed on its twig. Only WorkspaceVcs can
/// construct this request while retaining the selected content through the
/// branch transaction. A handoff or gate must require the bound basis, never
/// infer it from the declaration's cut id or scope digest.
#[derive(Clone, Copy, Debug)]
pub struct BindContributionBasis<'a> {
    unit_id: &'a str,
    selection: &'a crate::vcs::FlowingSelection,
    bound_at: &'a str,
}

impl<'a> BindContributionBasis<'a> {
    pub(crate) fn new(
        unit_id: &'a str,
        selection: &'a crate::vcs::FlowingSelection,
        bound_at: &'a str,
    ) -> Self {
        Self {
            unit_id,
            selection,
            bound_at,
        }
    }

    pub fn unit_id(self) -> &'a str {
        self.unit_id
    }
    pub fn selection(self) -> &'a crate::vcs::FlowingSelection {
        self.selection
    }
    pub fn bound_at(self) -> &'a str {
        self.bound_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContributionBasis {
    pub unit_id: String,
    pub basis_digest: String,
    pub atoms: Vec<crate::vcs::FlowingSourceAtom>,
    pub bound_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BindContributionBasisOutcome {
    Bound,
    Existing,
    IdentityMismatch,
    UnitMissing,
    PinMissing,
    PinReleased,
    SelectionMismatch,
    CutMissing,
    CutMismatch,
    AtomOwned {
        unit_id: String,
        cut_id: String,
        path: String,
    },
    Invalid {
        field: &'static str,
    },
}

/// The content-derived witness is constructed only by WorkspaceVcs. A store
/// caller cannot submit asserted target bytes in place of an actual read.
#[derive(Clone, Copy, Debug)]
pub struct HandoffContribution<'a> {
    op_id: &'a str,
    witness: &'a crate::vcs::FlowingTargetEffects,
    actor: &'a str,
    recorded_at: &'a str,
}

impl<'a> HandoffContribution<'a> {
    pub(crate) fn new(
        op_id: &'a str,
        witness: &'a crate::vcs::FlowingTargetEffects,
        actor: &'a str,
        recorded_at: &'a str,
    ) -> Self {
        Self {
            op_id,
            witness,
            actor,
            recorded_at,
        }
    }

    pub fn op_id(self) -> &'a str {
        self.op_id
    }
    pub fn witness(self) -> &'a crate::vcs::FlowingTargetEffects {
        self.witness
    }
    pub fn actor(self) -> &'a str {
        self.actor
    }
    pub fn recorded_at(self) -> &'a str {
        self.recorded_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HandoffReceipt {
    pub op_id: String,
    pub unit_id: String,
    pub source_branch_id: String,
    pub source_cut_id: String,
    pub source_manifest_hash: String,
    pub source_basis_digest: String,
    pub target_branch_id: String,
    pub target_before_cut_id: Option<String>,
    pub target_after_cut_id: String,
    pub target_after_manifest_hash: String,
    pub effects: Vec<crate::vcs::FlowingTargetEffect>,
    pub original_principal: String,
    pub actor: String,
    pub recorded_at: String,
}

/// One indivisible head move and complete per-unit receipt roster. The stored
/// batch receipt is checked against every individual row on read, so an
/// interrupted or corrupted partial transfer cannot look complete.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FlowingBatchHandoffReceipt {
    pub derivation_id: String,
    pub witness_digest: String,
    pub target_branch_id: String,
    pub target_before_cut_id: Option<String>,
    pub target_after_cut_id: String,
    pub target_after_manifest_hash: String,
    pub units: Vec<HandoffReceipt>,
    pub actor: String,
    pub recorded_at: String,
}

#[derive(Clone, Copy, Debug)]
pub struct HandoffBatchContribution<'a> {
    derivation_id: &'a str,
    expected_witness_digest: &'a str,
    actor: &'a str,
    recorded_at: &'a str,
}

impl<'a> HandoffBatchContribution<'a> {
    pub(crate) fn new(
        derivation_id: &'a str,
        expected_witness_digest: &'a str,
        actor: &'a str,
        recorded_at: &'a str,
    ) -> Self {
        Self {
            derivation_id,
            expected_witness_digest,
            actor,
            recorded_at,
        }
    }
    pub fn derivation_id(self) -> &'a str {
        self.derivation_id
    }
    pub fn expected_witness_digest(self) -> &'a str {
        self.expected_witness_digest
    }
    pub fn actor(self) -> &'a str {
        self.actor
    }
    pub fn recorded_at(self) -> &'a str {
        self.recorded_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandoffBatchContributionOutcome {
    Transferred(FlowingBatchHandoffReceipt),
    Existing(FlowingBatchHandoffReceipt),
    IdentityMismatch,
    DerivationMissing,
    DerivationMismatch,
    WitnessMismatch,
    SourceOrderUnproven,
    MissingContent { content_id: String },
    UnitAlreadyTransferred { unit_id: String },
    UnitMissing { unit_id: String },
    BasisMissing { unit_id: String },
    BasisMismatch { unit_id: String },
    PinMissing { unit_id: String },
    PinReleased { unit_id: String },
    SourceNotActive { unit_id: String },
    SourceNotParent { unit_id: String },
    TargetMissing,
    TargetNotActive,
    TargetReserved { holder: String },
    TargetStale { current_head_cut_id: Option<String> },
    TargetFenceRefused,
    TargetCutMissing,
    TargetCutMismatch,
    TargetCutAuthorshipMismatch,
    TrunkRequiresGate,
    Invalid { field: &'static str },
}

/// Immutable mixed-content derivation prepared before any target ref move.
/// This does not establish source-order or dependent read-basis compatibility.
/// Recording it leaves every unit owed on its source line; a later atomic
/// handoff must check this exact row and transfer every unit together.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowingDerivedCut {
    pub derivation_id: String,
    pub witness: crate::vcs::FlowingBatchTargetEffects,
    pub witness_digest: String,
    pub actor: String,
    pub recorded_at: String,
}

#[derive(Clone, Copy, Debug)]
pub struct RecordFlowingDerivedCut<'a> {
    derivation_id: &'a str,
    witness: &'a crate::vcs::FlowingBatchTargetEffects,
    actor: &'a str,
    recorded_at: &'a str,
}

impl<'a> RecordFlowingDerivedCut<'a> {
    pub(crate) fn new(
        derivation_id: &'a str,
        witness: &'a crate::vcs::FlowingBatchTargetEffects,
        actor: &'a str,
        recorded_at: &'a str,
    ) -> Self {
        Self {
            derivation_id,
            witness,
            actor,
            recorded_at,
        }
    }

    pub fn derivation_id(self) -> &'a str {
        self.derivation_id
    }
    pub fn witness(self) -> &'a crate::vcs::FlowingBatchTargetEffects {
        self.witness
    }
    pub fn actor(self) -> &'a str {
        self.actor
    }
    pub fn recorded_at(self) -> &'a str {
        self.recorded_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordFlowingDerivedCutOutcome {
    Recorded(FlowingDerivedCut),
    Existing(FlowingDerivedCut),
    IdentityMismatch,
    WitnessMismatch,
    MissingContent { content_id: String },
    CutAlreadyDerived,
    CutMissing,
    CutMismatch,
    CutAuthorshipMismatch,
    UnitMissing { unit_id: String },
    BasisMissing { unit_id: String },
    BasisMismatch { unit_id: String },
    PinMissing { unit_id: String },
    PinReleased { unit_id: String },
    SourceNotActive { unit_id: String },
    SourceNotParent { unit_id: String },
    TargetMissing,
    TargetNotActive,
    TrunkRequiresGate,
    Invalid { field: &'static str },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandoffContributionOutcome {
    Transferred(HandoffReceipt),
    Existing(HandoffReceipt),
    IdentityMismatch,
    AlreadyTransferred,
    UnitMissing,
    BasisMissing,
    BasisMismatch,
    PinMissing,
    PinReleased,
    SourceMissing,
    SourceNotActive,
    TargetMissing,
    TargetNotActive,
    TargetNotParent,
    TrunkRequiresGate,
    TargetReserved { holder: String },
    TargetStale { current_head_cut_id: Option<String> },
    TargetFenceRefused,
    TargetCutMissing,
    TargetCutMismatch,
    TargetCutAuthorshipMismatch,
    TargetManifestMissing,
    Invalid { field: &'static str },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReleasePrivateCutOutcome {
    Released,
    AlreadyReleased,
    HasDeclaredUnit,
    Missing,
    Invalid { field: &'static str },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleasePrivateCut<'a> {
    pub pin_id: &'a str,
    pub released_by: &'a str,
    pub reason: &'a str,
    pub released_at: &'a str,
}

pub trait FlowingSources {
    fn pin_private_cut(
        &mut self,
        request: PinPrivateCut<'_>,
    ) -> crate::StoreResult<PinPrivateCutOutcome>;
    fn private_cut_pin(&self, pin_id: &str) -> crate::StoreResult<Option<PrivateCutPin>>;
    fn declare_contribution(
        &mut self,
        request: DeclareContribution<'_>,
    ) -> crate::StoreResult<DeclareContributionOutcome>;
    fn contribution_declaration(
        &self,
        unit_id: &str,
    ) -> crate::StoreResult<Option<ContributionDeclaration>>;
    /// Complete declaration inventory for a source line. Candidate selection
    /// must see zero-effect units as well as units with content atoms.
    fn source_contributions(
        &self,
        source_branch_id: &str,
    ) -> crate::StoreResult<Vec<ContributionDeclaration>>;
    fn bind_contribution_basis(
        &mut self,
        request: BindContributionBasis<'_>,
    ) -> crate::StoreResult<BindContributionBasisOutcome>;
    fn contribution_basis(&self, unit_id: &str) -> crate::StoreResult<Option<ContributionBasis>>;
    fn handoff_contribution(
        &mut self,
        request: HandoffContribution<'_>,
    ) -> crate::StoreResult<HandoffContributionOutcome>;
    fn handoff_receipt(&self, op_id: &str) -> crate::StoreResult<Option<HandoffReceipt>>;
    fn contribution_handoff(&self, unit_id: &str) -> crate::StoreResult<Option<HandoffReceipt>>;
    /// Exact handoff inventory for one receiving branch. The caller must
    /// compare this roster with the branch's actual cut lineage before using
    /// it as a source-unit frontier; a receipt alone does not prove content.
    fn target_handoffs(&self, target_branch_id: &str) -> crate::StoreResult<Vec<HandoffReceipt>>;
    fn record_flowing_derived_cut(
        &mut self,
        request: RecordFlowingDerivedCut<'_>,
    ) -> crate::StoreResult<RecordFlowingDerivedCutOutcome>;
    fn flowing_derived_cut(
        &self,
        derivation_id: &str,
    ) -> crate::StoreResult<Option<FlowingDerivedCut>>;
    fn handoff_batch_contribution(
        &mut self,
        request: HandoffBatchContribution<'_>,
    ) -> crate::StoreResult<HandoffBatchContributionOutcome>;
    fn handoff_batch_receipt(
        &self,
        derivation_id: &str,
    ) -> crate::StoreResult<Option<FlowingBatchHandoffReceipt>>;
    fn target_handoff_batch(
        &self,
        target_after_cut_id: &str,
    ) -> crate::StoreResult<Option<FlowingBatchHandoffReceipt>>;
    /// Only an explicit release can end an undeclared pin. A declared unit
    /// keeps the pin until an exact handoff or admission receipt transfers
    /// responsibility under a later operation.
    fn release_private_cut(
        &mut self,
        request: ReleasePrivateCut<'_>,
    ) -> crate::StoreResult<ReleasePrivateCutOutcome>;
}

pub fn missing_pin_field(request: PinPrivateCut<'_>) -> Option<&'static str> {
    [
        ("pin_id", request.pin_id),
        ("twig_branch_id", request.twig_branch_id),
        ("cut_id", request.cut_id),
        ("manifest_hash", request.manifest_hash),
        ("principal", request.principal),
        ("retained_at", request.retained_at),
    ]
    .into_iter()
    .find_map(|(name, value)| value.trim().is_empty().then_some(name))
}

pub fn missing_declaration_field(request: DeclareContribution<'_>) -> Option<&'static str> {
    [
        ("unit_id", request.unit_id),
        ("pin_id", request.pin_id),
        ("principal", request.principal),
        ("intent", request.intent),
        ("read_basis_digest", request.read_basis_digest),
        ("dependency_basis_digest", request.dependency_basis_digest),
        ("scope_digest", request.scope_digest),
        ("declared_at", request.declared_at),
    ]
    .into_iter()
    .find_map(|(name, value)| value.trim().is_empty().then_some(name))
}

pub fn missing_release_field(request: ReleasePrivateCut<'_>) -> Option<&'static str> {
    [
        ("pin_id", request.pin_id),
        ("released_by", request.released_by),
        ("reason", request.reason),
        ("released_at", request.released_at),
    ]
    .into_iter()
    .find_map(|(name, value)| value.trim().is_empty().then_some(name))
}

pub fn missing_basis_field(request: BindContributionBasis<'_>) -> Option<&'static str> {
    [
        ("unit_id", request.unit_id),
        ("bound_at", request.bound_at),
        ("basis_digest", request.selection.digest()),
    ]
    .into_iter()
    .find_map(|(name, value)| value.trim().is_empty().then_some(name))
    .or_else(|| request.selection.changes().is_empty().then_some("changes"))
}

pub fn missing_handoff_field(request: HandoffContribution<'_>) -> Option<&'static str> {
    [
        ("op_id", request.op_id),
        ("unit_id", request.witness.unit_id()),
        ("basis_digest", request.witness.basis_digest()),
        ("target_branch_id", request.witness.target_branch_id()),
        ("target_after_cut_id", request.witness.target_after_cut_id()),
        (
            "target_after_manifest_hash",
            request.witness.target_after_manifest_hash(),
        ),
        ("actor", request.actor),
        ("recorded_at", request.recorded_at),
    ]
    .into_iter()
    .find_map(|(name, value)| value.trim().is_empty().then_some(name))
    .or_else(|| {
        request
            .witness
            .target_before_cut_id()
            .is_some_and(|value| value.trim().is_empty())
            .then_some("target_before_cut_id")
    })
    .or_else(|| request.witness.effects().is_empty().then_some("effects"))
}

pub fn missing_derived_cut_field(request: RecordFlowingDerivedCut<'_>) -> Option<&'static str> {
    [
        ("derivation_id", request.derivation_id),
        ("target_branch_id", request.witness.target_branch_id()),
        ("target_after_cut_id", request.witness.target_after_cut_id()),
        (
            "target_after_manifest_hash",
            request.witness.target_after_manifest_hash(),
        ),
        ("actor", request.actor),
        ("recorded_at", request.recorded_at),
    ]
    .into_iter()
    .find_map(|(field, value)| value.trim().is_empty().then_some(field))
    .or_else(|| request.witness.units().is_empty().then_some("units"))
}

pub fn derived_cut_digest(witness: &crate::vcs::FlowingBatchTargetEffects) -> String {
    let bytes = serde_json::to_vec(&("flowing-derived-cut-v1", witness))
        .expect("derived-cut witness serializes");
    format!("sha256:{}", crate::chunking::content_hash_hex(&bytes))
}

pub fn batch_handoff_digest(receipt: &FlowingBatchHandoffReceipt) -> String {
    let bytes = serde_json::to_vec(&("flowing-batch-handoff-v1", receipt))
        .expect("batch handoff receipt serializes");
    format!("sha256:{}", crate::chunking::content_hash_hex(&bytes))
}

pub fn missing_batch_handoff_field(request: HandoffBatchContribution<'_>) -> Option<&'static str> {
    [
        ("derivation_id", request.derivation_id),
        ("expected_witness_digest", request.expected_witness_digest),
        ("actor", request.actor),
        ("recorded_at", request.recorded_at),
    ]
    .into_iter()
    .find_map(|(field, value)| value.trim().is_empty().then_some(field))
}
