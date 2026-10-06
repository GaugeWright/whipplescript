//! Exact, per-admission import evidence (DR-0131, RC-2).
//!
//! A program version can be reused under a changed package lock. Checked
//! version creation retains an immutable witness basis, while each call to
//! the version-creation API records a separate operation. A changed-IR
//! re-attestation records an unwitnessed operation. Other accepting paths
//! still need coverage before this population can describe a Home.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{StoreError, StoreResult};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProgramImportEdge {
    pub import: String,
    pub package_id: String,
    pub version: String,
    pub source_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProgramImportWitness {
    pub program_source_digest: String,
    /// Present when a version's source id hashes a larger checked identity
    /// that contains the exact program source (for example an authored host
    /// package). Older and direct-source witnesses use program_source_digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_source_digest: Option<String>,
    pub lock_digest: String,
    pub compiler_artifact_digest: String,
    pub examined: Vec<String>,
    pub edges: Vec<ProgramImportEdge>,
    pub edge_digest: String,
    /// `None` is unknown for this rule-effect construct class, including older
    /// witnesses. `Some` with no edges proves this class was examined and had
    /// no uses; it says nothing about other construct-bearing IR forms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constructs: Option<ProgramConstructCapture>,
    /// `None` is unknown for compiler-inventoried declarations. `Some(empty)`
    /// means that exact checked program examined this class and found none.
    /// This field is separate from rule-effect constructs because declarations
    /// have no effect capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declarations: Option<ProgramDeclarationCapture>,
    /// `None` is unknown for ordinary and construct capability calls in older
    /// witnesses. `Some(empty)` proves this one compiler-inventoried class was
    /// examined. It does not classify other provider or content handles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_calls: Option<ProgramPackageCallCapture>,
    /// `None` on a legacy witness leaves provider-binding paths unknown.
    /// `Some` inventories compiler-owned selectors, not resolved external
    /// identities or live update edges.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_bindings: Option<ProgramProviderBindingCapture>,
    /// `None` leaves the compiler's resource fields unknown on older witnesses.
    /// `Some` classifies their spellings at this exact checked admission; it
    /// does not resolve external resource identities or establish live edges.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_fields: Option<ProgramResourceFieldCapture>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramResourceField {
    ChannelWorkspace,
    ChannelDestination,
    FileStoreRoot,
    FileStoreReadGlobs,
    FileStoreWriteGlobs,
    SourcePath,
    SourceWatch,
    SourceUrl,
    SourceEndpoint,
    SourceAuthSecret,
    SourceVerifiedCredential,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramResourceFieldMeaning {
    ProviderWorkspaceSelector,
    ProviderDestinationSelector,
    LocalRootPath,
    PathPolicy,
    LocalFileInput,
    LocalFileWatchPattern,
    HttpFetchEndpoint,
    InboundRoute,
    CredentialSelector,
}

impl ProgramResourceField {
    pub fn meaning(self) -> ProgramResourceFieldMeaning {
        match self {
            Self::ChannelWorkspace => ProgramResourceFieldMeaning::ProviderWorkspaceSelector,
            Self::ChannelDestination => ProgramResourceFieldMeaning::ProviderDestinationSelector,
            Self::FileStoreRoot => ProgramResourceFieldMeaning::LocalRootPath,
            Self::FileStoreReadGlobs | Self::FileStoreWriteGlobs => {
                ProgramResourceFieldMeaning::PathPolicy
            }
            Self::SourcePath => ProgramResourceFieldMeaning::LocalFileInput,
            Self::SourceWatch => ProgramResourceFieldMeaning::LocalFileWatchPattern,
            Self::SourceUrl => ProgramResourceFieldMeaning::HttpFetchEndpoint,
            Self::SourceEndpoint => ProgramResourceFieldMeaning::InboundRoute,
            Self::SourceAuthSecret | Self::SourceVerifiedCredential => {
                ProgramResourceFieldMeaning::CredentialSelector
            }
        }
    }

    fn owner_kind(self) -> &'static str {
        match self {
            Self::ChannelWorkspace | Self::ChannelDestination => "channel",
            Self::FileStoreRoot | Self::FileStoreReadGlobs | Self::FileStoreWriteGlobs => {
                "file_store"
            }
            Self::SourcePath
            | Self::SourceWatch
            | Self::SourceUrl
            | Self::SourceEndpoint
            | Self::SourceAuthSecret
            | Self::SourceVerifiedCredential => "source",
        }
    }

    fn max_values(self) -> Option<usize> {
        match self {
            Self::FileStoreReadGlobs | Self::FileStoreWriteGlobs => None,
            _ => Some(1),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramResourceFieldScope {
    DeclaredFieldsV1,
}

/// An empty `values` preserves an omitted optional clause or an empty glob
/// policy; the field itself remains examined. Each field has one fixed meaning
/// and is unresolved for dependency routing until its host binding is proved.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramResourceFieldUse {
    pub occurrence: usize,
    pub owner: String,
    pub field: ProgramResourceField,
    pub meaning: ProgramResourceFieldMeaning,
    pub values: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramResourceFieldCapture {
    pub scope: ProgramResourceFieldScope,
    pub examined: Vec<ProgramResourceFieldUse>,
    pub digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramProviderBindingScope {
    DeclarationsAndEffectsV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramProviderTargetResolution {
    StaticDeclaration,
    DynamicExpression,
}

/// A provider spelling is a local selector. `None` retains an omitted clause;
/// its meaning depends on the site (for example a file store defaults to local,
/// while a coercion may be chosen by the runtime selection ladder).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "site_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProgramProviderBindingSite {
    Harness {
        name: String,
        kind: String,
    },
    Tracker {
        name: String,
        provider: String,
    },
    Channel {
        name: String,
        provider: String,
    },
    Vault {
        name: String,
        provider: Option<String>,
    },
    FileStore {
        name: String,
        provider: Option<String>,
    },
    Source {
        name: String,
        provider: String,
    },
    Agent {
        name: String,
        provider: Option<String>,
        harness: Option<String>,
    },
    Coerce {
        name: String,
        provider: Option<String>,
    },
    AgentTell {
        rule: String,
        effect: String,
        agent: String,
        target_resolution: ProgramProviderTargetResolution,
    },
    SchemaCoerce {
        rule: String,
        effect: String,
        declaration: Option<String>,
        prompt_provider: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramProviderBindingUse {
    pub occurrence: usize,
    pub site: ProgramProviderBindingSite,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramProviderBindingCapture {
    pub scope: ProgramProviderBindingScope,
    pub examined: Vec<ProgramProviderBindingUse>,
    pub digest: String,
}

/// The fields of `IrPackageCall` have fixed, deliberately narrow meanings:
/// `target` names a local capability binding, `tracker_resources` names local
/// tracker scopes, and `argument` is opaque data. None alone asserts a live
/// dependency on another package or Home. The scope version makes a future
/// change to those meanings an explicit witness-format change.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramPackageCallScope {
    CapabilityCallV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramPackageCallUse {
    pub occurrence: usize,
    pub rule_name: String,
    pub effect_id: String,
    pub target: String,
    pub argument: Option<String>,
    pub tracker_resources: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramPackageCallCapture {
    pub scope: ProgramPackageCallScope,
    pub examined: Vec<ProgramPackageCallUse>,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProgramDeclarationUse {
    pub occurrence: usize,
    pub keyword: String,
    pub name: String,
    pub scope: String,
    pub family: String,
    pub lowering: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProgramDeclarationEdge {
    pub declaration: ProgramDeclarationUse,
    pub registration_id: String,
    pub library_id: String,
    pub registration_version: String,
    pub provider_package: String,
    pub provider_source_digest: String,
    pub meaning: ProgramConstructMeaning,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProgramDeclarationCapture {
    pub examined: Vec<ProgramDeclarationUse>,
    pub edges: Vec<ProgramDeclarationEdge>,
    pub edge_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProgramConstructUse {
    pub occurrence: usize,
    pub keyword: String,
    pub scope: String,
    pub family: String,
    pub lowering: String,
    pub capability: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramConstructMeaning {
    LiveDependency,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProgramConstructEdge {
    pub use_form: ProgramConstructUse,
    pub registration_id: String,
    pub library_id: String,
    pub registration_version: String,
    pub provider_package: String,
    pub provider_source_digest: String,
    pub meaning: ProgramConstructMeaning,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProgramConstructCapture {
    pub scope: ProgramConstructScope,
    pub examined: Vec<ProgramConstructUse>,
    pub edges: Vec<ProgramConstructEdge>,
    pub edge_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramConstructScope {
    RuleEffect,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramImportAdmissionRecord {
    pub program_id: String,
    pub version_id: String,
    pub witness_digest: String,
    /// The exact accepting operation committed with this witness. A reused
    /// version may have many operations, so the version ID cannot stand in for
    /// this identity at a Home journal boundary (DR-0150).
    pub operation_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProgramImportOperationKind {
    Checked,
    Unwitnessed,
    LegacyGap,
}

impl TryFrom<&str> for ProgramImportOperationKind {
    type Error = StoreError;

    fn try_from(value: &str) -> StoreResult<Self> {
        match value {
            "checked" => Ok(Self::Checked),
            "unwitnessed" => Ok(Self::Unwitnessed),
            "legacy-gap" => Ok(Self::LegacyGap),
            other => Err(StoreError::Conflict(format!(
                "unknown program import operation kind {other}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramImportOperation {
    pub sequence: i64,
    pub operation_id: String,
    pub version_id: String,
    pub witness_digest: Option<String>,
    pub kind: ProgramImportOperationKind,
}

impl ProgramImportOperation {
    /// Decode persisted evidence without turning malformed rows into a
    /// checked operation. Both store backends use this read boundary.
    pub fn from_stored_row(
        sequence: i64,
        operation_id: String,
        version_id: String,
        witness_digest: Option<String>,
        kind: &str,
    ) -> StoreResult<Self> {
        let kind = kind.try_into()?;
        if sequence <= 0
            || operation_id.is_empty()
            || version_id.is_empty()
            || (kind == ProgramImportOperationKind::Checked) != witness_digest.is_some()
            || witness_digest
                .as_deref()
                .is_some_and(|digest| !is_digest(digest))
        {
            return Err(StoreError::Conflict(
                "malformed program import operation row".into(),
            ));
        }
        Ok(Self {
            sequence,
            operation_id,
            version_id,
            witness_digest,
            kind,
        })
    }
}

/// One store's observed operation population at a monotone sequence frontier.
/// This read does not establish that every Home accepting path writes the
/// ledger, or that a checked witness still matches current source inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramImportOperationRoster {
    pub frontier: i64,
    pub operations: Vec<ProgramImportOperation>,
}

pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS program_import_admissions (
    version_id TEXT NOT NULL REFERENCES program_versions(version_id),
    witness_digest TEXT NOT NULL,
    witness_json TEXT NOT NULL,
    PRIMARY KEY (version_id, witness_digest)
)";

/// One row per version-creation call or changed-IR re-attestation, including
/// repeated calls returning the same version. Existing stores cannot reconstruct old calls;
/// their migration records a conservative unknown gap for every old version.
pub const OPERATIONS_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS program_import_operations (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id TEXT NOT NULL UNIQUE,
    version_id TEXT NOT NULL REFERENCES program_versions(version_id),
    witness_digest TEXT,
    kind TEXT NOT NULL CHECK (kind IN ('checked', 'unwitnessed', 'legacy-gap')),
    FOREIGN KEY (version_id, witness_digest)
        REFERENCES program_import_admissions(version_id, witness_digest),
    CHECK ((kind = 'checked') = (witness_digest IS NOT NULL))
)";

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Home-correlated accepting operations use the same opaque identity shape as
/// store-minted operations, so one pending pointer names one target row.
pub fn validate_operation_id(value: &str) -> StoreResult<()> {
    let suffix = value.strip_prefix("imp_").unwrap_or("");
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StoreError::Conflict(
            "invalid program import operation identity".into(),
        ));
    }
    Ok(())
}

/// Native direct-source ids may be the first 128 bits of SHA-256; hosted ones
/// retain all 256 bits. A host package may instead hash a checked composite
/// identity containing those source bytes. The witness retains both digests.
pub fn matches_source_id(witness: &ProgramImportWitness, source_id: &str) -> bool {
    let version_source = witness
        .version_source_digest
        .as_deref()
        .unwrap_or(&witness.program_source_digest);
    matches!(source_id.len(), 32 | 64)
        && source_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && if source_id.len() == 32 {
            version_source.starts_with(source_id)
        } else {
            version_source == source_id
        }
}

/// Check the witness's internal structure before it is retained. The compiler
/// boundary is responsible for proving that `examined` really is every
/// applicable import in the checked IR.
pub fn encode(witness: &ProgramImportWitness) -> StoreResult<(String, String)> {
    for (label, digest) in [
        ("program source", witness.program_source_digest.as_str()),
        ("package lock", witness.lock_digest.as_str()),
        (
            "compiler artifact",
            witness.compiler_artifact_digest.as_str(),
        ),
        ("edge set", witness.edge_digest.as_str()),
    ] {
        if !is_digest(digest) {
            return Err(StoreError::Conflict(format!(
                "import witness {label} lacks an exact lowercase SHA-256 digest"
            )));
        }
    }
    if witness
        .version_source_digest
        .as_deref()
        .is_some_and(|digest| !is_digest(digest))
    {
        return Err(StoreError::Conflict(
            "import witness version source lacks an exact lowercase SHA-256 digest".into(),
        ));
    }
    if witness.examined.iter().any(|name| name.is_empty())
        || witness.examined.windows(2).any(|pair| pair[0] >= pair[1])
        || witness.examined.len() != witness.edges.len()
        || witness
            .examined
            .iter()
            .zip(&witness.edges)
            .any(|(name, edge)| {
                edge.import != *name
                    || edge.package_id.is_empty()
                    || edge.version.is_empty()
                    || !is_digest(&edge.source_digest)
            })
    {
        return Err(StoreError::Conflict(
            "import witness has incomplete or unordered edges".into(),
        ));
    }
    let edge_json = serde_json::to_string(&witness.edges)?;
    if crate::items::sha256_hex(&edge_json) != witness.edge_digest {
        return Err(StoreError::Conflict(
            "import witness edge digest differs from its edges".into(),
        ));
    }
    if let Some(constructs) = &witness.constructs {
        if !is_digest(&constructs.edge_digest)
            || constructs.examined.len() != constructs.edges.len()
            || constructs
                .examined
                .iter()
                .enumerate()
                .any(|(index, use_form)| {
                    use_form.occurrence != index
                        || use_form.keyword.is_empty()
                        || use_form.scope.is_empty()
                        || use_form.family.is_empty()
                        || use_form.lowering.is_empty()
                        || use_form.capability.is_empty()
                })
            || constructs
                .examined
                .iter()
                .zip(&constructs.edges)
                .any(|(use_form, edge)| {
                    edge.use_form != *use_form
                        || edge.registration_id.is_empty()
                        || edge.library_id.is_empty()
                        || edge.registration_version.is_empty()
                        || edge.provider_package.is_empty()
                        || !is_digest(&edge.provider_source_digest)
                })
        {
            return Err(StoreError::Conflict(
                "construct witness has incomplete or unordered edges".into(),
            ));
        }
        let edge_json = serde_json::to_string(&constructs.edges)?;
        if crate::items::sha256_hex(&edge_json) != constructs.edge_digest {
            return Err(StoreError::Conflict(
                "construct witness edge digest differs from its edges".into(),
            ));
        }
    }
    if let Some(declarations) = &witness.declarations {
        if !is_digest(&declarations.edge_digest)
            || declarations.examined.len() != declarations.edges.len()
            || declarations
                .examined
                .windows(2)
                .any(|pair| pair[0].occurrence >= pair[1].occurrence)
            || declarations.examined.iter().any(|declaration| {
                declaration.keyword.is_empty()
                    || declaration.name.is_empty()
                    || declaration.scope.is_empty()
                    || declaration.family.is_empty()
                    || declaration.lowering.is_empty()
            })
            || declarations
                .examined
                .iter()
                .zip(&declarations.edges)
                .any(|(declaration, edge)| {
                    edge.declaration != *declaration
                        || edge.registration_id.is_empty()
                        || edge.library_id.is_empty()
                        || edge.registration_version.is_empty()
                        || edge.provider_package.is_empty()
                        || !is_digest(&edge.provider_source_digest)
                })
        {
            return Err(StoreError::Conflict(
                "declaration witness has incomplete or unordered edges".into(),
            ));
        }
        let edge_json = serde_json::to_string(&declarations.edges)?;
        if crate::items::sha256_hex(&edge_json) != declarations.edge_digest {
            return Err(StoreError::Conflict(
                "declaration witness edge digest differs from its edges".into(),
            ));
        }
    }
    if let Some(calls) = &witness.package_calls {
        if !is_digest(&calls.digest)
            || calls.examined.iter().enumerate().any(|(index, call)| {
                call.occurrence != index
                    || call.rule_name.is_empty()
                    || call.effect_id.is_empty()
                    || call.target.is_empty()
                    || call.tracker_resources.iter().any(String::is_empty)
            })
        {
            return Err(StoreError::Conflict(
                "package-call witness has incomplete or unordered uses".into(),
            ));
        }
        let examined_json = serde_json::to_string(&calls.examined)?;
        if crate::items::sha256_hex(&examined_json) != calls.digest {
            return Err(StoreError::Conflict(
                "package-call witness digest differs from its uses".into(),
            ));
        }
    }
    if let Some(bindings) = &witness.provider_bindings {
        if !is_digest(&bindings.digest)
            || bindings
                .examined
                .iter()
                .enumerate()
                .any(|(index, use_site)| {
                    if use_site.occurrence != index {
                        return true;
                    }
                    match &use_site.site {
                        ProgramProviderBindingSite::Harness { name, kind } => {
                            name.is_empty() || kind.is_empty()
                        }
                        ProgramProviderBindingSite::Tracker { name, provider }
                        | ProgramProviderBindingSite::Channel { name, provider }
                        | ProgramProviderBindingSite::Source { name, provider } => {
                            name.is_empty() || provider.is_empty()
                        }
                        ProgramProviderBindingSite::Vault { name, provider }
                        | ProgramProviderBindingSite::FileStore { name, provider }
                        | ProgramProviderBindingSite::Coerce { name, provider } => {
                            name.is_empty() || provider.as_ref().is_some_and(String::is_empty)
                        }
                        ProgramProviderBindingSite::Agent {
                            name,
                            provider,
                            harness,
                        } => {
                            name.is_empty()
                                || provider.as_ref().is_some_and(String::is_empty)
                                || harness.as_ref().is_some_and(String::is_empty)
                                || (provider.is_some() && harness.is_some())
                        }
                        ProgramProviderBindingSite::AgentTell {
                            rule,
                            effect,
                            agent,
                            target_resolution: _,
                        } => rule.is_empty() || effect.is_empty() || agent.is_empty(),
                        ProgramProviderBindingSite::SchemaCoerce {
                            rule,
                            effect,
                            declaration,
                            prompt_provider,
                        } => {
                            rule.is_empty()
                                || effect.is_empty()
                                || declaration.as_ref().is_some_and(String::is_empty)
                                || prompt_provider.as_ref().is_some_and(String::is_empty)
                                || (declaration.is_some() && prompt_provider.is_some())
                        }
                    }
                })
        {
            return Err(StoreError::Conflict(
                "provider-binding witness has incomplete or unordered uses".into(),
            ));
        }
        let examined_json = serde_json::to_string(&bindings.examined)?;
        if crate::items::sha256_hex(&examined_json) != bindings.digest {
            return Err(StoreError::Conflict(
                "provider-binding witness digest differs from its uses".into(),
            ));
        }
    }
    if let Some(resources) = &witness.resource_fields {
        let mut by_owner: BTreeMap<(&str, &str), BTreeSet<ProgramResourceField>> = BTreeMap::new();
        let invalid = !is_digest(&resources.digest)
            || resources.examined.iter().enumerate().any(|(index, field)| {
                field.occurrence != index
                    || field.owner.is_empty()
                    || field.meaning != field.field.meaning()
                    || field.values.iter().any(String::is_empty)
                    || field
                        .field
                        .max_values()
                        .is_some_and(|maximum| field.values.len() > maximum)
                    || (field.field == ProgramResourceField::FileStoreRoot
                        && field.values.len() != 1)
                    || !by_owner
                        .entry((field.field.owner_kind(), &field.owner))
                        .or_default()
                        .insert(field.field)
            });
        let incomplete = by_owner.iter().any(|((kind, _), fields)| {
            let expected: &[ProgramResourceField] = match *kind {
                "channel" => &[
                    ProgramResourceField::ChannelWorkspace,
                    ProgramResourceField::ChannelDestination,
                ],
                "file_store" => &[
                    ProgramResourceField::FileStoreRoot,
                    ProgramResourceField::FileStoreReadGlobs,
                    ProgramResourceField::FileStoreWriteGlobs,
                ],
                "source" => &[
                    ProgramResourceField::SourcePath,
                    ProgramResourceField::SourceWatch,
                    ProgramResourceField::SourceUrl,
                    ProgramResourceField::SourceEndpoint,
                    ProgramResourceField::SourceAuthSecret,
                    ProgramResourceField::SourceVerifiedCredential,
                ],
                _ => unreachable!(),
            };
            fields.len() != expected.len() || expected.iter().any(|field| !fields.contains(field))
        });
        if invalid || incomplete {
            return Err(StoreError::Conflict(
                "resource-field witness has incomplete or misclassified fields".into(),
            ));
        }
        let examined_json = serde_json::to_string(&resources.examined)?;
        if crate::items::sha256_hex(&examined_json) != resources.digest {
            return Err(StoreError::Conflict(
                "resource-field witness digest differs from its fields".into(),
            ));
        }
    }
    let json = serde_json::to_string(witness)?;
    let digest = crate::items::sha256_hex(&json);
    Ok((digest, json))
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::{NewInstance, NewProgramVersion, SqliteStore};
    use rusqlite::OptionalExtension;

    const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SOURCE_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const LOCK: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const NEXT_LOCK: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const COMPILER: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    #[test]
    fn operation_roster_refuses_an_unknown_kind() {
        assert!(matches!(
            ProgramImportOperationKind::try_from("future-kind"),
            Err(StoreError::Conflict(message)) if message.contains("unknown program import operation kind future-kind")
        ));
    }

    #[test]
    fn operation_roster_refuses_malformed_persisted_evidence() {
        assert!(ProgramImportOperation::from_stored_row(
            0,
            "op".into(),
            "version".into(),
            None,
            "unwitnessed",
        )
        .is_err());
        assert!(ProgramImportOperation::from_stored_row(
            1,
            "op".into(),
            "version".into(),
            None,
            "checked",
        )
        .is_err());
        assert!(ProgramImportOperation::from_stored_row(
            1,
            "op".into(),
            "version".into(),
            Some(LOCK.into()),
            "unwitnessed",
        )
        .is_err());
        assert!(ProgramImportOperation::from_stored_row(
            1,
            "op".into(),
            "version".into(),
            Some("not-a-digest".into()),
            "checked",
        )
        .is_err());
    }

    fn version(name: &'static str) -> NewProgramVersion<'static> {
        NewProgramVersion {
            program_name: name,
            source_hash: SOURCE_ID,
            ir_hash: COMPILER,
            compiler_version: "test-compiler",
            ir_snapshot: None,
            declared_capabilities_json: "[]",
            declared_profiles_json: "[]",
            declared_skills_json: "[]",
            declared_schemas_json: "[]",
            analysis_summary_json: "{}",
            generated_artifacts_json: "[]",
            artifact_root: None,
        }
    }

    fn witness(lock: &str) -> ProgramImportWitness {
        let edges = vec![ProgramImportEdge {
            import: "local.paint".into(),
            package_id: "pkg-paint".into(),
            version: "1".into(),
            source_digest: SOURCE.into(),
        }];
        ProgramImportWitness {
            program_source_digest: SOURCE.into(),
            version_source_digest: None,
            lock_digest: lock.into(),
            compiler_artifact_digest: COMPILER.into(),
            examined: vec!["local.paint".into()],
            edge_digest: crate::items::sha256_hex(
                &serde_json::to_string(&edges).expect("fixture edge JSON"),
            ),
            edges,
            constructs: None,
            declarations: None,
            package_calls: None,
            provider_bindings: None,
            resource_fields: None,
        }
    }

    #[test]
    fn package_call_witness_keeps_legacy_unknown_and_refuses_incomplete_capture() {
        let legacy = witness(LOCK);
        let (_, legacy_json) = encode(&legacy).unwrap();
        assert!(!legacy_json.contains("package_calls"));

        let mut checked = legacy.clone();
        let examined = vec![
            ProgramPackageCallUse {
                occurrence: 0,
                rule_name: "ask".into(),
                effect_id: "effect-one".into(),
                target: "memory.query".into(),
                argument: Some("opaque-input".into()),
                tracker_resources: vec!["backlog".into()],
            },
            ProgramPackageCallUse {
                occurrence: 1,
                rule_name: "save".into(),
                // Effect identifiers are local to rules, so this can repeat.
                effect_id: "effect-one".into(),
                target: "memory.write".into(),
                argument: None,
                tracker_resources: vec![],
            },
        ];
        checked.package_calls = Some(ProgramPackageCallCapture {
            scope: ProgramPackageCallScope::CapabilityCallV1,
            digest: crate::items::sha256_hex(&serde_json::to_string(&examined).unwrap()),
            examined,
        });
        assert!(encode(&checked).is_ok());
        let mut malformed = checked.clone();
        let calls = malformed.package_calls.as_mut().unwrap();
        calls.examined[1].occurrence = 0;
        calls.digest = crate::items::sha256_hex(&serde_json::to_string(&calls.examined).unwrap());
        assert!(matches!(
            encode(&malformed),
            Err(StoreError::Conflict(message)) if message.contains("package-call witness has incomplete or unordered uses")
        ));
        checked.package_calls.as_mut().unwrap().examined[0].target = "changed".into();
        assert!(matches!(
            encode(&checked),
            Err(StoreError::Conflict(message)) if message.contains("package-call witness digest differs")
        ));
    }

    #[test]
    fn provider_binding_witness_keeps_legacy_unknown_and_refuses_corrupt_capture() {
        let legacy = witness(LOCK);
        let (_, legacy_json) = encode(&legacy).unwrap();
        assert!(!legacy_json.contains("provider_bindings"));

        let examined = vec![
            ProgramProviderBindingUse {
                occurrence: 0,
                site: ProgramProviderBindingSite::Agent {
                    name: "worker".into(),
                    provider: Some("codex".into()),
                    harness: None,
                },
            },
            ProgramProviderBindingUse {
                occurrence: 1,
                site: ProgramProviderBindingSite::AgentTell {
                    rule: "ask".into(),
                    effect: "effect1".into(),
                    agent: "worker".into(),
                    target_resolution: ProgramProviderTargetResolution::StaticDeclaration,
                },
            },
        ];
        let mut checked = legacy;
        checked.provider_bindings = Some(ProgramProviderBindingCapture {
            scope: ProgramProviderBindingScope::DeclarationsAndEffectsV1,
            digest: crate::items::sha256_hex(&serde_json::to_string(&examined).unwrap()),
            examined,
        });
        assert!(encode(&checked).is_ok());

        let mut malformed = checked.clone();
        let bindings = malformed.provider_bindings.as_mut().unwrap();
        bindings.examined[1].occurrence = 0;
        bindings.digest =
            crate::items::sha256_hex(&serde_json::to_string(&bindings.examined).unwrap());
        assert!(matches!(
            encode(&malformed),
            Err(StoreError::Conflict(message)) if message.contains("provider-binding witness has incomplete or unordered uses")
        ));

        let mut double_binding = checked.clone();
        let bindings = double_binding.provider_bindings.as_mut().unwrap();
        bindings.examined[0].site = ProgramProviderBindingSite::Agent {
            name: "worker".into(),
            provider: Some("codex".into()),
            harness: Some("other".into()),
        };
        bindings.digest =
            crate::items::sha256_hex(&serde_json::to_string(&bindings.examined).unwrap());
        assert!(matches!(
            encode(&double_binding),
            Err(StoreError::Conflict(message)) if message.contains("provider-binding witness has incomplete or unordered uses")
        ));

        let bindings = checked.provider_bindings.as_mut().unwrap();
        bindings.examined[0].site = ProgramProviderBindingSite::Agent {
            name: "worker".into(),
            provider: Some("changed".into()),
            harness: None,
        };
        assert!(matches!(
            encode(&checked),
            Err(StoreError::Conflict(message)) if message.contains("provider-binding witness digest differs from its uses")
        ));
    }

    #[test]
    fn resource_field_witness_preserves_absence_and_refuses_false_classification() {
        let legacy = witness(LOCK);
        assert!(!encode(&legacy).unwrap().1.contains("resource_fields"));
        let examined = vec![
            ProgramResourceFieldUse {
                occurrence: 0,
                owner: "ops".into(),
                field: ProgramResourceField::ChannelWorkspace,
                meaning: ProgramResourceFieldMeaning::ProviderWorkspaceSelector,
                values: vec![],
            },
            ProgramResourceFieldUse {
                occurrence: 1,
                owner: "ops".into(),
                field: ProgramResourceField::ChannelDestination,
                meaning: ProgramResourceFieldMeaning::ProviderDestinationSelector,
                values: vec!["#ops".into()],
            },
        ];
        let mut checked = legacy;
        checked.resource_fields = Some(ProgramResourceFieldCapture {
            scope: ProgramResourceFieldScope::DeclaredFieldsV1,
            digest: crate::items::sha256_hex(&serde_json::to_string(&examined).unwrap()),
            examined,
        });
        assert!(encode(&checked).is_ok());

        let mut omitted = checked.clone();
        let capture = omitted.resource_fields.as_mut().unwrap();
        capture.examined.pop();
        capture.digest =
            crate::items::sha256_hex(&serde_json::to_string(&capture.examined).unwrap());
        assert!(matches!(
            encode(&omitted),
            Err(StoreError::Conflict(message)) if message.contains("incomplete or misclassified")
        ));

        let mut false_edge = checked.clone();
        let capture = false_edge.resource_fields.as_mut().unwrap();
        capture.examined[1].meaning = ProgramResourceFieldMeaning::HttpFetchEndpoint;
        capture.digest =
            crate::items::sha256_hex(&serde_json::to_string(&capture.examined).unwrap());
        assert!(matches!(
            encode(&false_edge),
            Err(StoreError::Conflict(message)) if message.contains("incomplete or misclassified")
        ));

        checked.resource_fields.as_mut().unwrap().examined[1].values = vec!["changed".into()];
        assert!(matches!(
            encode(&checked),
            Err(StoreError::Conflict(message)) if message.contains("digest differs")
        ));
    }

    #[test]
    fn home_reattestation_recovers_exact_instance_transition() {
        const HOME_OPERATION: &str = "imp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut store = SqliteStore::open_in_memory().unwrap();
        let original = store
            .create_program_version_with_import_witness(version("home-reattest"), &witness(LOCK))
            .unwrap();
        let first = store
            .create_instance(NewInstance {
                program_id: &original.program_id,
                version_id: &original.version_id,
                input_json: "{}",
            })
            .unwrap();
        let other = store
            .create_instance(NewInstance {
                program_id: &original.program_id,
                version_id: &original.version_id,
                input_json: "{}",
            })
            .unwrap();
        let changed = NewProgramVersion {
            ir_hash: NEXT_LOCK,
            ..version("home-reattest")
        };
        assert!(matches!(
            store.reattest_instance_program_with_import_witness_at_id(
                &first.instance_id,
                version("home-reattest"),
                &witness(LOCK),
                HOME_OPERATION,
            ),
            Err(StoreError::Conflict(message)) if message.contains("no exact target operation")
        ));
        let admitted = store
            .reattest_instance_program_with_import_witness_at_id(
                &first.instance_id,
                changed,
                &witness(LOCK),
                HOME_OPERATION,
            )
            .unwrap();
        assert_eq!(admitted.operation_id, HOME_OPERATION);
        let after = store.program_import_operation_roster().unwrap();
        assert_eq!(
            store
                .reattest_instance_program_with_import_witness_at_id(
                    &first.instance_id,
                    changed,
                    &witness(LOCK),
                    HOME_OPERATION,
                )
                .unwrap(),
            admitted
        );
        assert_eq!(store.program_import_operation_roster().unwrap(), after);
        let mut wrong_source = witness(LOCK);
        wrong_source.program_source_digest = NEXT_LOCK.into();
        assert!(matches!(
            store.reattest_instance_program_with_import_witness_at_id(
                &first.instance_id,
                changed,
                &wrong_source,
                HOME_OPERATION,
            ),
            Err(StoreError::Conflict(message)) if message.contains("program source differs")
        ));
        assert!(matches!(
            store.reattest_instance_program_with_import_witness_at_id(
                &first.instance_id,
                changed,
                &witness(NEXT_LOCK),
                HOME_OPERATION,
            ),
            Err(StoreError::Conflict(message)) if message.contains("different evidence")
        ));
        store
            .connection
            .execute(
                "UPDATE events SET correlation_id = NULL WHERE correlation_id = ?1",
                [HOME_OPERATION],
            )
            .unwrap();
        assert!(matches!(
            store.reattest_instance_program_with_import_witness_at_id(
                &first.instance_id,
                changed,
                &witness(LOCK),
                HOME_OPERATION,
            ),
            Err(StoreError::Conflict(message)) if message.contains("instance transition")
        ));
        store
            .connection
            .execute(
                "UPDATE events SET correlation_id = ?1 WHERE instance_id = ?2 \
                 AND event_type = 'instance.program.reattested'",
                rusqlite::params![HOME_OPERATION, &first.instance_id],
            )
            .unwrap();
        assert!(matches!(
            store.reattest_instance_program_with_import_witness_at_id(
                &other.instance_id,
                changed,
                &witness(LOCK),
                HOME_OPERATION,
            ),
            Err(StoreError::Conflict(message)) if message.contains("another transition")
        ));
        assert_eq!(
            store
                .get_instance(&other.instance_id)
                .unwrap()
                .unwrap()
                .version_id,
            original.version_id
        );
        assert_eq!(store.program_import_operation_roster().unwrap(), after);

        // A prior unjournaled transition with the same from/to pair cannot
        // be retroactively relabeled as this Home operation on replay.
        let mut prior = SqliteStore::open_in_memory().unwrap();
        let original = prior
            .create_program_version_with_import_witness(version("prior-transition"), &witness(LOCK))
            .unwrap();
        let instance = prior
            .create_instance(NewInstance {
                program_id: &original.program_id,
                version_id: &original.version_id,
                input_json: "{}",
            })
            .unwrap();
        let next = NewProgramVersion {
            ir_hash: NEXT_LOCK,
            ..version("prior-transition")
        };
        prior
            .reattest_instance_program_with_import_witness(
                &instance.instance_id,
                next,
                &witness(LOCK),
            )
            .unwrap();
        prior
            .reattest_instance_program_with_import_witness(
                &instance.instance_id,
                version("prior-transition"),
                &witness(LOCK),
            )
            .unwrap();
        let prior_roster = prior.program_import_operation_roster().unwrap();
        assert!(matches!(
            prior.reattest_instance_program_with_import_witness_at_id(
                &instance.instance_id,
                next,
                &witness(LOCK),
                HOME_OPERATION,
            ),
            Err(StoreError::Conflict(message)) if message.contains("prior instance transition")
        ));
        assert_eq!(
            prior.program_import_operation_roster().unwrap(),
            prior_roster
        );
        assert_eq!(
            prior
                .get_instance(&instance.instance_id)
                .unwrap()
                .unwrap()
                .version_id,
            original.version_id
        );
    }

    #[test]
    fn home_chosen_operation_identity_commits_once_with_exact_witness() {
        const OPERATION_ID: &str = "imp_11111111111111111111111111111111";
        let mut store = SqliteStore::open_in_memory().unwrap();
        let checked = store
            .create_program_version_with_import_witness_at_id(
                version("home-chosen"),
                &witness(LOCK),
                OPERATION_ID,
            )
            .unwrap();
        assert_eq!(checked.operation_id, OPERATION_ID);
        let exact = crate::RuntimeStore::program_import_operation(&store, OPERATION_ID)
            .unwrap()
            .unwrap();
        assert!(crate::RuntimeStore::program_import_operation(
            &store,
            "imp_ffffffffffffffffffffffffffffffff"
        )
        .unwrap()
        .is_none());
        assert_eq!(exact.version_id, checked.version_id);
        assert_eq!(
            exact.witness_digest.as_deref(),
            Some(checked.witness_digest.as_str())
        );
        assert_eq!(exact.kind, ProgramImportOperationKind::Checked);
        assert_eq!(
            store
                .create_program_version_with_import_witness_at_id(
                    version("home-chosen"),
                    &witness(LOCK),
                    OPERATION_ID,
                )
                .unwrap(),
            checked,
            "an exact retry recovers the one immutable target operation"
        );
        assert!(store
            .create_program_version_with_import_witness_at_id(
                version("home-chosen"),
                &witness(COMPILER),
                OPERATION_ID,
            )
            .is_err());

        assert!(store
            .create_program_version_with_import_witness_at_id(
                version("another-program"),
                &witness(LOCK),
                OPERATION_ID,
            )
            .is_err());
        assert!(store
            .create_program_version_with_import_witness_at_id(
                version("bad-id"),
                &witness(LOCK),
                "not-an-operation-id",
            )
            .is_err());
        let roster = store.program_import_operation_roster().unwrap();
        assert_eq!(
            roster.operations.len(),
            1,
            "retries never mint another operation"
        );
        assert!(store
            .connection
            .query_row(
                "SELECT program_id FROM programs WHERE name = 'another-program'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .unwrap()
            .is_none());
        store
            .connection
            .execute(
                "UPDATE program_import_admissions SET witness_json = '{}' \
                 WHERE version_id = ?1 AND witness_digest = ?2",
                rusqlite::params![checked.version_id, checked.witness_digest],
            )
            .unwrap();
        assert!(
            store
                .create_program_version_with_import_witness_at_id(
                    version("home-chosen"),
                    &witness(LOCK),
                    OPERATION_ID,
                )
                .is_err(),
            "an exact retry must inspect retained witness bytes"
        );
    }

    #[test]
    fn construct_capture_is_retained_with_its_accepting_operation_or_refused_atomically() {
        let use_form = ProgramConstructUse {
            occurrence: 0,
            keyword: "send".into(),
            scope: "rule_body".into(),
            family: "effect_operation".into(),
            lowering: "capability.call".into(),
            capability: "messaging.send".into(),
        };
        let edge = ProgramConstructEdge {
            use_form: use_form.clone(),
            registration_id: "messaging.send".into(),
            library_id: "std.messaging".into(),
            registration_version: "1".into(),
            provider_package: "std.messaging".into(),
            provider_source_digest: COMPILER.into(),
            meaning: ProgramConstructMeaning::LiveDependency,
        };
        let mut checked = witness(LOCK);
        let edges = vec![edge];
        let edge_digest = crate::items::sha256_hex(&serde_json::to_string(&edges).unwrap());
        checked.constructs = Some(ProgramConstructCapture {
            scope: ProgramConstructScope::RuleEffect,
            examined: vec![use_form],
            edges,
            edge_digest,
        });
        let mut store = SqliteStore::open_in_memory().unwrap();
        let admitted = store
            .create_program_version_with_import_witness(version("construct-checked"), &checked)
            .unwrap();
        assert_eq!(
            store
                .program_import_witness(&admitted.version_id, &admitted.witness_digest)
                .unwrap(),
            Some(checked.clone())
        );
        let roster = store.program_import_operation_roster().unwrap();
        assert_eq!(roster.operations.len(), 1);
        assert_eq!(
            roster.operations[0].witness_digest.as_deref(),
            Some(admitted.witness_digest.as_str())
        );

        let mut malformed = checked;
        malformed.constructs.as_mut().unwrap().edges[0].provider_source_digest =
            "not-a-digest".into();
        assert!(matches!(
            store.create_program_version_with_import_witness(version("construct-invalid"), &malformed),
            Err(StoreError::Conflict(message)) if message.contains("construct witness has incomplete or unordered edges")
        ));
        assert_eq!(store.program_import_operation_roster().unwrap(), roster);
        malformed.constructs.as_mut().unwrap().edges[0].provider_source_digest = COMPILER.into();
        malformed.constructs.as_mut().unwrap().edge_digest = LOCK.into();
        assert!(matches!(
            store.create_program_version_with_import_witness(version("construct-invalid"), &malformed),
            Err(StoreError::Conflict(message)) if message.contains("construct witness edge digest differs")
        ));
        assert_eq!(store.program_import_operation_roster().unwrap(), roster);
    }

    #[test]
    fn declaration_capture_is_distinct_from_unknown_and_refuses_malformed_edges_atomically() {
        let mut store = SqliteStore::open_in_memory().unwrap();
        let older = witness(LOCK);
        let older_json = serde_json::to_value(&older).unwrap();
        assert!(older_json.get("declarations").is_none());
        assert_eq!(
            serde_json::from_value::<ProgramImportWitness>(older_json)
                .unwrap()
                .declarations,
            None
        );

        let declaration = ProgramDeclarationUse {
            occurrence: 3,
            keyword: "source clock".into(),
            name: "daily".into(),
            scope: "top_level".into(),
            family: "source_declaration".into(),
            lowering: "clock_source".into(),
        };
        let edge = ProgramDeclarationEdge {
            declaration: declaration.clone(),
            registration_id: "time.clock_source".into(),
            library_id: "std.time".into(),
            registration_version: "0.1.0".into(),
            provider_package: "std.time".into(),
            provider_source_digest: COMPILER.into(),
            meaning: ProgramConstructMeaning::LiveDependency,
        };
        let edges = vec![edge];
        let mut checked = older;
        checked.declarations = Some(ProgramDeclarationCapture {
            examined: vec![declaration],
            edge_digest: crate::items::sha256_hex(&serde_json::to_string(&edges).unwrap()),
            edges,
        });
        let admitted = store
            .create_program_version_with_import_witness(version("declaration-checked"), &checked)
            .unwrap();
        assert_eq!(
            store
                .program_import_witness(&admitted.version_id, &admitted.witness_digest)
                .unwrap(),
            Some(checked.clone())
        );
        let roster = store.program_import_operation_roster().unwrap();
        assert_eq!(roster.operations.len(), 1);

        let mut malformed = checked.clone();
        malformed.declarations.as_mut().unwrap().edges[0]
            .declaration
            .name = "other".into();
        assert!(matches!(
            store.create_program_version_with_import_witness(version("declaration-invalid"), &malformed),
            Err(StoreError::Conflict(message)) if message.contains("declaration witness has incomplete or unordered edges")
        ));
        assert_eq!(store.program_import_operation_roster().unwrap(), roster);
        malformed = checked;
        malformed.declarations.as_mut().unwrap().edge_digest = LOCK.into();
        assert!(matches!(
            store.create_program_version_with_import_witness(version("declaration-invalid"), &malformed),
            Err(StoreError::Conflict(message)) if message.contains("declaration witness edge digest differs")
        ));
        assert_eq!(store.program_import_operation_roster().unwrap(), roster);

        let mut empty = witness(LOCK);
        empty.declarations = Some(ProgramDeclarationCapture {
            examined: Vec::new(),
            edges: Vec::new(),
            edge_digest: crate::items::sha256_hex("[]"),
        });
        let admitted = store
            .create_program_version_with_import_witness(version("declaration-empty"), &empty)
            .unwrap();
        assert_eq!(
            store
                .program_import_witness(&admitted.version_id, &admitted.witness_digest)
                .unwrap(),
            Some(empty)
        );
    }

    #[test]
    fn full_source_digest_binds_the_runtime_content_id() {
        let source = "use local.paint\nworkflow Paint\n";
        let mut witness = witness(LOCK);
        witness.program_source_digest = crate::items::sha256_hex(source);
        assert!(matches_source_id(&witness, &crate::stable_hash_hex(source)));
        assert!(matches_source_id(&witness, &witness.program_source_digest));
        assert!(!matches_source_id(&witness, ""));
        assert!(!matches_source_id(&witness, SOURCE_ID));
        assert!(!matches_source_id(&witness, SOURCE));
        assert!(!matches_source_id(
            &witness,
            &witness.program_source_digest[..63]
        ));
    }

    #[test]
    fn composite_version_source_retains_the_exact_program_source() {
        let mut checked = witness(LOCK);
        checked.version_source_digest = Some(NEXT_LOCK.into());
        assert!(matches_source_id(&checked, NEXT_LOCK));
        assert!(!matches_source_id(&checked, SOURCE));
        assert_eq!(checked.program_source_digest, SOURCE);
        assert!(encode(&checked).is_ok());
        checked.version_source_digest = Some("not-a-digest".into());
        assert!(encode(&checked).is_err());
    }

    #[test]
    fn malformed_digest_and_incomplete_edge_set_refuse_encoding() {
        let mut malformed = witness(LOCK);
        malformed.compiler_artifact_digest = "short".into();
        assert!(matches!(
            encode(&malformed),
            Err(StoreError::Conflict(message)) if message.contains("exact lowercase SHA-256 digest")
        ));
        let mut incomplete = witness(LOCK);
        incomplete.examined.push("local.unresolved".into());
        assert!(matches!(
            encode(&incomplete),
            Err(StoreError::Conflict(message)) if message.contains("incomplete or unordered edges")
        ));
    }

    #[test]
    fn exact_import_admissions_are_immutable_per_basis_even_when_version_is_reused() {
        let mut store = SqliteStore::open_in_memory().unwrap();
        let first_witness = witness(LOCK);
        let full_source = store
            .create_program_version_with_import_witness(
                NewProgramVersion {
                    source_hash: SOURCE,
                    ..version("hosted-full-source")
                },
                &first_witness,
            )
            .unwrap();
        assert_eq!(
            store
                .program_import_witness(&full_source.version_id, &full_source.witness_digest)
                .unwrap(),
            Some(first_witness.clone())
        );
        let first = store
            .create_program_version_with_import_witness(version("paint"), &first_witness)
            .unwrap();
        assert_eq!(
            store
                .program_import_witness(&first.version_id, &first.witness_digest)
                .unwrap(),
            Some(first_witness.clone())
        );
        let repeated = store
            .create_program_version_with_import_witness(version("paint"), &first_witness)
            .unwrap();
        assert_eq!(repeated.program_id, first.program_id);
        assert_eq!(repeated.version_id, first.version_id);
        assert_eq!(repeated.witness_digest, first.witness_digest);
        assert_ne!(repeated.operation_id, first.operation_id);
        let unwitnessed = store.create_program_version(version("paint")).unwrap();
        assert_eq!(unwitnessed.version_id, first.version_id);

        let changed_lock = witness(NEXT_LOCK);
        let second = store
            .create_program_version_with_import_witness(version("paint"), &changed_lock)
            .unwrap();
        assert_eq!(second.version_id, first.version_id);
        assert_ne!(second.witness_digest, first.witness_digest);
        assert_eq!(
            store
                .program_import_witness(&second.version_id, &second.witness_digest)
                .unwrap(),
            Some(changed_lock)
        );
        assert_eq!(
            store
                .program_import_witness(&first.version_id, &first.witness_digest)
                .unwrap(),
            Some(first_witness)
        );
        let rows: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM program_import_admissions",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 3);
        let roster = store.program_import_operation_roster().unwrap();
        assert_eq!(roster.frontier, roster.operations.last().unwrap().sequence);
        let operations: Vec<_> = roster
            .operations
            .iter()
            .filter(|operation| operation.version_id == first.version_id)
            .collect();
        assert_eq!(operations.len(), 4);
        assert_eq!(operations[0].operation_id, first.operation_id);
        assert_eq!(operations[1].operation_id, repeated.operation_id);
        assert_eq!(operations[3].operation_id, second.operation_id);
        assert!(operations
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence));
        assert_eq!(
            operations
                .iter()
                .filter(|operation| operation.kind == ProgramImportOperationKind::Checked)
                .count(),
            3
        );
        assert_eq!(
            operations
                .iter()
                .filter(|operation| {
                    operation.kind == ProgramImportOperationKind::Unwitnessed
                        && operation.witness_digest.is_none()
                })
                .count(),
            1
        );
        store
            .connection
            .execute(
                "UPDATE program_versions SET source_hash = ?1 WHERE version_id = ?2",
                rusqlite::params!["eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", &first.version_id],
            )
            .unwrap();
        assert!(matches!(
            store.program_import_witness(&first.version_id, &first.witness_digest),
            Err(StoreError::Conflict(message)) if message.contains("differs from its version")
        ));
    }

    #[test]
    fn bad_import_witness_rolls_back_the_program_version() {
        let mut store = SqliteStore::open_in_memory().unwrap();
        let mut bad = witness(LOCK);
        bad.edge_digest = NEXT_LOCK.into();
        assert!(matches!(
            store.create_program_version_with_import_witness(version("bad"), &bad),
            Err(StoreError::Conflict(message)) if message.contains("edge digest differs")
        ));
        let mut wrong_source = witness(LOCK);
        wrong_source.program_source_digest = NEXT_LOCK.into();
        assert!(matches!(
            store.create_program_version_with_import_witness(version("wrong-source"), &wrong_source),
            Err(StoreError::Conflict(message)) if message.contains("program source differs")
        ));
        let rows: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM program_versions", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rows, 0);
        let operations: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM program_import_operations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(operations, 0);
    }

    #[test]
    fn checked_reattestation_moves_the_instance_with_its_import_witness() {
        let mut store = SqliteStore::open_in_memory().unwrap();
        let first = store
            .create_program_version_with_import_witness(version("rechecked"), &witness(LOCK))
            .unwrap();
        let instance = store
            .create_instance(NewInstance {
                program_id: &first.program_id,
                version_id: &first.version_id,
                input_json: "{}",
            })
            .unwrap();
        let before_checked_refusals = store.program_import_operation_roster().unwrap();
        assert!(matches!(
            store.reattest_instance_program_with_import_witness(
                "missing-instance",
                NewProgramVersion {
                    ir_hash: NEXT_LOCK,
                    ..version("rechecked")
                },
                &witness(LOCK),
            ),
            Err(StoreError::Conflict(message)) if message.contains("unknown instance")
        ));
        assert!(matches!(
            store.reattest_instance_program_with_import_witness(
                &instance.instance_id,
                NewProgramVersion {
                    source_hash: NEXT_LOCK,
                    ir_hash: NEXT_LOCK,
                    ..version("rechecked")
                },
                &witness(LOCK),
            ),
            Err(StoreError::Conflict(message)) if message.contains("same authored program")
        ));
        assert!(matches!(
            store.reattest_instance_program_with_import_witness(
                &instance.instance_id,
                version("rechecked"),
                &witness(LOCK),
            ),
            Err(StoreError::Conflict(message)) if message.contains("changed compiler IR")
        ));
        let mut wrong_source = witness(LOCK);
        wrong_source.program_source_digest = NEXT_LOCK.into();
        assert!(matches!(
            store.reattest_instance_program_with_import_witness(
                &instance.instance_id,
                NewProgramVersion {
                    ir_hash: NEXT_LOCK,
                    ..version("rechecked")
                },
                &wrong_source,
            ),
            Err(StoreError::Conflict(message)) if message.contains("program source differs")
        ));
        assert_eq!(
            store.program_import_operation_roster().unwrap(),
            before_checked_refusals
        );
        assert_eq!(
            store
                .get_instance(&instance.instance_id)
                .unwrap()
                .unwrap()
                .version_id,
            first.version_id
        );
        let changed = NewProgramVersion {
            ir_hash: NEXT_LOCK,
            ..version("rechecked")
        };
        let checked = store
            .reattest_instance_program_with_import_witness(
                &instance.instance_id,
                changed,
                &witness(LOCK),
            )
            .unwrap();
        assert_ne!(checked.version_id, first.version_id);
        assert_eq!(
            store
                .get_instance(&instance.instance_id)
                .unwrap()
                .unwrap()
                .version_id,
            checked.version_id
        );
        assert_eq!(
            store
                .program_import_witness(&checked.version_id, &checked.witness_digest)
                .unwrap(),
            Some(witness(LOCK))
        );
        let roster = store.program_import_operation_roster().unwrap();
        assert_eq!(roster.operations.len(), 2);
        assert_eq!(roster.operations[1].operation_id, checked.operation_id);
        assert_eq!(
            roster.operations[1].kind,
            ProgramImportOperationKind::Checked
        );
        assert_eq!(
            roster.operations[1].witness_digest.as_deref(),
            Some(checked.witness_digest.as_str())
        );

        let mut bad = witness(LOCK);
        bad.edge_digest = NEXT_LOCK.into();
        let refused = store.reattest_instance_program_with_import_witness(
            &instance.instance_id,
            NewProgramVersion {
                ir_hash: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                ..version("rechecked")
            },
            &bad,
        );
        assert!(refused.is_err());
        assert_eq!(store.program_import_operation_roster().unwrap(), roster);
        assert_eq!(
            store
                .get_instance(&instance.instance_id)
                .unwrap()
                .unwrap()
                .version_id,
            checked.version_id
        );
    }

    #[test]
    fn migration_keeps_prior_acceptance_unknown_after_version_reuse() {
        let mut store = SqliteStore::open_in_memory().unwrap();
        let first = store
            .create_program_version_with_import_witness(version("old"), &witness(LOCK))
            .unwrap();
        // Model an existing store stamped before operation tracking. Its
        // earlier checked witness says nothing about each old accepting call.
        store
            .connection
            .execute_batch(
                "DROP TABLE program_import_operations;
                 DELETE FROM schema_migrations WHERE version = 6;",
            )
            .unwrap();
        crate::initialize_runtime_schema_on(&store.connection).unwrap();
        let prior = store.program_import_operation_roster().unwrap();
        assert_eq!(prior.operations.len(), 1);
        assert_eq!(
            prior.operations[0].kind,
            ProgramImportOperationKind::LegacyGap
        );
        store
            .create_program_version_with_import_witness(version("old"), &witness(LOCK))
            .unwrap();
        let current = store.program_import_operation_roster().unwrap();
        assert!(current.frontier > prior.frontier);
        let rows: Vec<_> = current
            .operations
            .into_iter()
            .map(|operation| (operation.version_id, operation.kind))
            .collect();
        assert_eq!(
            rows,
            [
                (
                    first.version_id.clone(),
                    ProgramImportOperationKind::LegacyGap
                ),
                (first.version_id, ProgramImportOperationKind::Checked)
            ]
        );
    }
}
