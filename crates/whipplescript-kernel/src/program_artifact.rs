//! Complete compiler output, distinct from the diagnostic snapshot. Decoding
//! restores checked data; the immutable version/content owner supplies trust.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use whipplescript_parser::{action_plan::resolved::TypedActionPlan, ExecutionSemantics, IrProgram};

pub const FORMAT: &str = "whipplescript-executable-program/v1";
pub const TYPED_FORMAT: &str = "whipplescript-executable-program/v2";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    format: String,
    source_hash: String,
    ir_hash: String,
    program: IrProgram,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TypedArtifact {
    format: String,
    source_hash: String,
    ir_hash: String,
    program: IrProgram,
    typed_actions: BTreeMap<String, TypedActionPlan>,
}

#[derive(Serialize)]
struct TypedIdentity<'a> {
    format: &'static str,
    ir_identity: String,
    typed_actions: &'a BTreeMap<String, TypedActionPlan>,
}

const TYPED_IDENTITY_FORMAT: &str = "whipplescript-executable-identity/v1";

/// Complete compiler output restored from an immutable version artifact.
/// Legacy v1 programs have no managed plans; typed v2 programs carry exactly
/// one checked plan for every lowered rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutableProgram {
    pub(crate) program: IrProgram,
    pub(crate) typed_actions: BTreeMap<String, TypedActionPlan>,
}

impl ExecutableProgram {
    pub fn program(&self) -> &IrProgram {
        &self.program
    }

    pub fn typed_actions(&self) -> &BTreeMap<String, TypedActionPlan> {
        &self.typed_actions
    }

    pub fn identity_hash(&self) -> Result<String, String> {
        self.validate()?;
        let identity = match self.program.execution_semantics {
            ExecutionSemantics::LegacyActionChainsV1 => self.program.to_snapshot(),
            ExecutionSemantics::TypedActionsV1 => {
                typed_identity_projection(&self.program, &self.typed_actions)?
            }
        };
        Ok(whipplescript_parser::snapshot::identity_hash(&identity))
    }

    /// Re-check the structural dispatch boundary on the kernel-owned value.
    pub fn validate(&self) -> Result<(), String> {
        match self.program.execution_semantics {
            ExecutionSemantics::LegacyActionChainsV1 if self.typed_actions.is_empty() => Ok(()),
            ExecutionSemantics::LegacyActionChainsV1 => {
                Err("legacy executable program cannot carry typed action plans".into())
            }
            ExecutionSemantics::TypedActionsV1 => {
                validate_typed_program(&self.program, &self.typed_actions)
            }
        }
    }
}

/// The identities of the immutable version requesting this captured program.
pub struct Expected<'a> {
    pub source_hash: &'a str,
    pub ir_hash: &'a str,
    pub workflow: &'a str,
    pub semantics: ExecutionSemantics,
}

/// The read side of an immutable program version. Hosts use the same result
/// for execution and inspection, so an old firing can never be explained by
/// recompiling today's source or silently falling back after a corrupt capture.
pub enum RecordedLoad {
    Ready(Box<ExecutableProgram>),
    Unavailable(String),
}

/// Decode the execution selector and executable reference stored in a program
/// version's analysis summary. Only absence selects the historical semantics;
/// a malformed or non-string selector is an unavailable version.
pub fn recorded_execution_metadata(
    analysis: &str,
) -> Result<
    (
        whipplescript_parser::ExecutionSemantics,
        Option<serde_json::Value>,
    ),
    String,
> {
    let value: serde_json::Value = serde_json::from_str(analysis)
        .map_err(|_| "its analysis metadata is not valid JSON".to_owned())?;
    let object = value
        .as_object()
        .ok_or_else(|| "its analysis metadata is not an object".to_owned())?;
    let tag = match object.get("execution_semantics") {
        None => None,
        Some(serde_json::Value::String(tag)) => Some(tag.as_str()),
        Some(_) => return Err("its execution_semantics tag is not a string".to_owned()),
    };
    let semantics = whipplescript_parser::ExecutionSemantics::from_recorded_tag(tag)
        .map_err(|error| error.to_string())?;
    Ok((semantics, object.get("executable_program").cloned()))
}

/// Load one exact recorded program version without mutating runtime state.
/// Typed versions require their complete captured executable. Old legacy
/// versions may use their content-addressed source only when no capture was
/// ever recorded, preserving the pre-capture compatibility contract.
pub fn load_recorded_version<S: RuntimeStore>(
    store: &S,
    version_id: &str,
) -> StoreResult<RecordedLoad> {
    let Some(view) = store.get_program_version(version_id)? else {
        return Ok(RecordedLoad::Unavailable(
            "the version record is missing".into(),
        ));
    };
    let (semantics, artifact) = match recorded_execution_metadata(&view.analysis_summary_json) {
        Ok(metadata) => metadata,
        Err(detail) => return Ok(RecordedLoad::Unavailable(detail)),
    };
    match load(
        store,
        artifact.as_ref(),
        Expected {
            source_hash: &view.source_hash,
            ir_hash: &view.ir_hash,
            workflow: &view.program_name,
            semantics,
        },
    )? {
        Load::Ready(executable) => return Ok(RecordedLoad::Ready(executable)),
        Load::Unavailable(detail) => return Ok(RecordedLoad::Unavailable(detail)),
        Load::Absent => {}
    }
    if semantics != whipplescript_parser::ExecutionSemantics::LegacyActionChainsV1 {
        return Ok(RecordedLoad::Unavailable(
            "the typed executable capture is absent".into(),
        ));
    }
    let Some(source) = store.get_content(&view.source_hash)? else {
        return Ok(RecordedLoad::Unavailable(
            "its source is not in the content store (the version was never driven since source pinning landed)".into(),
        ));
    };
    let compiled = whipplescript_parser::execution_semantics::compile_recorded_program_with_root(
        &source,
        Some(&view.program_name),
        semantics,
    );
    Ok(match compiled.ir {
        Some(program) => RecordedLoad::Ready(Box::new(ExecutableProgram {
            program,
            typed_actions: BTreeMap::new(),
        })),
        None => RecordedLoad::Unavailable("its stored source no longer compiles".into()),
    })
}

pub fn encode(program: &IrProgram, source_hash: &str) -> Result<String, String> {
    if program.execution_semantics != ExecutionSemantics::LegacyActionChainsV1 {
        return Err("legacy executable program format cannot carry typed action semantics".into());
    }
    let ir_hash = whipplescript_parser::snapshot::identity_hash(&program.to_snapshot());
    let artifact = Artifact {
        format: FORMAT.into(),
        source_hash: source_hash.into(),
        ir_hash: ir_hash.clone(),
        program: program.clone(),
    };
    let bytes = encode_legacy_artifact(&artifact)?;
    decode(
        &bytes,
        Expected {
            source_hash,
            ir_hash: &ir_hash,
            workflow: &program.workflow,
            semantics: program.execution_semantics,
        },
    )?;
    Ok(bytes)
}

pub fn encode_typed(
    program: &IrProgram,
    typed_actions: &BTreeMap<String, TypedActionPlan>,
    source_hash: &str,
) -> Result<String, String> {
    validate_typed_program(program, typed_actions)?;
    let identity = typed_identity_projection(program, typed_actions)?;
    let ir_hash = whipplescript_parser::snapshot::identity_hash(&identity);
    let artifact = TypedArtifact {
        format: TYPED_FORMAT.into(),
        source_hash: source_hash.into(),
        ir_hash: ir_hash.clone(),
        program: program.clone(),
        typed_actions: typed_actions.clone(),
    };
    let bytes = serde_json::to_string(&artifact).map_err(|e| format!("executable program: {e}"))?;
    decode(
        &bytes,
        Expected {
            source_hash,
            ir_hash: &ir_hash,
            workflow: &program.workflow,
            semantics: program.execution_semantics,
        },
    )?;
    Ok(bytes)
}

pub fn decode(bytes: &str, expected: Expected<'_>) -> Result<ExecutableProgram, String> {
    match artifact_format(bytes)?.as_str() {
        FORMAT => decode_legacy(bytes, expected),
        TYPED_FORMAT => decode_typed(bytes, expected),
        _ => Err("unsupported executable program format".into()),
    }
}

fn decode_legacy(bytes: &str, expected: Expected<'_>) -> Result<ExecutableProgram, String> {
    let artifact: Artifact =
        serde_json::from_str(bytes).map_err(|e| format!("executable program: {e}"))?;
    // Round-trip canonicality also refuses missing optional fields and data
    // serde could otherwise discard. The writer is the sole byte producer.
    if encode_legacy_artifact(&artifact)? != bytes {
        // MUTATION-SUCCESS-EXPR: Ok(ExecutableProgram { program: artifact.program.clone(), typed_actions: BTreeMap::new() })
        return Err("executable program is not its complete canonical encoding".into());
    }
    if artifact.source_hash != expected.source_hash
        || artifact.ir_hash != expected.ir_hash
        || artifact.program.workflow != expected.workflow
        || artifact.program.execution_semantics != expected.semantics
        || whipplescript_parser::snapshot::identity_hash(&artifact.program.to_snapshot())
            != expected.ir_hash
    {
        // MUTATION-SUCCESS-EXPR: Ok(ExecutableProgram { program: artifact.program.clone(), typed_actions: BTreeMap::new() })
        return Err("executable program differs from its recorded version".into());
    }
    if artifact.program.execution_semantics != ExecutionSemantics::LegacyActionChainsV1 {
        // MUTATION-SUCCESS-EXPR: Ok(ExecutableProgram { program: artifact.program.clone(), typed_actions: BTreeMap::new() })
        return Err("executable program format does not match its execution semantics".into());
    }
    Ok(ExecutableProgram {
        program: artifact.program,
        typed_actions: BTreeMap::new(),
    })
}

/// Preserve the frozen v1 wire shape while the live IR uses the plural
/// resource projection required by composed actions. A legacy effect can name
/// at most one resource; typed v2 artifacts serialize `resources` directly.
fn encode_legacy_artifact(artifact: &Artifact) -> Result<String, String> {
    let encoded =
        serde_json::to_string(artifact).map_err(|e| format!("executable program: {e}"))?;
    let key = "\"resources\":";
    let mut rewritten = String::with_capacity(encoded.len());
    let mut cursor = 0;

    while let Some(relative_start) = encoded[cursor..].find(key) {
        let key_start = cursor + relative_start;
        let value_start = key_start + key.len();
        rewritten.push_str(&encoded[cursor..key_start]);
        rewritten.push_str("\"resource\":");

        let mut values =
            serde_json::Deserializer::from_str(&encoded[value_start..]).into_iter::<Vec<String>>();
        let resources = values
            .next()
            .transpose()
            .map_err(|e| format!("executable program: {e}"))?
            .ok_or_else(|| "executable program: resource list is missing".to_owned())?;
        let consumed = values.byte_offset();
        match resources.as_slice() {
            [] => rewritten.push_str("null"),
            [resource] => rewritten.push_str(
                &serde_json::to_string(resource).map_err(|e| format!("executable program: {e}"))?,
            ),
            _ => {
                return Err(
                    "legacy executable program effect cannot carry multiple resources".into(),
                )
            }
        }
        cursor = value_start + consumed;
    }
    rewritten.push_str(&encoded[cursor..]);
    Ok(rewritten)
}

fn decode_typed(bytes: &str, expected: Expected<'_>) -> Result<ExecutableProgram, String> {
    let artifact: TypedArtifact =
        serde_json::from_str(bytes).map_err(|e| format!("executable program: {e}"))?;
    if artifact.format != TYPED_FORMAT {
        // MUTATION-SUCCESS-EXPR: Ok(ExecutableProgram { program: artifact.program.clone(), typed_actions: artifact.typed_actions.clone() })
        return Err("unsupported executable program format".into());
    }
    if serde_json::to_string(&artifact).map_err(|e| e.to_string())? != bytes {
        // MUTATION-SUCCESS-EXPR: Ok(ExecutableProgram { program: artifact.program.clone(), typed_actions: artifact.typed_actions.clone() })
        return Err("executable program is not its complete canonical encoding".into());
    }
    if artifact.source_hash != expected.source_hash
        || artifact.ir_hash != expected.ir_hash
        || artifact.program.workflow != expected.workflow
        || artifact.program.execution_semantics != expected.semantics
        || whipplescript_parser::snapshot::identity_hash(&typed_identity_projection(
            &artifact.program,
            &artifact.typed_actions,
        )?) != expected.ir_hash
    {
        // MUTATION-SUCCESS-EXPR: Ok(ExecutableProgram { program: artifact.program.clone(), typed_actions: artifact.typed_actions.clone() })
        return Err("executable program differs from its recorded version".into());
    }
    validate_typed_program(&artifact.program, &artifact.typed_actions)?;
    Ok(ExecutableProgram {
        program: artifact.program,
        typed_actions: artifact.typed_actions,
    })
}

fn artifact_format(bytes: &str) -> Result<String, String> {
    let value: serde_json::Value =
        serde_json::from_str(bytes).map_err(|e| format!("executable program: {e}"))?;
    value
        .as_object()
        .and_then(|object| object.get("format"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "executable program: format is missing or not a string".into())
}

/// Canonical identity document for the new execution machine. The managed
/// plans participate in version identity alongside the diagnostic IR
/// projection, so changing a plan can never retain the old executable hash.
pub fn typed_identity_projection(
    program: &IrProgram,
    typed_actions: &BTreeMap<String, TypedActionPlan>,
) -> Result<String, String> {
    validate_typed_program(program, typed_actions)?;
    serde_json::to_string(&TypedIdentity {
        format: TYPED_IDENTITY_FORMAT,
        ir_identity: whipplescript_parser::snapshot::identity_projection(&program.to_snapshot()),
        typed_actions,
    })
    .map_err(|e| format!("typed executable identity: {e}"))
}

/// Canonical executable identity for compiler output. This is the one public
/// choice point shared by publishers, so a typed plan map cannot be captured
/// under the diagnostic-only legacy IR hash.
pub fn identity_projection(
    program: &IrProgram,
    typed_actions: Option<&BTreeMap<String, TypedActionPlan>>,
) -> Result<String, String> {
    match (program.execution_semantics, typed_actions) {
        (ExecutionSemantics::LegacyActionChainsV1, None) => Ok(
            whipplescript_parser::snapshot::identity_projection(&program.to_snapshot()),
        ),
        (ExecutionSemantics::TypedActionsV1, Some(typed_actions)) => {
            typed_identity_projection(program, typed_actions)
        }
        (ExecutionSemantics::LegacyActionChainsV1, Some(_)) => {
            Err("legacy compiler output cannot carry typed action plans".into())
        }
        (ExecutionSemantics::TypedActionsV1, None) => {
            Err("typed compiler output is missing its action plans".into())
        }
    }
}

fn validate_typed_program(
    program: &IrProgram,
    typed_actions: &BTreeMap<String, TypedActionPlan>,
) -> Result<(), String> {
    if program.execution_semantics != ExecutionSemantics::TypedActionsV1 {
        return Err("typed executable program requires typed action semantics".into());
    }
    let expected: BTreeSet<_> = program
        .rules
        .iter()
        .map(|rule| rule.name.as_str())
        .collect();
    let actual: BTreeSet<_> = typed_actions.keys().map(String::as_str).collect();
    if program.rules.len() != typed_actions.len() || actual != expected {
        return Err("typed executable program must carry exactly one plan for every rule".into());
    }
    for (rule, typed) in typed_actions {
        typed.validate_structure()?;
        if typed.plan.root_rule.as_ref().map(|root| root.name.as_str()) != Some(rule.as_str()) {
            return Err(format!(
                "typed executable plan `{rule}` does not name its owning rule"
            ));
        }
    }
    Ok(())
}

use crate::ProgramVersionInput;
use whipplescript_store::{RuntimeStore, StoreError, StoreResult};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    format: String,
    content_hash: String,
}

/// Create the blob before publishing its reference in an immutable version.
/// An orphaned content-addressed blob is not an executable version.
pub(crate) fn capture<S: RuntimeStore>(
    store: &S,
    input: &ProgramVersionInput<'_>,
    program: &IrProgram,
) -> StoreResult<String> {
    let summary = crate::program_analysis_summary_json(program);
    let Some(snapshot) = input.ir_snapshot else {
        return Ok(summary);
    };
    let identity = whipplescript_parser::snapshot::identity_projection(&program.to_snapshot());
    if input.program_name != program.workflow
        || snapshot != identity
        || crate::stable_hash_hex(&identity) != input.ir_hash
    {
        // MUTATION-SUCCESS-EXPR: Ok(summary)
        return Err(StoreError::Conflict(
            "program capture identity mismatch".into(),
        ));
    }
    let bytes = encode(program, input.source_hash).map_err(invalid)?;
    let reference = Reference {
        format: FORMAT.into(),
        content_hash: store.put_content(&bytes)?,
    };
    let mut summary: serde_json::Value =
        serde_json::from_str(&summary).map_err(|e| invalid(e.to_string()))?;
    summary
        .as_object_mut()
        .expect("generated program summary is an object")
        .insert(
            "executable_program".into(),
            serde_json::to_value(reference).map_err(|e| invalid(e.to_string()))?,
        );
    Ok(summary.to_string())
}

/// Capture the complete managed executable beside the legacy path. Runtime
/// recorded-semantics selection remains gated until the typed rule-pass driver
/// consumes the returned plans.
pub fn capture_typed<S: RuntimeStore>(
    store: &S,
    input: &ProgramVersionInput<'_>,
    program: &IrProgram,
    typed_actions: &BTreeMap<String, TypedActionPlan>,
) -> StoreResult<String> {
    capture_bytes(
        store,
        input,
        program,
        typed_actions,
        TYPED_FORMAT,
        encode_typed(program, typed_actions, input.source_hash),
    )
}

fn capture_bytes<S: RuntimeStore>(
    store: &S,
    input: &ProgramVersionInput<'_>,
    program: &IrProgram,
    typed_actions: &BTreeMap<String, TypedActionPlan>,
    format: &str,
    encoded: Result<String, String>,
) -> StoreResult<String> {
    let summary = crate::program_analysis_summary_json(program);
    let Some(snapshot) = input.ir_snapshot else {
        // MUTATION-SUCCESS-EXPR: Ok(summary)
        return Err(StoreError::Conflict(
            "typed program capture requires its verified identity snapshot".into(),
        ));
    };
    let identity = typed_identity_projection(program, typed_actions).map_err(invalid)?;
    if input.program_name != program.workflow
        || snapshot != identity
        || crate::stable_hash_hex(&identity) != input.ir_hash
    {
        return Err(StoreError::Conflict(
            "program capture identity mismatch".into(),
        ));
    }
    let bytes = encoded.map_err(invalid)?;
    let reference = Reference {
        format: format.into(),
        content_hash: store.put_content(&bytes)?,
    };
    let mut summary: serde_json::Value =
        serde_json::from_str(&summary).map_err(|e| invalid(e.to_string()))?;
    summary
        .as_object_mut()
        .expect("generated program summary is an object")
        .insert(
            "executable_program".into(),
            serde_json::to_value(reference).map_err(|e| invalid(e.to_string()))?,
        );
    Ok(summary.to_string())
}
fn invalid(message: String) -> StoreError {
    StoreError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message,
    ))
}

pub(crate) enum Load {
    Absent,
    Ready(Box<ExecutableProgram>),
    Unavailable(String),
}

/// Absence alone permits the legacy source path. A present, unreadable capture
/// is an unavailable version, never permission to reinterpret its source.
pub(crate) fn load<S: RuntimeStore>(
    store: &S,
    reference: Option<&serde_json::Value>,
    expected: Expected<'_>,
) -> StoreResult<Load> {
    let Some(raw) = reference else {
        return Ok(Load::Absent);
    };
    let reference: Reference = match serde_json::from_value(raw.clone()) {
        Ok(reference) => reference,
        Err(e) => {
            return Ok(Load::Unavailable(format!(
                "invalid program artifact reference: {e}"
            )))
        }
    };
    if reference.format != FORMAT && reference.format != TYPED_FORMAT {
        return Ok(Load::Unavailable(
            "unsupported program artifact reference format".into(),
        ));
    }
    let Some(bytes) = store.get_content(&reference.content_hash)? else {
        return Ok(Load::Unavailable(
            "captured executable program is missing from the content store".into(),
        ));
    };
    if crate::stable_hash_hex(&bytes) != reference.content_hash {
        return Ok(Load::Unavailable(
            "captured executable program content hash does not match".into(),
        ));
    }
    if let Ok(format) = artifact_format(&bytes) {
        if matches!(format.as_str(), FORMAT | TYPED_FORMAT) && format != reference.format {
            return Ok(Load::Unavailable(
                "program artifact reference format does not match its content".into(),
            ));
        }
    }
    Ok(match decode(&bytes, expected) {
        Ok(program) => Load::Ready(Box::new(program)),
        Err(issue) => Load::Unavailable(issue),
    })
}

#[cfg(any(test, feature = "test-support"))]
pub mod conformance;
#[cfg(test)]
mod tests;
