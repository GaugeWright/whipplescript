//! Recorded execution compatibility, independent of the source default.
//!
//! Add a supported path only with executable lowering and replay witnesses.
//! Recognizing a future source grammar is not support for executing its tag.

use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ExecutionSemantics {
    #[serde(rename = "dr0023-action-chains-v1")]
    LegacyActionChainsV1,
    /// Executable identity for the managed action-scope machine.
    #[serde(rename = "dr0100-typed-actions-v1")]
    TypedActionsV1,
}

impl ExecutionSemantics {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LegacyActionChainsV1 => "dr0023-action-chains-v1",
            Self::TypedActionsV1 => "dr0100-typed-actions-v1",
        }
    }

    /// Absence is the historical contract, never the current source default.
    pub fn from_recorded_tag(tag: Option<&str>) -> Result<Self, UnsupportedExecutionSemantics> {
        match tag {
            None | Some("dr0023-action-chains-v1") => Ok(Self::LegacyActionChainsV1),
            Some("dr0100-typed-actions-v1") => Ok(Self::TypedActionsV1),
            Some(tag) => Err(UnsupportedExecutionSemantics(format!(
                "unsupported recorded execution semantics {tag:?}"
            ))),
        }
    }

    /// Preserve historical identity bytes. Every new path must make an explicit
    /// choice here, and must include its tag in the executable identity.
    pub(crate) fn snapshot_tag(self) -> Option<&'static str> {
        match self {
            Self::LegacyActionChainsV1 => None,
            Self::TypedActionsV1 => Some("dr0100-typed-actions-v1"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsupportedExecutionSemantics(String);

impl fmt::Display for UnsupportedExecutionSemantics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UnsupportedExecutionSemantics {}

/// Runtime compatibility entry point. Hosts obtain `semantics` from stored
/// analysis metadata; source authors cannot select an alternate dialect.
pub fn compile_recorded_program_with_root(
    source: &str,
    root: Option<&str>,
    semantics: ExecutionSemantics,
) -> crate::CompileOutput {
    crate::compile_with_execution_semantics(source, root, semantics)
}
