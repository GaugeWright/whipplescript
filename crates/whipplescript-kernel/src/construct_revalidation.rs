//! Current-basis revalidation of retained RC-3 construct edges.
//!
//! An admission retains each construct and declaration edge with the exact
//! registration and provider source it resolved against. That evidence is
//! about the basis the admission saw; it does not say the edge still holds.
//! This pure check compares each retained edge with a caller-supplied current
//! basis and reports it `Current` only when the same registration, unchanged
//! in identity and shape, and the same provider source are still the ones the
//! current basis resolves. Any drift makes that edge unknown. It never
//! re-resolves an edge to a newer registration: a moved edge is not the edge
//! that was admitted, and calling it current would launder the move.
//!
//! An unknown class (`None` in the witness) stays unknown. The check covers
//! the two retained classes only and makes no Home-wide claim.

use serde::Serialize;
use whipplescript_core::{ConstructRegistration, ContractRegistry};
use whipplescript_store::program_imports::{
    ProgramConstructEdge, ProgramDeclarationEdge, ProgramImportWitness,
};

use crate::construct_coverage::ResolvedConstructSource;
use crate::exec_http::sha256_hex;

/// The basis a retained edge is judged against: the registry and provider
/// sources the current host would admit the same checked program under.
pub struct CurrentConstructBasis<'a> {
    pub registry: &'a ContractRegistry,
    pub compiler_artifact_digest: &'a str,
    pub sources: &'a [ResolvedConstructSource<'a>],
}

/// Why a retained edge is no longer known to hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstructEdgeDrift {
    /// The current registry has no registration with the retained id.
    RegistrationAbsent,
    /// The current registry has more than one registration with that id.
    RegistrationAmbiguous,
    /// The registration's library, version or construct shape moved.
    RegistrationChanged,
    /// A rule-effect edge's `capability.call` contract is gone.
    EffectContractAbsent,
    /// No current source owns the retained package provider.
    ProviderSourceUnavailable,
    /// More than one current source owns the retained package provider.
    ProviderSourceAmbiguous,
    /// The provider's source (or, for std, the compiler artifact) moved.
    ProviderSourceChanged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "standing", content = "drift", rename_all = "snake_case")]
pub enum ConstructEdgeStanding {
    Current,
    Unknown(ConstructEdgeDrift),
}

/// Per-edge standing, in retained edge order. `None` is a class the witness
/// never examined, which no current basis can make known.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RetainedConstructStanding {
    pub constructs: Option<Vec<ConstructEdgeStanding>>,
    pub declarations: Option<Vec<ConstructEdgeStanding>>,
}

impl RetainedConstructStanding {
    /// True only when both classes were examined and every edge holds.
    pub fn all_current(&self) -> bool {
        [&self.constructs, &self.declarations]
            .into_iter()
            .all(|class| {
                class.as_ref().is_some_and(|edges| {
                    edges
                        .iter()
                        .all(|edge| *edge == ConstructEdgeStanding::Current)
                })
            })
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn require_edge_digest<T: Serialize>(edges: &[T], digest: &str, class: &str) -> Result<(), String> {
    let json = serde_json::to_vec(edges).map_err(|error| error.to_string())?;
    if sha256_hex(&json) == digest {
        Ok(())
    } else {
        Err(format!("retained {class} edges do not match their digest"))
    }
}

/// The one current registration carrying `id`, or why there is none.
fn registration<'a>(
    registry: &'a ContractRegistry,
    id: &str,
) -> Result<&'a ConstructRegistration, ConstructEdgeDrift> {
    let mut matches = registry.constructs.iter().filter(|form| form.id == id);
    let form = matches
        .next()
        .ok_or(ConstructEdgeDrift::RegistrationAbsent)?;
    if matches.next().is_some() {
        return Err(ConstructEdgeDrift::RegistrationAmbiguous);
    }
    Ok(form)
}

fn provider(
    current: &CurrentConstructBasis<'_>,
    library_id: &str,
    provider_package: &str,
    provider_source_digest: &str,
) -> ConstructEdgeStanding {
    let current_digest = if library_id.starts_with("std.") {
        if provider_package != library_id {
            return ConstructEdgeStanding::Unknown(ConstructEdgeDrift::ProviderSourceChanged);
        }
        current.compiler_artifact_digest
    } else {
        let mut owners = current.sources.iter().filter(|source| {
            source.library_id == library_id && source.package_name == provider_package
        });
        let Some(owner) = owners.next() else {
            return ConstructEdgeStanding::Unknown(ConstructEdgeDrift::ProviderSourceUnavailable);
        };
        if owners.next().is_some() {
            return ConstructEdgeStanding::Unknown(ConstructEdgeDrift::ProviderSourceAmbiguous);
        }
        owner.source_digest
    };
    if current_digest == provider_source_digest {
        ConstructEdgeStanding::Current
    } else {
        ConstructEdgeStanding::Unknown(ConstructEdgeDrift::ProviderSourceChanged)
    }
}

fn construct_edge(
    edge: &ProgramConstructEdge,
    current: &CurrentConstructBasis<'_>,
) -> ConstructEdgeStanding {
    let form = match registration(current.registry, &edge.registration_id) {
        Ok(form) => form,
        Err(drift) => return ConstructEdgeStanding::Unknown(drift),
    };
    let use_form = &edge.use_form;
    if form.library_id != edge.library_id
        || form.version != edge.registration_version
        || form.keyword != use_form.keyword
        || form.scope != use_form.scope
        || form.construct_family != use_form.family
        || form.lowering_target != use_form.lowering
        || form.target_capability.as_deref() != Some(use_form.capability.as_str())
    {
        return ConstructEdgeStanding::Unknown(ConstructEdgeDrift::RegistrationChanged);
    }
    if !current.registry.effect_contracts.iter().any(|contract| {
        contract.id == use_form.capability && contract.effect_kind == "capability.call"
    }) {
        return ConstructEdgeStanding::Unknown(ConstructEdgeDrift::EffectContractAbsent);
    }
    provider(
        current,
        &edge.library_id,
        &edge.provider_package,
        &edge.provider_source_digest,
    )
}

fn declaration_edge(
    edge: &ProgramDeclarationEdge,
    current: &CurrentConstructBasis<'_>,
) -> ConstructEdgeStanding {
    let form = match registration(current.registry, &edge.registration_id) {
        Ok(form) => form,
        Err(drift) => return ConstructEdgeStanding::Unknown(drift),
    };
    let declaration = &edge.declaration;
    if form.library_id != edge.library_id
        || form.version != edge.registration_version
        || form.keyword != declaration.keyword
        || form.scope != declaration.scope
        || form.construct_family != declaration.family
        || form.lowering_target != declaration.lowering
        || form.target_capability.is_some()
    {
        return ConstructEdgeStanding::Unknown(ConstructEdgeDrift::RegistrationChanged);
    }
    provider(
        current,
        &edge.library_id,
        &edge.provider_package,
        &edge.provider_source_digest,
    )
}

/// Judge every retained edge of `witness` against `current`. A witness whose
/// retained edges no longer match their own digest is refused rather than
/// judged, and so is a current basis without an exact compiler identity.
pub fn revalidate(
    witness: &ProgramImportWitness,
    current: &CurrentConstructBasis<'_>,
) -> Result<RetainedConstructStanding, String> {
    if !is_digest(current.compiler_artifact_digest) {
        return Err("current construct basis lacks an exact compiler artifact digest".into());
    }
    let constructs = witness
        .constructs
        .as_ref()
        .map(|capture| {
            require_edge_digest(&capture.edges, &capture.edge_digest, "construct")?;
            Ok::<_, String>(
                capture
                    .edges
                    .iter()
                    .map(|edge| construct_edge(edge, current))
                    .collect(),
            )
        })
        .transpose()?;
    let declarations = witness
        .declarations
        .as_ref()
        .map(|capture| {
            require_edge_digest(&capture.edges, &capture.edge_digest, "declaration")?;
            Ok::<_, String>(
                capture
                    .edges
                    .iter()
                    .map(|edge| declaration_edge(edge, current))
                    .collect(),
            )
        })
        .transpose()?;
    Ok(RetainedConstructStanding {
        constructs,
        declarations,
    })
}

#[cfg(test)]
mod tests;
