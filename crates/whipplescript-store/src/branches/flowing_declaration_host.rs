//! Body-free host projection of one durable source-unit declaration.
//!
//! The owning source store supplies both the declaration and its private cut
//! pin. This projection binds their immutable identities without putting the
//! free-form intent on the wire. It is evidence only, not source admission or
//! permission to publish content.

use serde::{Deserialize, Serialize};

use super::flowing_sources::{ContributionDeclaration, FlowingSources, PrivateCutPin};
use crate::{StoreError, StoreResult};

pub const FLOWING_DECLARATION_EVIDENCE_V1: &str = "whipplescript.flowing_declaration_evidence.v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowingHostDeclarationEvidenceV1 {
    pub schema: String,
    pub unit_id: String,
    pub pin_id: String,
    pub source_branch_id: String,
    pub source_cut_id: String,
    pub source_manifest_hash: String,
    pub principal: String,
    pub intent_digest: String,
    pub read_basis_digest: String,
    pub dependency_basis_digest: String,
    pub scope_digest: String,
    pub declaration_digest: String,
}

pub trait FlowingDeclarationEvidenceReader {
    fn read_declaration(&self, unit_id: &str) -> StoreResult<Option<ContributionDeclaration>>;
    fn read_private_pin(&self, pin_id: &str) -> StoreResult<Option<PrivateCutPin>>;
}

impl<T: FlowingSources> FlowingDeclarationEvidenceReader for T {
    fn read_declaration(&self, unit_id: &str) -> StoreResult<Option<ContributionDeclaration>> {
        self.contribution_declaration(unit_id)
    }

    fn read_private_pin(&self, pin_id: &str) -> StoreResult<Option<PrivateCutPin>> {
        self.private_cut_pin(pin_id)
    }
}

fn invalid(reason: &str) -> StoreError {
    StoreError::Conflict(format!(
        "flowing declaration host evidence refuses: {reason}"
    ))
}

fn digest(domain: &str, value: &impl Serialize) -> StoreResult<String> {
    let bytes = serde_json::to_vec(&(domain, value))?;
    Ok(format!(
        "sha256:{}",
        crate::chunking::content_hash_hex(&bytes)
    ))
}

pub fn read_declaration_evidence(
    sources: &impl FlowingDeclarationEvidenceReader,
    unit_id: &str,
) -> StoreResult<Option<FlowingHostDeclarationEvidenceV1>> {
    if unit_id.trim().is_empty() {
        return Err(invalid("unit identity is empty"));
    }
    let Some(declaration) = sources.read_declaration(unit_id)? else {
        return Ok(None);
    };
    if declaration.unit_id != unit_id {
        return Err(invalid("declaration differs from requested unit"));
    }
    let pin = sources
        .read_private_pin(&declaration.pin_id)?
        .ok_or_else(|| invalid("declaration private cut pin is missing"))?;
    Ok(Some(FlowingHostDeclarationEvidenceV1::from_retained(
        &declaration,
        &pin,
    )?))
}

impl FlowingHostDeclarationEvidenceV1 {
    fn from_retained(
        declaration: &ContributionDeclaration,
        pin: &PrivateCutPin,
    ) -> StoreResult<Self> {
        if declaration.pin_id != pin.pin_id
            || declaration.source_branch_id != pin.twig_branch_id
            || declaration.source_cut_id != pin.cut_id
            || declaration.source_manifest_hash != pin.manifest_hash
            || declaration.principal != pin.principal
        {
            return Err(invalid("declaration and private cut pin differ"));
        }
        let evidence = Self {
            schema: FLOWING_DECLARATION_EVIDENCE_V1.into(),
            unit_id: declaration.unit_id.clone(),
            pin_id: declaration.pin_id.clone(),
            source_branch_id: declaration.source_branch_id.clone(),
            source_cut_id: declaration.source_cut_id.clone(),
            source_manifest_hash: declaration.source_manifest_hash.clone(),
            principal: declaration.principal.clone(),
            intent_digest: digest("flowing-host-intent-v1", &declaration.intent)?,
            read_basis_digest: declaration.read_basis_digest.clone(),
            dependency_basis_digest: declaration.dependency_basis_digest.clone(),
            scope_digest: declaration.scope_digest.clone(),
            declaration_digest: digest(
                "flowing-host-declaration-v1",
                &(
                    &declaration.unit_id,
                    &declaration.pin_id,
                    &declaration.source_branch_id,
                    &declaration.source_cut_id,
                    &declaration.source_manifest_hash,
                    &declaration.principal,
                    &declaration.intent,
                    &declaration.read_basis_digest,
                    &declaration.dependency_basis_digest,
                    &declaration.scope_digest,
                    &declaration.declared_at,
                ),
            )?,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    /// Strict wire decoding is a shape check. It does not authenticate the
    /// owning source store or prove the private cut remains live.
    pub fn decode(bytes: &[u8]) -> StoreResult<Self> {
        let evidence: Self = serde_json::from_slice(bytes)?;
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> StoreResult<()> {
        if self.schema != FLOWING_DECLARATION_EVIDENCE_V1 {
            return Err(invalid("wrong declaration evidence schema"));
        }
        for value in [
            &self.unit_id,
            &self.pin_id,
            &self.source_branch_id,
            &self.source_cut_id,
            &self.source_manifest_hash,
            &self.principal,
            &self.intent_digest,
            &self.read_basis_digest,
            &self.dependency_basis_digest,
            &self.scope_digest,
            &self.declaration_digest,
        ] {
            if value.trim().is_empty() {
                return Err(invalid("required declaration evidence identity is empty"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    struct FixtureReader {
        declaration: Option<ContributionDeclaration>,
        pin: Option<PrivateCutPin>,
    }

    impl FlowingDeclarationEvidenceReader for FixtureReader {
        fn read_declaration(&self, _unit_id: &str) -> StoreResult<Option<ContributionDeclaration>> {
            Ok(self.declaration.clone())
        }

        fn read_private_pin(&self, _pin_id: &str) -> StoreResult<Option<PrivateCutPin>> {
            Ok(self.pin.clone())
        }
    }

    fn pair() -> (ContributionDeclaration, PrivateCutPin) {
        (
            ContributionDeclaration {
                unit_id: "unit-a".into(),
                pin_id: "pin-a".into(),
                source_branch_id: "twig-a".into(),
                source_cut_id: "cut-a".into(),
                source_manifest_hash: "manifest-a".into(),
                principal: "member-a".into(),
                intent: "private free-form intent".into(),
                read_basis_digest: "read-a".into(),
                dependency_basis_digest: "dependency-a".into(),
                scope_digest: "scope-a".into(),
                declared_at: "2026-10-06T00:00:00Z".into(),
            },
            PrivateCutPin {
                pin_id: "pin-a".into(),
                twig_branch_id: "twig-a".into(),
                cut_id: "cut-a".into(),
                manifest_hash: "manifest-a".into(),
                principal: "member-a".into(),
                retained_at: "2026-10-06T00:00:00Z".into(),
                released_at: None,
                released_by: None,
                release_reason: None,
            },
        )
    }

    fn assert_refusal(error: StoreError, text: &str) {
        assert!(matches!(error, StoreError::Conflict(message) if message.contains(text)));
    }

    #[test]
    fn exact_declaration_and_pin_project_without_intent_text() {
        let (declaration, pin) = pair();
        let reader = FixtureReader {
            declaration: Some(declaration.clone()),
            pin: Some(pin),
        };
        let evidence = read_declaration_evidence(&reader, "unit-a")
            .unwrap()
            .unwrap();
        assert_eq!(evidence.source_cut_id, "cut-a");
        let bytes = serde_json::to_vec(&evidence).unwrap();
        let wire = String::from_utf8(bytes.clone()).unwrap();
        assert!(!wire.contains(&declaration.intent));
        assert_eq!(
            FlowingHostDeclarationEvidenceV1::decode(&bytes).unwrap(),
            evidence
        );
    }

    #[test]
    fn reader_refuses_empty_wrong_or_unbacked_declaration() {
        let (declaration, pin) = pair();
        let missing = FixtureReader {
            declaration: None,
            pin: None,
        };
        assert_refusal(
            read_declaration_evidence(&missing, "").unwrap_err(),
            "unit identity is empty",
        );
        assert!(read_declaration_evidence(&missing, "unit-a")
            .unwrap()
            .is_none());
        let wrong = FixtureReader {
            declaration: Some(declaration.clone()),
            pin: Some(pin.clone()),
        };
        assert_refusal(
            read_declaration_evidence(&wrong, "unit-other").unwrap_err(),
            "declaration differs from requested unit",
        );
        let unbacked = FixtureReader {
            declaration: Some(declaration.clone()),
            pin: None,
        };
        assert_refusal(
            read_declaration_evidence(&unbacked, "unit-a").unwrap_err(),
            "declaration private cut pin is missing",
        );
        let mut wrong_pin = pin;
        wrong_pin.cut_id = "another-cut".into();
        let wrong = FixtureReader {
            declaration: Some(declaration),
            pin: Some(wrong_pin),
        };
        assert_refusal(
            read_declaration_evidence(&wrong, "unit-a").unwrap_err(),
            "declaration and private cut pin differ",
        );
    }

    #[test]
    fn strict_declaration_wire_refuses_unknown_missing_and_empty_fields() {
        let (declaration, pin) = pair();
        let evidence = FlowingHostDeclarationEvidenceV1::from_retained(&declaration, &pin).unwrap();
        let original = serde_json::to_value(evidence).unwrap();
        let mut extra = original.clone();
        extra["intent"] = json!("private free-form intent");
        assert!(
            FlowingHostDeclarationEvidenceV1::decode(&serde_json::to_vec(&extra).unwrap()).is_err()
        );
        let mut missing = original.clone();
        missing.as_object_mut().unwrap().remove("source_cut_id");
        assert!(
            FlowingHostDeclarationEvidenceV1::decode(&serde_json::to_vec(&missing).unwrap())
                .is_err()
        );
        let mut version = original.clone();
        version["schema"] = json!("whipplescript.flowing_declaration_evidence.v2");
        assert_refusal(
            FlowingHostDeclarationEvidenceV1::decode(&serde_json::to_vec(&version).unwrap())
                .unwrap_err(),
            "wrong declaration evidence schema",
        );
        let mut empty = original;
        empty["intent_digest"] = json!("");
        assert_refusal(
            FlowingHostDeclarationEvidenceV1::decode(&serde_json::to_vec(&empty).unwrap())
                .unwrap_err(),
            "required declaration evidence identity is empty",
        );
    }
}
