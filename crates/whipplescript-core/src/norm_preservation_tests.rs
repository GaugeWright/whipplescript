use super::*;
struct Host(PreservationWitness);
impl PreservationVerifier for Host {
    fn verify_preservation_basis(&self, w: &PreservationWitness) -> bool {
        w == &self.0
    }
}
fn version(name: &str) -> EvidenceVersion {
    EvidenceVersion {
        name: name.into(),
        version: "1".into(),
        digest: name.into(),
    }
}
fn fixture() -> PreservationWitness {
    let source = [
        (
            "src/auth.py",
            ObservationAspect::Content,
            ObservationValue::Present("code".into()),
        ),
        (
            "config/optional",
            ObservationAspect::Presence,
            ObservationValue::Absent,
        ),
        (
            "src",
            ObservationAspect::Membership,
            ObservationValue::Present("members".into()),
        ),
        (
            "external:service",
            ObservationAspect::Metadata,
            ObservationValue::Present("epoch".into()),
        ),
    ]
    .into_iter()
    .map(|(resource, aspect, value)| DependencyObservation {
        key: ObservationKey {
            resource: resource.into(),
            aspect,
        },
        value,
    })
    .collect::<Vec<_>>();
    PreservationWitness {
        id: "verified-closure".into(),
        context: PreservationContext {
            requirement: version("auth"),
            method: version("calls"),
            policy: version("policy"),
            source_artifact: "before".into(),
            target_artifact: "after-unrelated-edit".into(),
            boundary: version("complete-interpreter"),
        },
        basis: PreservationBasis::CompleteExact,
        mode: PreservationMode::Deterministic,
        target: source.clone(),
        source,
        gaps: BTreeSet::new(),
    }
}
fn evaluate(w: &PreservationWitness) -> PreservationJudgment {
    evaluate_preservation(&w.context, w, &Host(w.clone()))
}
#[test]
fn norm_preservation_accepts_verified_closure_and_ceiling_without_relabelling_source() {
    for basis in [
        PreservationBasis::CompleteExact,
        PreservationBasis::EnforcedCeiling,
    ] {
        let mut w = fixture();
        w.basis = basis;
        let result = evaluate(&w);
        assert!(result.preserved);
        assert!(result.diagnostics.is_empty());
        assert_eq!(result.context.source_artifact, "before");
        assert_eq!(result.context.target_artifact, "after-unrelated-edit");
        w.source.reverse();
        assert!(evaluate(&w).preserved);
        w.target[0].value = ObservationValue::Present("changed".into());
        assert!(!evaluate(&w).preserved);
        w.target = w.source.clone();
        assert!(
            evaluate(&w).preserved,
            "an edit followed by undo restores equality"
        );
    }
}
#[test]
fn norm_preservation_requires_exact_context_and_independent_verification() {
    let original = fixture();
    let expected = original.context.clone();
    for n in 0..6 {
        let mut w = original.clone();
        match n {
            0 => w.context.requirement = version("other"),
            1 => w.context.method = version("other"),
            2 => w.context.policy = version("other"),
            3 => w.context.source_artifact = "other".into(),
            4 => w.context.target_artifact = "other".into(),
            _ => w.context.boundary = version("other"),
        }
        let result = evaluate_preservation(&expected, &w, &Host(w.clone()));
        assert!(!result.preserved);
        assert!(result
            .diagnostics
            .contains(&PreservationDiagnostic::ContextMismatch));
    }
    let mut forged = original.clone();
    forged.id = "self-certified".into();
    let result = evaluate_preservation(&expected, &forged, &Host(original));
    assert!(!result.preserved);
    assert!(result
        .diagnostics
        .contains(&PreservationDiagnostic::UnverifiedBasis));
}
#[test]
fn norm_preservation_refuses_partial_sampled_gapped_and_invalid_bases() {
    for basis in [PreservationBasis::PartialTrace, PreservationBasis::Unknown] {
        let mut w = fixture();
        w.basis = basis;
        let result = evaluate(&w);
        assert!(!result.preserved);
        assert!(result
            .diagnostics
            .contains(&PreservationDiagnostic::IncompleteBasis));
    }
    for mode in [PreservationMode::Sampled, PreservationMode::Unknown] {
        let mut w = fixture();
        w.mode = mode;
        let result = evaluate(&w);
        assert!(!result.preserved);
        assert!(result
            .diagnostics
            .contains(&PreservationDiagnostic::Nondeterministic));
    }
    let mut w = fixture();
    w.gaps.insert("escaped subprocess".into());
    assert!(!evaluate(&w).preserved);
    for n in 0..3 {
        let mut w = fixture();
        match n {
            0 => w.id.clear(),
            1 => w.context.boundary.digest.clear(),
            _ => w.context.target_artifact.clear(),
        };
        assert!(!evaluate(&w).preserved);
    }
}
#[test]
fn norm_preservation_compares_every_aspect_and_refuses_missing_duplicate_or_ambiguous_values() {
    for i in 0..4 {
        let mut w = fixture();
        w.target[i].value = ObservationValue::Present("changed".into());
        let result = evaluate(&w);
        assert!(!result.preserved);
        assert!(result
            .diagnostics
            .contains(&PreservationDiagnostic::Changed(w.target[i].key.clone())));
    }
    for source in [false, true] {
        let mut w = fixture();
        let items = if source { &mut w.source } else { &mut w.target };
        items.push(items[0].clone());
        let result = evaluate(&w);
        assert!(!result.preserved);
        assert!(result.diagnostics.contains(&if source {
            PreservationDiagnostic::DuplicateSource(w.source[0].key.clone())
        } else {
            PreservationDiagnostic::DuplicateTarget(w.target[0].key.clone())
        }));
    }
    let mut w = fixture();
    let missing = w.target.remove(0);
    let result = evaluate(&w);
    assert!(!result.preserved);
    assert!(result
        .diagnostics
        .contains(&PreservationDiagnostic::MissingTarget(missing.key)));
    let mut w = fixture();
    w.source.remove(0);
    assert!(!evaluate(&w).preserved);
    let mut w = fixture();
    w.source[0].key.resource.clear();
    w.target = w.source.clone();
    assert!(!evaluate(&w).preserved);
    let mut w = fixture();
    w.source[0].value = ObservationValue::Present(String::new());
    w.target = w.source.clone();
    assert!(!evaluate(&w).preserved);
}
