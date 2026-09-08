//! The effect inspected by an execution authority must still be the effect
//! claimed by dispatch. Backends read this row inside their start transaction.
use crate::{ClaimableEffect, StoreError, StoreResult};

pub const SELECT: &str = "SELECT candidate.effect_id, candidate.kind, \
    candidate.target, candidate.profile, candidate.input_json, \
    candidate.required_capabilities, \
    COALESCE(effect_versions.declared_profiles, active_versions.declared_profiles, '[]') AS declared_profiles \
    FROM effects AS candidate \
    LEFT JOIN instances ON instances.instance_id = candidate.instance_id \
    LEFT JOIN program_versions AS active_versions ON active_versions.version_id = instances.version_id \
    LEFT JOIN program_versions AS effect_versions ON effect_versions.version_id = candidate.program_version_id \
    WHERE candidate.instance_id = ?1 AND candidate.effect_id = ?2";

/// This compares observations, not grants. A successful comparison never
/// substitutes for current authorization or ordinary dispatch eligibility.
pub fn check(expected: &ClaimableEffect, observed: Option<&ClaimableEffect>) -> StoreResult<()> {
    if observed != Some(expected) {
        return Err(StoreError::Conflict(
            "dispatch effect differs from the authorized observation".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "native")]
pub(crate) fn native(
    connection: &rusqlite::Connection,
    instance: &str,
    effect_id: &str,
    expected: &ClaimableEffect,
) -> StoreResult<()> {
    use rusqlite::OptionalExtension;
    let observed = connection
        .query_row(SELECT, [instance, effect_id], |row| {
            Ok(ClaimableEffect {
                effect_id: row.get(0)?,
                kind: row.get(1)?,
                target: row.get(2)?,
                profile: row.get(3)?,
                input_json: row.get(4)?,
                required_capabilities_json: row.get(5)?,
                declared_profiles_json: row.get(6)?,
            })
        })
        .optional()?;
    check(expected, observed.as_ref())
}

/// One fixture for native and the deployed hosted schema. The reference is a
/// prior observation; every stale coordinate must refuse without a dispatch.
#[doc(hidden)]
pub mod conformance {
    use super::*;
    use crate::{NewEffect, NewInstance, RuleCommit, RunStart, RuntimeStore};

    pub fn run_suite(store: &mut impl RuntimeStore) {
        let version = crate::host_actions::conformance::register(store);
        store
            .register_capability_schema(crate::CapabilitySchemaRegistration {
                capability: "file.write",
                description: "observed dispatch fixture",
                schema_json: "{}",
                registered_by_package_id: None,
            })
            .expect("register capability");
        store
            .bind_capability(crate::CapabilityBinding {
                binding_id: "observed-files",
                program_id: Some(&version.program_id),
                capability: "file.write",
                provider: "files",
                config_json: "{}",
            })
            .expect("bind capability");
        store
            .register_effect_provider(crate::EffectProviderRegistration {
                provider_id: "observed-files",
                effect_kind: "file.write",
                provider: "files",
                capability: "file.write",
                config_json: "{}",
                registered_by_package_id: None,
            })
            .expect("register provider");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("create instance");
        let id = instance.instance_id.as_str();
        store
            .commit_rule(RuleCommit {
                instance_id: id,
                rule: "observed",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[NewEffect {
                    effect_id: "observed-save",
                    kind: "file.write",
                    target: None,
                    input_json: r#"{"body":"accepted input"}"#,
                    status: "queued",
                    idempotency_key: "observed-save",
                    required_capabilities_json: "[]",
                    profile: None,
                    correlation_id: None,
                    source_span_json: None,
                    timeout_seconds: None,
                }],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("observed-rule"),
                marks: &[],
                context_json: None,
            })
            .expect("commit effect");
        let observed = store
            .claimable_effects(id)
            .expect("claimable effects")
            .into_iter()
            .find(|effect| effect.effect_id == "observed-save")
            .expect("file effect is eligible");
        let run = RunStart {
            instance_id: id,
            effect_id: &observed.effect_id,
            run_id: "observed-run",
            provider: "files",
            worker_id: "fixture",
            lease_id: "observed-lease",
            lease_expires_at: "2030-01-01T00:00:00Z",
            metadata_json: "{}",
        };
        let before = store.list_events(id).expect("initial events");
        let before_effects = store.list_effects(id).expect("initial effects");
        for coordinate in [
            "effect",
            "kind",
            "target",
            "profile",
            "input",
            "capabilities",
            "profiles",
            "missing",
        ] {
            let mut expected = observed.clone();
            match coordinate {
                "effect" | "missing" => expected.effect_id = "missing-effect".into(),
                "kind" => expected.kind = "file.read".into(),
                "target" => expected.target = Some("other-target".into()),
                "profile" => expected.profile = Some("other-profile".into()),
                "input" => expected.input_json = r#"{"body":"a different input"}"#.into(),
                "capabilities" => expected.required_capabilities_json = r#"["extra"]"#.into(),
                "profiles" => expected.declared_profiles_json = r#"["extra"]"#.into(),
                _ => unreachable!(),
            }
            let attempt = RunStart {
                effect_id: if coordinate == "missing" {
                    "missing-effect"
                } else {
                    run.effect_id
                },
                ..run
            };
            let error = store
                .start_dispatch_observed(attempt, &expected)
                .expect_err("changed observation must refuse dispatch");
            assert!(
                matches!(error, StoreError::Conflict(ref message) if message == "dispatch effect differs from the authorized observation"),
                "{coordinate}: {error:?}"
            );
            assert_eq!(
                store.list_events(id).expect("events after refusal"),
                before,
                "{coordinate}"
            );
            assert_eq!(
                store.list_effects(id).expect("effects after refusal"),
                before_effects,
                "{coordinate}"
            );
            assert!(
                store.list_runs(id).expect("runs after refusal").is_empty(),
                "{coordinate}"
            );
        }
        store
            .start_dispatch_observed(run, &observed)
            .expect("unchanged observation dispatches");
        let dispatched = store.list_events(id).expect("dispatched events");
        assert_eq!(store.list_runs(id).expect("dispatched runs").len(), 1);
        store.rebuild_projections(id).expect("rebuild dispatch");
        assert!(
            store.start_dispatch_observed(run, &observed).is_err(),
            "reattachment never grants fresh I/O"
        );
        assert_eq!(
            store.list_events(id).expect("reattachment events"),
            dispatched
        );
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    #[test]
    fn native_dispatch_observation_conformance() {
        super::conformance::run_suite(&mut crate::SqliteStore::open_in_memory().expect("store"));
    }
}
