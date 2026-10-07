//! The external-effect handler family (HA-4) over a real runtime store.
//!
//! `signal.emit` and the legacy `event.emit` inject a durable event, so they
//! take fresh observed dispatch like the four file handlers: a recorded
//! run-start is never permission to deliver again, and a changed effect
//! definition is refused inside the dispatch transaction before anything is
//! written. Native and Durable Object stores run this same fixture.
use crate::{
    effect_config::EffectConfig,
    effect_handlers::{run_event_effect_generic, run_notify_effect_generic, DeliveryGovernance},
    RuntimeKernel,
};
use serde_json::{json, Value};
use whipplescript_store::{
    ClaimableEffect, NewEffect, NewInstance, RuleCommit, RunStart, RuntimeStore, StoreError,
};

/// A governance policy that must never be consulted: both fixture instances
/// share one package, so delivery is intra-package.
struct NoCrossPackageDelivery;
impl DeliveryGovernance for NoCrossPackageDelivery {
    fn any_internal_workflow(&self, _: &[String]) -> Result<bool, String> {
        panic!("intra-package delivery consults no cross-package policy")
    }
}

struct Fixture {
    sender: String,
    target: String,
}

fn seed<S: RuntimeStore>(store: &mut S, kind: &str, target_for: impl Fn(&str) -> Value) -> Fixture {
    let version = whipplescript_store::host_actions::conformance::register(store);
    let provider = provider(kind);
    store
        .register_capability_schema(whipplescript_store::CapabilitySchemaRegistration {
            capability: kind,
            description: "external-effect fixture",
            schema_json: "{}",
            registered_by_package_id: None,
        })
        .expect("register external capability");
    store
        .bind_capability(whipplescript_store::CapabilityBinding {
            binding_id: "fixture-external",
            program_id: Some(&version.program_id),
            capability: kind,
            provider,
            config_json: "{}",
        })
        .expect("bind external capability");
    store
        .register_effect_provider(whipplescript_store::EffectProviderRegistration {
            provider_id: "fixture-external",
            effect_kind: kind,
            provider,
            capability: kind,
            config_json: "{}",
            registered_by_package_id: None,
        })
        .expect("register external provider");
    let instance = || {
        store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("create external-effect instance")
            .instance_id
    };
    let sender = instance();
    let target = instance();
    let input = target_for(&target);
    store
        .commit_rule(RuleCommit {
            instance_id: &sender,
            rule: "fixture",
            trigger_event_id: None,
            facts: &[],
            consumed_fact_ids: &[],
            effects: &[NewEffect {
                effect_id: "external",
                kind,
                target: (kind == "event.emit").then_some("fixture.emitted"),
                input_json: &input.to_string(),
                status: "queued",
                idempotency_key: "external-command",
                required_capabilities_json: "[]",
                profile: None,
                correlation_id: None,
                source_span_json: None,
                timeout_seconds: None,
            }],
            dependencies: &[],
            terminal: None,
            idempotency_key: Some("fixture"),
            marks: &[],
            context_json: None,
        })
        .expect("admit external effect");
    Fixture { sender, target }
}

fn provider(kind: &str) -> &'static str {
    if kind == "signal.emit" {
        "notify"
    } else {
        "fixture"
    }
}

fn input(kind: &str, target: &str) -> Value {
    if kind == "signal.emit" {
        json!({
            "target_instance": target,
            "event": "fixture.signal",
            "payload": {"status": "ok"},
        })
    } else {
        json!({"event_type": "fixture.emitted", "payload": {"status": "ok"}})
    }
}

fn run<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    kind: &str,
    sender: &str,
    effect: &ClaimableEffect,
) -> Result<whipplescript_store::StoredEvent, StoreError> {
    if kind == "signal.emit" {
        run_notify_effect_generic(kernel, sender, effect, &NoCrossPackageDelivery)
    } else {
        let config = EffectConfig {
            provider: "fixture".into(),
            outcome_failed: false,
        };
        run_event_effect_generic(kernel, sender, effect, &config)
    }
}

/// Where the injected event lands: the target instance for a signal, the
/// sender's own log for the legacy `event.emit`.
fn delivered<S: RuntimeStore>(kernel: &RuntimeKernel<S>, kind: &str, fixture: &Fixture) -> usize {
    let (instance, name) = if kind == "signal.emit" {
        (&fixture.target, "fixture.signal")
    } else {
        (&fixture.sender, "fixture.emitted")
    };
    kernel
        .store()
        .list_facts(instance)
        .expect("delivered facts")
        .iter()
        .filter(|fact| fact.name == name)
        .count()
}

fn history<S: RuntimeStore>(kernel: &RuntimeKernel<S>, fixture: &Fixture) -> usize {
    kernel
        .store()
        .list_events(&fixture.sender)
        .expect("sender")
        .len()
        + kernel
            .store()
            .list_events(&fixture.target)
            .expect("target")
            .len()
}

fn claim<S: RuntimeStore>(kernel: &RuntimeKernel<S>, sender: &str) -> ClaimableEffect {
    let mut effects = kernel.claimable_effects(sender).expect("claimable");
    assert_eq!(effects.len(), 1, "exactly the fixture effect is claimable");
    effects.remove(0)
}

/// Success, then no redispatch of the completed effect.
fn delivers_once<S: RuntimeStore>(store: S, kind: &str) {
    let mut store = store;
    let fixture = seed(&mut store, kind, |target| input(kind, target));
    let mut kernel = RuntimeKernel::new(store);
    let effect = claim(&kernel, &fixture.sender);
    let terminal = run(&mut kernel, kind, &fixture.sender, &effect).expect("deliver");
    let recorded = kernel
        .store()
        .list_events(&fixture.sender)
        .expect("sender history")
        .into_iter()
        .find(|event| event.event_id == terminal.event_id)
        .expect("terminal is recorded");
    let payload: Value = serde_json::from_str(&recorded.payload_json).expect("terminal payload");
    assert_eq!(payload["status"], "completed", "{kind}: {payload}");
    assert_eq!(delivered(&kernel, kind, &fixture), 1, "{kind}");
    let started = kernel
        .store()
        .list_events(&fixture.sender)
        .expect("sender history")
        .into_iter()
        .filter(|event| event.event_type == "effect.run_started")
        .count();
    assert_eq!(started, 1, "{kind}: one fresh dispatch");

    let before = history(&kernel, &fixture);
    assert!(
        run(&mut kernel, kind, &fixture.sender, &effect).is_err(),
        "{kind}: a completed effect is not redispatched"
    );
    assert_eq!(history(&kernel, &fixture), before, "{kind}");
    assert_eq!(delivered(&kernel, kind, &fixture), 1, "{kind}");
}

/// A recorded run-start without a terminal (an interruption after dispatch)
/// is not permission to deliver: the handler refuses instead of reattaching.
fn interrupted_dispatch_is_not_reattached<S: RuntimeStore>(store: S, kind: &str) {
    let mut store = store;
    let fixture = seed(&mut store, kind, |target| input(kind, target));
    let mut kernel = RuntimeKernel::new(store);
    let effect = claim(&kernel, &fixture.sender);
    let (run_id, lease_id) = if kind == "signal.emit" {
        ("notify-run", "notify-lease")
    } else {
        ("event-run", "event-lease")
    };
    let run_id = crate::idempotency_key(&[&fixture.sender, &effect.effect_id, run_id]);
    let lease_id = crate::idempotency_key(&[&fixture.sender, &effect.effect_id, lease_id]);
    kernel
        .start_dispatch_observed(
            RunStart {
                instance_id: &fixture.sender,
                effect_id: &effect.effect_id,
                run_id: &run_id,
                provider: provider(kind),
                worker_id: "interrupted-worker",
                lease_id: &lease_id,
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            },
            &effect,
        )
        .expect("an earlier worker dispatched, then stopped");
    let before = history(&kernel, &fixture);
    assert!(
        run(&mut kernel, kind, &fixture.sender, &effect).is_err(),
        "{kind}: a recorded attempt is not reattached for new delivery"
    );
    assert_eq!(history(&kernel, &fixture), before, "{kind}");
    assert_eq!(delivered(&kernel, kind, &fixture), 0, "{kind}");
}

/// A caller whose observation differs from the stored definition is refused
/// inside the dispatch transaction, before any event is written.
fn changed_observation_is_refused<S: RuntimeStore>(store: S, kind: &str) {
    let mut store = store;
    let fixture = seed(&mut store, kind, |target| input(kind, target));
    let mut kernel = RuntimeKernel::new(store);
    let effect = claim(&kernel, &fixture.sender);
    let before = history(&kernel, &fixture);
    for field in ["input", "kind", "target", "capabilities"] {
        let mut changed = effect.clone();
        match field {
            "input" => {
                let mut value: Value = serde_json::from_str(&changed.input_json).expect("input");
                value["payload"]["status"] = json!("forged");
                changed.input_json = value.to_string();
            }
            "kind" => changed.kind = "file.read".into(),
            "target" => changed.target = Some("other.target".into()),
            "capabilities" => changed.required_capabilities_json = r#"["other"]"#.into(),
            _ => unreachable!(),
        }
        assert!(
            run(&mut kernel, kind, &fixture.sender, &changed).is_err(),
            "{kind}: changed {field} must refuse"
        );
        assert_eq!(history(&kernel, &fixture), before, "{kind}: {field}");
    }
    assert_eq!(delivered(&kernel, kind, &fixture), 0, "{kind}");
    run(&mut kernel, kind, &fixture.sender, &effect).expect("the exact observation still delivers");
    assert_eq!(delivered(&kernel, kind, &fixture), 1, "{kind}");
}

/// Run every case for both handlers over fresh stores from `make`.
pub fn check<S: RuntimeStore>(make: impl Fn() -> S) {
    for kind in ["signal.emit", "event.emit"] {
        delivers_once(make(), kind);
        interrupted_dispatch_is_not_reattached(make(), kind);
        changed_observation_is_refused(make(), kind);
    }
}
