use super::*;
use crate::coerce::{CoerceRequest, FakeCoerceClient};
use crate::harness::MockAgentHarness;
use crate::source_action::Boundary;
use crate::{AgentTurnExecution, CoerceExecution};

const DECLARATIONS: &str = r#"
workflow Captures
output result Answer
class Answer { text string }
agent worker { provider mock capacity 2 }
coerce classify(first string, second string?) -> Answer {
  prompt "{{ first }} {{ second }} {{ ctx.output_format }}"
}
rule finish when started => { complete result { text "done" } }
"#;

struct AllowDelivery;

impl crate::effect_handlers::DeliveryGovernance for AllowDelivery {
    fn any_internal_workflow(&self, _resources: &[String]) -> Result<bool, String> {
        Ok(false)
    }
}
fn settle_coerce(f: &mut Fixture, effect: &OwnedEffect, text: &str) {
    settle_coerce_value(f, effect, json!({"text":text}));
}
fn settle_coerce_value(f: &mut Fixture, effect: &OwnedEffect, value: Value) {
    let input: Value = serde_json::from_str(&effect.input_json).expect("coerce input");
    let request = CoerceRequest::with_evidence_hashes(
        input["function_name"].as_str().expect("function").into(),
        input["arguments"].to_string(),
        input["output_type"].as_str().expect("output").into(),
    );
    f.kernel
        .run_coerce(
            CoerceExecution {
                instance_id: &f.instance,
                effect_id: &effect.effect_id,
                run_id: &format!("run-{}", effect.effect_id),
                provider: "fixture",
                worker_id: "fixture",
                lease_id: &format!("lease-{}", effect.effect_id),
                lease_expires_at: "2030-01-01T00:00:00Z",
                request: &request,
                model: None,
            },
            &FakeCoerceClient::succeeds(value.to_string()),
        )
        .expect("coerce settlement");
}

#[test]
fn managed_prompt_native_returns_its_string_after_reopen() {
    let source = format!(
        "{}action ask(name string) -> string {{ prompt \"Hello {{{{ name }}}}\" as reply\nreturn reply }}\nrule finish when started => {{ ask(\"Ada\") as reply\ncomplete result {{ text reply }} }}",
        DECLARATIONS.split("rule finish").next().unwrap()
    );
    let parsed = whipplescript_parser::parse_program(&source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let typed =
        whipplescript_parser::action_plan::resolved::resolve_rule_types(&parsed.program, "finish")
            .unwrap();
    let path = std::env::temp_dir().join(format!(
        "managed-prompt-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut f = Fixture::with_source(SqliteStore::open(&path).unwrap(), DECLARATIONS);
    let first = timer_fixture::project_typed(&f, &typed);
    let [effect] = first.lowering.effects.as_slice() else {
        panic!("one prompt effect")
    };
    let input: Value = serde_json::from_str(&effect.input_json).unwrap();
    assert_eq!(input["function_name"], "prompt");
    assert_eq!(input["prompt"], "Hello Ada");
    timer_fixture::commit(&mut f, &first);
    settle_coerce_value(&mut f, effect, json!("native prompt"));
    let done = timer_fixture::project_typed(&f, &typed);
    assert_eq!(done.root.boundary, Boundary::Succeeded(()));
    assert_eq!(
        serde_json::from_str::<Value>(&done.lowering.terminal.as_ref().unwrap().payload_json)
            .unwrap(),
        json!({"text":"native prompt"})
    );
    timer_fixture::commit(&mut f, &done);
    drop(f);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn managed_decide_native_returns_its_structural_value_after_reopen() {
    let source = format!(
        "{}action judge(name string) -> Answer {{ decide \"Review {{{{ name }}}}\" -> {{ text string }} as verdict\nafter verdict succeeds {{ return verdict }} }}\nrule finish when started => {{ judge(\"Ada\") as verdict\ncomplete result verdict }}",
        DECLARATIONS.split("rule finish").next().unwrap()
    );
    let parsed = whipplescript_parser::parse_program(&source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let typed =
        whipplescript_parser::action_plan::resolved::resolve_rule_types(&parsed.program, "finish")
            .unwrap();
    let path = std::env::temp_dir().join(format!(
        "managed-decide-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut f = Fixture::with_source(SqliteStore::open(&path).unwrap(), DECLARATIONS);
    let first = timer_fixture::project_typed(&f, &typed);
    let [effect] = first.lowering.effects.as_slice() else {
        panic!("one decide effect")
    };
    let input: Value = serde_json::from_str(&effect.input_json).unwrap();
    assert_eq!(input["function_name"], "decide");
    assert_eq!(input["prompt"], "Review Ada");
    assert_eq!(
        input["output_schema"]["properties"]["text"]["type"],
        "string"
    );
    timer_fixture::commit(&mut f, &first);
    settle_coerce_value(&mut f, effect, json!({"text":"native decision"}));
    let done = timer_fixture::project_typed(&f, &typed);
    assert_eq!(done.root.boundary, Boundary::Succeeded(()));
    assert_eq!(
        serde_json::from_str::<Value>(&done.lowering.terminal.as_ref().unwrap().payload_json)
            .unwrap(),
        json!({"text":"native decision"})
    );
    timer_fixture::commit(&mut f, &done);
    drop(f);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn managed_script_exec_native_returns_its_typed_value_after_reopen() {
    const SOURCE: &str = r#"use std.script
workflow Captures
output result Answer
class Answer { text string }
class ScriptReport { text string }
action render(input string) -> ScriptReport {
  exec render with input -> ScriptReport as report
  after report succeeds { return report }
}
rule finish when started => { render("Ada") as report
complete result { text report.text } }
"#;
    let parsed = whipplescript_parser::parse_program(SOURCE);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let typed =
        whipplescript_parser::action_plan::resolved::resolve_rule_types(&parsed.program, "finish")
            .unwrap();
    let path = std::env::temp_dir().join(format!(
        "managed-exec-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut f = Fixture::with_source(SqliteStore::open(&path).unwrap(), SOURCE);
    use whipplescript_store::{CapabilityBinding, CapabilitySchemaRegistration, RunStart};
    f.kernel
        .store()
        .register_capability_schema(CapabilitySchemaRegistration {
            capability: "script.render",
            description: "fixture script",
            schema_json: "{}",
            registered_by_package_id: None,
        })
        .unwrap();
    f.kernel
        .store()
        .bind_capability(CapabilityBinding {
            binding_id: "fixture-script-render",
            program_id: None,
            capability: "script.render",
            provider: "builtin-script",
            config_json: "{}",
        })
        .unwrap();
    let first = timer_fixture::project_typed(&f, &typed);
    let [effect] = first.lowering.effects.as_slice() else {
        panic!("one exec effect")
    };
    let input: Value = serde_json::from_str(&effect.input_json).unwrap();
    assert_eq!(input["mode"], "capability");
    assert_eq!(input["capability"], "render");
    assert_eq!(input["stdin"], "Ada");
    assert_eq!(input["parse"]["schema"], "ScriptReport");
    timer_fixture::commit(&mut f, &first);
    let run_id = format!("run-{}", effect.effect_id);
    f.kernel
        .start_run(RunStart {
            instance_id: &f.instance,
            effect_id: &effect.effect_id,
            run_id: &run_id,
            provider: "exec",
            // `whip-exec`, not a fixture name: `retain_exec_settlement` looks the
            // invocation up by (provider, worker_id) and refuses a settlement
            // with no running run behind it.
            worker_id: "whip-exec",
            lease_id: "exec-lease",
            lease_expires_at: "2030-01-01T00:00:00Z",
            metadata_json: r#"{"mode":"capability","capability":"render"}"#,
        })
        .unwrap();
    crate::exec_http::settle_exec_http_result(
        &mut f.kernel,
        &crate::exec_http::ExecSettleContext {
            // The run's OWN stored input: `retain_exec_settlement` compares
            // them, so a fixture that spells its own is a fixture that drifts.
            input_json: &effect.input_json,
            instance_id: &f.instance,
            effect_id: &effect.effect_id,
            run_id: &run_id,
            capability: "render",
            script_sha256: "fixture-sha",
            cache: None,
            ingest_schema: "ScriptReport",
            // This fixture settles a direct in-process run, which carries no
            // executor-protocol response and no broker journal to point back at.
            executor_response: None,
            executor_transport: "in-process",
            dispatch_plan: None,
            resolution_event_id: None,
        },
        Ok((
            0,
            r#"{"text":"native render"}"#.into(),
            String::new(),
            Some(crate::exec_http::ExecIngest::Single(json!({
                "text": "native render"
            }))),
        )),
    )
    .unwrap();
    let result_fact = f
        .kernel
        .store()
        .list_facts(&f.instance)
        .unwrap()
        .into_iter()
        .find(|fact| fact.name == "exec.command.completed")
        .unwrap();
    consume_record(&mut f, &result_fact.fact_id);
    let Fixture {
        kernel,
        ir,
        instance,
        frame,
        context,
    } = f;
    drop(kernel);
    let mut f = Fixture {
        kernel: RuntimeKernel::new(wrap(SqliteStore::open(&path).unwrap())),
        ir,
        instance,
        frame,
        context,
    };
    let done = timer_fixture::project_typed(&f, &typed);
    assert_eq!(done.root.boundary, Boundary::Succeeded(()));
    assert_eq!(
        serde_json::from_str::<Value>(&done.lowering.terminal.as_ref().unwrap().payload_json)
            .unwrap(),
        json!({"text":"native render"})
    );
    timer_fixture::commit(&mut f, &done);
    drop(f);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn managed_file_read_native_returns_its_structural_value_after_reopen() {
    let root = std::env::temp_dir().join(format!(
        "managed-file-read-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("guide.md"), "native guide").unwrap();
    let source = format!(
        r#"workflow NativeFiles
file store workspace {{ root {:?} allow read ["*.md"] }}
output result Answer
class Answer {{ text string }}
action load() -> string {{
  read markdown from workspace at "guide.md" as document
  after document succeeds {{ return document.content }}
}}
rule finish when started => {{ load() as content
complete result {{ text content }} }}
"#,
        root.to_string_lossy()
    );
    let parsed = whipplescript_parser::parse_program(&source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let typed =
        whipplescript_parser::action_plan::resolved::resolve_rule_types(&parsed.program, "finish")
            .unwrap();
    let database = root.join("runtime.sqlite");
    let mut f = Fixture::with_source(SqliteStore::open(&database).unwrap(), &source);
    use whipplescript_store::{
        CapabilityBinding, CapabilitySchemaRegistration, EffectProviderRegistration,
    };
    f.kernel
        .store()
        .register_capability_schema(CapabilitySchemaRegistration {
            capability: "file.read",
            description: "fixture file read",
            schema_json: "{}",
            registered_by_package_id: None,
        })
        .unwrap();
    f.kernel
        .store()
        .register_effect_provider(EffectProviderRegistration {
            provider_id: "fixture-files-read",
            effect_kind: "file.read",
            provider: "files",
            capability: "file.read",
            config_json: "{}",
            registered_by_package_id: None,
        })
        .unwrap();
    f.kernel
        .store()
        .bind_capability(CapabilityBinding {
            binding_id: "fixture-files-read",
            program_id: None,
            capability: "file.read",
            provider: "files",
            config_json: "{}",
        })
        .unwrap();
    let first = timer_fixture::project_typed(&f, &typed);
    let [effect] = first.lowering.effects.as_slice() else {
        panic!("one file read effect")
    };
    let input: Value = serde_json::from_str(&effect.input_json).unwrap();
    assert_eq!(input["path"], "guide.md");
    assert_eq!(input["format"], "markdown");
    timer_fixture::commit(&mut f, &first);
    let claimable = f.kernel.claimable_effects(&f.instance).unwrap();
    let [claimable] = claimable.as_slice() else {
        panic!("file read is claimable")
    };
    crate::effect_handlers::run_file_effect_generic(
        &mut f.kernel,
        &whipplescript_store::files::NativeFileStore,
        &f.instance,
        claimable,
    )
    .unwrap();
    let result_fact = f
        .kernel
        .store()
        .list_facts(&f.instance)
        .unwrap()
        .into_iter()
        .find(|fact| fact.name == "file.read.completed")
        .unwrap();
    consume_record(&mut f, &result_fact.fact_id);
    let Fixture {
        kernel,
        ir,
        instance,
        frame,
        context,
    } = f;
    drop(kernel);
    let mut f = Fixture {
        kernel: RuntimeKernel::new(wrap(SqliteStore::open(&database).unwrap())),
        ir,
        instance,
        frame,
        context,
    };
    let done = timer_fixture::project_typed(&f, &typed);
    assert_eq!(done.root.boundary, Boundary::Succeeded(()));
    assert_eq!(
        serde_json::from_str::<Value>(&done.lowering.terminal.as_ref().unwrap().payload_json)
            .unwrap(),
        json!({"text":"native guide"})
    );
    timer_fixture::commit(&mut f, &done);
    drop(f);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn managed_file_import_native_returns_its_admission_receipt_after_reopen() {
    let root = std::env::temp_dir().join(format!(
        "managed-file-import-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("tickets.json"),
        r#"[{"owner":"alice","priority":4},{"owner":"bob","priority":1}]"#,
    )
    .unwrap();
    let source = format!(
        r#"workflow NativeImports
file store workspace {{ root {:?} allow read ["*.json"] }}
output result Answer
class Answer {{ count int }}
class Ticket {{ owner string priority int }}
action load(path string) -> int {{
  import json Ticket from workspace at path as imported
  after imported succeeds {{ return imported.admitted }}
}}
rule finish when started => {{ load("tickets.json") as count
complete result {{ count count }} }}
"#,
        root.to_string_lossy()
    );
    let parsed = whipplescript_parser::parse_program(&source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let typed =
        whipplescript_parser::action_plan::resolved::resolve_rule_types(&parsed.program, "finish")
            .unwrap();
    let database = root.join("runtime.sqlite");
    let mut f = Fixture::with_source(SqliteStore::open(&database).unwrap(), &source);
    use whipplescript_store::{
        CapabilityBinding, CapabilitySchemaRegistration, EffectProviderRegistration,
    };
    f.kernel
        .store()
        .register_capability_schema(CapabilitySchemaRegistration {
            capability: "file.import",
            description: "fixture file import",
            schema_json: "{}",
            registered_by_package_id: None,
        })
        .unwrap();
    f.kernel
        .store()
        .register_effect_provider(EffectProviderRegistration {
            provider_id: "fixture-files-import",
            effect_kind: "file.import",
            provider: "files",
            capability: "file.import",
            config_json: "{}",
            registered_by_package_id: None,
        })
        .unwrap();
    f.kernel
        .store()
        .bind_capability(CapabilityBinding {
            binding_id: "fixture-files-import",
            program_id: None,
            capability: "file.import",
            provider: "files",
            config_json: "{}",
        })
        .unwrap();
    let first = timer_fixture::project_typed(&f, &typed);
    let [effect] = first.lowering.effects.as_slice() else {
        panic!("one file import effect")
    };
    let input: Value = serde_json::from_str(&effect.input_json).unwrap();
    assert_eq!(input["path"], "tickets.json");
    assert_eq!(input["path_expr"], "path");
    assert_eq!(input["schema"], "Ticket");
    assert_eq!(input["required_fields"], json!(["owner", "priority"]));
    timer_fixture::commit(&mut f, &first);
    let claimable = f.kernel.claimable_effects(&f.instance).unwrap();
    let [claimable] = claimable.as_slice() else {
        panic!("file import is claimable")
    };
    crate::effect_handlers::run_file_import_effect_generic(
        &mut f.kernel,
        &whipplescript_store::files::NativeFileStore,
        &f.instance,
        claimable,
    )
    .unwrap();
    assert_eq!(
        f.kernel
            .store()
            .list_facts(&f.instance)
            .unwrap()
            .iter()
            .filter(|fact| fact.name == "Ticket")
            .count(),
        2
    );
    let result_fact = f
        .kernel
        .store()
        .list_facts(&f.instance)
        .unwrap()
        .into_iter()
        .find(|fact| fact.name == "file.import.completed")
        .unwrap();
    consume_record(&mut f, &result_fact.fact_id);
    let Fixture {
        kernel,
        ir,
        instance,
        frame,
        context,
    } = f;
    drop(kernel);
    let mut f = Fixture {
        kernel: RuntimeKernel::new(wrap(SqliteStore::open(&database).unwrap())),
        ir,
        instance,
        frame,
        context,
    };
    let done = timer_fixture::project_typed(&f, &typed);
    assert_eq!(done.root.boundary, Boundary::Succeeded(()));
    assert_eq!(
        serde_json::from_str::<Value>(&done.lowering.terminal.as_ref().unwrap().payload_json)
            .unwrap(),
        json!({"count":2})
    );
    timer_fixture::commit(&mut f, &done);
    drop(f);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn managed_signal_native_delivers_and_returns_its_receipt_after_reopen() {
    let root = std::env::temp_dir().join(format!(
        "managed-signal-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let source = r#"workflow NativeSignals
signal go.now { target string }
signal task.done { id string }
output result Answer
class Answer { event string }
action notify(target string) -> string {
  emit signal task.done to target { id "T-1" } as sent
  after sent succeeds { return sent.event }
}

rule finish when go.now as go => { notify(go.target) as event
complete result { event event } }
"#;
    let parsed = whipplescript_parser::parse_program(source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let typed =
        whipplescript_parser::action_plan::resolved::resolve_rule_types(&parsed.program, "finish")
            .unwrap();
    let database = root.join("runtime.sqlite");
    let mut f = Fixture::with_source(SqliteStore::open(&database).unwrap(), source);
    use whipplescript_store::{
        CapabilityBinding, CapabilitySchemaRegistration, EffectProviderRegistration,
    };
    f.kernel
        .store()
        .register_capability_schema(CapabilitySchemaRegistration {
            capability: "signal.emit",
            description: "fixture directed signal",
            schema_json: "{}",
            registered_by_package_id: None,
        })
        .unwrap();
    f.kernel
        .store()
        .register_effect_provider(EffectProviderRegistration {
            provider_id: "fixture-signal",
            effect_kind: "signal.emit",
            provider: "notify",
            capability: "signal.emit",
            config_json: "{}",
            registered_by_package_id: None,
        })
        .unwrap();
    f.kernel
        .store()
        .bind_capability(CapabilityBinding {
            binding_id: "fixture-signal",
            program_id: None,
            capability: "signal.emit",
            provider: "notify",
            config_json: "{}",
        })
        .unwrap();
    let version = f
        .kernel
        .store()
        .get_instance(&f.instance)
        .unwrap()
        .and_then(|instance| {
            f.kernel
                .store()
                .get_program_version(&instance.version_id)
                .unwrap()
        })
        .unwrap();
    let receiver = f
        .kernel
        .store()
        .create_instance(whipplescript_store::NewInstance {
            program_id: &version.program_id,
            version_id: &version.version_id,
            input_json: "{}",
        })
        .unwrap()
        .instance_id;
    let received = f
        .kernel
        .ingest_external_event(
            &f.instance,
            "go.now",
            &json!({"target":receiver}).to_string(),
            Some("go"),
        )
        .unwrap();
    f.kernel
        .derive_fact(
            &f.instance,
            "go.now",
            &received.event_id,
            &json!({"target":receiver}).to_string(),
            Some(&received.event_id),
            Some("go-fact"),
        )
        .unwrap();
    let go = f
        .kernel
        .store()
        .list_facts(&f.instance)
        .unwrap()
        .into_iter()
        .find(|fact| fact.name == "go.now")
        .unwrap();
    f.frame.trigger_event = Some(received.event_id.clone());
    f.context = RuleContext {
        trigger_event_id: Some(received.event_id),
        identity: None,
        bindings: vec![("go".into(), go)],
    };
    let first = timer_fixture::project_typed(&f, &typed);
    let [effect] = first.lowering.effects.as_slice() else {
        panic!("one signal effect")
    };
    let input: Value = serde_json::from_str(&effect.input_json).unwrap();
    assert_eq!(input["target_instance"], receiver);
    assert_eq!(input["payload"], json!({"id":"T-1"}));
    timer_fixture::commit(&mut f, &first);
    let claimable = f.kernel.claimable_effects(&f.instance).unwrap();
    let [claimable] = claimable.as_slice() else {
        panic!("signal is claimable")
    };
    crate::effect_handlers::run_notify_effect_generic(
        &mut f.kernel,
        &f.instance.clone(),
        claimable,
        &AllowDelivery,
    )
    .unwrap();
    assert!(f
        .kernel
        .store()
        .list_facts(&receiver)
        .unwrap()
        .iter()
        .any(|fact| fact.name == "task.done" && fact.value_json == r#"{"id":"T-1"}"#));
    let result_fact = f
        .kernel
        .store()
        .list_facts(&f.instance)
        .unwrap()
        .into_iter()
        .find(|fact| fact.name == "signal.emit.completed")
        .unwrap();
    consume_record(&mut f, &result_fact.fact_id);
    let Fixture {
        kernel,
        ir,
        instance,
        frame,
        context,
    } = f;
    drop(kernel);
    let mut f = Fixture {
        kernel: RuntimeKernel::new(wrap(SqliteStore::open(&database).unwrap())),
        ir,
        instance,
        frame,
        context,
    };
    let done = timer_fixture::project_typed(&f, &typed);
    assert_eq!(done.root.boundary, Boundary::Succeeded(()));
    assert_eq!(
        serde_json::from_str::<Value>(&done.lowering.terminal.as_ref().unwrap().payload_json)
            .unwrap(),
        json!({"event":"task.done"})
    );
    timer_fixture::commit(&mut f, &done);
    drop(f);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn managed_counter_native_consumes_and_returns_its_ok_receipt_after_reopen() {
    let root = std::env::temp_dir().join(format!(
        "managed-counter-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let source = r#"workflow NativeCounter
class Customer { id string }
counter budget { key Customer cap 10 reset daily timezone "UTC" }
output result Answer
class Answer { remaining int }
action spend(customer string, units int) -> int {
  consume budget for customer amount units as spent
  after spent ok as outcome { return outcome.remaining }
  after spent over as outcome { return outcome.remaining }
}
rule finish when started => { spend("C-1", 3) as remaining
complete result { remaining remaining } }
"#;
    let parsed = whipplescript_parser::parse_program(source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let typed =
        whipplescript_parser::action_plan::resolved::resolve_rule_types(&parsed.program, "finish")
            .unwrap();
    let database = root.join("runtime.sqlite");
    let mut f = Fixture::with_source(SqliteStore::open(&database).unwrap(), source);
    use whipplescript_store::{
        CapabilityBinding, CapabilitySchemaRegistration, EffectProviderRegistration,
    };
    f.kernel
        .store()
        .register_capability_schema(CapabilitySchemaRegistration {
            capability: "counter.consume",
            description: "fixture counter",
            schema_json: "{}",
            registered_by_package_id: None,
        })
        .unwrap();
    f.kernel
        .store()
        .register_effect_provider(EffectProviderRegistration {
            provider_id: "fixture-counter",
            effect_kind: "counter.consume",
            provider: "coordination",
            capability: "counter.consume",
            config_json: "{}",
            registered_by_package_id: None,
        })
        .unwrap();
    f.kernel
        .store()
        .bind_capability(CapabilityBinding {
            binding_id: "fixture-counter",
            program_id: None,
            capability: "counter.consume",
            provider: "coordination",
            config_json: "{}",
        })
        .unwrap();
    let first = timer_fixture::project_typed(&f, &typed);
    let [effect] = first.lowering.effects.as_slice() else {
        panic!("one counter effect")
    };
    let input: Value = serde_json::from_str(&effect.input_json).unwrap();
    assert_eq!(input["counter"], "budget");
    assert_eq!(input["key"], "C-1");
    assert_eq!(input["amount"], 3);
    timer_fixture::commit(&mut f, &first);
    let claimable = f.kernel.claimable_effects(&f.instance).unwrap();
    let [claimable] = claimable.as_slice() else {
        panic!("counter is claimable")
    };
    crate::effect_handlers::run_coordination_effect_generic(
        &mut f.kernel,
        &f.instance.clone(),
        claimable,
        "2026-09-13T12:00:00Z",
    )
    .unwrap();
    let result_fact = f
        .kernel
        .store()
        .list_facts(&f.instance)
        .unwrap()
        .into_iter()
        .find(|fact| fact.name == "counter.consume.completed")
        .unwrap();
    let result: Value = serde_json::from_str(&result_fact.value_json).unwrap();
    assert_eq!(result["value"]["variant"], "Ok");
    assert_eq!(result["value"]["remaining"], 7);
    consume_record(&mut f, &result_fact.fact_id);
    let Fixture {
        kernel,
        ir,
        instance,
        frame,
        context,
    } = f;
    drop(kernel);
    let mut f = Fixture {
        kernel: RuntimeKernel::new(wrap(SqliteStore::open(&database).unwrap())),
        ir,
        instance,
        frame,
        context,
    };
    let done = timer_fixture::project_typed(&f, &typed);
    assert_eq!(done.root.boundary, Boundary::Succeeded(()));
    assert_eq!(
        serde_json::from_str::<Value>(&done.lowering.terminal.as_ref().unwrap().payload_json)
            .unwrap(),
        json!({"remaining":7})
    );
    timer_fixture::commit(&mut f, &done);
    drop(f);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn managed_ledger_native_appends_and_returns_its_sequence_after_reopen() {
    let root = std::env::temp_dir().join(format!(
        "managed-ledger-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let source = r#"use std.coord
workflow NativeLedger
class Decision { area string choice string }
ledger decisions { entry Decision partition by area retain 90d }
output result Answer
class Answer { sequence int }
action record(area string, choice string) -> int {
  append Decision { area area choice choice } to decisions as saved
  after saved succeeds { return saved.seq }
}
rule finish when started => { record("api", "typed values") as sequence
complete result { sequence sequence } }
"#;
    let parsed = whipplescript_parser::parse_program(source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let typed =
        whipplescript_parser::action_plan::resolved::resolve_rule_types(&parsed.program, "finish")
            .unwrap();
    let database = root.join("runtime.sqlite");
    let mut f = Fixture::with_source(SqliteStore::open(&database).unwrap(), source);
    use whipplescript_store::coordination::Coordination;
    use whipplescript_store::{
        CapabilityBinding, CapabilitySchemaRegistration, EffectProviderRegistration,
    };
    f.kernel
        .store()
        .register_capability_schema(CapabilitySchemaRegistration {
            capability: "ledger.append",
            description: "fixture ledger",
            schema_json: "{}",
            registered_by_package_id: None,
        })
        .unwrap();
    f.kernel
        .store()
        .register_effect_provider(EffectProviderRegistration {
            provider_id: "fixture-ledger",
            effect_kind: "ledger.append",
            provider: "coordination",
            capability: "ledger.append",
            config_json: "{}",
            registered_by_package_id: None,
        })
        .unwrap();
    f.kernel
        .store()
        .bind_capability(CapabilityBinding {
            binding_id: "fixture-ledger",
            program_id: None,
            capability: "ledger.append",
            provider: "coordination",
            config_json: "{}",
        })
        .unwrap();
    let first = timer_fixture::project_typed(&f, &typed);
    let [effect] = first.lowering.effects.as_slice() else {
        panic!("one append effect")
    };
    let input: Value = serde_json::from_str(&effect.input_json).unwrap();
    assert_eq!(input["ledger"], "decisions");
    assert_eq!(input["partition"], "api");
    assert_eq!(
        input["entry"],
        json!({"area":"api","choice":"typed values"})
    );
    timer_fixture::commit(&mut f, &first);
    let claimable = f.kernel.claimable_effects(&f.instance).unwrap();
    let [claimable] = claimable.as_slice() else {
        panic!("append is claimable")
    };
    crate::effect_handlers::run_coordination_effect_generic(
        &mut f.kernel,
        &f.instance.clone(),
        claimable,
        "2026-09-13T12:00:00Z",
    )
    .unwrap();
    let entries = f
        .kernel
        .store()
        .list_entries_for_owner(None, Some("decisions"), Some("api"))
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].seq, 1);
    assert_eq!(
        serde_json::from_str::<Value>(&entries[0].payload_json).unwrap(),
        json!({"area":"api","choice":"typed values"})
    );
    let result_fact = f
        .kernel
        .store()
        .list_facts(&f.instance)
        .unwrap()
        .into_iter()
        .find(|fact| fact.name == "ledger.append.completed")
        .unwrap();
    let result: Value = serde_json::from_str(&result_fact.value_json).unwrap();
    assert_eq!(result["value"]["variant"], "Appended");
    assert_eq!(result["value"]["seq"], 1);
    consume_record(&mut f, &result_fact.fact_id);
    let Fixture {
        kernel,
        ir,
        instance,
        frame,
        context,
    } = f;
    drop(kernel);
    let mut f = Fixture {
        kernel: RuntimeKernel::new(wrap(SqliteStore::open(&database).unwrap())),
        ir,
        instance,
        frame,
        context,
    };
    let done = timer_fixture::project_typed(&f, &typed);
    assert_eq!(done.root.boundary, Boundary::Succeeded(()));
    assert_eq!(
        serde_json::from_str::<Value>(&done.lowering.terminal.as_ref().unwrap().payload_json)
            .unwrap(),
        json!({"sequence":1})
    );
    timer_fixture::commit(&mut f, &done);
    drop(f);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn managed_tracker_file_native_returns_its_item_id_after_reopen() {
    let root = std::env::temp_dir().join(format!(
        "managed-tracker-file-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let source = r#"use std.tracker
workflow NativeTrackerFile
tracker backlog
output result Answer
class Answer { item string }
action file(title string) -> string {
  file issue into backlog { title title body "from workflow" labels ["bug"] metadata { source "api" } } as filed
  after filed succeeds { return filed.id }
}
rule finish when started => { file("Fix login") as item
complete result { item item } }
"#;
    let parsed = whipplescript_parser::parse_program(source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let typed =
        whipplescript_parser::action_plan::resolved::resolve_rule_types(&parsed.program, "finish")
            .unwrap();
    let database = root.join("runtime.sqlite");
    let mut f = Fixture::with_source(SqliteStore::open(&database).unwrap(), source);
    use whipplescript_store::items::WorkItems;
    use whipplescript_store::{
        CapabilityBinding, CapabilitySchemaRegistration, EffectProviderRegistration,
    };
    f.kernel
        .store()
        .register_capability_schema(CapabilitySchemaRegistration {
            capability: "tracker.file",
            description: "fixture tracker",
            schema_json: "{}",
            registered_by_package_id: None,
        })
        .unwrap();
    f.kernel
        .store()
        .register_effect_provider(EffectProviderRegistration {
            provider_id: "fixture-tracker",
            effect_kind: "tracker.file",
            provider: "queue",
            capability: "tracker.file",
            config_json: "{}",
            registered_by_package_id: None,
        })
        .unwrap();
    f.kernel
        .store()
        .bind_capability(CapabilityBinding {
            binding_id: "fixture-tracker",
            program_id: None,
            capability: "tracker.file",
            provider: "queue",
            config_json: "{}",
        })
        .unwrap();
    let first = timer_fixture::project_typed(&f, &typed);
    let [effect] = first.lowering.effects.as_slice() else {
        panic!("one tracker filing")
    };
    let input: Value = serde_json::from_str(&effect.input_json).unwrap();
    assert_eq!(input["queue"], "backlog");
    assert_eq!(input["item"]["title"], "Fix login");
    timer_fixture::commit(&mut f, &first);
    let claimable = f.kernel.claimable_effects(&f.instance).unwrap();
    let [claimable] = claimable.as_slice() else {
        panic!("tracker filing is claimable")
    };
    crate::effect_handlers::run_queue_effect_generic(
        &mut f.kernel,
        &f.instance.clone(),
        claimable,
        "2026-09-13T12:00:00Z",
        &crate::effect_config::EffectConfig::default(),
    )
    .unwrap();
    let items = f.kernel.store().list_items(Some("backlog"), None).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].id, "WS-1");
    assert_eq!(items[0].title, "Fix login");
    let result_fact = f
        .kernel
        .store()
        .list_facts(&f.instance)
        .unwrap()
        .into_iter()
        .find(|fact| fact.name == "tracker.file.completed")
        .unwrap();
    let result: Value = serde_json::from_str(&result_fact.value_json).unwrap();
    assert_eq!(result["value"]["id"], "WS-1");
    consume_record(&mut f, &result_fact.fact_id);
    let Fixture {
        kernel,
        ir,
        instance,
        frame,
        context,
    } = f;
    drop(kernel);
    let mut f = Fixture {
        kernel: RuntimeKernel::new(wrap(SqliteStore::open(&database).unwrap())),
        ir,
        instance,
        frame,
        context,
    };
    let done = timer_fixture::project_typed(&f, &typed);
    assert_eq!(done.root.boundary, Boundary::Succeeded(()));
    assert_eq!(
        serde_json::from_str::<Value>(&done.lowering.terminal.as_ref().unwrap().payload_json)
            .unwrap(),
        json!({"item":"WS-1"})
    );
    timer_fixture::commit(&mut f, &done);
    drop(f);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn managed_tracker_lifecycle_native_composes_and_reopens() {
    let root = std::env::temp_dir().join(format!(
        "managed-tracker-lifecycle-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let source = r#"use std.tracker
workflow NativeTrackerLifecycle
tracker backlog
output result Answer
class Answer { item string status string }
action close(title string) -> Answer {
  file issue into backlog { title title body "native" labels ["bug"] } as filed
  after filed succeeds {
    claim filed as held
    after held succeeds {
      release held as reopened
      after reopened succeeds {
        claim reopened as reclaimed
        after reclaimed succeeds {
          finish reclaimed { summary "verified" } as finished
          after finished succeeds { return { item finished.id, status finished.status } }
        }
      }
    }
  }
}
rule finish when started => { close("Fix login") as result
complete result result }
"#;
    let parsed = whipplescript_parser::parse_program(source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let typed =
        whipplescript_parser::action_plan::resolved::resolve_rule_types(&parsed.program, "finish")
            .unwrap();
    let database = root.join("runtime.sqlite");
    let mut f = Fixture::with_source(SqliteStore::open(&database).unwrap(), source);
    use whipplescript_store::items::WorkItems;
    use whipplescript_store::{
        CapabilityBinding, CapabilitySchemaRegistration, EffectProviderRegistration,
    };
    for kind in [
        "tracker.file",
        "tracker.claim",
        "tracker.release",
        "tracker.finish",
    ] {
        f.kernel
            .store()
            .register_capability_schema(CapabilitySchemaRegistration {
                capability: kind,
                description: "fixture tracker lifecycle",
                schema_json: "{}",
                registered_by_package_id: None,
            })
            .unwrap();
        f.kernel
            .store()
            .register_effect_provider(EffectProviderRegistration {
                provider_id: kind,
                effect_kind: kind,
                provider: "queue",
                capability: kind,
                config_json: "{}",
                registered_by_package_id: None,
            })
            .unwrap();
        f.kernel
            .store()
            .bind_capability(CapabilityBinding {
                binding_id: kind,
                program_id: None,
                capability: kind,
                provider: "queue",
                config_json: "{}",
            })
            .unwrap();
    }
    for expected in [
        "tracker.file",
        "tracker.claim",
        "tracker.release",
        "tracker.claim",
        "tracker.finish",
    ] {
        let progress = timer_fixture::project_typed(&f, &typed);
        let [effect] = progress.lowering.effects.as_slice() else {
            panic!("one {expected} effect")
        };
        assert_eq!(effect.kind, expected);
        timer_fixture::commit(&mut f, &progress);
        let claimable = f.kernel.claimable_effects(&f.instance).unwrap();
        let effect = claimable
            .iter()
            .find(|effect| effect.kind == expected)
            .expect("new lifecycle effect is claimable");
        crate::effect_handlers::run_queue_effect_generic(
            &mut f.kernel,
            &f.instance.clone(),
            effect,
            "2026-09-13T12:00:00Z",
            &crate::effect_config::EffectConfig::default(),
        )
        .unwrap();
        let result_fact = f
            .kernel
            .store()
            .list_facts(&f.instance)
            .unwrap()
            .into_iter()
            .find(|fact| fact.name == format!("{expected}.completed"))
            .expect("lifecycle result fact");
        consume_record(&mut f, &result_fact.fact_id);
    }
    let items = f.kernel.store().list_items(Some("backlog"), None).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].id, "WS-1");
    assert_eq!(items[0].status, "closed");
    let Fixture {
        kernel,
        ir,
        instance,
        frame,
        context,
    } = f;
    drop(kernel);
    let mut f = Fixture {
        kernel: RuntimeKernel::new(wrap(SqliteStore::open(&database).unwrap())),
        ir,
        instance,
        frame,
        context,
    };
    let done = timer_fixture::project_typed(&f, &typed);
    assert_eq!(done.root.boundary, Boundary::Succeeded(()));
    assert_eq!(
        serde_json::from_str::<Value>(&done.lowering.terminal.as_ref().unwrap().payload_json)
            .unwrap(),
        json!({"item":"WS-1","status":"closed"})
    );
    timer_fixture::commit(&mut f, &done);
    drop(f);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn managed_file_write_native_returns_public_receipt_after_reopen() {
    let root = std::env::temp_dir().join(format!(
        "managed-file-write-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let source = format!(
        r#"workflow NativeWrites
file store workspace {{ root {:?} allow write ["*.md"] }}
output result Answer
class Answer {{ text string }}
action save(path string, body string) -> string {{
  write markdown to workspace at path {{ body body mode upsert }} as written
  after written succeeds {{ return written.content_hash }}
}}
rule finish when started => {{ save("guide.md", "native guide") as digest
complete result {{ text digest }} }}
"#,
        root.to_string_lossy()
    );
    let parsed = whipplescript_parser::parse_program(&source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let typed =
        whipplescript_parser::action_plan::resolved::resolve_rule_types(&parsed.program, "finish")
            .unwrap();
    let database = root.join("runtime.sqlite");
    let mut f = Fixture::with_source(SqliteStore::open(&database).unwrap(), &source);
    use whipplescript_store::{
        CapabilityBinding, CapabilitySchemaRegistration, EffectProviderRegistration,
    };
    f.kernel
        .store()
        .register_capability_schema(CapabilitySchemaRegistration {
            capability: "file.write",
            description: "fixture file write",
            schema_json: "{}",
            registered_by_package_id: None,
        })
        .unwrap();
    f.kernel
        .store()
        .register_effect_provider(EffectProviderRegistration {
            provider_id: "fixture-files-write",
            effect_kind: "file.write",
            provider: "files",
            capability: "file.write",
            config_json: "{}",
            registered_by_package_id: None,
        })
        .unwrap();
    f.kernel
        .store()
        .bind_capability(CapabilityBinding {
            binding_id: "fixture-files-write",
            program_id: None,
            capability: "file.write",
            provider: "files",
            config_json: "{}",
        })
        .unwrap();
    let first = timer_fixture::project_typed(&f, &typed);
    let [effect] = first.lowering.effects.as_slice() else {
        panic!("one file write effect")
    };
    let input: Value = serde_json::from_str(&effect.input_json).unwrap();
    assert_eq!(input["path"], "guide.md");
    assert_eq!(input["body"], "native guide");
    timer_fixture::commit(&mut f, &first);
    let claimable = f.kernel.claimable_effects(&f.instance).unwrap();
    let [claimable] = claimable.as_slice() else {
        panic!("file write is claimable")
    };
    crate::effect_handlers::run_file_write_effect_generic(
        &mut f.kernel,
        &whipplescript_store::files::NativeFileStore,
        &f.instance,
        claimable,
    )
    .unwrap();
    assert_eq!(
        std::fs::read_to_string(root.join("guide.md")).unwrap(),
        "native guide"
    );
    let result_fact = f
        .kernel
        .store()
        .list_facts(&f.instance)
        .unwrap()
        .into_iter()
        .find(|fact| fact.name == "file.write.completed")
        .unwrap();
    consume_record(&mut f, &result_fact.fact_id);
    let Fixture {
        kernel,
        ir,
        instance,
        frame,
        context,
    } = f;
    drop(kernel);
    let mut f = Fixture {
        kernel: RuntimeKernel::new(wrap(SqliteStore::open(&database).unwrap())),
        ir,
        instance,
        frame,
        context,
    };
    let done = timer_fixture::project_typed(&f, &typed);
    assert_eq!(done.root.boundary, Boundary::Succeeded(()));
    assert_eq!(
        serde_json::from_str::<Value>(&done.lowering.terminal.as_ref().unwrap().payload_json)
            .unwrap(),
        json!({"text":whipplescript_store::stable_hash_hex("native guide")})
    );
    timer_fixture::commit(&mut f, &done);
    drop(f);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn managed_file_export_native_uses_its_admitted_collection_after_reopen() {
    let root = std::env::temp_dir().join(format!(
        "managed-file-export-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let source = format!(
        r#"workflow NativeExports
file store workspace {{ root {:?} allow write ["*.jsonl"] }}
output result Answer
class Answer {{ count int }}
class Ticket {{ owner string priority int }}
action save(path string) -> int {{
  export jsonl Ticket to workspace at path {{ where priority > 2 mode upsert }} as written
  after written succeeds {{ return written.row_count }}
}}
rule finish when started => {{ save("tickets.jsonl") as count
complete result {{ count count }} }}
"#,
        root.to_string_lossy()
    );
    let parsed = whipplescript_parser::parse_program(&source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let typed =
        whipplescript_parser::action_plan::resolved::resolve_rule_types(&parsed.program, "finish")
            .unwrap();
    let database = root.join("runtime.sqlite");
    let mut f = Fixture::with_source(SqliteStore::open(&database).unwrap(), &source);
    use whipplescript_store::{
        CapabilityBinding, CapabilitySchemaRegistration, EffectProviderRegistration,
    };
    f.kernel
        .store()
        .register_capability_schema(CapabilitySchemaRegistration {
            capability: "file.export",
            description: "fixture file export",
            schema_json: "{}",
            registered_by_package_id: None,
        })
        .unwrap();
    f.kernel
        .store()
        .register_effect_provider(EffectProviderRegistration {
            provider_id: "fixture-files-export",
            effect_kind: "file.export",
            provider: "files",
            capability: "file.export",
            config_json: "{}",
            registered_by_package_id: None,
        })
        .unwrap();
    f.kernel
        .store()
        .bind_capability(CapabilityBinding {
            binding_id: "fixture-files-export",
            program_id: None,
            capability: "file.export",
            provider: "files",
            config_json: "{}",
        })
        .unwrap();
    for (key, owner, priority) in [("alice", "alice", 4), ("bob", "bob", 1)] {
        f.kernel
            .derive_fact(
                &f.instance,
                "Ticket",
                key,
                &json!({"owner":owner,"priority":priority}).to_string(),
                None,
                Some(&format!("seed-{key}")),
            )
            .unwrap();
    }
    let first = timer_fixture::project_typed(&f, &typed);
    let [effect] = first.lowering.effects.as_slice() else {
        panic!("one file export effect")
    };
    let input: Value = serde_json::from_str(&effect.input_json).unwrap();
    assert_eq!(
        input["rows_argument"]["value"],
        json!([{"owner":"alice","priority":4}])
    );
    timer_fixture::commit(&mut f, &first);

    // A later matching fact cannot retarget already admitted external work.
    f.kernel
        .derive_fact(
            &f.instance,
            "Ticket",
            "carol",
            &json!({"owner":"carol","priority":5}).to_string(),
            None,
            Some("seed-carol"),
        )
        .unwrap();
    let claimable = f.kernel.claimable_effects(&f.instance).unwrap();
    let [claimable] = claimable.as_slice() else {
        panic!("file export is claimable")
    };
    crate::effect_handlers::run_file_export_effect_generic(
        &mut f.kernel,
        &whipplescript_store::files::NativeFileStore,
        &f.instance,
        claimable,
    )
    .unwrap();
    assert_eq!(
        std::fs::read_to_string(root.join("tickets.jsonl")).unwrap(),
        "{\"owner\":\"alice\",\"priority\":4}\n"
    );
    let result_fact = f
        .kernel
        .store()
        .list_facts(&f.instance)
        .unwrap()
        .into_iter()
        .find(|fact| fact.name == "file.export.completed")
        .unwrap();
    consume_record(&mut f, &result_fact.fact_id);
    let Fixture {
        kernel,
        ir,
        instance,
        frame,
        context,
    } = f;
    drop(kernel);
    let mut f = Fixture {
        kernel: RuntimeKernel::new(wrap(SqliteStore::open(&database).unwrap())),
        ir,
        instance,
        frame,
        context,
    };
    let done = timer_fixture::project_typed(&f, &typed);
    assert_eq!(done.root.boundary, Boundary::Succeeded(()));
    assert_eq!(
        serde_json::from_str::<Value>(&done.lowering.terminal.as_ref().unwrap().payload_json)
            .unwrap(),
        json!({"count":1})
    );
    timer_fixture::commit(&mut f, &done);
    drop(f);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn managed_tell_native_investigation_and_policy_join_inline_or_extracted_after_reopen() {
    for nested in [false, true] {
        let source = if nested {
            r#"
workflow Captures
action investigate(text string) -> string {
  tell worker "Investigate {{ text }}" as turn
  return turn
}
action review() -> Answer {
  investigate("ticket") as turn
  coerce classify("policy", null) as policy
  coerce classify(turn, policy.text) as joined
  case joined { Answer as final => { return final } }
}
rule finish when started => { review() as result
complete result result }
"#
        } else {
            r#"
workflow Captures
rule finish when started => {
  tell worker "Investigate ticket" as turn
  coerce classify("policy", null) as policy
  coerce classify(turn, policy.text) as joined
  case joined { Answer as final => { complete result final } }
}
"#
        };
        let path = std::env::temp_dir().join(format!(
            "managed-tell-{}-{nested}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let typed_source = format!(
            "{}{}",
            DECLARATIONS.split("rule finish").next().unwrap(),
            source.trim().strip_prefix("workflow Captures").unwrap()
        );
        let parsed = whipplescript_parser::parse_program(&typed_source);
        assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
        let typed = whipplescript_parser::action_plan::resolved::resolve_rule_types(
            &parsed.program,
            "finish",
        )
        .unwrap();
        let artifact = crate::source_action::plan_artifact::encode_typed(&typed).unwrap();
        let mut f = Fixture::with_source(SqliteStore::open(&path).unwrap(), DECLARATIONS);
        f.kernel
            .store()
            .register_profile(whipplescript_store::ProfileRegistration {
                profile_id: "fixture-profile",
                name: "no-repo",
                description: "fixture profile",
                enforcement_mode: "enforce",
                allowed_capabilities_json: r#"["agent.tell"]"#,
                config_json: "{}",
            })
            .unwrap();
        let first = timer_fixture::project_typed(&f, &typed);
        assert_eq!(first.lowering.effects.len(), 2);
        let tell = first
            .lowering
            .effects
            .iter()
            .find(|effect| effect.kind == "agent.tell")
            .unwrap();
        let policy = first
            .lowering
            .effects
            .iter()
            .find(|effect| effect.kind == "schema.coerce")
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&tell.input_json).unwrap()["prompt"],
            "Investigate ticket"
        );
        assert!(first.lowering.facts.is_empty());
        timer_fixture::commit(&mut f, &first);
        settle_coerce(&mut f, policy, "policy result");
        assert!(timer_fixture::project_typed(&f, &typed)
            .lowering
            .effects
            .is_empty());
        f.kernel
            .run_agent_turn(
                AgentTurnExecution {
                    instance_id: &f.instance,
                    effect_id: &tell.effect_id,
                    run_id: &format!("run-{}", tell.effect_id),
                    provider: "mock",
                    worker_id: "fixture",
                    lease_id: &format!("lease-{}", tell.effect_id),
                    lease_expires_at: "2030-01-01T00:00:00Z",
                    agent: "worker",
                    profile: tell.profile.as_deref(),
                    input_json: &tell.input_json,
                    skill_names: &[],
                },
                &MockAgentHarness::completed("investigation result"),
            )
            .unwrap();
        let turn_fact = f
            .kernel
            .store()
            .list_facts(&f.instance)
            .unwrap()
            .into_iter()
            .find(|fact| fact.name == "agent.turn.completed")
            .unwrap();
        consume_record(&mut f, &turn_fact.fact_id);
        let Fixture {
            kernel,
            ir,
            instance,
            frame,
            context,
        } = f;
        drop(kernel);
        drop(typed);
        let typed = crate::source_action::plan_artifact::decode_typed(&artifact).unwrap();
        let mut f = Fixture {
            kernel: RuntimeKernel::new(wrap(SqliteStore::open(&path).unwrap())),
            ir,
            instance,
            frame,
            context,
        };
        let joined = timer_fixture::project_typed(&f, &typed);
        assert_eq!(joined.lowering.effects.len(), 1);
        let input: Value = serde_json::from_str(&joined.lowering.effects[0].input_json).unwrap();
        assert_eq!(
            input["arguments"],
            json!({"arg0":"investigation result","arg1":"policy result"})
        );
        assert!(joined.lowering.action_captures.is_empty());
        timer_fixture::commit(&mut f, &joined);
        settle_coerce(&mut f, &joined.lowering.effects[0], "review result");
        let done = timer_fixture::project_typed(&f, &typed);
        assert_eq!(done.root.boundary, Boundary::Succeeded(()));
        assert!(done.lowering.facts.is_empty());
        assert_eq!(
            serde_json::from_str::<Value>(&done.lowering.terminal.as_ref().unwrap().payload_json)
                .unwrap(),
            json!({"text":"review result"})
        );
        timer_fixture::commit(&mut f, &done);
        let replay = timer_fixture::project_typed(&f, &typed);
        assert_eq!(
            done.lowering.terminal.as_ref().unwrap().idempotency_key,
            replay.lowering.terminal.as_ref().unwrap().idempotency_key
        );
        let before = f.events().len();
        let report = step_instance_generic(&mut f.kernel, &f.instance, &f.ir, None, None).unwrap();
        assert_eq!(report.committed_rules, 0);
        assert_eq!(f.events().len(), before);
        assert_eq!(
            f.kernel
                .store()
                .get_instance(&f.instance)
                .unwrap()
                .unwrap()
                .status,
            "completed"
        );
        assert_eq!(
            f.events()
                .iter()
                .filter(|e| e.event_type == "workflow.completed")
                .count(),
            1
        );
        assert_eq!(f.kernel.store().list_effects(&f.instance).unwrap().len(), 3);
        assert_eq!(
            f.events()
                .iter()
                .filter(|event| event.event_type == "agent.turn.completed")
                .count(),
            1
        );
        assert!(!f
            .kernel
            .store()
            .list_facts(&f.instance)
            .unwrap()
            .iter()
            .any(|fact| fact.name == "agent.turn.completed"));
        drop(f);
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn managed_effect_contract_native_refuses_a_declared_agent_outside_the_captured_domain() {
    for recorded in [false, true] {
        let declarations = DECLARATIONS.replace(
            "agent worker",
            "agent other { provider mock capacity 2 }\nagent worker",
        );
        let source = format!("{}action ask(who AgentRef<worker>) -> string {{ tell who \"Work\" as turn\nreturn turn }}\nrule finish when started => {{ ask(worker) as result }}", declarations.split("rule finish").next().unwrap());
        let typed = whipplescript_parser::action_plan::resolved::resolve_rule_types(
            &whipplescript_parser::parse_program(&source).program,
            "finish",
        )
        .unwrap();
        let artifact = crate::source_action::plan_artifact::encode_typed(&typed).unwrap();
        let typed = crate::source_action::plan_artifact::decode_typed(&artifact).unwrap();
        let path = std::env::temp_dir().join(format!(
            "effect-domain-{}-{recorded}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut f = Fixture::with_source(SqliteStore::open(&path).unwrap(), &declarations);
        let mut first = timer_fixture::project_typed(&f, &typed);
        assert_eq!(first.lowering.effects[0].target.as_deref(), Some("worker"));
        if recorded {
            let mut input: Value =
                serde_json::from_str(&first.lowering.effects[0].input_json).unwrap();
            input["agent"] = json!("other");
            first.lowering.effects[0].target = Some("other".into());
            first.lowering.effects[0].input_json = input.to_string();
        } else {
            assert_eq!(first.lowering.action_captures.len(), 1);
            first.lowering.action_captures[0].arguments[0].value = json!("other");
            first.lowering.effects.clear();
        }
        timer_fixture::commit(&mut f, &first);
        let before = f.events().len();
        let error = timer_fixture::try_project_typed(&f, &typed).unwrap_err();
        assert!(
            error.message.contains("outside its checked agent domain"),
            "{error:?}"
        );
        assert_eq!(f.events().len(), before);
        assert_eq!(
            f.kernel.store().list_effects(&f.instance).unwrap().len(),
            usize::from(recorded)
        );
        drop(f);
        std::fs::remove_file(path).unwrap();
    }
}
