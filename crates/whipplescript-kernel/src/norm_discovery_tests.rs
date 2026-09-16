use super::*;
use crate::norm_execution::fixtures::*;
use crate::norm_runner::PythonEngine;
use serde_json::json;
use std::cell::Cell;

#[test]
fn discovery_reuses_execution_installation_checks_for_both_observers() {
    for protected in [false, true] {
        let mut method = method();
        if protected {
            method.runtime.engine = PythonEngine::Cpython3147Wasi {
                artifact_path: "/runtime/python.wasm".into(),
                artifact_sha256: "a".repeat(64),
            };
            method.runtime.executable = "whip".into();
        }
        let mut support = template();
        support["method"] = json!(method);
        let (ledger, id) = fixture(Some(support), true);
        let view = ledger.norm_view(&Boundary).unwrap();
        let selected = view.requirement_inventory().unwrap().requirements[&id].clone();
        let candidate = artifact("def allow(user): return False");
        let mut installed = script();
        installed.body = method.adapter().into();
        installed.sha256 = crate::exec_http::sha256_hex(installed.body.as_bytes());
        installed.argv_json = if protected {
            json!(["whip", "executor", "observe-norm", "{script}"])
        } else {
            json!(["python3", "-I", "{script}"])
        }
        .to_string();
        let calls = Cell::new(0);
        let identity = discover(&selected, &candidate, &installed, |runtime| {
            assert_eq!(runtime, &method.runtime);
            calls.set(calls.get() + 1);
            Ok(())
        })
        .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(identity, method.reference());
        let prepared = PreparedNormExecution::prepare(
            &history(&ledger),
            &Boundary,
            &candidate,
            &installed,
            selection(&view.ledger, &id),
        )
        .unwrap();
        assert_eq!(identity, prepared.runner().method().reference());
        for fault in [
            "name",
            "body",
            "digest",
            "argv",
            "bad-argv",
            "environment",
            "bad-environment",
            "reuse",
        ] {
            let mut changed = installed.clone();
            match fault {
                "name" => changed.name.clear(),
                "body" => changed.body.push_str("changed"),
                "digest" => changed.sha256 = "b".repeat(64),
                "argv" => changed.argv_json = json!(["different"]).to_string(),
                "bad-argv" => changed.argv_json = "{".into(),
                "environment" => changed.env_json = json!({"PYTHONPATH":"/outside"}).to_string(),
                "bad-environment" => changed.env_json = "{".into(),
                _ => changed.hermetic = true,
            }
            assert!(
                discover(&selected, &candidate, &changed, |_| panic!(
                    "installation refusal before runtime verification"
                ))
                .is_err(),
                "{fault}"
            );
        }
        let refused = discover(&selected, &candidate, &installed, |_| {
            Err("host runtime is unavailable".into())
        })
        .unwrap_err();
        assert_eq!(refused, "host runtime is unavailable");
    }
}

#[test]
fn discovery_requires_usable_contract_candidate_and_meaning() {
    let (ledger, id) = fixture(Some(template()), true);
    let view = ledger.norm_view(&Boundary).unwrap();
    let selected = view.requirement_inventory().unwrap().requirements[&id].clone();
    let candidate = artifact("def allow(user): return False");
    for fault in [
        "meaning",
        "template",
        "invalid-template",
        "module",
        "cases",
        "empty-family",
    ] {
        let mut changed = selected.clone();
        match fault {
            "meaning" => changed.requirement = None,
            "template" => changed.declaration.as_mut().unwrap().support_contract = None,
            "invalid-template" => {
                changed.declaration.as_mut().unwrap().support_contract = Some("{}".into())
            }
            _ => {
                let mut support = template();
                if fault == "module" {
                    support["method"]["module"] = json!("absent");
                } else {
                    support["cases"] = json!([]);
                    if fault == "empty-family" {
                        support["method"]["cases"] = json!([]);
                    }
                }
                changed.declaration.as_mut().unwrap().support_contract = Some(support.to_string());
            }
        }
        assert!(
            discover(&changed, &candidate, &script(), |_| panic!(
                "unusable support before host verification"
            ))
            .is_err(),
            "{fault}"
        );
    }
}
