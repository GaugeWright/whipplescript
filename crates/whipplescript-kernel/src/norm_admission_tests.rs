use std::cell::RefCell;

use super::*;
use crate::norm_execution::fixtures::{self as f, Boundary};
use serde_json::json;
use whipplescript_store::branches::{BranchStore, Branches, CutRecord, MAINLINE_BRANCH_ID};
use whipplescript_store::content::ContentBlobs;
use whipplescript_store::items::WorkItemStore;
use whipplescript_store::norm::NormAct;
use whipplescript_store::norm_artifact::{capture_cut, ArtifactLimits};
use whipplescript_store::SqliteStore;

/// A native ledger a test can append to between a gate's preparation and its
/// commit, as a concurrent writer would.
struct Ledger(RefCell<WorkItemStore>);

impl AdmissionLedger for Ledger {
    fn bootstrapped(&self) -> StoreResult<bool> {
        self.0.borrow().bootstrapped()
    }
    fn capture(&self, verifier: &dyn NormVerifier) -> StoreResult<(NormView, Vec<TrackerEvent>)> {
        self.0.borrow().capture(verifier)
    }
    fn exclusively(
        &self,
        f: &mut dyn FnMut() -> StoreResult<GateCommit>,
    ) -> StoreResult<GateCommit> {
        self.0.borrow().exclusively(f)
    }
}

/// A base cut and a proposed one, with the files a gate judges.
fn cuts() -> (BranchStore, f::Blobs) {
    let blobs = f::Blobs::default();
    let mut branches = BranchStore::open(":memory:").expect("the fixture's own step");
    branches
        .ensure_mainline("t0")
        .expect("the fixture's own step");
    for (cut, body) in [("base", "old"), ("proposed", "new")] {
        let file = blobs.put(body.as_bytes()).expect("the fixture's own step");
        let root = blobs
            .put(json!({"main.py": file}).to_string().as_bytes())
            .expect("the fixture's own step");
        branches
            .record_cut(CutRecord {
                cut_id: cut,
                change_id: cut,
                branch_id: MAINLINE_BRANCH_ID,
                manifest_hash: &root,
                parent_cut_id: None,
                origin: None,
                actor: None,
                intent: None,
                recorded_at: "t1",
            })
            .expect("the fixture's own step");
    }
    (branches, blobs)
}

#[test]
fn the_gate_admits_what_is_supported_and_refuses_what_changed_or_is_not() {
    let runtime = SqliteStore::open_in_memory().unwrap();
    let (store, record) = f::fixture(Some(f::template()), false);
    // The host says how to read the ledger's vocabularies: the requirement's
    // is context.
    let requirement_vocabulary = store.norm_view(&Boundary).unwrap().records[&record]
        .vocabulary
        .clone();
    let configuration = PlanningConfiguration::parse(
        &json!({"capability":"observer","roles":[{"vocabulary":requirement_vocabulary,"interpretation":"context"}]})
            .to_string(),
    )
    .unwrap();
    let mut runtime_binding = f::method().runtime;
    runtime_binding.engine = crate::norm_runner::PythonEngine::Cpython3147Wasi {
        artifact_path: "/opt/reactor.wasm".into(),
        artifact_sha256: "a".repeat(64),
    };
    runtime_binding.executable = "/usr/local/bin/whip".into();
    let policy =
        ProtectedPythonPolicy::new(&serde_json::to_string(&runtime_binding).unwrap(), "t9")
            .unwrap();
    let verify = |_: &PythonRuntime| Ok(());
    let host = || {
        Ok(AdmissionHost {
            verifier: &Boundary,
            configuration: &configuration,
            runtime: &runtime,
            policy: &policy,
            verify_runtime: &verify,
        })
    };
    let (branches, blobs) = cuts();
    let capture = |cut: &str| capture_cut(&branches, &blobs, cut, ArtifactLimits::default());

    // No norm ledger: nothing is gated, the certificate says so, and the ref
    // moves inside the commit.
    let empty = Ledger(RefCell::new(WorkItemStore::open_in_memory().unwrap()));
    let mut gate = NormMainlineAdmission::new(&empty, host(), AdmissionDoor::Promote, "main");
    assert_eq!(
        gate.prepare(Some("base"), "proposed", &capture).unwrap(),
        GateVerdict::Admit
    );
    assert_eq!(gate.certificate().unwrap().anchor, None);
    let mut moved = false;
    assert_eq!(
        gate.commit(&mut || {
            moved = true;
            Ok(())
        })
        .unwrap(),
        GateCommit::Committed
    );
    assert!(moved);
    // A commit nothing prepared is refused.
    let mut unprepared = NormMainlineAdmission::new(&empty, host(), AdmissionDoor::Promote, "main");
    assert!(matches!(
        unprepared.commit(&mut || Ok(())),
        Err(StoreError::Conflict(message)) if message == "the mainline gate has no certificate"
    ));

    // A ledger the host cannot evaluate refuses, saying why.
    let ledger = Ledger(RefCell::new(store));
    let mut blind = NormMainlineAdmission::new(
        &ledger,
        Err::<AdmissionHost<'_, SqliteStore>, _>("no planning is configured".into()),
        AdmissionDoor::Promote,
        "main",
    );
    let GateVerdict::Refuse(refusal) = blind.prepare(Some("base"), "proposed", &capture).unwrap()
    else {
        panic!("an unevaluable ledger admitted a proposal");
    };
    assert_eq!(
        refusal.reason,
        "the mainline's gated requirements cannot be evaluated: no planning is configured"
    );

    // The requirement is not yet effective, so nothing is gated and the
    // proposal is admitted at the ledger's current state.
    let mut gate = NormMainlineAdmission::new(&ledger, host(), AdmissionDoor::Promote, "main");
    assert_eq!(
        gate.prepare(Some("base"), "proposed", &capture).unwrap(),
        GateVerdict::Admit
    );
    let certified = gate.certificate().unwrap().clone();
    assert!(certified.anchor.is_some());
    assert!(certified.requirements.is_empty());
    // The requirement's acceptance lands before the commit: the certificate is
    // stale and the ref does not move (NP-14).
    {
        let mut store = ledger.0.borrow_mut();
        let view = store.norm_view(&Boundary).unwrap();
        let current = &view.records[&record];
        store
            .append_norm_event(
                &f::sign(
                    "accept",
                    NormAct::Transition {
                        ledger: view.ledger.clone(),
                        authority: None,
                        vocabulary: current.vocabulary.clone(),
                        record: record.clone(),
                        previous: current.head.clone(),
                        status: "accepted".into(),
                    },
                ),
                &Boundary,
            )
            .unwrap();
    }
    let mut moved = false;
    assert_eq!(
        gate.commit(&mut || {
            moved = true;
            Ok(())
        })
        .unwrap(),
        GateCommit::Stale {
            changed: "the norm ledger changed after the admission was prepared".into()
        }
    );
    assert!(!moved, "a stale certificate never moves the ref");
    // Prepared again, the now-effective requirement has no support at the
    // proposal, and the refusal names it (NP-15).
    let GateVerdict::Refuse(refusal) = gate.prepare(Some("base"), "proposed", &capture).unwrap()
    else {
        panic!("an unsupported requirement admitted a proposal");
    };
    assert!(refusal.reason.contains(&record), "{}", refusal.reason);
    assert!(refusal.detail["method_gaps"]
        .as_array()
        .is_some_and(|gaps| gaps.iter().any(|gap| gap == &json!(record))));
}

/// A reservation's selectors cover their future members (norm-plane §7): a
/// subtree covers files it does not hold yet, an exact path only itself,
/// and a pattern the gate cannot resolve conservatively covers everything.
#[test]
fn reservation_selectors_cover_future_members_and_widen_what_they_cannot_resolve() {
    assert!(covers("src/**", "src/parser.py"));
    assert!(covers("src/**", "src/not/yet/created.py"));
    assert!(covers("src/**", "src"));
    assert!(!covers("src/**", "srcs/parser.py"));
    assert!(!covers("src/**", "README.md"));
    assert!(covers("src/auth.py", "src/auth.py"));
    assert!(!covers("src/auth.py", "src/parser.py"));
    assert!(covers("**", "README.md"));
    assert!(covers("src/*.py", "checks/q0.json"));
    assert_eq!(
        changed_paths(
            &[
                ("a".to_owned(), "1".to_owned()),
                ("b".to_owned(), "2".to_owned())
            ]
            .into(),
            &[
                ("b".to_owned(), "3".to_owned()),
                ("c".to_owned(), "4".to_owned())
            ]
            .into(),
        ),
        ["a", "b", "c"].map(str::to_owned).into()
    );
}
