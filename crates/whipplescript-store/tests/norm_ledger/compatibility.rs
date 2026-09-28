// Typed norm compatibility (norm-plane §11.1, slice U1): the ledger checks
// the typed parts of effective requirements whose domains overlap, jointly and
// within a bound, and a checker's verdict enters only as an observation.

fn accept(keys: &Keys, store: &mut WorkItemStore, record: &str, nonce: &str) {
    let event = transition_current(keys, store, record, "accepted", "owner", nonce);
    store.append_norm_event(&event, keys).unwrap();
}

fn obligation(keys: &Keys, store: &mut WorkItemStore, name: &str, domain: &str) -> String {
    let id = inventory_create(
        keys,
        store,
        "obligation",
        name,
        json!({"name": name, "proposition": "typed", "domain": domain, "subject": format!("{domain}x")}),
    );
    accept(keys, store, &id, &format!("accept-{name}"));
    id
}

fn constrain(
    keys: &Keys,
    store: &mut WorkItemStore,
    requirement: &str,
    declarations: &[&str],
    formula: &str,
    nonce: &str,
) -> String {
    let id = inventory_create(
        keys,
        store,
        "constraint",
        nonce,
        json!({"requirement": requirement, "declarations": declarations, "formula": formula}),
    );
    accept(keys, store, &id, &format!("accept-{nonce}"));
    id
}

#[test]
fn norm_compatibility_checks_overlapping_typed_requirements_jointly() {
    use whipplescript_core::norm_compatibility::{Outcome, Value};
    let (keys, mut store) = inventory_store(NormCharter::bundled().unwrap());
    let bools = ["x: bool", "y: bool", "z: bool"];
    let a = obligation(&keys, &mut store, "a", "src/");
    let b = obligation(&keys, &mut store, "b", "src/");
    let c = obligation(&keys, &mut store, "c", "src/auth/");
    let elsewhere = obligation(&keys, &mut store, "elsewhere", "docs/");
    let prose = obligation(&keys, &mut store, "prose", "src/");
    constrain(&keys, &mut store, &a, &bools, "x = y", "a-typed");
    constrain(&keys, &mut store, &b, &bools, "y = z", "b-typed");
    let third = constrain(&keys, &mut store, &c, &bools, "x != z", "c-typed");
    // `docs/` shares the variable name but not the region: never compared.
    constrain(&keys, &mut store, &elsewhere, &["x: bool"], "x = false", "docs-typed");
    let broken = constrain(&keys, &mut store, &prose, &["x: float"], "x = 1", "broken");

    let view = store.norm_view(&keys).unwrap();
    let checked = view.compatibility().unwrap();
    let triple = checked
        .components
        .iter()
        .find(|component| component.norms.contains(&a))
        .unwrap();
    // Pairwise each is satisfiable; jointly the three are not, and the core
    // names all three.
    let mut core = vec![a.clone(), b.clone(), c.clone()];
    core.sort();
    assert_eq!(triple.outcome, Outcome::Incompatible { core });
    let docs = checked
        .components
        .iter()
        .find(|component| component.norms == [elsewhere.clone()])
        .expect("a disjoint region is its own component");
    assert!(matches!(docs.outcome, Outcome::Compatible { .. }));
    assert!(checked.untyped.contains(&prose), "{checked:?}");
    assert!(checked.malformed.contains_key(&broken));

    // Retiring one constraint leaves the other two compatible, with a witness.
    let retire = transition_current(&keys, &store, &third, "retired", "owner", "retire-c");
    store.append_norm_event(&retire, &keys).unwrap();
    let view = store.norm_view(&keys).unwrap();
    let checked = view.compatibility().unwrap();
    let pair = checked
        .components
        .iter()
        .find(|component| component.norms.contains(&a))
        .unwrap();
    let Outcome::Compatible { witness } = &pair.outcome else {
        panic!("{pair:?}");
    };
    assert_eq!(witness["x"], witness["z"]);
    assert!(matches!(witness["x"], Value::Bool(_)));
    assert!(checked.untyped.contains(&c));

    // A checker's verdict enters as an observation: recorded, settling nothing.
    let before = view.records.clone();
    let verdict = inventory_create(
        &keys,
        &mut store,
        "verdict",
        "verdict",
        json!({
            "family": "norm-compatibility", "subject": [a, b], "outcome": "compatible",
            "basis": view.frontier.iter().cloned().collect::<Vec<_>>().join(","),
            "mode": "bounded-exhaustive", "witness": "{\"x\":true,\"y\":true,\"z\":true}",
        }),
    );
    let after = store.norm_view(&keys).unwrap();
    assert_eq!(after.records[&verdict].status, "recorded");
    for (id, record) in &before {
        assert_eq!(&after.records[id], record, "a verdict moves no lifecycle");
    }
}

#[test]
fn a_constraint_role_names_typed_required_fields() {
    let keys = Keys::new();
    for (field, value_type, why) in [
        ("formula", json!({"type": "list", "item": {"type": "text"}}), "a text formula"),
        ("declarations", json!({"type": "text"}), "a text list of declarations"),
        ("requirement", json!({"type": "text"}), "a text requirement"),
        (
            "requirement",
            json!({"type": "reference", "form": "revision"}),
            "a revision requirement",
        ),
    ] {
        let mut charter = NormCharter::bundled().unwrap();
        let entry = charter
            .vocabularies
            .iter_mut()
            .find(|entry| entry.constraint.is_some())
            .unwrap();
        let slot = entry
            .definition
            .fields
            .iter_mut()
            .find(|slot| slot.name == field)
            .unwrap();
        slot.value_type = serde_json::from_value(value_type).unwrap();
        let mut store = WorkItemStore::open_in_memory().unwrap();
        let refused = store
            .append_norm_event(
                &keys.sign(
                    "owner",
                    "mistyped-constraint",
                    NormAct::Bootstrap {
                        creator: "worker".into(),
                        charter,
                    },
                ),
                &keys,
            )
            .expect_err(why);
        assert!(
            format!("{refused:?}").contains("a constraint role names"),
            "{why}: {refused:?}"
        );
    }
}
