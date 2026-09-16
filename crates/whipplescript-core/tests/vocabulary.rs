#[cfg(test)]
mod tests {
    use serde_json::json;
    use whipplescript_core::vocabulary::*;

    fn definition() -> VocabularyDefinition {
        serde_json::from_value(json!({
        "name":"review", "version":"1",
        "fields":[
            {"name":"title","required":true,"value_type":{"type":"text"}},
            {"name":"count","required":false,"value_type":{"type":"integer"}},
            {"name":"urgent","required":false,"value_type":{"type":"boolean"}},
            {"name":"scope","required":false,"value_type":{"type":"enum","values":["local","shared"]}},
            {"name":"tags","required":false,"value_type":{"type":"list","item":{"type":"text"}}},
            {"name":"detail","required":false,"value_type":{"type":"object","fields":[
                {"name":"reason","required":true,"value_type":{"type":"text"}}
            ]}}
        ],
        "status":{"values":["draft","accepted","withdrawn"],"initial":"draft","transitions":[
            {"from":"draft","to":"accepted","admission":{"requires":"authority","scope":"governance.accept"}},
            {"from":"draft","to":"withdrawn","admission":{"requires":"public"}}
        ]}
    })).expect("valid test vocabulary")
    }

    #[test]
    fn declarations_and_record_shapes_are_data() {
        let vocabulary = Vocabulary::new(definition()).unwrap();
        vocabulary
            .validate_record(&json!({"title":"change"}), "draft")
            .unwrap();
        vocabulary.validate_record(&json!({"title":"change","count":18446744073709551615_u64,"urgent":true,"scope":"shared","tags":["one","two"],"detail":{"reason":"repair"}}),"accepted").unwrap();
        vocabulary
            .validate_record(&json!({"title":"change","count":-1}), "draft")
            .unwrap();
        assert_eq!(
            vocabulary.transition("draft", "withdrawn").unwrap(),
            &AdmissionPredicate::Public {}
        );
        assert_eq!(
            vocabulary.transition("draft", "accepted").unwrap(),
            &AdmissionPredicate::Authority {
                scope: "governance.accept".into()
            }
        );
        let mut second = definition();
        second.name = "experiment".into();
        second.status.values = vec!["queued".into(), "observed".into()];
        second.status.initial = "queued".into();
        second.status.transitions.clear();
        let second = Vocabulary::new(second).unwrap();
        second
            .validate_record(&json!({"title":"sample"}), "observed")
            .unwrap();
        assert!(matches!(
            second.validate_status("accepted"),
            Err(VocabularyError::InvalidStatus(_))
        ));
    }

    #[test]
    fn malformed_records_name_the_exact_failed_field() {
        let vocabulary = Vocabulary::new(definition()).unwrap();
        for (value, path, reason) in [
            (json!([]), "fields", "expected object"),
            (json!({}), "fields.title", "required field missing"),
            (json!({"title":null}), "fields.title", "expected Text"),
            (json!({"title":1}), "fields.title", "expected Text"),
            (
                json!({"title":"ok","other":true}),
                "fields.other",
                "unknown field",
            ),
            (
                json!({"title":"ok","count":1.5}),
                "fields.count",
                "expected Integer",
            ),
            (
                json!({"title":"ok","count":null}),
                "fields.count",
                "expected Integer",
            ),
            (
                json!({"title":"ok","urgent":"true"}),
                "fields.urgent",
                "expected Boolean",
            ),
            (
                json!({"title":"ok","tags":"one"}),
                "fields.tags",
                "expected list",
            ),
            (
                json!({"title":"ok","tags":["one",2]}),
                "fields.tags[1]",
                "expected Text",
            ),
            (
                json!({"title":"ok","detail":{}}),
                "fields.detail.reason",
                "required field missing",
            ),
            (
                json!({"title":"ok","detail":{"reason":"ok","other":1}}),
                "fields.detail.other",
                "unknown field",
            ),
        ] {
            assert_eq!(
                vocabulary.validate_record(&value, "draft"),
                Err(VocabularyError::InvalidRecord {
                    path: path.into(),
                    reason: reason.into()
                })
            );
        }
        for scope in [json!("outside"), json!(3)] {
            assert!(
                matches!(vocabulary.validate_record(&json!({"title":"ok","scope":scope}),"draft"),Err(VocabularyError::InvalidRecord {path,..}) if path == "fields.scope")
            );
        }
    }

    #[test]
    fn valid_status_is_not_a_transition_rule() {
        let vocabulary = Vocabulary::new(definition()).unwrap();
        for (from, to) in [("accepted", "withdrawn"), ("draft", "draft")] {
            assert_eq!(
                vocabulary.transition(from, to),
                Err(VocabularyError::MissingTransition {
                    from: from.into(),
                    to: to.into()
                })
            );
        }
        for (from, to) in [("invented", "draft"), ("draft", "invented")] {
            assert_eq!(
                vocabulary.transition(from, to),
                Err(VocabularyError::InvalidStatus("invented".into()))
            );
        }
    }

    #[test]
    fn historical_versions_are_exact_and_immutable() {
        let original = Vocabulary::new(definition()).unwrap();
        let mut registry = VocabularyRegistry::default();
        let old_ref = registry.register(original.clone()).unwrap();
        assert_eq!(registry.register(original).unwrap(), old_ref);
        let mut changed = definition();
        changed.status.transitions[0].admission = AdmissionPredicate::Public {};
        let changed = Vocabulary::new(changed).unwrap();
        assert_ne!(changed.reference().digest, old_ref.digest);
        assert!(matches!(
            registry.register(changed),
            Err(VocabularyError::ConflictingVersion { .. })
        ));
        let mut next = definition();
        next.version = "2".into();
        next.status.transitions[0].admission = AdmissionPredicate::Public {};
        let new_ref = registry.register(Vocabulary::new(next).unwrap()).unwrap();
        assert_eq!(
            registry
                .get(&new_ref)
                .unwrap()
                .transition("draft", "accepted")
                .unwrap(),
            &AdmissionPredicate::Public {}
        );
        assert!(matches!(
            registry
                .get(&old_ref)
                .unwrap()
                .transition("draft", "accepted")
                .unwrap(),
            AdmissionPredicate::Authority { .. }
        ));
        for reference in [
            {
                let mut r = old_ref.clone();
                r.digest = new_ref.digest.clone();
                r
            },
            {
                let mut r = old_ref.clone();
                r.version = "absent".into();
                r
            },
            {
                let mut r = old_ref.clone();
                r.name = "other".into();
                r
            },
        ] {
            assert_eq!(
                registry.get(&reference),
                Err(VocabularyError::UnknownVocabulary(reference))
            );
        }
    }

    #[test]
    fn declarations_refuse_empty_ambiguous_and_out_of_domain_rules() {
        let base = serde_json::to_value(definition()).unwrap();
        for (pointer, replacement, error_path) in [
            ("/name", json!(" "), "name"),
            ("/version", json!(""), "version"),
            ("/fields/0/name", json!(""), "fields"),
            ("/fields/1/name", json!("title"), "fields"),
            ("/status/values", json!([]), "status.values"),
            ("/status/values/0", json!(""), "status.values"),
            ("/status/values/1", json!("draft"), "status.values"),
            ("/status/initial", json!("unknown"), "status.initial"),
            (
                "/status/transitions/0/from",
                json!("unknown"),
                "status.transitions[0]",
            ),
            (
                "/status/transitions/0/to",
                json!("unknown"),
                "status.transitions[0]",
            ),
            (
                "/status/transitions/1/to",
                json!("accepted"),
                "status.transitions[1]",
            ),
            (
                "/status/transitions/0/admission/scope",
                json!(""),
                "status.transitions[0].admission.scope",
            ),
            ("/fields/3/value_type/values", json!([]), "fields.scope"),
            (
                "/fields/3/value_type/values",
                json!(["local", "local"]),
                "fields.scope",
            ),
            (
                "/fields/5/value_type/fields/0/name",
                json!(""),
                "fields.detail",
            ),
        ] {
            let mut bad = base.clone();
            *bad.pointer_mut(pointer).unwrap() = replacement;
            let result = Vocabulary::new(serde_json::from_value(bad).unwrap());
            assert!(
                matches!(&result,Err(VocabularyError::InvalidDefinition {path,..}) if path == error_path),
                "{pointer}: {result:?}"
            );
        }
        let mut bad = definition();
        bad.fields.push(FieldDefinition {
            name: "nested".into(),
            required: false,
            value_type: ValueType::List {
                item: Box::new(ValueType::Enum { values: vec![] }),
            },
        });
        assert!(
            matches!(Vocabulary::new(bad),Err(VocabularyError::InvalidDefinition {path,..}) if path == "fields.nested")
        );
    }

    #[test]
    fn round_trip_covers_every_field_and_rejects_unknown_syntax() {
        let vocabulary = Vocabulary::new(definition()).unwrap();
        let encoded = serde_json::to_string(vocabulary.definition()).unwrap();
        assert_eq!(
            Vocabulary::new(serde_json::from_str(&encoded).unwrap()).unwrap(),
            vocabulary
        );
        assert_eq!(vocabulary.reference().digest.len(), 64);
        let mut value = serde_json::to_value(definition()).unwrap();
        value["ignored_authority"] = json!(true);
        assert!(serde_json::from_value::<VocabularyDefinition>(value).is_err());
        let mut value = serde_json::to_value(definition()).unwrap();
        value["status"]["transitions"][0]["admission"] =
            json!({"requires":"public","scope":"silently dropped"});
        assert!(serde_json::from_value::<VocabularyDefinition>(value).is_err());
    }

    #[test]
    fn raw_ingress_does_not_resolve_duplicate_fields_by_order() {
        let vocabulary = Vocabulary::new(definition()).unwrap();
        for input in [
            r#"{"title":"first","title":"second"}"#,
            r#"{"title":"second","title":"first"}"#,
            r#"{"title":"ok","detail":{"reason":"first","reason":"second"}}"#,
        ] {
            assert!(
                matches!(vocabulary.parse_record_json(input,"draft"),Err(VocabularyError::InvalidRecord {reason,..}) if reason.contains("duplicate field"))
            );
        }
        let input =
            r#"{"title":"ok","urgent":false,"count":-1,"tags":["one"],"detail":{"reason":"test"}}"#;
        assert_eq!(
            vocabulary.parse_record_json(input, "draft").unwrap(),
            serde_json::from_str::<serde_json::Value>(input).unwrap()
        );
        assert!(vocabulary
            .parse_record_json(r#"{"title":"ok","count":null}"#, "draft")
            .is_err());
        assert!(vocabulary
            .parse_record_json(r#"{"title":"ok","count":1.5}"#, "draft")
            .is_err());
        assert!(vocabulary
            .parse_record_json(r#"{"title":"ok"} trailing"#, "draft")
            .is_err());
    }

    #[test]
    fn reference_format_is_stable_across_input_object_key_order() {
        let reordered = r#"{"status":{"transitions":[],"initial":"draft","values":["draft"]},"fields":[],"version":"1","name":"frozen"}"#;
        let vocabulary = Vocabulary::new(serde_json::from_str(reordered).unwrap()).unwrap();
        assert_eq!(
            vocabulary.reference().digest,
            "b764360fcd4ff310c5a844bb0b1b3fc10c7d6c7fb6e96706356f2c952515d11d"
        );
        for value_type in ["text", "boolean", "integer"] {
            assert!(
                serde_json::from_value::<ValueType>(json!({"type":value_type,"ignored":true}))
                    .is_err()
            );
        }
    }
}
