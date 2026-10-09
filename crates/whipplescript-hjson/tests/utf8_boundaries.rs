use serde_json::Value;

#[test]
fn single_quoted_unicode_never_panics_and_preserves_valid_values() {
    for text in ["€", "🙂", "é", "普通"] {
        let raw = format!("'{}'", text);
        let outcome = std::panic::catch_unwind(|| deser_hjson::from_str::<Value>(&raw));
        assert!(
            outcome.is_ok(),
            "valid single quote must not panic: {:?}",
            raw
        );
        assert_eq!(
            outcome
                .expect("no parser panic")
                .expect("valid quoted value"),
            Value::String(text.into())
        );
    }
}

#[test]
fn malformed_unicode_quoted_or_comment_input_refuses_without_panicking() {
    for raw in [
        "'€",
        "'🙂",
        "'''€",
        "'🙂' /* unfinished",
        r#""\u€€""#,
        r#""\🙂""#,
    ] {
        let outcome = std::panic::catch_unwind(|| deser_hjson::from_str::<Value>(raw));
        assert!(outcome.is_ok(), "malformed input must not panic: {:?}", raw);
        assert!(
            outcome.expect("no parser panic").is_err(),
            "malformed input must refuse: {:?}",
            raw
        );
    }
}

#[test]
fn non_ascii_escape_selector_refuses_without_panicking() {
    let raw = r#""\🙂""#;
    let outcome = std::panic::catch_unwind(|| deser_hjson::from_str::<Value>(raw));
    assert!(outcome.is_ok(), "invalid Unicode escape must not panic");
    assert!(outcome.expect("no parser panic").is_err());
}

#[test]
fn root_multiline_unicode_and_ascii_preserve_valid_format() {
    for (raw, expected) in [
        ("'''€🙂'''", "€🙂"),
        ("'''ascii'''", "ascii"),
        ("'''\n€🙂\n'''", "€🙂"),
    ] {
        assert_eq!(
            deser_hjson::from_str::<Value>(raw).expect("valid root multiline"),
            Value::String(expected.into())
        );
    }
}

#[test]
fn unicode_hex_span_and_truncated_multiline_end_refuse_without_panicking() {
    for raw in [r#""\u€€""#, "'''€'", "'''€''"] {
        let outcome = std::panic::catch_unwind(|| deser_hjson::from_str::<Value>(raw));
        assert!(outcome.is_ok(), "malformed span must not panic: {:?}", raw);
        assert!(outcome.expect("no parser panic").is_err());
    }
}
