use serde::Deserialize;
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Scalar {
    Bool(bool),
    Null(Option<()>),
    Number(f64),
    Text(String),
}
#[test]
fn full_hjson_scalar_tokens_preserve_dates_leading_zero_and_overflow_strings() {
    for raw in [
        "2026-04-28",
        "01",
        "-01",
        ".5",
        "1e999",
        "falsehood",
        "nullify",
        "trueStory",
        "12suffix",
    ] {
        match deser_hjson::from_str::<Scalar>(raw).expect("HJSON complete scalar") {
            Scalar::Text(text) => assert_eq!(text, raw),
            other => panic!("expected preserved string for {:?}, got {:?}", raw, other),
        }
    }
    match deser_hjson::from_str::<Scalar>("false").expect("boolean") {
        Scalar::Bool(value) => assert!(!value),
        other => panic!("{:?}", other),
    }
    assert!(matches!(
        deser_hjson::from_str::<Scalar>("null").expect("null"),
        Scalar::Null(None)
    ));
    match deser_hjson::from_str::<Scalar>("-1.25e2").expect("number") {
        Scalar::Number(value) => assert_eq!(value, -125.0),
        other => panic!("{:?}", other),
    }
}
#[test]
fn incomplete_comments_are_not_clean_eof_even_in_braceless_input() {
    for raw in ["{} /", "{} *", "{} /*", "{} /* unfinished", "a:1\n/*"] {
        assert!(
            deser_hjson::from_str::<std::collections::BTreeMap<String, Scalar>>(raw).is_err(),
            "{:?}",
            raw
        );
    }
}

#[test]
fn hjson_optional_fraction_digits_match_company_number_tokens() {
    for (raw, expected) in [("1.", 1.0), ("1.e2", 100.0), ("-1.E-2", -0.01)] {
        match deser_hjson::from_str::<Scalar>(raw).expect("HJSON number extension") {
            Scalar::Number(value) => assert_eq!(value, expected),
            other => panic!("expected number {:?}, got {:?}", raw, other),
        }
    }
}

#[test]
fn first_comment_marker_controls_scalar_and_later_markers_are_comment_text() {
    for raw in [
        "true # note containing // marker",
        "true /* note containing // */",
        "true // note containing #",
    ] {
        match deser_hjson::from_str::<Scalar>(raw).expect("actual boolean with comments") {
            Scalar::Bool(value) => assert!(value),
            other => panic!("expected bool for {:?}, got {:?}", raw, other),
        }
    }
}
