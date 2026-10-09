use {deser_hjson::from_str, serde::Deserialize, std::collections::HashMap};

#[macro_use]
mod common;

#[test]
fn test_untagged_minus_sign() {
    #[derive(Deserialize, PartialEq, Debug)]
    #[serde(untagged)]
    enum E {
        Map(HashMap<String, String>),
        Str(String),
    }
    type Thing = HashMap<String, E>;
    let h = r#"{
        key1: {}
        key2: -value2
        key3: value3
    }"#;

    let thing: Thing = from_str(h).expect("upstream parser conformance");
    assert_eq!(
        thing.get("key1").expect("upstream parser conformance"),
        &E::Map(HashMap::new())
    );
    assert_eq!(
        thing.get("key2").expect("upstream parser conformance"),
        &E::Str("-value2".to_string())
    );
    assert_eq!(
        thing.get("key3").expect("upstream parser conformance"),
        &E::Str("value3".to_string())
    );
}
