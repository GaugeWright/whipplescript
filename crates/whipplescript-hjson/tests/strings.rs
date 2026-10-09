use {deser_hjson::from_str, serde::Deserialize, std::collections::HashMap};

#[macro_use]
mod common;

#[test]
fn test_string() {
    #[derive(Deserialize, PartialEq, Debug)]
    struct W {
        c: String,
    }
    assert_eq!(
        W {
            c: "test".to_string()
        },
        from_str("{c:test\n}").expect("upstream parser conformance")
    );
    assert_eq!(
        W {
            c: "test".to_string()
        },
        from_str("{c:\"test\"}").expect("upstream parser conformance")
    );
    assert_eq!(
        W {
            c: "test".to_string()
        },
        from_str("{c:'test'}").expect("upstream parser conformance")
    );
    assert_eq!(
        W {
            c: "test".to_string()
        },
        from_str("{'c':'test'}").expect("upstream parser conformance")
    );
    assert_eq!(
        W {
            c: "test".to_string()
        },
        from_str("{\"c\":'test'}").expect("upstream parser conformance")
    );
    assert_eq!(
        W {
            c: "xterm -e \"vi /some/path\"".to_string()
        },
        from_str(
            r#"{
            c: "xterm -e \"vi /some/path\""
        }"#
        )
        .expect("upstream parser conformance"),
    );
    assert_eq!(
        W {
            c: "\x0C\x0C".to_string()
        },
        from_str("{c:\"\\f\\u000C\"}").expect("upstream parser conformance")
    );
}

#[test]
fn test_weird_map_keys() {
    #[derive(Deserialize, PartialEq, Debug)]
    struct W {
        map: HashMap<String, String>,
    }
    let hjson = r#"{
        map: {
            <none>: 0
            // π: 3.14
            τ: 6.28
            'τ/2': π
            /: slash // hard one
            \: "" // no trap here
        }
    }"#;
    let value = W {
        map: mo! {
            "<none>": "0",
            "τ": "6.28",
            "τ/2": "π",
            "/": "slash // hard one", // quoteless string values go til line end
            "\\": "",
        },
    };
    assert_eq!(value, from_str(hjson).expect("upstream parser conformance"));
}
