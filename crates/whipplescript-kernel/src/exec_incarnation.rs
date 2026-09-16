//! Process-incarnation binding for controller-mediated executor delivery.
//! Identity is supplied by the running server, never inferred from its owner.
use serde::{Deserialize, Serialize};
use serde_json::Value;

const PROTOCOL: &str = "whipplescript.exec.incarnation/v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Handshake {
    protocol: String,
    incarnation: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Delivery {
    protocol: String,
    incarnation: String,
    dispatch: Value,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    protocol: String,
    incarnation: String,
    status: u16,
    body: Value,
}

fn validate(protocol: &str, incarnation: &str, expected: &str) -> Result<(), String> {
    if protocol != PROTOCOL || incarnation.is_empty() || incarnation != expected {
        return Err("executor incarnation binding differs or is empty".into());
    }
    Ok(())
}

pub fn handshake(incarnation: &str) -> Result<String, String> {
    validate(PROTOCOL, incarnation, incarnation)?;
    serde_json::to_string(&Handshake {
        protocol: PROTOCOL.into(),
        incarnation: incarnation.into(),
    })
    .map_err(|e| e.to_string())
}

pub fn read_handshake(response: &str) -> Result<String, String> {
    let value: Handshake = serde_json::from_str(response).map_err(|e| e.to_string())?;
    validate(&value.protocol, &value.incarnation, &value.incarnation)?;
    Ok(value.incarnation)
}

pub fn delivery(incarnation: &str, dispatch: Value) -> Result<String, String> {
    validate(PROTOCOL, incarnation, incarnation)?;
    serde_json::to_string(&Delivery {
        protocol: PROTOCOL.into(),
        incarnation: incarnation.into(),
        dispatch,
    })
    .map_err(|e| e.to_string())
}

/// Called by the server before invoking any executor handler.
pub fn read_delivery(request: &str, actual: &str) -> Result<Value, String> {
    let value: Delivery = serde_json::from_str(request).map_err(|e| e.to_string())?;
    validate(&value.protocol, &value.incarnation, actual)?;
    Ok(value.dispatch)
}

pub fn completion(incarnation: &str, status: u16, body: Value) -> Result<String, String> {
    validate(PROTOCOL, incarnation, incarnation)?;
    serde_json::to_string(&Completion {
        protocol: PROTOCOL.into(),
        incarnation: incarnation.into(),
        status,
        body,
    })
    .map_err(|e| e.to_string())
}

pub fn read_completion(response: &str, expected: &str) -> Result<(u16, Value), String> {
    let value: Completion = serde_json::from_str(response).map_err(|e| e.to_string())?;
    validate(&value.protocol, &value.incarnation, expected)?;
    Ok((value.status, value.body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn exec_incarnation_preserves_dispatch_and_completion_with_exact_binding() {
        let identity = read_handshake(&handshake("process-1").unwrap()).unwrap();
        let dispatch = json!({"protocol":"whip-executor/1", "stdin":{"original":true}});
        let request = delivery(&identity, dispatch.clone()).unwrap();
        assert_eq!(read_delivery(&request, &identity).unwrap(), dispatch);
        assert!(read_delivery(&request, "restarted-process").is_err());
        let body = json!({"exit_code":7,"stdout":"original"});
        let response = completion(&identity, 503, body.clone()).unwrap();
        assert_eq!(read_completion(&response, &identity).unwrap(), (503, body));
        assert!(read_completion(&response, "restarted-process").is_err());
    }

    #[test]
    fn exec_incarnation_refuses_legacy_empty_and_extended_messages() {
        assert!(handshake("").is_err());
        assert!(delivery("", Value::Null).is_err());
        assert!(completion("", 200, Value::Null).is_err());
        let samples = [
            handshake("p").unwrap(),
            delivery("p", Value::Null).unwrap(),
            completion("p", 200, Value::Null).unwrap(),
        ];
        for (index, sample) in samples.iter().enumerate() {
            for (field, replacement) in [
                ("protocol", json!("legacy")),
                ("incarnation", json!("")),
                ("extra", json!(true)),
            ] {
                let mut altered: Value = serde_json::from_str(sample).unwrap();
                altered[field] = replacement;
                let encoded = altered.to_string();
                let refused = match index {
                    0 => read_handshake(&encoded).is_err(),
                    1 => read_delivery(&encoded, "p").is_err(),
                    _ => read_completion(&encoded, "p").is_err(),
                };
                assert!(refused, "accepted altered field {field} in message {index}");
            }
        }
        assert!(read_handshake(r#"{"protocol":"whip-executor/1","ok":true}"#).is_err());
        assert!(read_delivery(r#"{"protocol":"whip-executor/1"}"#, "p").is_err());
        assert!(read_completion(r#"{"exit_code":0}"#, "p").is_err());
    }
}
