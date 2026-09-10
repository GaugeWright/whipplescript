//! Optional deep-check reports from synthetic fixtures, never from user stores.
use serde::Serialize;

#[allow(dead_code)] // The recording-only journey also compiles this shared helper.
pub fn record<S, T: Serialize>(scenario: &str, message_type: &str, value: &T) {
    record_into::<S, T>(
        "WHIPPLESCRIPT_ACTION_REPORT_DIR",
        scenario,
        message_type,
        value,
    );
}

#[allow(dead_code)] // The legacy-only journey also compiles this shared helper.
pub fn record_scoped<S, T: Serialize>(scenario: &str, message_type: &str, value: &T) {
    record_into::<S, T>(
        "WHIPPLESCRIPT_SCOPED_ACTION_REPORT_DIR",
        scenario,
        message_type,
        value,
    );
}

#[allow(dead_code)] // Older journeys do not emit independent recording messages.
pub fn record_recording<S, T: Serialize>(scenario: &str, message_type: &str, value: &T) {
    record_into::<S, T>(
        "WHIPPLESCRIPT_RECORDING_ACTION_REPORT_DIR",
        scenario,
        message_type,
        value,
    );
}

fn record_into<S, T: Serialize>(variable: &str, scenario: &str, message_type: &str, value: &T) {
    let Some(directory) = std::env::var_os(variable) else {
        return;
    };
    let store = std::any::type_name::<S>();
    let placement = if store.contains("DoSqliteStore<") {
        "hosted"
    } else if store.ends_with("::NativeStores") {
        "native"
    } else {
        panic!("unclassified action contract fixture store: {store}");
    };
    let report = serde_json::json!({
        "placement": placement,
        "scenario": scenario,
        "message_type": message_type,
        "value": value,
    });
    let bytes = serde_json::to_vec(&report).expect("serialize fixture report");
    let path = std::path::PathBuf::from(directory).join(format!(
        "{message_type}-{}.json",
        whipplescript_store::stable_hash_hex(
            &String::from_utf8(bytes.clone()).expect("JSON UTF-8")
        )
    ));
    std::fs::write(path, bytes).expect("write requested fixture report");
}
