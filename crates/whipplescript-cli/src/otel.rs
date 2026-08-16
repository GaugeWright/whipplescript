//! OTLP telemetry export: config resolution, endpoint safety checks, and the span/attribute encoders.
//!
//! Moved verbatim out of `main.rs`; `use super::*` keeps the imports and
//! sibling helpers it already resolved against in scope.

use super::*;
pub(crate) fn otel_export(options: &CliOptions) -> ExitCode {
    let usage = "usage: whip otel-export <instance> [--dry-run] [--telemetry-allowlist <Schema.field,...>]\n  env: OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_EXPORTER_OTLP_PROTOCOL (http/json), OTEL_EXPORTER_OTLP_HEADERS, OTEL_RESOURCE_ATTRIBUTES, OTEL_SERVICE_NAME, WHIPPLESCRIPT_TELEMETRY_ALLOWLIST";
    let mut instance_id = None;
    let mut dry_run = false;
    let mut allowlist_flag: Option<String> = None;
    let mut args = options.args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--dry-run" => dry_run = true,
            "--telemetry-allowlist" => {
                let Some(value) = args.next() else {
                    eprintln!(
                        "otel-export: --telemetry-allowlist requires a value: <Schema.field,Schema.field,...>"
                    );
                    return ExitCode::from(2);
                };
                allowlist_flag = Some(value.clone());
            }
            other if other.starts_with('-') => {
                eprintln!("unknown otel-export option `{other}`");
                return ExitCode::from(2);
            }
            value if instance_id.is_none() => instance_id = Some(value.to_owned()),
            _ => {
                eprintln!("{usage}");
                return ExitCode::from(2);
            }
        }
    }
    let Some(instance_id) = instance_id else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };
    // Validate export config before any network I/O; `--dry-run` runs the same
    // validation (spec/std-telemetry.md Static Checks). Header values are
    // secrets and never surface in output or the cursor file.
    let config = match resolve_otel_config() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("otel-export: {error}");
            return ExitCode::from(2);
        }
    };
    // T4 content allowlist carrier: the flag wins over the env variable
    // (spec/std-telemetry.md "Allowlist mechanism v1"). Shape errors are
    // config errors before any store or network I/O.
    let allowlist_raw = allowlist_flag.or_else(|| {
        env::var("WHIPPLESCRIPT_TELEMETRY_ALLOWLIST")
            .ok()
            .filter(|value| !value.trim().is_empty())
    });
    let allowlist = match allowlist_raw
        .as_deref()
        .map(parse_telemetry_allowlist)
        .transpose()
    {
        Ok(allowlist) => allowlist,
        Err(error) => {
            eprintln!("otel-export: {error}");
            return ExitCode::from(2);
        }
    };
    let store = match open_store_or_exit(options) {
        Ok(store) => store,
        Err(code) => return code,
    };
    let runs = match store.list_runs(&instance_id) {
        Ok(runs) => runs,
        Err(error) => return report_store_error("failed to list runs", error),
    };
    let effects = match store.list_effects(&instance_id) {
        Ok(effects) => effects,
        Err(error) => return report_store_error("failed to list effects", error),
    };
    // T4 allowlist validation + content collection, before any network I/O.
    // Validation strength (honest statement): entries validate against the
    // *compiled program's* declared class schemas — the instance row gives
    // its program version, whose `analysis_summary` carries the full
    // schema/field lists the compiler recorded (kernel
    // `program_analysis_summary_json`). This is real IR-derived schema
    // knowledge, not a shape heuristic. An allowlist whose instance,
    // program version, or schema catalog is unreachable is refused (fail
    // closed); an unknown schema or field is a config error, no export.
    let content_facts = if let Some(allowlist) = &allowlist {
        let catalog = match otel_schema_catalog(&store, &instance_id) {
            Ok(catalog) => catalog,
            Err(error) => {
                eprintln!("otel-export: {error}");
                return ExitCode::from(2);
            }
        };
        for (schema, field) in allowlist {
            let known = catalog
                .get(schema)
                .is_some_and(|fields| fields.contains(field));
            if !known {
                eprintln!(
                    "otel-export: telemetry allowlist entry `{schema}.{field}` does not name a declared schema field of this instance's program"
                );
                return ExitCode::from(2);
            }
        }
        // Where allowlisted content genuinely exists on the export path
        // (honest statement): only runs and effects export, and neither
        // carries schema-typed field values directly — effect `input_json`
        // is a kind-specific envelope (rule/key/path/arguments, no declared
        // schema payload) and run `metadata_json` redacts values by design.
        // Effect-run OUTPUT fields typed by a declared schema DO exist as
        // completion facts (`schema.coerce.succeeded` and kin) carrying
        // `output_type` + `value` + the producing `run_id`, so those attach
        // to the run's span below. Plain recorded facts have no spans of
        // their own yet (drift D8), so they do not export.
        match store.list_facts_including_consumed(&instance_id) {
            Ok(facts) => facts
                .iter()
                .filter_map(|fact| {
                    let value = json_from_str(&fact.value_json);
                    let run_id = value.get("run_id")?.as_str()?.to_owned();
                    let schema = value.get("output_type")?.as_str()?.to_owned();
                    let fields = value.get("value")?.as_object()?.clone();
                    Some((run_id, schema, fields))
                })
                .collect::<Vec<_>>(),
            Err(error) => return report_store_error("failed to list facts", error),
        }
    } else {
        Vec::new()
    };
    drop(store);

    // Emit-once cursor, scoped per (provider, endpoint, mapping_version): runs
    // already exported under this scope are skipped; a new endpoint gets full
    // history exactly once (spec/std-telemetry.md "Cursor scoping"). A crash
    // mid-export resumes from the cursor without duplication.
    let cursor_path = options.store_path.with_extension("otel-cursor.json");
    let scope_key = otel_scope_key(&config.endpoint);
    let mut cursor = read_otel_cursor_v2(&cursor_path);
    let exported = cursor
        .get("cursors")
        .and_then(|cursors| cursors.get(&scope_key))
        .and_then(|scope| scope.get("instances"))
        .and_then(|instances| instances.get(&instance_id))
        .and_then(Value::as_array)
        .map(|ids| {
            ids.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<std::collections::BTreeSet<_>>()
        })
        .unwrap_or_default();

    let trace_id = format!(
        "{:032x}",
        u128::from(stable_hash(&instance_id)) << 64 | u128::from(stable_hash("trace"))
    );
    let service_name = config.service_name.clone();
    let mut spans = Vec::new();
    let mut newly_exported = Vec::new();
    for run in &runs {
        // Only terminal runs export (a span needs an end); running work
        // exports on a later pass.
        if run.status == "running" || exported.contains(&run.run_id) {
            continue;
        }
        let effect = effects
            .iter()
            .find(|effect| effect.effect_id == run.effect_id);
        // Spans are named after source constructs so traces read like the
        // workflow; content stays structural (ids, kinds, statuses) per the
        // export content policy.
        let name = effect
            .map(|effect| {
                let rule = json_from_str(&effect.input_json)
                    .get("rule")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_default();
                if rule.is_empty() {
                    effect.kind.clone()
                } else {
                    format!("{}.{}", rule, effect.kind)
                }
            })
            .unwrap_or_else(|| "run".to_owned());
        let mut attributes = vec![
            otel_attr("whipplescript.instance_id", &instance_id),
            otel_attr("whipplescript.effect_id", &run.effect_id),
            otel_attr("whipplescript.run_id", &run.run_id),
            otel_attr("whipplescript.provider", &run.provider),
            otel_attr("whipplescript.effect.status", &run.status),
        ];
        if let Some(effect) = effect {
            attributes.push(otel_attr("whipplescript.effect.kind", &effect.kind));
            // GenAI semantic conventions (version-pinned in the spec) for
            // model-backed spans, so fleets land in LLM dashboards natively.
            if effect.kind == "agent.tell" || effect.kind == "schema.coerce" {
                attributes.push(otel_attr("gen_ai.system", &run.provider));
            }
        }
        // T4 allowlisted content: an allowlisted `<Schema>.<field>` exports as
        // span attribute `whipplescript.field.<Schema>.<field>` on the span of
        // the run whose schema-typed output carried it; everything else stays
        // structural. With no allowlist this loop never runs and the payload
        // is byte-identical to the structural export.
        if let Some(allowlist) = &allowlist {
            for (fact_run_id, schema, fields) in &content_facts {
                if fact_run_id != &run.run_id {
                    continue;
                }
                for (entry_schema, field) in allowlist {
                    if entry_schema != schema {
                        continue;
                    }
                    let Some(value) = fields.get(field) else {
                        continue;
                    };
                    let rendered = match value {
                        Value::String(text) => text.clone(),
                        other => other.to_string(),
                    };
                    attributes.push(otel_attr(
                        &format!("whipplescript.field.{schema}.{field}"),
                        &rendered,
                    ));
                }
            }
        }
        spans.push(json!({
            "traceId": trace_id,
            "spanId": format!("{:016x}", stable_hash(&run.run_id)),
            "name": name,
            "kind": 1,
            "startTimeUnixNano": otel_nanos(&run.started_at),
            "endTimeUnixNano": otel_nanos(run.completed_at.as_deref().unwrap_or(&run.started_at)),
            "status": {"code": if run.status == "completed" { 1 } else { 2 }},
            "attributes": attributes,
        }));
        newly_exported.push(run.run_id.clone());
    }
    if spans.is_empty() {
        println!("otel-export {instance_id}: nothing new to export");
        return ExitCode::SUCCESS;
    }
    // service.name from OTEL_SERVICE_NAME wins; OTEL_RESOURCE_ATTRIBUTES adds
    // the rest of the resource attributes (spec/std-telemetry.md Q2). With no
    // resource attributes set this is byte-identical to the shipped payload.
    let mut resource_attributes = vec![otel_attr("service.name", &service_name)];
    for (key, value) in &config.resource_attributes {
        if key == "service.name" {
            continue;
        }
        resource_attributes.push(otel_attr(key, value));
    }
    let payload = json!({
        "resourceSpans": [{
            "resource": {"attributes": resource_attributes},
            "scopeSpans": [{
                "scope": {"name": "whipplescript", "version": whipplescript_core::version()},
                "spans": spans,
            }],
        }],
    });

    if dry_run {
        println!("{payload:#}");
        return ExitCode::SUCCESS;
    }
    let endpoint = config.endpoint.clone();
    if let Err(error) = otel_post(&endpoint, &config.headers, &payload.to_string()) {
        // Failure isolation: the log persists; the exporter catches up on the
        // next pass. Nothing was marked exported.
        eprintln!("otel-export failed (will catch up next pass): {error}");
        return ExitCode::FAILURE;
    }
    let mut all = exported;
    all.extend(newly_exported.iter().cloned());
    // Record the newly-exported runs under this scope's cursor entry; the scope
    // carries its provider/endpoint/mapping_version so `status` can list it.
    if !cursor["cursors"].is_object() {
        cursor["cursors"] = json!({});
    }
    let scope_entry = cursor["cursors"]
        .as_object_mut()
        .expect("cursors is an object")
        .entry(scope_key)
        .or_insert_with(|| json!({ "instances": {} }));
    scope_entry["provider"] = json!(OTEL_PROVIDER_ID);
    scope_entry["endpoint"] = json!(endpoint);
    scope_entry["mapping_version"] = json!(OTEL_MAPPING_VERSION);
    if !scope_entry["instances"].is_object() {
        scope_entry["instances"] = json!({});
    }
    scope_entry["instances"][&instance_id] = json!(all.into_iter().collect::<Vec<_>>());
    if let Err(error) = fs::write(&cursor_path, cursor.to_string()) {
        eprintln!("failed to persist otel cursor: {error}");
        return ExitCode::FAILURE;
    }
    println!(
        "otel-export {instance_id}: exported {} span(s) to {endpoint}",
        newly_exported.len()
    );
    ExitCode::SUCCESS
}

fn otel_attr(key: &str, value: &str) -> Value {
    json!({"key": key, "value": {"stringValue": value}})
}

/// The declared class schemas (name -> field names) of the instance's compiled
/// program, read from the stored program version's `analysis_summary` — the
/// schema knowledge the export path genuinely has. Any missing link
/// (instance, program version, or schema catalog) is an error so an allowlist
/// can fail closed instead of silently skipping validation.
fn otel_schema_catalog(
    store: &SqliteStore,
    instance_id: &str,
) -> Result<std::collections::BTreeMap<String, std::collections::BTreeSet<String>>, String> {
    let instance = store
        .get_instance(instance_id)
        .map_err(|error| {
            format!("telemetry allowlist refused: failed to read instance: {error:?}")
        })?
        .ok_or_else(|| {
            format!(
                "telemetry allowlist refused: instance `{instance_id}` not found, so no program schemas are reachable to validate against"
            )
        })?;
    let version = store
        .get_program_version(&instance.version_id)
        .map_err(|error| {
            format!("telemetry allowlist refused: failed to read program version: {error:?}")
        })?
        .ok_or_else(|| {
            format!(
                "telemetry allowlist refused: program version `{}` not found, so no program schemas are reachable to validate against",
                instance.version_id
            )
        })?;
    let summary = json_from_str(&version.analysis_summary_json);
    let Some(schemas) = summary.get("schemas").and_then(Value::as_array) else {
        return Err(
            "telemetry allowlist refused: this program version carries no schema catalog to validate against"
                .to_owned(),
        );
    };
    let mut catalog = std::collections::BTreeMap::new();
    for schema in schemas {
        let Some(name) = schema.get("name").and_then(Value::as_str) else {
            continue;
        };
        let fields = schema
            .get("fields")
            .and_then(Value::as_array)
            .map(|fields| {
                fields
                    .iter()
                    .filter_map(|field| field.get("name").and_then(Value::as_str))
                    .map(str::to_owned)
                    .collect::<std::collections::BTreeSet<_>>()
            })
            .unwrap_or_default();
        catalog.insert(name.to_owned(), fields);
    }
    Ok(catalog)
}

/// `YYYY-MM-DD HH:MM:SS` (store timestamps) to Unix nanoseconds, best-effort.
fn otel_nanos(timestamp: &str) -> String {
    let normalized = timestamp.replace(' ', "T");
    let seconds = iso_like_to_unix_seconds(&normalized).unwrap_or(0);
    format!("{}", (seconds as i128) * 1_000_000_000)
}

/// Provider id contributed by the embedded manifest (spec/std-telemetry.md).
pub(crate) const OTEL_PROVIDER_ID: &str = "otlp";

/// OTLP mapping version; a bump deliberately re-exports under a new cursor scope.
pub(crate) const OTEL_MAPPING_VERSION: u64 = 1;

/// Resolved, validated OTLP exporter configuration read from the standard OTel
/// environment (spec/std-telemetry.md "Auth Headers And Cursor Scoping").
/// Header values are secrets: never printed by `--dry-run`/`status`, never
/// written to the cursor file, never exported.
struct OtelExportConfig {
    endpoint: String,
    service_name: String,
    headers: Vec<(String, String)>,
    resource_attributes: Vec<(String, String)>,
}

/// Read + validate the OTel export environment, failing before any network I/O
/// on an unsupported protocol, a malformed header/resource list, or auth headers
/// over an unsafe plaintext endpoint.
fn resolve_otel_config() -> Result<OtelExportConfig, String> {
    // Endpoint resolution ladder (std-telemetry.md T3): environment wins,
    // then the std.telemetry manifest's `otlp` registry default, then the
    // OTLP local-collector convention.
    let endpoint = env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .ok()
        .or_else(|| embedded_operator_provider_default("std.telemetry", "otlp", "endpoint"))
        .unwrap_or_else(|| "http://localhost:4318".to_owned());
    let service_name = env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "whipplescript".to_owned());

    // Protocol validates before export: only the shipped wire shape is
    // accepted; anything else is a config error, not a silent ignore.
    if let Ok(protocol) = env::var("OTEL_EXPORTER_OTLP_PROTOCOL") {
        let protocol = protocol.trim();
        if !protocol.is_empty() && protocol != "http/json" {
            return Err(format!(
                "OTEL_EXPORTER_OTLP_PROTOCOL=`{protocol}` is unsupported; v1 exports only `http/json`"
            ));
        }
    }

    let headers = match env::var("OTEL_EXPORTER_OTLP_HEADERS") {
        Ok(raw) => parse_otel_kv_list(&raw)
            .map_err(|error| format!("OTEL_EXPORTER_OTLP_HEADERS: {error}"))?,
        Err(_) => Vec::new(),
    };
    let resource_attributes = match env::var("OTEL_RESOURCE_ATTRIBUTES") {
        Ok(raw) => parse_otel_kv_list(&raw)
            .map_err(|error| format!("OTEL_RESOURCE_ATTRIBUTES: {error}"))?,
        Err(_) => Vec::new(),
    };

    // Sending credentials in cleartext is the hazard the spec calls out: refuse
    // auth headers over a plaintext endpoint unless the host is loopback (a
    // local Collector) or the operator explicitly opts in.
    if !headers.is_empty() && !otel_endpoint_carries_headers_safely(&endpoint) {
        return Err(format!(
            "refusing to send {} auth header(s) over plaintext endpoint `{endpoint}`: use an https:// endpoint, a loopback host, or set WHIPPLESCRIPT_OTEL_ALLOW_INSECURE_HEADERS=1 to override",
            headers.len()
        ));
    }

    Ok(OtelExportConfig {
        endpoint,
        service_name,
        headers,
        resource_attributes,
    })
}

/// Whether auth headers may ride this endpoint: `https://` always; plaintext
/// only for a loopback host or with the documented insecure opt-in.
fn otel_endpoint_carries_headers_safely(endpoint: &str) -> bool {
    if endpoint.starts_with("https://") {
        return true;
    }
    if env::var("WHIPPLESCRIPT_OTEL_ALLOW_INSECURE_HEADERS")
        .map(|value| {
            let value = value.trim();
            !value.is_empty() && value != "0"
        })
        .unwrap_or(false)
    {
        return true;
    }
    otel_endpoint_is_loopback(endpoint)
}

/// True when the endpoint's host is loopback (`localhost`, `127.0.0.0/8`, `::1`).
fn otel_endpoint_is_loopback(endpoint: &str) -> bool {
    let authority = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
        .unwrap_or(endpoint);
    let authority = authority.split(['/', '?', '#']).next().unwrap_or(authority);
    let host = if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal, e.g. `[::1]:4318`.
        rest.split(']').next().unwrap_or(rest)
    } else {
        authority
            .rsplit_once(':')
            .map(|(host, _)| host)
            .unwrap_or(authority)
    };
    let host = host.to_ascii_lowercase();
    host == "localhost" || host == "::1" || host.starts_with("127.")
}

/// Parse an OTel comma-separated `key=value` list (headers or resource
/// attributes); values are percent-decoded per the OTel spec.
fn parse_otel_kv_list(raw: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for pair in raw.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| format!("expected `key=value`, got `{pair}`"))?;
        let key = key.trim();
        if key.is_empty() {
            return Err(format!("empty key in `{pair}`"));
        }
        out.push((key.to_owned(), otel_percent_decode(value.trim())));
    }
    Ok(out)
}

/// Minimal percent-decoding for OTel header/attribute values (`%XX` octets).
fn otel_percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Cursor scope key = H(provider, endpoint, mapping_version), so a new endpoint
/// or mapping bump gets its own emit-once ledger (spec/std-telemetry.md).
fn otel_scope_key(endpoint: &str) -> String {
    format!(
        "{:016x}",
        stable_hash(&format!(
            "{OTEL_PROVIDER_ID}|{endpoint}|{OTEL_MAPPING_VERSION}"
        ))
    )
}

/// Read the scope-keyed (version 2) cursor file. A legacy v1 file is treated as
/// absent — ignored on read, superseded on first write (no migration).
pub(crate) fn read_otel_cursor_v2(path: &Path) -> Value {
    let parsed = fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok());
    match parsed {
        Some(value) if value.get("version").and_then(Value::as_u64) == Some(2) => value,
        _ => json!({ "version": 2, "cursors": {} }),
    }
}

/// OTLP/HTTP POST over the in-tree `ureq` client — `https://` and plaintext
/// both work; the sidecar peer is usually a local OpenTelemetry Collector. Auth
/// headers ride the request; the response body is ignored beyond status.
fn otel_post(endpoint: &str, headers: &[(String, String)], body: &str) -> Result<(), String> {
    let url = otel_traces_url(endpoint)?;
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("whipplescript-telemetry")
        .build();
    let mut request = agent.post(&url).set("Content-Type", "application/json");
    for (name, value) in headers {
        request = request.set(name, value);
    }
    match request.send_bytes(body.as_bytes()) {
        Ok(_) => Ok(()),
        Err(ureq::Error::Status(code, _)) => Err(format!("collector responded {code}")),
        Err(ureq::Error::Transport(transport)) => Err(format!("{url}: {transport}")),
    }
}

/// Resolve the OTLP traces URL from a base endpoint, appending the `/v1/traces`
/// signal path (the shipped POST target).
fn otel_traces_url(endpoint: &str) -> Result<String, String> {
    if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
        return Err(format!(
            "unsupported endpoint `{endpoint}`: expected an http:// or https:// URL"
        ));
    }
    Ok(format!("{}/v1/traces", endpoint.trim_end_matches('/')))
}
