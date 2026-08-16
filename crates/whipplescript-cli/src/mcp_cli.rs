//! The `whip mcp` subcommand surface: registry CRUD plus the trust-evidence writers (pin, attest, forget).
//!
//! Moved verbatim out of `main.rs`; `use super::*` keeps the imports and
//! sibling helpers it already resolved against in scope.

use super::*;
/// `whip mcp ...` — the operator door onto the MCP server registry
/// (`spec/mcp-support-design-note.md`). Every subcommand here writes EVIDENCE
/// (a pin, an attestation, a role file). The matching REQUIREMENT — the minimum
/// trust rung a turn must meet — lives in the signed governance envelope
/// (`require mcp <rung>`), never here, so attesting a server cannot also lower
/// the bar it is judged against.
pub(crate) fn mcp_command(options: &CliOptions) -> ExitCode {
    let usage = command_usage("mcp").unwrap_or_default();
    let mut positional = Vec::new();
    let mut url = None::<String>;
    let mut command = None::<String>;
    let mut args = Vec::<String>::new();
    let mut env = std::collections::BTreeMap::<String, String>::new();
    let mut headers = std::collections::BTreeMap::<String, String>::new();
    let mut trust_annotations = false;
    let mut iter = options.args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--url" => url = iter.next().cloned(),
            "--command" => command = iter.next().cloned(),
            "--arg" => {
                if let Some(value) = iter.next() {
                    args.push(value.clone());
                }
            }
            "--env" | "--header" => {
                let Some(pair) = iter.next() else {
                    eprintln!("{arg} needs KEY=VALUE");
                    return ExitCode::from(2);
                };
                let Some((key, value)) = pair.split_once('=') else {
                    eprintln!("{arg} needs KEY=VALUE, got `{pair}`");
                    return ExitCode::from(2);
                };
                if arg == "--env" {
                    env.insert(key.to_owned(), value.to_owned());
                } else {
                    headers.insert(key.to_owned(), value.to_owned());
                }
            }
            "--trust-annotations" => trust_annotations = true,
            other if other.starts_with('-') => {
                eprintln!("unknown mcp option `{other}`");
                return ExitCode::from(2);
            }
            other => positional.push(other.to_owned()),
        }
    }
    let subcommand = positional.first().map(String::as_str);
    let name = positional.get(1).cloned();
    match subcommand {
        Some("list") => mcp_list(options),
        Some("add") => mcp_add(name, url, command, args, env, headers),
        Some("import") => mcp_import(name),
        Some("status") => mcp_status(options, name),
        Some("pin") | Some("sync") => mcp_pin(name, subcommand == Some("sync")),
        Some("attest") => mcp_attest(name, trust_annotations),
        Some("forget") => mcp_forget(name),
        _ => {
            eprintln!("{usage}");
            ExitCode::from(2)
        }
    }
}

fn mcp_registry_or_exit(
) -> Result<std::collections::BTreeMap<String, mcp_tools::McpServerConfig>, ExitCode> {
    mcp_tools::load_registry().map_err(|error| {
        eprintln!("{error}");
        ExitCode::FAILURE
    })
}

fn mcp_list(options: &CliOptions) -> ExitCode {
    let registry = match mcp_registry_or_exit() {
        Ok(registry) => registry,
        Err(code) => return code,
    };
    if options.json {
        let rows: Vec<serde_json::Value> = registry
            .values()
            .map(|server| {
                json!({
                    "name": server.name,
                    "rung": server.rung().as_str(),
                    "transport": match &server.transport {
                        mcp_tools::McpTransport::Stdio { .. } => "stdio",
                        mcp_tools::McpTransport::Http { .. } => "http",
                    },
                    "pinned_tools": server.pin.as_ref().map_or(0, serde_json::Map::len),
                    "roles": server.roles.keys().collect::<Vec<_>>(),
                })
            })
            .collect();
        println!("{}", json!({ "servers": rows }));
        return ExitCode::SUCCESS;
    }
    if registry.is_empty() {
        println!("no MCP servers registered");
        println!("add one with `whip mcp add <name> --command <cmd>` or import an existing");
        println!("config with `whip mcp import ~/.claude.json`");
        return ExitCode::SUCCESS;
    }
    for server in registry.values() {
        let transport = match &server.transport {
            mcp_tools::McpTransport::Stdio { command, .. } => format!("stdio: {command}"),
            mcp_tools::McpTransport::Http { url, .. } => format!("http: {url}"),
        };
        println!("{}  [{}]  {transport}", server.name, server.rung().as_str());
    }
    ExitCode::SUCCESS
}

fn mcp_save_one(server: mcp_tools::McpServerConfig) -> ExitCode {
    let mut registry = match mcp_registry_or_exit() {
        Ok(registry) => registry,
        Err(code) => return code,
    };
    let name = server.name.clone();
    registry.insert(name.clone(), server);
    match mcp_tools::save_registry(&registry) {
        Ok(path) => {
            println!("wrote {}", path.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn mcp_add(
    name: Option<String>,
    url: Option<String>,
    command: Option<String>,
    args: Vec<String>,
    env: std::collections::BTreeMap<String, String>,
    headers: std::collections::BTreeMap<String, String>,
) -> ExitCode {
    let Some(name) = name else {
        eprintln!("usage: whip mcp add <name> (--url <url> | --command <cmd> [--arg <a>]...)");
        return ExitCode::from(2);
    };
    let transport = match (url, command) {
        (Some(url), None) => {
            // Fail at `add`, not at first use: an operator who pastes an
            // http:// endpoint should learn immediately, while they still have
            // the correct URL in hand.
            if let Err(error) = mcp_tools::refuse_plaintext_endpoint(&name, &url) {
                eprintln!("{error}");
                return ExitCode::FAILURE;
            }
            mcp_tools::McpTransport::Http { url, headers }
        }
        (None, Some(command)) => mcp_tools::McpTransport::Stdio { command, args, env },
        (Some(_), Some(_)) => {
            eprintln!("give either --url or --command, not both");
            return ExitCode::from(2);
        }
        (None, None) => {
            eprintln!("`whip mcp add` needs --url <url> or --command <cmd>");
            return ExitCode::from(2);
        }
    };
    let server = mcp_tools::McpServerConfig {
        name: name.clone(),
        transport,
        pin: None,
        trust_annotations: false,
        roles: std::collections::BTreeMap::new(),
    };
    let code = mcp_save_one(server);
    if code == ExitCode::SUCCESS {
        // Rung 0 is a complete path, and saying so is the point: the server
        // works right now, and the ladder above it is optional.
        println!("added `{name}` at rung `unattested` — usable now, and every call is");
        println!("recorded as untrusted. Grant it per turn by naming the tools you use:");
        println!("    tell agent with access to {name} {{ some_tool other_tool }} \"...\"");
        println!("Run `whip mcp status {name}` to see what it offers, then");
        println!("`whip mcp pin {name}` to freeze the manifest against silent changes.");
    }
    code
}

fn mcp_import(path: Option<String>) -> ExitCode {
    let Some(path) = path else {
        eprintln!("usage: whip mcp import <file>   (a Claude Code / Cursor style config)");
        return ExitCode::from(2);
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("could not read {path}: {error}");
            return ExitCode::FAILURE;
        }
    };
    let value: serde_json::Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{path} is not valid JSON: {error}");
            return ExitCode::FAILURE;
        }
    };
    let imported = match mcp_tools::servers_from_mcp_servers_block(&value) {
        Ok(servers) => servers,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let mut registry = match mcp_registry_or_exit() {
        Ok(registry) => registry,
        Err(code) => return code,
    };
    let mut names = Vec::new();
    for server in imported {
        names.push(server.name.clone());
        // Importing is not trusting: an imported server lands at rung 0 and
        // keeps any evidence it had already accrued here.
        match registry.get(&server.name) {
            Some(existing) => {
                let mut merged = server;
                // Evidence carries over ONLY if the transport is unchanged. A
                // re-import that repoints a name at a different command or URL
                // is a different server wearing a known name; inheriting its
                // pin and attestation would hand a stranger someone else's
                // trust, and the pin would no longer describe what runs.
                if merged.transport == existing.transport {
                    merged.pin = existing.pin.clone();
                    merged.trust_annotations = existing.trust_annotations;
                    merged.roles = existing.roles.clone();
                } else {
                    println!(
                        "note: `{}` now points at a different command/URL — its pin, \
                         attestation, and roles were dropped; re-review it with \
                         `whip mcp status {}`",
                        merged.name, merged.name
                    );
                }
                registry.insert(merged.name.clone(), merged);
            }
            None => {
                registry.insert(server.name.clone(), server);
            }
        }
    }
    match mcp_tools::save_registry(&registry) {
        Ok(path) => {
            println!("imported {} server(s): {}", names.len(), names.join(", "));
            println!("wrote {}", path.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn mcp_lookup(
    name: Option<String>,
) -> Result<
    (
        String,
        mcp_tools::McpServerConfig,
        std::collections::BTreeMap<String, mcp_tools::McpServerConfig>,
    ),
    ExitCode,
> {
    let Some(name) = name else {
        eprintln!("that subcommand needs a server name");
        return Err(ExitCode::from(2));
    };
    let registry = mcp_registry_or_exit()?;
    let Some(server) = registry.get(&name).cloned() else {
        eprintln!("no MCP server named `{name}` (see `whip mcp list`)");
        return Err(ExitCode::FAILURE);
    };
    Ok((name, server, registry))
}

/// Connect and report what a server offers, plus how its live manifest compares
/// to the pin. This is the door an admin reads before attesting or classifying.
fn mcp_status(options: &CliOptions, name: Option<String>) -> ExitCode {
    let (name, server, _) = match mcp_lookup(name) {
        Ok(found) => found,
        Err(code) => return code,
    };
    let mut client = match mcp_tools::McpClient::connect(&server) {
        Ok(client) => client,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let live = match client.list_tools() {
        Ok(live) => live,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let drift = server
        .pin
        .as_ref()
        .map(|pin| whipplescript_kernel::mcp::manifest_drift(pin, &live))
        .unwrap_or_default();
    let annotated = live
        .iter()
        .filter(|tool| tool.annotations.is_some())
        .count();
    if options.json {
        println!(
            "{}",
            json!({
                "name": name,
                "rung": server.rung().as_str(),
                "tools": live.iter().map(|tool| json!({
                    "name": tool.name,
                    "annotated": tool.annotations.is_some(),
                    "read_only_hint": tool.claims_read_only(),
                })).collect::<Vec<_>>(),
                "annotated": annotated,
                "drift": drift,
            })
        );
        return ExitCode::SUCCESS;
    }
    println!("{name}  [{}]", server.rung().as_str());
    println!("{} tool(s), {annotated} annotated", live.len());
    for tool in &live {
        let hint = if tool.annotations.is_none() {
            "unannotated"
        } else if tool.claims_read_only() {
            "claims read-only"
        } else {
            "claims mutating"
        };
        println!("  {:<32} {hint}", tool.name);
    }
    if annotated < live.len() && server.rung() >= whipplescript_kernel::mcp::McpRung::Attested {
        println!();
        println!(
            "note: {} tool(s) carry no annotation, so they can only be granted by name",
            live.len() - annotated
        );
        println!("      or through a role you define in the config file.");
    }
    if !drift.is_empty() {
        println!();
        println!("PIN DRIFT — this server no longer matches its pinned manifest:");
        for entry in &drift {
            println!("  {entry}");
        }
        println!("turns granting this server will fail until you review and re-pin");
        println!("with `whip mcp sync {name}`.");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Freeze (or re-freeze) the manifest. `sync` is the same operation after a
/// drift, named differently because re-pinning is a review decision.
fn mcp_pin(name: Option<String>, resync: bool) -> ExitCode {
    let (name, mut server, mut registry) = match mcp_lookup(name) {
        Ok(found) => found,
        Err(code) => return code,
    };
    let mut client = match mcp_tools::McpClient::connect(&server) {
        Ok(client) => client,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let live = match client.list_tools() {
        Ok(live) => live,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(existing) = &server.pin {
        let drift = whipplescript_kernel::mcp::manifest_drift(existing, &live);
        if drift.is_empty() {
            println!("`{name}` already matches its pin ({} tools)", live.len());
            return ExitCode::SUCCESS;
        }
        if !resync {
            eprintln!("`{name}` has drifted from its pin:");
            for entry in &drift {
                eprintln!("  {entry}");
            }
            eprintln!("review the change, then re-pin with `whip mcp sync {name}`");
            return ExitCode::FAILURE;
        }
        println!("re-pinning `{name}` over {} change(s):", drift.len());
        for entry in &drift {
            println!("  {entry}");
        }
    }
    server.pin = Some(whipplescript_kernel::mcp::manifest_pin(&live));
    let rung = server.rung();
    registry.insert(name.clone(), server);
    match mcp_tools::save_registry(&registry) {
        Ok(path) => {
            println!(
                "pinned {} tool(s) of `{name}` [{}]",
                live.len(),
                rung.as_str()
            );
            println!("wrote {}", path.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

/// Attest that a pinned server's self-reported annotations may be believed.
/// This is the act that turns hints into admissible classification — and it is
/// deliberately explicit, because the official reference server annotates a
/// tool that dumps the whole environment as read-only and non-destructive.
fn mcp_attest(name: Option<String>, trust_annotations: bool) -> ExitCode {
    if !trust_annotations {
        eprintln!("usage: whip mcp attest <name> --trust-annotations");
        eprintln!(
            "  attesting says you have read this server's tool list and believe its \
             self-reported annotations."
        );
        return ExitCode::from(2);
    }
    let (name, mut server, mut registry) = match mcp_lookup(name) {
        Ok(found) => found,
        Err(code) => return code,
    };
    if server.pin.is_none() {
        eprintln!("`{name}` is not pinned, so there is no fixed manifest to attest.");
        eprintln!("run `whip mcp pin {name}` first, then attest what you pinned.");
        return ExitCode::FAILURE;
    }
    server.trust_annotations = true;
    let rung = server.rung();
    registry.insert(name.clone(), server);
    match mcp_tools::save_registry(&registry) {
        Ok(path) => {
            println!("attested `{name}` — now at rung `{}`", rung.as_str());
            println!("wrote {}", path.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn mcp_forget(name: Option<String>) -> ExitCode {
    let (name, _, mut registry) = match mcp_lookup(name) {
        Ok(found) => found,
        Err(code) => return code,
    };
    registry.remove(&name);
    match mcp_tools::save_registry(&registry) {
        Ok(path) => {
            println!("removed `{name}`");
            println!("wrote {}", path.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
