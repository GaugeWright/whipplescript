//! `whip-remote-execution`: the endpoint as a process the wrapper starts for
//! a daemon. It reads its principals from `--principal name[=label,...]`,
//! serves the connections that name no handle as `--daemon <name>`, prints
//! one JSON line with the bound address and each principal's handle token,
//! and runs until its standard input closes or it is told to stop.

use std::sync::Arc;

use whipplescript_remote_execution::endpoint::Endpoint;
use whipplescript_remote_execution::runner::LocalRunner;
use whipplescript_remote_execution::store::Principal;

const USAGE: &str = "usage: whip-remote-execution --listen <addr> --scratch <dir> [--principal <name>[=<label>,...]]... [--daemon <name>]";

#[derive(Debug)]
struct Arguments {
    listen: String,
    scratch: String,
    principals: Vec<Principal>,
    daemon: Option<String>,
}

fn parse(args: &[String]) -> Result<Arguments, String> {
    let mut listen = None;
    let mut scratch = None;
    let mut principals = Vec::new();
    let mut daemon = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let value = || it.clone().next().cloned();
        match arg.as_str() {
            "--listen" => listen = value(),
            "--scratch" => scratch = value(),
            "--daemon" => daemon = value(),
            "--principal" => {
                let spec = value().ok_or_else(|| format!("--principal needs a value\n{USAGE}"))?;
                let (name, labels) = spec.split_once('=').unwrap_or((spec.as_str(), ""));
                if name.trim().is_empty() {
                    return Err(format!("a principal needs a name\n{USAGE}"));
                }
                principals.push(Principal {
                    name: name.to_owned(),
                    labels: labels
                        .split(',')
                        .map(str::trim)
                        .filter(|l| !l.is_empty())
                        .map(str::to_owned)
                        .collect(),
                });
            }
            other if other.starts_with("--") => {
                return Err(format!("unknown option {other}\n{USAGE}"));
            }
            _ => continue,
        }
        it.next();
    }
    Ok(Arguments {
        listen: listen.ok_or_else(|| format!("--listen is required\n{USAGE}"))?,
        scratch: scratch.ok_or_else(|| format!("--scratch is required\n{USAGE}"))?,
        principals,
        daemon,
    })
}

async fn run(args: Arguments) -> Result<(), String> {
    std::fs::create_dir_all(&args.scratch)
        .map_err(|error| format!("cannot create {}: {error}", args.scratch))?;
    let mut endpoint = Endpoint::new(Arc::new(LocalRunner::new(&args.scratch)));
    let mut handles = serde_json::Map::new();
    let mut daemon_handle = None;
    for principal in args.principals {
        let name = principal.name.clone();
        let (handle, _) = endpoint.admit(principal)?;
        if args.daemon.as_deref() == Some(name.as_str()) {
            daemon_handle = Some(handle.clone());
        }
        handles.insert(name, serde_json::Value::String(handle.0));
    }
    if let Some(name) = &args.daemon {
        let handle =
            daemon_handle.ok_or_else(|| format!("--daemon names no admitted principal: {name}"))?;
        endpoint.serve_daemon_as(handle)?;
    }
    let (listener, bound) = whipplescript_remote_execution::server::bind(&args.listen).await?;
    println!(
        "{}",
        serde_json::json!({"address": bound.to_string(), "executor": endpoint.executor_name(), "handles": handles})
    );
    let endpoint = Arc::new(endpoint);
    let stdin_closed = async {
        use tokio::io::AsyncReadExt;
        let mut sink = [0u8; 64];
        let mut stdin = tokio::io::stdin();
        while let Ok(read) = stdin.read(&mut sink).await {
            if read == 0 {
                break;
            }
        }
    };
    whipplescript_remote_execution::server::serve(endpoint, listener, stdin_closed).await
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match parse(&args) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("whip-remote-execution: {error}");
            return std::process::ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("whip-remote-execution: cannot start a runtime: {error}");
            return std::process::ExitCode::from(2);
        }
    };
    match runtime.block_on(run(parsed)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("whip-remote-execution: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn arguments_name_the_listener_the_scratch_and_the_principals() {
        let parsed = parse(&owned(&[
            "--listen",
            "127.0.0.1:0",
            "--scratch",
            "/tmp/s",
            "--principal",
            "owner=protected,internal",
            "--principal",
            "dev",
            "--daemon",
            "owner",
        ]))
        .unwrap();
        assert_eq!(parsed.listen, "127.0.0.1:0");
        assert_eq!(parsed.principals.len(), 2);
        assert_eq!(parsed.principals[0].labels.len(), 2);
        assert!(parsed.principals[1].labels.is_empty());
        assert_eq!(parsed.daemon.as_deref(), Some("owner"));
        assert!(parse(&owned(&["--scratch", "/tmp/s"]))
            .unwrap_err()
            .starts_with("--listen is required"));
        assert!(parse(&owned(&["--listen", "x"]))
            .unwrap_err()
            .starts_with("--scratch is required"));
        assert!(parse(&owned(&[
            "--listen",
            "x",
            "--scratch",
            "s",
            "--principal",
            "=a"
        ]))
        .unwrap_err()
        .starts_with("a principal needs a name"));
        assert!(
            parse(&owned(&["--listen", "x", "--scratch", "s", "--principal"]))
                .unwrap_err()
                .starts_with("--principal needs a value")
        );
        assert!(parse(&owned(&["--nope"]))
            .unwrap_err()
            .starts_with("unknown option --nope"));
    }
}
