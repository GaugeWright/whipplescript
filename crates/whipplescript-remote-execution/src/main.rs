//! `whip-remote-execution`: the endpoint as a process the wrapper starts for
//! a daemon. It reads its principals from `--principal name[=label,...]`,
//! serves the connections that name no handle as `--daemon <name>`, prints
//! one JSON line with the bound address and each principal's handle token,
//! and runs until its standard input closes or it is told to stop. With
//! `--state <file>` its store and action cache are that SQLite database, so
//! the next process over the same file serves what this one stored; with
//! `--content <file>` as well, its bytes are the workspace's content store.
//! With `--sidecar <http://host:port>` its actions run at a Class-A executor
//! (`whip executor`) instead of on this host, over HTTP or HTTPS,
//! authenticated with `WHIP_EXECUTOR_TOKEN` when that is set; `--sidecar-ca
//! <pem>` adds a pool's own authority to the platform's roots.

use std::sync::Arc;

use whipplescript_remote_execution::endpoint::Endpoint;
use whipplescript_remote_execution::runner::{ActionRunner, LocalRunner};
use whipplescript_remote_execution::sidecar::SidecarRunner;
use whipplescript_remote_execution::store::Principal;

const USAGE: &str = "usage: whip-remote-execution --listen <addr> --scratch <dir> [--state <file> [--content <file>]] [--sidecar <http(s)://host:port> [--sidecar-ca <pem>]] [--principal <name>[=<label>,...]]... [--daemon <name>]";

#[derive(Debug)]
struct Arguments {
    listen: String,
    scratch: String,
    state: Option<String>,
    content: Option<String>,
    sidecar: Option<String>,
    sidecar_ca: Option<String>,
    principals: Vec<Principal>,
    daemon: Option<String>,
}

fn parse(args: &[String]) -> Result<Arguments, String> {
    let mut listen = None;
    let mut scratch = None;
    let mut state = None;
    let mut content = None;
    let mut sidecar = None;
    let mut sidecar_ca = None;
    let mut principals = Vec::new();
    let mut daemon = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let value = || it.clone().next().cloned();
        match arg.as_str() {
            "--listen" => listen = value(),
            "--scratch" => scratch = value(),
            "--state" => state = value(),
            "--content" => content = value(),
            "--sidecar" => sidecar = value(),
            "--sidecar-ca" => sidecar_ca = value(),
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
    if content.is_some() && state.is_none() {
        return Err(format!(
            "--content needs --state: the uses that scope shared bytes must outlive the process as the bytes do\n{USAGE}"
        ));
    }
    if sidecar_ca.is_some() && sidecar.is_none() {
        return Err(format!(
            "--sidecar-ca needs --sidecar: it names the authority of the executor actions run at\n{USAGE}"
        ));
    }
    Ok(Arguments {
        listen: listen.ok_or_else(|| format!("--listen is required\n{USAGE}"))?,
        scratch: scratch.ok_or_else(|| format!("--scratch is required\n{USAGE}"))?,
        state,
        content,
        sidecar,
        sidecar_ca,
        principals,
        daemon,
    })
}

async fn run(args: Arguments) -> Result<(), String> {
    std::fs::create_dir_all(&args.scratch)
        .map_err(|error| format!("cannot create {}: {error}", args.scratch))?;
    let runner: Arc<dyn ActionRunner> = match &args.sidecar {
        Some(url) => {
            let token = std::env::var("WHIP_EXECUTOR_TOKEN").ok();
            Arc::new(match &args.sidecar_ca {
                Some(ca) => SidecarRunner::trusting(url, token, std::path::Path::new(ca))?,
                None => SidecarRunner::new(url, token)?,
            })
        }
        None => Arc::new(LocalRunner::new(&args.scratch)),
    };
    let mut endpoint = match (&args.state, &args.content) {
        (Some(state), Some(content)) => Endpoint::open_sharing(
            runner,
            std::path::Path::new(state),
            std::path::Path::new(content),
        )?,
        (Some(state), None) => Endpoint::open(runner, std::path::Path::new(state))?,
        (None, _) => Endpoint::new(runner),
    };
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
        serde_json::json!({"address": bound.to_string(), "executor": endpoint.executor_name(), "handles": handles, "state": args.state, "content": args.content})
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
            "--state",
            "/tmp/s/endpoint.sqlite",
            "--content",
            "/tmp/s/vcs-content.sqlite",
            "--sidecar",
            "https://pool.example:8443",
            "--sidecar-ca",
            "/tmp/s/pool-ca.pem",
            "--principal",
            "owner=protected,internal",
            "--principal",
            "dev",
            "--daemon",
            "owner",
        ]))
        .unwrap();
        assert_eq!(parsed.listen, "127.0.0.1:0");
        assert_eq!(parsed.state.as_deref(), Some("/tmp/s/endpoint.sqlite"));
        assert_eq!(parsed.content.as_deref(), Some("/tmp/s/vcs-content.sqlite"));
        assert_eq!(parsed.sidecar.as_deref(), Some("https://pool.example:8443"));
        assert_eq!(parsed.sidecar_ca.as_deref(), Some("/tmp/s/pool-ca.pem"));
        assert!(parse(&owned(&[
            "--listen",
            "x",
            "--scratch",
            "s",
            "--sidecar-ca",
            "c"
        ]))
        .unwrap_err()
        .starts_with("--sidecar-ca needs --sidecar: "));
        assert!(parse(&owned(&[
            "--listen",
            "x",
            "--scratch",
            "s",
            "--content",
            "c"
        ]))
        .unwrap_err()
        .starts_with("--content needs --state: "));
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
