//! `whip-custodian` — the credential custodian daemon (DR-0053).
//!
//! Runs as a separate security principal from whip. Admin operations
//! (init/import/list/revoke) act on the sealed store directly and are gated
//! by holding the store passphrase; the custody protocol itself has no admin
//! surface and no `get`.
//!
//! The passphrase comes from `WHIPPLESCRIPT_CUSTODIAN_PASSPHRASE` or
//! `--passphrase-file` (0600). r0 `process` sealing is dev-grade and every
//! reply carries `degraded: true` saying so.

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use zeroize::Zeroizing;

use whipplescript_custodian::store::SealedStore;
use whipplescript_custodian::{Custodian, DeniedEgress};
use whipplescript_custody::{CredentialKind, CredentialName};

const USAGE: &str = "usage:
  whip-custodian init   --store <path>
  whip-custodian import --store <path> --name <credential> --kind <kind> [--budget <n>] [--from-env <VAR> | --from-file <path> | --from-stdin | --remote-transit <key_name>]
  whip-custodian list   --store <path>
  whip-custodian revoke --store <path> --name <credential>
  whip-custodian serve  --store <path> --socket <path> [--egress-allow <host,host,*.suffix>]

passphrase: WHIPPLESCRIPT_CUSTODIAN_PASSPHRASE or --passphrase-file <path>
openbao (r3): serve connects when BAO_ADDR (or VAULT_ADDR) is set, using BAO_TOKEN (or VAULT_TOKEN)";

struct Args {
    flags: std::collections::BTreeMap<String, String>,
    switches: std::collections::BTreeSet<String>,
}

impl Args {
    fn parse(argv: &[String]) -> Result<Self, String> {
        let mut flags = std::collections::BTreeMap::new();
        let mut switches = std::collections::BTreeSet::new();
        let mut i = 0;
        while i < argv.len() {
            let arg = &argv[i];
            let Some(name) = arg.strip_prefix("--") else {
                return Err(format!("unexpected argument {arg:?}"));
            };
            if matches!(name, "from-stdin") {
                switches.insert(name.to_string());
                i += 1;
                continue;
            }
            let value = argv
                .get(i + 1)
                .ok_or_else(|| format!("--{name} needs a value"))?;
            flags.insert(name.to_string(), value.clone());
            i += 2;
        }
        Ok(Self { flags, switches })
    }

    fn need(&self, name: &str) -> Result<&str, String> {
        self.flags
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| format!("--{name} is required"))
    }
}

fn passphrase(args: &Args) -> Result<Zeroizing<String>, String> {
    if let Some(path) = args.flags.get("passphrase-file") {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read passphrase file: {e}"))?;
        return Ok(Zeroizing::new(raw.trim_end_matches('\n').to_string()));
    }
    match std::env::var("WHIPPLESCRIPT_CUSTODIAN_PASSPHRASE") {
        Ok(p) if !p.is_empty() => Ok(Zeroizing::new(p)),
        _ => Err(
            "no passphrase: set WHIPPLESCRIPT_CUSTODIAN_PASSPHRASE or pass --passphrase-file"
                .to_string(),
        ),
    }
}

fn run() -> Result<(), String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = argv.split_first() else {
        return Err(USAGE.to_string());
    };
    let args = Args::parse(rest)?;
    let store_path = PathBuf::from(args.need("store")?);
    let pass = passphrase(&args)?;

    match command.as_str() {
        "init" => {
            if store_path.exists() {
                return Err(format!("store already exists at {}", store_path.display()));
            }
            let store =
                SealedStore::create(Some(store_path.clone()), &pass).map_err(|e| e.to_string())?;
            store.persist().map_err(|e| e.to_string())?;
            println!("initialized r0 store at {}", store_path.display());
            Ok(())
        }
        "import" => {
            let name = CredentialName::new(args.need("name")?)?;
            let kind = CredentialKind::parse(args.need("kind")?)?;
            let budget = args
                .flags
                .get("budget")
                .map(|b| b.parse::<u64>().map_err(|e| format!("bad --budget: {e}")))
                .transpose()?;
            // An r3 remote entry: only a key name is recorded; the material
            // lives in the OpenBao transit engine and never touches this box.
            if let Some(key_name) = args.flags.get("remote-transit") {
                for local in ["from-env", "from-file"] {
                    if args.flags.contains_key(local) {
                        return Err(format!("--remote-transit conflicts with --{local}"));
                    }
                }
                if args.switches.contains("from-stdin") {
                    return Err("--remote-transit conflicts with --from-stdin".to_string());
                }
                let mut store = SealedStore::open(&store_path, &pass).map_err(|e| e.to_string())?;
                store
                    .register_remote(name.clone(), kind, key_name.clone(), budget)
                    .map_err(|e| e.to_string())?;
                println!(
                    "imported {} (kind {kind}, remote openbao transit key {key_name:?})",
                    name.resource_id()
                );
                return Ok(());
            }
            let material: Zeroizing<Vec<u8>> = if let Some(var) = args.flags.get("from-env") {
                Zeroizing::new(
                    std::env::var(var)
                        .map_err(|_| format!("environment variable {var} is not set"))?
                        .into_bytes(),
                )
            } else if let Some(path) = args.flags.get("from-file") {
                Zeroizing::new(std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?)
            } else if args.switches.contains("from-stdin") {
                let mut buf = Vec::new();
                std::io::stdin()
                    .read_to_end(&mut buf)
                    .map_err(|e| e.to_string())?;
                while buf.last() == Some(&b'\n') {
                    buf.pop();
                }
                Zeroizing::new(buf)
            } else {
                return Err(
                    "one of --from-env, --from-file, --from-stdin, --remote-transit is required"
                        .to_string(),
                );
            };
            let mut store = SealedStore::open(&store_path, &pass).map_err(|e| e.to_string())?;
            store
                .register(name.clone(), kind, material, budget)
                .map_err(|e| e.to_string())?;
            println!("imported {} (kind {kind})", name.resource_id());
            Ok(())
        }
        "list" => {
            let store = SealedStore::open(&store_path, &pass).map_err(|e| e.to_string())?;
            for (name, entry) in store.entries() {
                println!(
                    "{}\tkind={}\trevoked={}",
                    name.resource_id(),
                    entry.kind,
                    entry.revoked
                );
            }
            Ok(())
        }
        "revoke" => {
            let name = CredentialName::new(args.need("name")?)?;
            let mut store = SealedStore::open(&store_path, &pass).map_err(|e| e.to_string())?;
            if store.revoke(&name).map_err(|e| e.to_string())? {
                println!("revoked {}", name.resource_id());
                Ok(())
            } else {
                Err(format!("no credential named {}", name.resource_id()))
            }
        }
        "serve" => {
            let socket = PathBuf::from(args.need("socket")?);
            let store = SealedStore::open(&store_path, &pass).map_err(|e| e.to_string())?;
            // Egress is deny-by-default (DR-0053 §9 / the mTLS-concentration
            // bound): without --egress-allow the custodian refuses every
            // request/mint at the network layer, loudly.
            let egress: Box<dyn whipplescript_custodian::Egress> =
                match args.flags.get("egress-allow") {
                    Some(hosts) => {
                        let allow: Vec<String> = hosts
                            .split(',')
                            .map(str::trim)
                            .filter(|h| !h.is_empty())
                            .map(str::to_owned)
                            .collect();
                        eprintln!("whip-custodian: egress allowed to {allow:?}");
                        Box::new(whipplescript_custodian::egress::UreqEgress::new(allow))
                    }
                    None => Box::new(DeniedEgress),
                };
            let mut custodian = Custodian::new(store, egress);
            // r3: connect to OpenBao when the environment names one. A
            // configured-but-unreachable OpenBao is a startup error, not a
            // daemon that silently serves remote entries it cannot reach.
            if let Some(client) =
                whipplescript_custodian::openbao::Client::from_env().map_err(|e| e.to_string())?
            {
                client
                    .token_lookup_self()
                    .map_err(|e| format!("openbao token lookup failed ({}): {e}", client.addr()))?;
                eprintln!("openbao transit connected (r3)");
                custodian = custodian.with_openbao(client);
            }
            let custodian = Arc::new(custodian);
            eprintln!(
                "whip-custodian: r0 process sealing (degraded), serving on {}",
                socket.display()
            );
            whipplescript_custodian::serve::serve(custodian, &socket).map_err(|e| e.to_string())
        }
        other => Err(format!("unknown command {other:?}\n{USAGE}")),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}
