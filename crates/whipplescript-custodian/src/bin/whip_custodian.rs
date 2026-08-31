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
// Only `serve` builds a shared custodian across connection threads.
#[cfg(target_family = "unix")]
use std::sync::Arc;

use zeroize::Zeroizing;

use whipplescript_custodian::store::SealedStore;
// Only `serve` builds a running custodian; the store commands act on the
// sealed store directly.
#[cfg(target_family = "unix")]
use whipplescript_custodian::{Custodian, DeniedEgress};
// A lease expiry is portable: it lives in the sealed store, which the crate
// keeps compiled everywhere, and `import` sets one on every platform. Only the
// running custodian above is unix-only.
use whipplescript_custodian::now_epoch_s;
use whipplescript_custody::{CredentialKind, CredentialName};

const USAGE: &str = "usage:
  whip-custodian init   --store <path>
  whip-custodian import --store <path> --name <credential> --kind <kind> [--budget <n>] [--from-env <VAR> | --from-file <path> | --from-stdin | --remote-transit <key_name> | --tpm-pcr <0,7>]
  whip-custodian list   --store <path>
  whip-custodian revoke --store <path> --name <credential>
  whip-custodian serve  --store <path> --socket <path> [--egress-allow <host,host,*.suffix>]
                        [--sign-prefix <cred>=<entry>[,<entry>][;<cred>=<entry>]]

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

/// Parse `--tpm-pcr 0,7` into slot numbers.
///
/// Ascending and de-duplicated, because the binding hashes values in slot
/// order: `7,0` and `0,7` would otherwise be two different bindings over the
/// same platform, and an operator who typed them in the other order would find
/// their credential stale for no reason they could see.
fn parse_pcr_slots(text: &str) -> Result<Vec<u32>, String> {
    let mut slots = Vec::new();
    for piece in text.split(',') {
        let piece = piece.trim();
        if piece.is_empty() {
            return Err("--tpm-pcr takes a comma-separated list of PCR slots, e.g. 0,7".to_owned());
        }
        let slot: u32 = piece
            .parse()
            .map_err(|_| format!("--tpm-pcr: `{piece}` is not a PCR slot number"))?;
        if !slots.contains(&slot) {
            slots.push(slot);
        }
    }
    // No emptiness check here, and deliberately: `split(',')` yields at least
    // one piece for every input including "", and an empty piece is already
    // refused above. A guard for it read like a second safety net and was in
    // fact unreachable — a refusal that cannot fire is one nobody can test, and
    // the sweep said so.
    slots.sort_unstable();
    Ok(slots)
}

#[cfg(feature = "tpm")]
fn import_tpm(
    store_path: &std::path::Path,
    pass: &str,
    name: CredentialName,
    kind: CredentialKind,
    slots: &[u32],
    budget: Option<u64>,
    lease_expires_at: Option<u64>,
) -> Result<(), String> {
    let mut context = whipplescript_custodian::tpm_device::context()?;
    // Read at registration so the binding records the platform as it IS, not as
    // an operator believes it to be. Every later use compares against this.
    let binding = whipplescript_custodian::tpm_device::read_binding(&mut context, slots)?;
    let mut store = SealedStore::open(store_path, pass).map_err(|e| e.to_string())?;
    let digest = binding.digest_hex.clone();
    store
        .register_tpm(name.clone(), kind, binding, budget, lease_expires_at)
        .map_err(|e| e.to_string())?;
    println!(
        "imported {} (kind {kind}, r2 hardware, bound to PCRs {slots:?} at {digest})",
        name.resource_id()
    );
    Ok(())
}

/// The same command in a custodian built without the `tpm` feature.
///
/// Refused rather than recorded: writing the entry would leave a credential
/// nothing on this host can ever use, and the operator would find out at the
/// first signature instead of here.
#[cfg(not(feature = "tpm"))]
fn import_tpm(
    _store_path: &std::path::Path,
    _pass: &str,
    _name: CredentialName,
    _kind: CredentialKind,
    _slots: &[u32],
    _budget: Option<u64>,
    _lease_expires_at: Option<u64>,
) -> Result<(), String> {
    Err("this custodian was built without the `tpm` feature, so it cannot bind a credential to a TPM: rebuild with `--features tpm` on a host that has the tss2 stack"
        .to_owned())
}

/// `--remote-transit` names a key that stays in OpenBao; the three local
/// sources hand this box the material itself. Naming both is not a preference
/// the tool can resolve — it is a contradiction about where the secret lives,
/// and guessing either way puts material somewhere the operator did not ask
/// for.
///
/// It is a free function on the parsed arguments rather than a check inline in
/// `run` because inline it sat behind a store path and a passphrase: reaching
/// it meant arranging an environment, so nothing ever did, and the mutation
/// sweep found it unexercised. The decision is about arguments alone, and now
/// needs nothing else to reach.
fn remote_transit_excludes_local_material(args: &Args) -> Result<(), String> {
    for local in ["from-env", "from-file"] {
        if args.flags.contains_key(local) {
            return Err(format!("--remote-transit conflicts with --{local}"));
        }
    }
    if args.switches.contains("from-stdin") {
        return Err("--remote-transit conflicts with --from-stdin".to_string());
    }
    Ok(())
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
            // `--lease <seconds>` is a DURATION from now, not an instant: an
            // operator reasons in "this key is good for an hour", and an
            // absolute timestamp on a command line is a clock-skew bug waiting
            // for a reader to make it.
            let lease_expires_at = args
                .flags
                .get("lease")
                .map(|seconds| {
                    seconds
                        .parse::<u64>()
                        .map_err(|e| format!("bad --lease: {e}"))
                        .map(|seconds| now_epoch_s() + seconds)
                })
                .transpose()?;
            // An r2 hardware entry: nothing is recorded but the platform state
            // the credential is bound to. The key is derived inside the TPM and
            // never existed on this box to begin with.
            if let Some(slots) = args.flags.get("tpm-pcr") {
                let slots = parse_pcr_slots(slots)?;
                return import_tpm(
                    &store_path,
                    &pass,
                    name,
                    kind,
                    &slots,
                    budget,
                    lease_expires_at,
                );
            }
            // An r3 remote entry: only a key name is recorded; the material
            // lives in the OpenBao transit engine and never touches this box.
            if let Some(key_name) = args.flags.get("remote-transit") {
                remote_transit_excludes_local_material(&args)?;
                let mut store = SealedStore::open(&store_path, &pass).map_err(|e| e.to_string())?;
                store
                    .register_remote(
                        name.clone(),
                        kind,
                        key_name.clone(),
                        budget,
                        lease_expires_at,
                    )
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
                .register(name.clone(), kind, material, budget, lease_expires_at)
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
        "serve" => serve_command(&args, &store_path, &pass),
        other => Err(format!("unknown command {other:?}\n{USAGE}")),
    }
}

/// The daemon. Unix-only because the listener is a Unix domain socket and the
/// 0o600 mode on it is the custody boundary (DR-0053 §4).
#[cfg(target_family = "unix")]
fn serve_command(
    args: &Args,
    store_path: &std::path::Path,
    pass: &Zeroizing<String>,
) -> Result<(), String> {
    let socket = PathBuf::from(args.need("socket")?);
    let store = SealedStore::open(store_path, pass).map_err(|e| e.to_string())?;
    // Egress is deny-by-default (DR-0053 §9 / the mTLS-concentration
    // bound): without --egress-allow the custodian refuses every
    // request/mint at the network layer, loudly.
    let egress: Box<dyn whipplescript_custodian::Egress> = match args.flags.get("egress-allow") {
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
    // The signing bound of DR-0053 §14's amendment. Configured HERE rather than
    // read from whip's governance for the same reason the egress allow-list is:
    // it must hold against a fully compromised whip, and a bound whip supplies
    // is one whip can choose.
    //
    // Unlike egress, absence ADMITS. Egress denies by default because a
    // custodian that egresses nowhere is safe and loud; a custodian that signs
    // nothing is neither — it would take down every deployment that signs today
    // rather than tighten it. Naming a credential is what opts it in.
    let mut sign_prefixes: std::collections::BTreeMap<
        whipplescript_custody::CredentialName,
        Vec<Vec<u8>>,
    > = std::collections::BTreeMap::new();
    // One flag, `;` between credentials and `,` between entries — the same
    // single-flag shape `--egress-allow <host,host>` uses, rather than a
    // repeated flag the argument parser does not carry.
    for spec in args
        .flags
        .get("sign-prefix")
        .map(String::as_str)
        .unwrap_or_default()
        .split(';')
        .map(str::trim)
        .filter(|spec| !spec.is_empty())
    {
        let (credential, entries) = spec.split_once('=').ok_or_else(|| {
            format!("--sign-prefix needs `<credential>=<entry>[,<entry>]`: {spec}")
        })?;
        let name = whipplescript_custody::CredentialName::new(credential.trim())
            .map_err(|e| format!("--sign-prefix credential: {e}"))?;
        let parsed = whipplescript_custody::sign_prefix::parse_list(entries)
            .map_err(|e| format!("--sign-prefix {credential}: {e}"))?;
        eprintln!(
            "whip-custodian: {} may sign {} prefix(es)",
            name,
            parsed.len()
        );
        sign_prefixes.entry(name).or_default().extend(parsed);
    }
    let mut custodian = Custodian::new(store, egress).with_sign_prefixes(sign_prefixes);
    // r3: connect to OpenBao when the environment names one. A
    // configured-but-unreachable OpenBao is a startup error, not a
    // daemon that silently serves remote entries it cannot reach.
    if let Some(client) =
        whipplescript_custodian::openbao::Client::from_env().map_err(|e| e.to_string())?
    {
        let lookup = client
            .token_lookup_self()
            .map_err(|e| format!("openbao token lookup failed ({}): {e}", client.addr()))?;
        let posture = whipplescript_custodian::openbao::TokenPosture::from_lookup(&lookup);
        eprintln!(
            "openbao transit connected (r3): {} lease {}s, renewable={}",
            client.addr(),
            posture.ttl_secs,
            posture.renewable
        );
        // A renewable token outlives its lease only if something
        // renews it. That belongs here rather than in the custody
        // path: renewal is per-connection and time-driven, and a
        // custodian that only renews when someone happens to sign
        // has already expired by the time it matters.
        let client = Arc::new(client);
        match whipplescript_custodian::openbao::spawn_token_renewal(Arc::clone(&client), posture) {
            // The handle is deliberately dropped: the thread runs for
            // the life of the process and there is nothing to join.
            Some(_handle) => eprintln!("openbao token renewal: started"),
            None => eprintln!(
                "openbao token renewal: nothing to renew (renewable={}, lease={}s) — if \
                     this token was meant to expire, r3 stops working when it does",
                posture.renewable, posture.ttl_secs
            ),
        }
        custodian = custodian.with_openbao(client);
    }
    let custodian = Arc::new(custodian);
    eprintln!(
        "whip-custodian: r0 process sealing (degraded), serving on {}",
        socket.display()
    );
    whipplescript_custodian::serve::serve(custodian, &socket).map_err(|e| e.to_string())
}

/// Everywhere else the store commands still work and the daemon refuses to
/// start. Refusing loudly beats a custodian that appears to serve over some
/// substitute transport nobody reviewed as an authority boundary.
#[cfg(not(target_family = "unix"))]
fn serve_command(
    _args: &Args,
    _store_path: &std::path::Path,
    _pass: &Zeroizing<String>,
) -> Result<(), String> {
    Err(
        "whip-custodian serve requires a Unix domain socket; this platform has none. \
         The store commands (init/import/list/revoke) work here."
            .to_string(),
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(argv: &[&str]) -> Args {
        let owned: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
        Args::parse(&owned).expect("arguments parse")
    }

    /// A custodian built without the `tpm` feature says so, rather than writing
    /// an entry nothing on this host can ever use.
    ///
    /// Compiled only in that configuration, because that is the only one where
    /// the refusal exists — and it is the configuration the default build and
    /// the green bar are in, so this is the path most likely to be hit.
    #[cfg(not(feature = "tpm"))]
    #[test]
    fn a_custodian_without_the_tpm_feature_refuses_to_bind_rather_than_recording() {
        let refused = import_tpm(
            std::path::Path::new("/nonexistent/store.json"),
            "pass",
            CredentialName::new("release/signing").expect("name"),
            CredentialKind::HmacSha256,
            &[0, 7],
            None,
            None,
        )
        .expect_err("this build cannot reach a TPM");
        assert!(
            refused.contains("built without the `tpm` feature"),
            "the refusal must name the cause: {refused}"
        );
        assert!(
            refused.contains("--features tpm"),
            "and the way forward: {refused}"
        );
        // It refuses BEFORE touching the store: the path above does not exist,
        // and a run that got as far as opening it would have failed differently.
    }

    #[test]
    fn pcr_slots_parse_into_an_ordered_deduplicated_binding() {
        // Ascending and de-duplicated because the binding hashes values in slot
        // order: `7,0` and `0,7` must be the same platform claim, or an
        // operator who typed them the other way round would find the credential
        // stale for a reason they could not see.
        assert_eq!(parse_pcr_slots("0,7").expect("parsed"), vec![0, 7]);
        assert_eq!(parse_pcr_slots("7,0").expect("parsed"), vec![0, 7]);
        assert_eq!(parse_pcr_slots("7, 0 ,7").expect("parsed"), vec![0, 7]);
        assert_eq!(parse_pcr_slots(" 4 ").expect("parsed"), vec![4]);
    }

    #[test]
    fn a_pcr_selection_that_names_nothing_usable_is_refused() {
        // An empty selection would bind to nothing and report fresh forever —
        // the exact failure freshness exists to prevent — so it is refused
        // where it is typed rather than at the first signature.
        //
        // Asserting the TEXT rather than `is_err()`: the two refusals here say
        // different things — a missing slot and an unparseable one — and an
        // operator needs to know which they hit. An `is_err()` assertion also
        // passes through a mutation of the message, so it measures nothing.
        for bad in ["", " ", "0,", ",7"] {
            assert_eq!(
                parse_pcr_slots(bad).expect_err("not a selection"),
                "--tpm-pcr takes a comma-separated list of PCR slots, e.g. 0,7",
                "`{bad}` names no slot"
            );
        }
        for bad in ["seven", "0,seven", "-1"] {
            assert_eq!(
                parse_pcr_slots(bad).expect_err("not a slot number"),
                format!(
                    "--tpm-pcr: `{}` is not a PCR slot number",
                    bad.rsplit(',').next().expect("piece")
                ),
                "`{bad}` names something that is not a slot"
            );
        }
    }

    #[test]
    fn remote_transit_refuses_every_local_material_source_by_name() {
        // Each source is named in the refusal, so an operator who passed two
        // reads which one to drop rather than being told "conflicting flags".
        for (argv, expected) in [
            (
                vec!["--remote-transit", "signing", "--from-env", "TOKEN"],
                "--remote-transit conflicts with --from-env",
            ),
            (
                vec!["--remote-transit", "signing", "--from-file", "/k"],
                "--remote-transit conflicts with --from-file",
            ),
            (
                vec!["--remote-transit", "signing", "--from-stdin"],
                "--remote-transit conflicts with --from-stdin",
            ),
        ] {
            let err = remote_transit_excludes_local_material(&parsed(&argv))
                .expect_err("a local source alongside --remote-transit is a contradiction");
            assert_eq!(err, expected);
        }
    }

    #[test]
    fn a_remote_key_on_its_own_is_admitted() {
        // The control: without this, the refusals above pass just as well when
        // the check refuses everything.
        remote_transit_excludes_local_material(&parsed(&["--remote-transit", "signing"]))
            .expect("a remote key with no local source is the whole point of r3");
    }
}
