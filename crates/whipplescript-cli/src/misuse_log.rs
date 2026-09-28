//! The log of invocations `whip` refused, kept to improve the command surface.
//!
//! Exit status 2 is the CLI's refusal of the invocation itself: an unknown
//! command, an unknown or missing argument, a malformed value, a `whip test`
//! source that does not compile. A program `whip check` finds wrong is exit 1
//! and is not here. Every refused invocation appends one JSON line, so the
//! spellings people and agents reach for that whip does not accept, and the
//! usage messages that did not tell them what was wanted, can be counted
//! instead of remembered.
//!
//! The log stays on the machine that wrote it. An argument that can carry a
//! secret is redacted before the line is written, because a mistyped
//! `whip auth set` holds the key it was meant to store.

use std::{
    fs::{self, OpenOptions},
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::json;

/// Names the log file, or `off` to keep none.
const LOG_VARIABLE: &str = "WHIPPLESCRIPT_MISUSE_LOG";
const LOG_SCHEMA: &str = "whipplescript.misuse.v0";
const LOG_FILE: &str = "misuse.jsonl";
/// Past this size the log becomes `<log>.1`, replacing the one before, so two
/// generations are kept and the file never grows without bound.
const ROTATE_AT_BYTES: u64 = 4 * 1024 * 1024;
/// An issue body passed as an argument is not what the log is for.
const MAX_ARGUMENT_CHARS: usize = 200;
const REDACTED: &str = "<redacted>";
/// A flag or `NAME=value` whose name holds one of these may carry a secret, so
/// its value is not written. Redacting a value that was harmless costs a detail;
/// keeping one that was not puts a credential in a plaintext file.
const SECRET_NAME_WORDS: &[&str] = &[
    "token",
    "secret",
    "password",
    "credential",
    "key",
    "auth",
    "cookie",
    "header",
    "env",
    "input",
];
/// Credentials common enough to recognise wherever they appear.
const SECRET_PREFIXES: &[&str] = &[
    "sk-",
    "xai-",
    "ghp_",
    "gho_",
    "ghs_",
    "ghu_",
    "ghr_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "AKIA",
    "eyJ",
    "Bearer ",
    "bearer ",
];

/// Append the refused invocation `argv` (without the program name) to the log.
/// A log that cannot be written is skipped silently: the refusal already said
/// what was wrong, and a second message about a diagnostics file would bury it.
pub(crate) fn record(argv: &[String]) {
    let Some(path) = log_path(|name| std::env::var(name).ok(), cfg!(debug_assertions)) else {
        return;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0);
    let _ = append(&path, &entry(argv, now, io::stdin().is_terminal()));
}

/// `$WHIPPLESCRIPT_MISUSE_LOG`, else `$XDG_STATE_HOME/whipplescript/misuse.jsonl`,
/// else `~/.local/state/whipplescript/misuse.jsonl`.
///
/// A debug build keeps no log unless the variable names one. Debug builds are
/// what the test suites spawn, and they refuse invocations on purpose by the
/// thousand; written to the default log, those would bury the entries it exists
/// for and then rotate them away.
fn log_path(var: impl Fn(&str) -> Option<String>, debug_build: bool) -> Option<PathBuf> {
    let set = |name: &str| var(name).filter(|value| !value.trim().is_empty());
    match set(LOG_VARIABLE) {
        Some(value) if value.trim() == "off" => None,
        Some(value) => Some(PathBuf::from(value)),
        None if debug_build => None,
        None => {
            let state = set("XDG_STATE_HOME")
                .map(PathBuf::from)
                .or_else(|| set("HOME").map(|home| Path::new(&home).join(".local/state")))?;
            Some(state.join("whipplescript").join(LOG_FILE))
        }
    }
}

fn entry(argv: &[String], at_unix_secs: i64, tty: bool) -> String {
    let at = chrono::DateTime::from_timestamp(at_unix_secs, 0)
        .map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default();
    json!({
        "schema": LOG_SCHEMA,
        "at": at,
        "version": whipplescript_core::version(),
        "argv": redact(argv),
        // Whether a person was at a terminal, as against an agent or a script.
        "tty": tty,
    })
    .to_string()
}

fn append(path: &Path, line: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if fs::metadata(path).is_ok_and(|metadata| metadata.len() >= ROTATE_AT_BYTES) {
        let mut previous = path.as_os_str().to_owned();
        previous.push(".1");
        // Two processes rotating at once can lose a generation. The log is a
        // sample of mistakes, not a ledger, so that is not worth a lock.
        let _ = fs::rename(path, previous);
    }
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    // One write per line: appends of this size from concurrent processes do
    // not interleave.
    options
        .open(path)?
        .write_all(format!("{line}\n").as_bytes())
}

/// The arguments as they will be written: secrets replaced and long values cut.
fn redact(argv: &[String]) -> Vec<String> {
    let mut written = Vec::with_capacity(argv.len());
    let mut previous_flag: Option<&str> = None;
    let mut words = 0;
    let mut auth = false;
    for arg in argv {
        let flag = previous_flag.take();
        let secret_assignment = arg.split_once('=').filter(|(name, _)| names_a_secret(name));
        let kept = if SECRET_PREFIXES.iter().any(|prefix| arg.starts_with(prefix)) {
            REDACTED.to_owned()
        } else if let Some((name, _)) = secret_assignment {
            format!("{name}={REDACTED}")
        } else if arg.starts_with('-') && arg != "-" {
            previous_flag = Some(arg);
            arg.clone()
        } else if flag.is_some_and(names_a_secret) {
            REDACTED.to_owned()
        } else if flag == Some("--store") {
            // The global option's value, not a word of the command.
            arg.clone()
        } else {
            words += 1;
            if words == 1 {
                auth = arg == "auth";
            }
            // `whip auth set <provider> <key>`: past the subcommand, a word may
            // be the key, and a missing provider puts it first.
            if auth && words > 2 {
                REDACTED.to_owned()
            } else {
                arg.clone()
            }
        };
        written.push(truncate(kept));
    }
    written
}

fn names_a_secret(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    SECRET_NAME_WORDS.iter().any(|word| name.contains(word))
}

fn truncate(arg: String) -> String {
    match arg.char_indices().nth(MAX_ARGUMENT_CHARS) {
        Some((cut, _)) => format!("{}…", &arg[..cut]),
        None => arg,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_owned()).collect()
    }

    fn env(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    #[test]
    fn a_release_build_logs_under_the_state_directory() {
        assert_eq!(
            log_path(env(&[("HOME", "/home/a")]), false),
            Some(PathBuf::from(
                "/home/a/.local/state/whipplescript/misuse.jsonl"
            ))
        );
        assert_eq!(
            log_path(
                env(&[("HOME", "/home/a"), ("XDG_STATE_HOME", "/state")]),
                false
            ),
            Some(PathBuf::from("/state/whipplescript/misuse.jsonl"))
        );
        assert_eq!(log_path(env(&[]), false), None);
    }

    #[test]
    fn the_variable_names_the_log_or_turns_it_off() {
        let named = &[(LOG_VARIABLE, "/tmp/m.jsonl"), ("HOME", "/home/a")];
        assert_eq!(
            log_path(env(named), false),
            Some(PathBuf::from("/tmp/m.jsonl"))
        );
        assert_eq!(
            log_path(env(named), true),
            Some(PathBuf::from("/tmp/m.jsonl"))
        );
        assert_eq!(
            log_path(env(&[(LOG_VARIABLE, "off"), ("HOME", "/home/a")]), false),
            None
        );
        // Empty is unset, as it is for every other WHIPPLESCRIPT_ path.
        assert_eq!(
            log_path(env(&[(LOG_VARIABLE, " "), ("HOME", "/home/a")]), false),
            Some(PathBuf::from(
                "/home/a/.local/state/whipplescript/misuse.jsonl"
            ))
        );
    }

    #[test]
    fn a_debug_build_logs_only_where_told() {
        assert_eq!(log_path(env(&[("HOME", "/home/a")]), true), None);
    }

    #[test]
    fn an_ordinary_mistake_is_written_as_typed() {
        let typed = args(&["--json", "issue", "close", "WS-1", "--actor", "claude"]);
        assert_eq!(redact(&typed), typed);
    }

    #[test]
    fn a_stored_credential_is_never_written() {
        assert_eq!(
            redact(&args(&["auth", "set", "anthropc", "not-a-real-key"])),
            args(&["auth", "set", REDACTED, REDACTED])
        );
        assert_eq!(
            redact(&args(&["--store", "s.sqlite", "auth", "set", "opaque-key"])),
            args(&["--store", "s.sqlite", "auth", "set", REDACTED])
        );
    }

    #[test]
    fn a_secret_flag_value_is_never_written() {
        assert_eq!(
            redact(&args(&[
                "mcp",
                "add",
                "x",
                "--header",
                "Authorization=Bearer abc"
            ])),
            args(&["mcp", "add", "x", "--header", "Authorization=<redacted>"])
        );
        assert_eq!(
            redact(&args(&[
                "run",
                "w.whip",
                "--input",
                "{\"a\":1}",
                "--token=abc"
            ])),
            args(&["run", "w.whip", "--input", REDACTED, "--token=<redacted>"])
        );
        // A secret-named flag that takes no value leaves the next flag alone.
        assert_eq!(
            redact(&args(&["deploy", "--set-secrets", "--dry-run"])),
            args(&["deploy", "--set-secrets", "--dry-run"])
        );
    }

    #[test]
    fn a_recognisable_credential_is_never_written_wherever_it_is() {
        assert_eq!(
            redact(&args(&[
                "mcp",
                "add",
                "x",
                "--arg",
                "ghp_abcdef",
                "sk-ant-api03-x"
            ])),
            args(&["mcp", "add", "x", "--arg", REDACTED, REDACTED])
        );
        assert_eq!(
            redact(&args(&["mcp", "add", "x", "--arg", "API_KEY=abc"])),
            args(&["mcp", "add", "x", "--arg", "API_KEY=<redacted>"])
        );
    }

    #[test]
    fn a_long_argument_is_cut() {
        let written = redact(&args(&["issue", "new", &"b".repeat(500)]));
        assert_eq!(written[2].chars().count(), MAX_ARGUMENT_CHARS + 1);
        assert!(written[2].ends_with('…'));
    }

    #[test]
    fn an_entry_is_one_json_line() {
        let line = entry(&args(&["isue", "list"]), 1_790_000_000, false);
        assert!(!line.contains('\n'));
        let value: serde_json::Value = serde_json::from_str(&line).expect("json");
        assert_eq!(value["schema"], LOG_SCHEMA);
        assert_eq!(value["at"], "2026-09-21T14:13:20Z");
        assert_eq!(value["argv"], json!(["isue", "list"]));
        assert_eq!(value["tty"], false);
    }

    #[test]
    fn the_log_rotates_rather_than_grows() {
        let dir = std::env::temp_dir().join(format!("whip-misuse-rotate-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("nested").join(LOG_FILE);
        append(&path, "first").expect("create");
        fs::write(&path, vec![b'x'; ROTATE_AT_BYTES as usize]).expect("fill");
        append(&path, "after").expect("rotate");
        assert_eq!(fs::read_to_string(&path).expect("log"), "after\n");
        let previous = dir.join("nested").join(format!("{LOG_FILE}.1"));
        assert_eq!(fs::metadata(previous).expect("kept").len(), ROTATE_AT_BYTES);
        let _ = fs::remove_dir_all(&dir);
    }
}
