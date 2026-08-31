//! Taking back out of a child's OUTPUT what whip put into its ENVIRONMENT.
//!
//! DR-0053 lists a per-run scrub table for the egress points the type system
//! cannot cover, and names the case: a script capability echoing its own token
//! to stdout. The type system stops whip from *naming* a secret's bytes; it has
//! nothing to say about bytes a child process chooses to print.
//!
//! Two callers inject on whip's behalf and so must take back out: a script
//! capability's declared `env`, and an MCP server's declared env and headers.
//! Both spawn or call something that whip handed a resolved value to, and both
//! feed what comes back into a durable record — the exec outcome into run
//! records and fact payloads, the MCP tool result into the next provider
//! request body. Those are four of the egress points DR-0053 lists.
//!
//! This is the whip-side twin of the custodian's `WireSecrets`, and it exists
//! for the mirror-image reason. There, whip cannot redact because it never
//! knows the material and only the custodian does. Here, whip DOES know the
//! material — `resolve_script_capability_env` read it out of the host
//! environment and handed it to the child — so whip is the party that can take
//! it back out, and the one responsible for it having been there at all.
//!
//! **Defence in depth behind the type system, not a second guarantee.** The
//! honest limits are stated on the members below and hold in the same shape as
//! the custodian's: substring redaction only, so a script that TRANSFORMS its
//! token — hashes it, prints a prefix — is not caught.

use std::collections::BTreeMap;

/// Below this many bytes a value is not redacted.
///
/// The floor is not a guess about secrets, it is a bound on damage. Every
/// declared env value is scrubbed (see `from_resolved_env` for why the
/// alternative is worse), so a script declaring `VERBOSE=1` would otherwise
/// have every `1` in its output replaced — the record would be destroyed to
/// protect a value that is not a secret. Eight bytes is short enough that no
/// real credential falls under it and long enough that flags and small
/// numbers do.
///
/// A secret shorter than this is the stated limit rather than a claim: it is
/// not redacted, and this comment is where that is admitted.
const MIN_REDACTED_LEN: usize = 8;

/// The values whip injected into a child — its environment, or a request
/// header — ready to be taken back out of what the child said in return.
#[derive(Debug, Default, Clone)]
pub struct InjectedSecrets {
    /// `(value, env name)`, longest value first so that when one value
    /// contains another the longer is replaced first and a redaction cannot
    /// leave a dangling fragment of a longer match.
    fragments: Vec<(String, String)>,
}

impl InjectedSecrets {
    /// Every declared value long enough to be worth redacting.
    ///
    /// **Every** value, not the ones that look like secrets. DR-0053 §15 ruled
    /// out inferring a label from bytes, in its redacting form as much as its
    /// refusing one, so there is no shape test here and there should not be:
    /// deciding by appearance would miss the token that does not look like one
    /// and would be a second, quieter labelling scheme besides the declared
    /// one.
    ///
    /// The cost of scrubbing a value that was only configuration is paid in a
    /// RECORD and never in behaviour — the script received the real value and
    /// ran on it. The cost of the opposite mistake is a credential in durable
    /// storage. That asymmetry is the whole argument for over-redacting here.
    pub fn from_resolved_env(resolved: &BTreeMap<String, String>) -> Self {
        let mut table = Self::default();
        for (name, value) in resolved {
            table.add(name, value);
        }
        table
    }

    /// Record one injected value, for callers that resolve them one at a time.
    ///
    /// Ordering is restored on every insert rather than once at the end: a
    /// caller that adds and then scrubs without a separate "finish" step is
    /// the easy thing to write, so the type must not have a state where it is
    /// built but not yet correct.
    pub fn add(&mut self, name: &str, value: &str) {
        if value.len() < MIN_REDACTED_LEN || self.fragments.iter().any(|(had, _)| had == value) {
            return;
        }
        self.fragments.push((value.to_owned(), name.to_owned()));
        self.fragments
            .sort_by_key(|(value, _)| usize::MAX - value.len());
    }

    /// Redact every known value from `text`, naming the env var it came from.
    ///
    /// The marker names the VARIABLE and never the value — an operator reading
    /// a scrubbed record needs to know which declaration leaked, and a hint at
    /// the material would reintroduce exactly what was removed.
    pub fn scrub(&self, text: &str) -> String {
        let mut out = text.to_owned();
        for (value, name) in &self.fragments {
            if out.contains(value.as_str()) {
                out = out.replace(value.as_str(), &format!("[redacted env {name}]"));
            }
        }
        out
    }

    /// Redact from raw child output.
    ///
    /// Non-UTF-8 output is left alone: it cannot carry the textual form that
    /// was injected, and re-encoding it would be a lie about what the child
    /// wrote. `String::from_utf8_lossy` downstream keeps its own behaviour.
    pub fn scrub_bytes(&self, bytes: &[u8]) -> Vec<u8> {
        if self.fragments.is_empty() {
            return bytes.to_vec();
        }
        match std::str::from_utf8(bytes) {
            Ok(text) => self.scrub(text).into_bytes(),
            Err(_) => bytes.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(pairs: &[(&str, &str)]) -> InjectedSecrets {
        InjectedSecrets::from_resolved_env(
            &pairs
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
        )
    }

    #[test]
    fn an_echoed_token_is_redacted_and_names_its_variable() {
        let secrets = table(&[("TOKEN", "fixture-token-not-a-secret")]);
        assert_eq!(
            secrets.scrub("using fixture-token-not-a-secret now"),
            "using [redacted env TOKEN] now"
        );
    }

    #[test]
    fn output_with_no_secret_in_it_is_untouched() {
        // The control: without it, a scrub that replaced everything would pass
        // the test above just as well.
        let secrets = table(&[("TOKEN", "fixture-token-not-a-secret")]);
        assert_eq!(secrets.scrub("nothing to see"), "nothing to see");
    }

    #[test]
    fn a_short_value_is_left_alone_so_a_flag_cannot_shred_the_record() {
        // `VERBOSE=1` must not turn every `1` in the output into a marker.
        let secrets = table(&[("VERBOSE", "1")]);
        // Asserted through behaviour rather than a getter: what matters is that
        // the record survives, not how the table represents the omission.
        assert_eq!(
            secrets.scrub("exited with 1 warning"),
            "exited with 1 warning"
        );
    }

    #[test]
    fn the_longer_of_two_overlapping_values_goes_first() {
        // `SHORT` is a prefix of `LONG`. Replacing the short one first would
        // leave `[redacted env SHORT]suffix` — a dangling tail of a value that
        // was supposed to disappear whole.
        let secrets = table(&[("SHORT", "abcdefghij"), ("LONG", "abcdefghijklmnopqrst")]);
        assert_eq!(
            secrets.scrub("x abcdefghijklmnopqrst y"),
            "x [redacted env LONG] y"
        );
    }

    #[test]
    fn non_utf8_output_passes_through_unchanged() {
        let secrets = table(&[("TOKEN", "fixture-token-not-a-secret")]);
        let raw = vec![0xff, 0xfe, 0x00, 0x41];
        assert_eq!(secrets.scrub_bytes(&raw), raw);
    }

    #[test]
    fn every_declared_value_is_scrubbed_not_only_secret_looking_ones() {
        // DR-0053 §15 ruled out inferring a label from bytes. A value that
        // looks like a hostname is redacted exactly as a token is.
        let secrets = table(&[("ENDPOINT", "internal.example.invalid")]);
        assert_eq!(
            secrets.scrub("GET internal.example.invalid/health"),
            "GET [redacted env ENDPOINT]/health"
        );
    }
}
