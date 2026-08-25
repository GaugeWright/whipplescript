//! DR-0067: the event log's hash chain.
//!
//! `UNIQUE(instance_id, sequence)` is ordering and dedup *within one store*.
//! Across machines it is nothing: entry 42 is well-formed on its own, so a
//! reader cannot tell "I have 1..40 and 42" from a complete prefix, and cannot
//! tell your entry 17 from mine. This module makes a prefix self-verifying by
//! committing each entry to the one before it, so the instance's high-water
//! mark is `(sequence, head_digest)` and a gap or substitution is structurally
//! impossible to hide.
//!
//! Pure and dependency-light on purpose: the durable-object host builds this
//! crate with `--no-default-features` (no rusqlite), and both hosts must
//! compute byte-identical digests or the chain means nothing across the seam.

use crate::items::sha256_hex;

/// The domain tag. Present so a digest computed here can never collide with one
/// computed for another purpose over the same bytes, and so a future encoding
/// change is a *different* tag rather than a silent re-identification of every
/// stored row.
const CANONICAL_TAG: &str = "whipplescript.event-chain.v1";

/// Field separator. Not load-bearing for injectivity — the length prefixes are
/// (see [`canonical_entry`]) — but it keeps a canonical string readable when a
/// digest mismatch has to be debugged by eye.
const FIELD_SEPARATOR: char = '\u{1e}';

/// Sequence 0 has no predecessor, so the chain starts from a digest derived
/// from the instance itself. Per-instance rather than global: a genesis shared
/// across instances would let a prefix of one instance verify as a prefix of
/// another, which is exactly the substitution the chain exists to refuse.
#[must_use]
pub fn genesis_digest(instance_id: &str) -> String {
    sha256_hex(&format!(
        "{CANONICAL_TAG}{FIELD_SEPARATOR}genesis{FIELD_SEPARATOR}{}:{instance_id}",
        instance_id.len()
    ))
}

/// One event's recorded columns, exactly as stored.
///
/// Every field is *recorded* rather than recomputed — `occurred_at` is the
/// stored timestamp, not a fresh clock read — which is what makes a backfill
/// over existing rows deterministic (DR-0067 §5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainEntry<'a> {
    pub event_id: &'a str,
    pub instance_id: &'a str,
    pub sequence: i64,
    pub event_type: &'a str,
    pub payload_json: &'a str,
    pub occurred_at: &'a str,
    pub source: &'a str,
    pub causation_id: Option<&'a str>,
    pub correlation_id: Option<&'a str>,
    pub idempotency_key: Option<&'a str>,
    pub format_version: Option<i64>,
}

/// An `events` row read back, owned.
///
/// [`ChainEntry`] borrows, which is right for hashing and wrong for a trait
/// that has to hand rows across a store boundary. Both hosts had a private copy
/// of this shape; one public type replaces both, so a column added to the chain
/// cannot be added to one host's reader and forgotten in the other's.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedChainEntry {
    pub event_id: String,
    pub sequence: i64,
    pub event_type: String,
    pub payload_json: String,
    pub occurred_at: String,
    pub source: Option<String>,
    pub causation_id: Option<String>,
    pub correlation_id: Option<String>,
    pub idempotency_key: Option<String>,
    pub format_version: Option<i64>,
}

impl OwnedChainEntry {
    /// Borrow as a [`ChainEntry`] for folding.
    ///
    /// `source` is NOT NULL in the schema; the `Option` is defensive for a
    /// store written before that was true, and an absent source must not be
    /// silently equal to an empty one — so the empty string here is a
    /// deliberate floor, not a coincidence.
    #[must_use]
    pub fn as_entry<'a>(&'a self, instance_id: &'a str) -> ChainEntry<'a> {
        ChainEntry {
            event_id: &self.event_id,
            instance_id,
            sequence: self.sequence,
            event_type: &self.event_type,
            payload_json: &self.payload_json,
            occurred_at: &self.occurred_at,
            source: self.source.as_deref().unwrap_or(""),
            causation_id: self.causation_id.as_deref(),
            correlation_id: self.correlation_id.as_deref(),
            idempotency_key: self.idempotency_key.as_deref(),
            format_version: self.format_version,
        }
    }
}

/// Fold owned rows, the shape a store hands back.
///
/// # Panics
/// Never; the borrow is local to the call.
#[must_use]
pub fn fold_owned(instance_id: &str, rows: &[OwnedChainEntry]) -> ChainHead {
    let entries: Vec<ChainEntry<'_>> = rows.iter().map(|row| row.as_entry(instance_id)).collect();
    fold_prefix(instance_id, &entries)
}

/// Length-prefix one field so the encoding is injective.
///
/// The hazard this closes: with a bare separator, a `payload_json` that itself
/// contains the separator could be split so that two *different* entries encode
/// identically — a forged entry with the same digest as an honest one. A
/// decimal byte length before the value makes the parse unambiguous regardless
/// of the value's content, so distinct entries always produce distinct strings.
/// `None` encodes as a token that no length prefix can produce, keeping a
/// missing field distinct from an empty one.
fn field(value: Option<&str>) -> String {
    match value {
        Some(text) => format!("{}:{text}", text.len()),
        None => "-".to_owned(),
    }
}

/// The canonical string for one entry. Injective over [`ChainEntry`].
#[must_use]
pub fn canonical_entry(entry: &ChainEntry<'_>) -> String {
    let sequence = entry.sequence.to_string();
    let format_version = entry.format_version.map(|version| version.to_string());
    let fields = [
        field(Some(CANONICAL_TAG)),
        field(Some(entry.event_id)),
        field(Some(entry.instance_id)),
        field(Some(&sequence)),
        field(Some(entry.event_type)),
        field(Some(entry.payload_json)),
        field(Some(entry.occurred_at)),
        field(Some(entry.source)),
        field(entry.causation_id),
        field(entry.correlation_id),
        field(entry.idempotency_key),
        field(format_version.as_deref()),
    ];
    fields.join(&FIELD_SEPARATOR.to_string())
}

/// `H(prev_digest ‖ canonical(entry))` — the entry's identity *and* its claim
/// about everything before it.
#[must_use]
pub fn entry_digest(prev_digest: &str, entry: &ChainEntry<'_>) -> String {
    sha256_hex(&format!(
        "{}{FIELD_SEPARATOR}{}",
        field(Some(prev_digest)),
        canonical_entry(entry)
    ))
}

/// An instance's high-water mark: how far the log goes, and what the whole
/// prefix hashes to. This is the value a reader pins (DR-0068) and the value an
/// append compare-and-sets against (DR-0067 §2).
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ChainHead {
    /// The last committed sequence, or `None` for an empty log.
    pub sequence: Option<i64>,
    /// The digest of the whole committed prefix — [`genesis_digest`] when empty.
    pub digest: String,
}

impl ChainHead {
    /// The head of an instance whose log is empty.
    #[must_use]
    pub fn empty(instance_id: &str) -> Self {
        Self {
            sequence: None,
            digest: genesis_digest(instance_id),
        }
    }
}

/// Walk a prefix and report the digest it actually hashes to.
///
/// Used by the backfill (DR-0067 §5) and by any reader verifying a prefix it
/// was served. Entries must be supplied in ascending sequence order; a caller
/// that hands them over out of order gets a digest that will not match, which
/// is the correct outcome rather than a silently repaired one.
#[must_use]
pub fn fold_prefix(instance_id: &str, entries: &[ChainEntry<'_>]) -> ChainHead {
    let mut digest = genesis_digest(instance_id);
    let mut sequence = None;
    for entry in entries {
        digest = entry_digest(&digest, entry);
        sequence = Some(entry.sequence);
    }
    ChainHead { sequence, digest }
}

/// DR-0068 §2: the log half of a cut — every in-scope instance's high-water
/// mark, recorded alongside the manifest root.
///
/// A `BTreeMap` so the encoding is order-stable: the cut is content-identified
/// elsewhere, and a map that serialized differently run to run would make two
/// identical cuts look different.
pub type LogHeads = std::collections::BTreeMap<String, ChainHead>;

/// Encode a cut's log heads for storage.
///
/// # Errors
/// Propagates a `serde_json` failure, which for this shape means an allocator
/// or writer fault rather than bad data.
pub fn encode_log_heads(heads: &LogHeads) -> Result<String, serde_json::Error> {
    serde_json::to_string(heads)
}

/// Decode a cut's recorded log heads.
///
/// # Errors
/// Fails when the stored text is not the recorded shape — which is a corrupt
/// or foreign cut row, and must refuse rather than read as "no instances".
pub fn decode_log_heads(encoded: &str) -> Result<LogHeads, serde_json::Error> {
    serde_json::from_str(encoded)
}

/// What a pinned cut's log half looks like against the store right now.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PinnedLogVerdict {
    /// Every pinned instance's recorded prefix is still exactly the pinned one.
    Intact,
    /// At least one instance no longer matches what the cut pinned. A runner
    /// holding this cut must refuse rather than proceed on a different world.
    Diverged(Vec<LogDivergence>),
}

/// One instance whose log no longer matches what a cut pinned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogDivergence {
    pub instance_id: String,
    pub pinned: ChainHead,
    /// The head the store reports now, or `None` when it could not be read.
    pub found: Option<ChainHead>,
}

/// Compare a cut's pinned heads against the heads a store reports now.
///
/// Pure so both hosts share it: the caller supplies `current`, which is the
/// only host-specific part.
#[must_use]
pub fn verify_pinned_logs(pinned: &LogHeads, current: &LogHeads) -> PinnedLogVerdict {
    let mut diverged = Vec::new();
    for (instance_id, head) in pinned {
        let found = current.get(instance_id);
        if found != Some(head) {
            diverged.push(LogDivergence {
                instance_id: instance_id.clone(),
                pinned: head.clone(),
                found: found.cloned(),
            });
        }
    }
    if diverged.is_empty() {
        PinnedLogVerdict::Intact
    } else {
        PinnedLogVerdict::Diverged(diverged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry<'a>(sequence: i64, payload: &'a str) -> ChainEntry<'a> {
        ChainEntry {
            event_id: "evt_one",
            instance_id: "inst_a",
            sequence,
            event_type: "fact.recorded",
            payload_json: payload,
            occurred_at: "2026-08-24T00:00:00Z",
            source: "worker",
            causation_id: None,
            correlation_id: None,
            idempotency_key: None,
            format_version: Some(2),
        }
    }

    #[test]
    fn genesis_is_per_instance() {
        assert_ne!(genesis_digest("inst_a"), genesis_digest("inst_b"));
    }

    #[test]
    fn a_digest_commits_to_its_predecessor() {
        let one = entry(1, "{}");
        let from_genesis = entry_digest(&genesis_digest("inst_a"), &one);
        let from_elsewhere = entry_digest(&genesis_digest("inst_b"), &one);
        assert_ne!(
            from_genesis, from_elsewhere,
            "the same entry on a different prefix must not share a digest"
        );
    }

    #[test]
    fn length_prefixing_defeats_separator_injection() {
        // Two entries whose payloads differ only in where a separator falls.
        // Without length prefixes these could encode identically; the digests
        // must differ.
        let left_payload = format!("a{FIELD_SEPARATOR}bc");
        let right_payload = format!("a{FIELD_SEPARATOR}b{FIELD_SEPARATOR}c");
        let left = entry(1, &left_payload);
        let right = entry(1, &right_payload);
        assert_ne!(canonical_entry(&left), canonical_entry(&right));
        let base = genesis_digest("inst_a");
        assert_ne!(entry_digest(&base, &left), entry_digest(&base, &right));
    }

    #[test]
    fn a_missing_field_differs_from_an_empty_one() {
        let mut absent = entry(1, "{}");
        absent.causation_id = None;
        let mut empty = entry(1, "{}");
        empty.causation_id = Some("");
        assert_ne!(canonical_entry(&absent), canonical_entry(&empty));
    }

    #[test]
    fn folding_a_prefix_is_order_sensitive() {
        let one = entry(1, "{\"a\":1}");
        let two = entry(2, "{\"b\":2}");
        let forward = fold_prefix("inst_a", &[one, two]);
        let backward = fold_prefix("inst_a", &[two, one]);
        assert_ne!(forward.digest, backward.digest);
        assert_eq!(forward.sequence, Some(2));
    }

    #[test]
    fn a_dropped_entry_changes_the_head() {
        let one = entry(1, "{\"a\":1}");
        let two = entry(2, "{\"b\":2}");
        let three = entry(3, "{\"c\":3}");
        let whole = fold_prefix("inst_a", &[one, two, three]);
        let gapped = fold_prefix("inst_a", &[one, three]);
        assert_ne!(
            whole.digest, gapped.digest,
            "a gap must be visible in the head digest"
        );
    }

    fn heads(pairs: &[(&str, i64, &str)]) -> LogHeads {
        pairs
            .iter()
            .map(|(instance, sequence, digest)| {
                (
                    (*instance).to_owned(),
                    ChainHead {
                        sequence: Some(*sequence),
                        digest: (*digest).to_owned(),
                    },
                )
            })
            .collect()
    }

    #[test]
    fn log_heads_round_trip_through_storage() {
        let pinned = heads(&[("inst_a", 4, "aa"), ("inst_b", 1, "bb")]);
        let encoded = encode_log_heads(&pinned).expect("encodes");
        assert_eq!(decode_log_heads(&encoded).expect("decodes"), pinned);
    }

    #[test]
    fn an_unmoved_world_verifies_intact() {
        let pinned = heads(&[("inst_a", 4, "aa")]);
        assert_eq!(
            verify_pinned_logs(&pinned, &pinned.clone()),
            PinnedLogVerdict::Intact
        );
    }

    /// The runner bite: an instance whose log advanced since the pin means the
    /// cut no longer names the world the runner would execute against.
    #[test]
    fn an_advanced_log_diverges_from_its_pin() {
        let pinned = heads(&[("inst_a", 4, "aa")]);
        let now = heads(&[("inst_a", 5, "cc")]);
        match verify_pinned_logs(&pinned, &now) {
            PinnedLogVerdict::Diverged(found) => {
                assert_eq!(found.len(), 1);
                assert_eq!(found[0].instance_id, "inst_a");
                assert_eq!(
                    found[0].found.as_ref().map(|head| head.sequence),
                    Some(Some(5))
                );
            }
            other => panic!("expected divergence, got {other:?}"),
        }
    }

    /// A pinned instance that has gone missing is divergence, not absence of
    /// evidence — the runner must refuse rather than skip it.
    #[test]
    fn a_vanished_instance_is_divergence_not_silence() {
        let pinned = heads(&[("inst_a", 4, "aa")]);
        let now = LogHeads::new();
        match verify_pinned_logs(&pinned, &now) {
            PinnedLogVerdict::Diverged(found) => {
                assert_eq!(found.len(), 1);
                assert!(found[0].found.is_none());
            }
            other => panic!("expected divergence, got {other:?}"),
        }
    }

    /// An instance the cut never pinned is out of scope, not a violation.
    #[test]
    fn an_unpinned_instance_does_not_diverge_a_cut() {
        let pinned = heads(&[("inst_a", 4, "aa")]);
        let now = heads(&[("inst_a", 4, "aa"), ("inst_new", 1, "dd")]);
        assert_eq!(verify_pinned_logs(&pinned, &now), PinnedLogVerdict::Intact);
    }

    #[test]
    fn an_empty_log_heads_at_genesis() {
        let head = ChainHead::empty("inst_a");
        assert_eq!(head.sequence, None);
        assert_eq!(head.digest, genesis_digest("inst_a"));
        assert_eq!(fold_prefix("inst_a", &[]), head);
    }
}
