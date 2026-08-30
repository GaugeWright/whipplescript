//! DR-0071 §5: erasure's authority of record is a hash-chained ledger in the
//! history plane, not a flag in the content plane.
//!
//! "This hash was erased at time T" is a **historical fact**, and it is exactly
//! the shape of every other entry in an append-only, ordered, hash-chained log.
//! It lived in the content tier in two differently-shaped places instead:
//! `content_erasures`, a per-blob tombstone table, and
//! `content_chunk_roots.erased_at`, a column the chunk tier's fail-closed
//! shared-chunk logic consulted during reassembly. So the one correctness
//! obligation in the content tier sat in the plane with the weakest integrity
//! guarantees, in two representations that could disagree, while the plane
//! built for durable ordered facts sat beside it unused.
//!
//! Three things follow from moving it, in the record's order of weight:
//!
//! - **It is a historical fact, and history is the log's job.** Chained, an
//!   erasure cannot be quietly un-recorded: dropping or rewriting an entry
//!   breaks every digest after it.
//! - **It makes a dumb backend sufficient.** Once the ledger answers "was this
//!   erased", a backend needs only put/get/delete. Erasure was the single
//!   obligation forcing backends to be clever, which is the whole point of
//!   putting the boundary at portability.
//! - **It removes a way to lie.** `EraseOutcome::Unsupported` is honest from a
//!   store that *cannot* delete bytes. It was not honest from one that deleted
//!   them and merely failed to remember — that is *absent* masquerading as *not
//!   supported*, one step from the *absent*-for-*erased* substitution DR-0066 §5
//!   refuses.
//!
//! Scoped honestly, per the record's own narrowing: this makes every erasure
//! **the substrate performs** honest. Bytes can still leave an object store
//! without passing through `erase` — a bucket lifecycle rule, an operator, an
//! adapter bug — and the ledger then has no entry, so the id reports *absent*
//! for bytes that are gone. Nothing in the content plane can close that hole,
//! because the hole is outside it.
//!
//! Pure and dependency-light, like [`crate::event_chain`]: the durable-object
//! host builds this crate with `--no-default-features`, and both hosts must
//! compute byte-identical digests or the chain means nothing across the seam.

use crate::items::sha256_hex;

/// The domain tag, so a digest computed here can never collide with one
/// computed for another purpose over the same bytes.
const CANONICAL_TAG: &str = "whipplescript.erasure-ledger.v1";

/// Field separator. The length prefixes carry injectivity; this keeps a
/// canonical string readable when a mismatch has to be debugged by eye.
const FIELD_SEPARATOR: char = '\u{1e}';

/// What was erased.
///
/// One ledger for both, deliberately. They were two tables answering the same
/// question in different shapes, and a reader had to know which tier an id
/// belonged to before it could ask whether the id was erased — which is exactly
/// the layout knowledge DR-0066 §7 keeps out of the contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErasedKind {
    /// A whole blob's payload.
    Blob,
    /// A chunked root: its chunk bodies are gone, its identity is retained.
    ChunkRoot,
}

impl ErasedKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::ChunkRoot => "chunk-root",
        }
    }

    /// Parse a stored kind. Unknown kinds are refused rather than defaulted:
    /// a ledger row this reader does not understand is not one it may treat as
    /// an ordinary blob erasure.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "blob" => Some(Self::Blob),
            "chunk-root" => Some(Self::ChunkRoot),
            _ => None,
        }
    }
}

/// One recorded erasure, exactly as stored.
///
/// Every field is *recorded* rather than recomputed — `erased_at` is the stored
/// timestamp, not a fresh clock read — so a backfill over existing rows is
/// deterministic, the same discipline DR-0067 §5 applies to the event chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerEntry<'a> {
    pub sequence: i64,
    pub id: &'a str,
    pub kind: ErasedKind,
    pub byte_len: i64,
    pub erased_at: &'a str,
}

/// Sequence 0 has no predecessor. Global rather than per-id: this ledger is one
/// ordered history of a store's erasures, and a per-id genesis would let one
/// id's prefix verify as another's.
#[must_use]
pub fn genesis_digest() -> String {
    sha256_hex(&format!("{CANONICAL_TAG}{FIELD_SEPARATOR}genesis"))
}

fn field(value: &str) -> String {
    format!("{}:{value}", value.len())
}

/// The canonical string for one entry. Injective over [`LedgerEntry`].
#[must_use]
pub fn canonical_entry(entry: &LedgerEntry<'_>) -> String {
    let sequence = entry.sequence.to_string();
    let byte_len = entry.byte_len.to_string();
    [
        field(CANONICAL_TAG),
        field(&sequence),
        field(entry.id),
        field(entry.kind.as_str()),
        field(&byte_len),
        field(entry.erased_at),
    ]
    .join(&FIELD_SEPARATOR.to_string())
}

/// `H(prev_digest ‖ canonical(entry))` — the entry's identity *and* its claim
/// about every erasure before it.
#[must_use]
pub fn entry_digest(prev_digest: &str, entry: &LedgerEntry<'_>) -> String {
    sha256_hex(&format!(
        "{}{FIELD_SEPARATOR}{}",
        field(prev_digest),
        canonical_entry(entry)
    ))
}

/// Fold a whole prefix, returning the digest it ends at.
///
/// What makes the ledger tamper-evident: a dropped or rewritten entry changes
/// every digest after it, so "this erasure was never recorded" is not something
/// a store can say quietly.
#[must_use]
pub fn fold(entries: &[LedgerEntry<'_>]) -> String {
    let mut digest = genesis_digest();
    for entry in entries {
        digest = entry_digest(&digest, entry);
    }
    digest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_ledger_folds_to_genesis() {
        assert_eq!(fold(&[]), genesis_digest());
    }

    /// The property the chain exists for: any change to any entry changes the
    /// head, so an erasure cannot be quietly un-recorded.
    #[test]
    fn every_field_is_committed_to_by_the_head() {
        let base = LedgerEntry {
            sequence: 1,
            id: "abc",
            kind: ErasedKind::Blob,
            byte_len: 12,
            erased_at: "2026-08-30T00:00:00Z",
        };
        let head = fold(&[base]);

        let variants = [
            LedgerEntry {
                sequence: 2,
                ..base
            },
            LedgerEntry { id: "abd", ..base },
            LedgerEntry {
                kind: ErasedKind::ChunkRoot,
                ..base
            },
            LedgerEntry {
                byte_len: 13,
                ..base
            },
            LedgerEntry {
                erased_at: "2026-08-30T00:00:01Z",
                ..base
            },
        ];
        for variant in variants {
            assert_ne!(
                fold(&[variant]),
                head,
                "changing {variant:?} left the head digest alone"
            );
        }
    }

    /// Dropping an entry from the middle must not leave a prefix that verifies.
    #[test]
    fn a_dropped_entry_breaks_every_digest_after_it() {
        let first = LedgerEntry {
            sequence: 1,
            id: "a",
            kind: ErasedKind::Blob,
            byte_len: 1,
            erased_at: "t1",
        };
        let second = LedgerEntry {
            sequence: 2,
            id: "b",
            kind: ErasedKind::Blob,
            byte_len: 2,
            erased_at: "t2",
        };
        let third = LedgerEntry {
            sequence: 3,
            id: "c",
            kind: ErasedKind::Blob,
            byte_len: 3,
            erased_at: "t3",
        };
        assert_ne!(
            fold(&[first, third]),
            fold(&[first, second, third]),
            "a ledger missing its middle entry must not fold to the same head"
        );
    }

    /// The length prefixes are what make the canonical string injective: two
    /// different field splits must not produce the same bytes.
    #[test]
    fn adjacent_fields_cannot_be_confused_for_one_another() {
        let split_one = LedgerEntry {
            sequence: 1,
            id: "ab",
            kind: ErasedKind::Blob,
            byte_len: 1,
            erased_at: "c",
        };
        let split_two = LedgerEntry {
            sequence: 1,
            id: "a",
            kind: ErasedKind::Blob,
            byte_len: 1,
            erased_at: "bc",
        };
        assert_ne!(canonical_entry(&split_one), canonical_entry(&split_two));
    }

    #[test]
    fn an_unknown_kind_is_refused_rather_than_defaulted() {
        assert_eq!(ErasedKind::parse("blob"), Some(ErasedKind::Blob));
        assert_eq!(ErasedKind::parse("chunk-root"), Some(ErasedKind::ChunkRoot));
        assert_eq!(ErasedKind::parse("packfile"), None);
    }
}
