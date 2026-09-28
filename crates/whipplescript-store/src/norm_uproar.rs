//! The norm ledger's UPROAR export binding (norm-plane §11.2, slice U1).
//!
//! Each admitted ledger event becomes one UPROAR wire v1 record: deterministic
//! CBOR, the closed record key set, set slots sorted by their encodings, and
//! `ref = SHA-256(det_cbor(record))`. The store keeps its own representation;
//! this is a projection through a versioned binding profile that grades every
//! slot from what the export actually carries. The records are unsigned: the
//! host holds no Ed25519 key for any ledger principal, so authorship is
//! declared, never demonstrated, and the profile says so.
//!
//! The wire rules are gaugenet's (`protocol/wire/spec.md`, frozen v1). This
//! module does not copy the schema; its codec is checked against the owner's
//! reference vectors, pinned by revision and digest in `contracts/uproar/`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::items::TrackerEvent;
use crate::norm::{NormView, SignedNormEvent};
use crate::StoreResult;

/// The binding profile this export follows.
pub const BINDING: &str = "whipplescript.norm.uproar-binding/1";

/// A deterministic CBOR data item (RFC 8949 §4.2.1): no floats, no tags, no
/// indefinite lengths, and maps ordered by their encoded keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Cbor {
    Unsigned(u64),
    Negative(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Bool(bool),
    Null,
}

fn head(major: u8, argument: u64, out: &mut Vec<u8>) {
    let major = major << 5;
    match argument {
        0..=23 => out.push(major | argument as u8),
        24..=0xff => out.extend([major | 24, argument as u8]),
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend((argument as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(major | 26);
            out.extend((argument as u32).to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend(argument.to_be_bytes());
        }
    }
}

impl Cbor {
    /// The deterministic encoding. Map entries are sorted by the bytewise
    /// order of their encoded keys whatever order they were built in.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Cbor::Unsigned(n) => head(0, *n, out),
            Cbor::Negative(n) => head(1, *n, out),
            Cbor::Bytes(bytes) => {
                head(2, bytes.len() as u64, out);
                out.extend(bytes);
            }
            Cbor::Text(text) => {
                head(3, text.len() as u64, out);
                out.extend(text.as_bytes());
            }
            Cbor::Array(items) => {
                head(4, items.len() as u64, out);
                for item in items {
                    item.encode_into(out);
                }
            }
            Cbor::Map(entries) => {
                let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = entries
                    .iter()
                    .map(|(key, value)| (key.encode(), value.encode()))
                    .collect();
                encoded.sort();
                head(5, encoded.len() as u64, out);
                for (key, value) in encoded {
                    out.extend(key);
                    out.extend(value);
                }
            }
            Cbor::Bool(false) => out.push(0xf4),
            Cbor::Bool(true) => out.push(0xf5),
            Cbor::Null => out.push(0xf6),
        }
    }

    /// Decode one deterministic item, refusing anything the v1 wire forbids:
    /// floats, tags, other simple values, indefinite lengths, non-shortest
    /// arguments, unsorted or duplicate map keys, and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Cbor, String> {
        let mut at = 0;
        let item = decode_at(bytes, &mut at)?;
        if at != bytes.len() {
            return Err("trailing bytes after the CBOR item".into());
        }
        Ok(item)
    }
}

fn decode_at(bytes: &[u8], at: &mut usize) -> Result<Cbor, String> {
    let initial = *bytes.get(*at).ok_or("truncated CBOR item")?;
    *at += 1;
    let major = initial >> 5;
    let info = initial & 0x1f;
    if major == 7 {
        return match initial {
            0xf4 => Ok(Cbor::Bool(false)),
            0xf5 => Ok(Cbor::Bool(true)),
            0xf6 => Ok(Cbor::Null),
            _ => Err(format!(
                "CBOR simple value or float {initial:#x} is not allowed"
            )),
        };
    }
    let argument = match info {
        0..=23 => u64::from(info),
        24..=27 => {
            let width = 1usize << (info - 24);
            let slice = bytes
                .get(*at..*at + width)
                .ok_or("truncated CBOR argument")?;
            *at += width;
            let value = slice
                .iter()
                .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
            let shortest = match width {
                1 => value >= 24,
                2 => value > 0xff,
                4 => value > 0xffff,
                _ => value > 0xffff_ffff,
            };
            if !shortest {
                return Err("CBOR argument is not in its shortest form".into());
            }
            value
        }
        _ => return Err("indefinite or reserved CBOR length".into()),
    };
    let take = |at: &mut usize, length: u64| -> Result<Vec<u8>, String> {
        let length = usize::try_from(length).map_err(|_| "CBOR length overflow")?;
        let slice = bytes
            .get(*at..*at + length)
            .ok_or("truncated CBOR string")?;
        *at += length;
        Ok(slice.to_vec())
    };
    Ok(match major {
        0 => Cbor::Unsigned(argument),
        1 => Cbor::Negative(argument),
        2 => Cbor::Bytes(take(at, argument)?),
        3 => Cbor::Text(
            String::from_utf8(take(at, argument)?).map_err(|_| "CBOR text is not UTF-8")?,
        ),
        4 => Cbor::Array(
            (0..argument)
                .map(|_| decode_at(bytes, at))
                .collect::<Result<_, _>>()?,
        ),
        5 => {
            let mut entries = Vec::new();
            let mut previous: Option<Vec<u8>> = None;
            for _ in 0..argument {
                let start = *at;
                let key = decode_at(bytes, at)?;
                let encoded = bytes[start..*at].to_vec();
                if previous
                    .as_ref()
                    .is_some_and(|previous| *previous >= encoded)
                {
                    return Err("CBOR map keys are unsorted or duplicated".into());
                }
                previous = Some(encoded);
                entries.push((key, decode_at(bytes, at)?));
            }
            Cbor::Map(entries)
        }
        _ => return Err(format!("CBOR tag {argument} is not allowed")),
    })
}

/// A lower-hex string.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A record's reference: SHA-256 of its deterministic encoding.
pub fn reference(record: &Cbor) -> [u8; 32] {
    Sha256::digest(record.encode()).into()
}

/// A self-certifying key id for a raw Ed25519 public key.
pub fn key_id(public_key: &[u8]) -> String {
    format!(
        "urn:gaugenet:key:ed25519:sha256:{}",
        hex(&Sha256::digest(public_key))
    )
}

/// The message an envelope's signature covers.
pub fn signing_message(record: &Cbor, repository: &str) -> Vec<u8> {
    let mut message = b"gaugenet/uproar-signature/1".to_vec();
    message.extend(reference(record));
    message.extend(repository.as_bytes());
    message
}

/// How well an export slot is carried (norm-plane §11.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Grade {
    Attested,
    Declared,
    SelfDeclared,
    Partial,
    Absent,
}

/// One graded slot of the binding profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Slot {
    pub slot: String,
    pub grade: Grade,
    /// What the grade rests on, or the gap that keeps it where it is.
    pub basis: String,
}

/// One exported record, and the ledger event it projects.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExportedRecord {
    pub event: String,
    pub reference: String,
    pub cbor: String,
}

/// What the observer cannot see, with its denominator when one is declared.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Opacity {
    pub exported: usize,
    /// Every act of the workspace, when a population is declared; `None`
    /// is an unknown denominator, reported rather than invented.
    pub population: Option<usize>,
    pub gap: Option<String>,
}

/// The export: its profile, graded slot by slot, and its records.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UproarExport {
    pub binding: String,
    pub repository: String,
    pub slots: Vec<Slot>,
    pub opacity: Opacity,
    pub records: Vec<ExportedRecord>,
}

fn text(value: &str) -> Cbor {
    Cbor::Text(value.to_owned())
}

/// A set slot: sorted by encoding, without duplicates (wire spec §3).
fn set(mut items: Vec<Cbor>) -> Cbor {
    items.sort_by_key(Cbor::encode);
    items.dedup();
    Cbor::Array(items)
}

impl NormView {
    /// Project the ledger's admitted events through the binding profile.
    /// `events` is the verified history this view was replayed from.
    pub fn uproar_export(
        &self,
        events: &[TrackerEvent],
        repository: &str,
    ) -> StoreResult<UproarExport> {
        let by_id: BTreeMap<&str, &TrackerEvent> = events
            .iter()
            .map(|event| (event.event_id.as_str(), event))
            .collect();
        let mut references: BTreeMap<String, [u8; 32]> = BTreeMap::new();
        let mut heads: BTreeMap<String, [u8; 32]> = BTreeMap::new();
        let mut records = Vec::new();
        for id in self.event_order() {
            let Some(event) = by_id.get(id.as_str()) else {
                continue;
            };
            let signed: SignedNormEvent = serde_json::from_str(&event.payload_json)?;
            let actor = &signed.statement.actor;
            let author = format!(
                "urn:whipplescript:principal:{}:{}",
                actor.principal, actor.key_id
            );
            let xrefs = event
                .parents
                .iter()
                .filter_map(|parent| references.get(parent))
                .map(|reference| Cbor::Bytes(reference.to_vec()))
                .collect();
            let writes = event.issue_id.iter().map(|record| text(record)).collect();
            let record = Cbor::Map(vec![
                (text("uproar"), Cbor::Unsigned(1)),
                (text("op"), text(&event.kind)),
                (text("author"), text(&author)),
                (
                    text("prev"),
                    heads
                        .get(&author)
                        .map_or(Cbor::Null, |head| Cbor::Bytes(head.to_vec())),
                ),
                (text("xrefs"), set(xrefs)),
                (text("decl_reads"), Cbor::Array(Vec::new())),
                (text("decl_writes"), set(writes)),
                (
                    text("writes"),
                    Cbor::Map(vec![
                        (text("event"), text(&event.event_id)),
                        (text("statement"), text(&event.payload_json)),
                    ]),
                ),
                (text("forecloses"), Cbor::Array(Vec::new())),
                (text("projections"), set(vec![text(BINDING)])),
                (text("anchor"), text(&self.ledger)),
                (text("attestations"), Cbor::Array(Vec::new())),
            ]);
            let reference = reference(&record);
            references.insert(event.event_id.clone(), reference);
            heads.insert(author, reference);
            records.push(ExportedRecord {
                event: event.event_id.clone(),
                reference: hex(&reference),
                cbor: hex(&record.encode()),
            });
        }
        let slot = |slot: &str, grade: Grade, basis: &str| Slot {
            slot: slot.into(),
            grade,
            basis: basis.into(),
        };
        Ok(UproarExport {
            binding: BINDING.into(),
            repository: repository.into(),
            slots: vec![
                slot(
                    "content reference",
                    Grade::Attested,
                    "each ledger event maps to exactly one record, and `records` carries that map; a source hash is not an export hash",
                ),
                slot(
                    "principal",
                    Grade::SelfDeclared,
                    "records are unsigned: the host holds no Ed25519 key for any principal, so the author is declared and no envelope demonstrates it",
                ),
                slot(
                    "cross-reference",
                    Grade::Declared,
                    "a record's xrefs are its event's causal parents, integrity-checked on read and not authorized by the substrate",
                ),
                slot(
                    "frontier",
                    Grade::Partial,
                    "the ledger's frontier only; the workspace's other stores are not causally joined to it",
                ),
                slot(
                    "reads / writes",
                    Grade::Partial,
                    "decl_writes names the record an act touched; reads are not declared",
                ),
                slot(
                    "intent / attestation",
                    Grade::Declared,
                    "the signed statement rides in writes; its signature is the ledger's, not a UPROAR envelope",
                ),
                slot(
                    "charter",
                    Grade::Attested,
                    "the bootstrap and every activation ride as signed statements with their exact vocabularies",
                ),
                slot("flux", Grade::Absent, "the norm ledger carries no postings"),
                slot(
                    "replay",
                    Grade::Absent,
                    "no derivation is exported with its implementation, inputs and fixtures",
                ),
            ],
            opacity: Opacity {
                exported: records.len(),
                population: None,
                gap: Some(
                    "the workspace declares no population of its acts; the ledger's share of them is unknown"
                        .into(),
                ),
            },
            records,
        })
    }
}

#[cfg(test)]
#[path = "norm_uproar_tests.rs"]
mod tests;
