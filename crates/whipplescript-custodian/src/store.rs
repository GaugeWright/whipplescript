//! The r0 `process` sealed store (DR-0053 §4).
//!
//! Material rests under a passphrase-derived key: PBKDF2-HMAC-SHA256 derives
//! the master key, each entry is sealed with ChaCha20-Poly1305 under a fresh
//! nonce, and the AEAD associated data binds the ciphertext to the entry's
//! name and kind so entries are not swappable inside the store file.
//!
//! r0's honest boundary, stated where the code lives: whip's *language*
//! cannot read this store, and a same-uid escape that reads the passphrase
//! can. r0 exists so a developer with no TPM gets a working custodian —
//! degraded and tagged, not a setup wall. The principal separation that makes
//! custody real starts at r1+; the seam is [`crate::Custodian`] speaking the
//! protocol either way.

use std::collections::BTreeMap;
use std::io::Write;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use whipplescript_custody::{CredentialKind, CredentialName};

const STORE_VERSION: u32 = 1;
const PBKDF2_ITERATIONS: u32 = 600_000;
const MASTER_KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;

#[derive(Debug)]
pub enum StoreError {
    Io(std::io::Error),
    Format(String),
    /// Wrong passphrase or corrupted/foreign ciphertext. AEAD cannot say
    /// which, and neither do we.
    Unsealable,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(e) => write!(f, "store io error: {e}"),
            StoreError::Format(d) => write!(f, "store format error: {d}"),
            StoreError::Unsealable => f.write_str("store entry cannot be unsealed"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e)
    }
}

#[derive(Serialize, Deserialize)]
struct StoreFile {
    version: u32,
    kdf: KdfParams,
    entries: BTreeMap<String, SealedEntry>,
}

#[derive(Serialize, Deserialize)]
struct KdfParams {
    algo: String,
    iterations: u32,
    salt_b64: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct SealedEntry {
    kind: CredentialKind,
    nonce_b64: String,
    sealed_b64: String,
    #[serde(default)]
    revoked: bool,
    /// Optional per-credential use budget (DR-0053 §9), enforced per
    /// custodian process lifetime at r0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    budget: Option<u64>,
}

/// One unsealed entry held in custodian memory. Material zeroizes on drop.
pub struct Entry {
    pub kind: CredentialKind,
    pub material: Zeroizing<Vec<u8>>,
    pub revoked: bool,
    pub budget: Option<u64>,
}

/// The passphrase-sealed store, fully unsealed into custodian memory at open.
/// The custodian is the principal that is *allowed* to hold material; whip is
/// the one that never does.
pub struct SealedStore {
    path: Option<PathBuf>,
    master_key: Zeroizing<[u8; MASTER_KEY_LEN]>,
    kdf: KdfParams,
    rng: SystemRandom,
    entries: BTreeMap<CredentialName, Entry>,
}

fn derive_master_key(
    passphrase: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, StoreError> {
    let iterations = NonZeroU32::new(iterations)
        .ok_or_else(|| StoreError::Format("kdf iterations must be non-zero".into()))?;
    let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        passphrase.as_bytes(),
        key.as_mut(),
    );
    Ok(key)
}

fn entry_aad(name: &CredentialName, kind: CredentialKind) -> Vec<u8> {
    format!("{}:{}", name.resource_id(), kind).into_bytes()
}

fn aead_key(master: &[u8; MASTER_KEY_LEN]) -> Result<LessSafeKey, StoreError> {
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, master)
        .map_err(|_| StoreError::Format("bad master key length".into()))?;
    Ok(LessSafeKey::new(unbound))
}

impl SealedStore {
    /// Create a fresh store (in memory until first [`Self::persist`]).
    pub fn create(path: Option<PathBuf>, passphrase: &str) -> Result<Self, StoreError> {
        let rng = SystemRandom::new();
        let mut salt = [0u8; SALT_LEN];
        rng.fill(&mut salt)
            .map_err(|_| StoreError::Format("rng failure".into()))?;
        let kdf = KdfParams {
            algo: "pbkdf2-hmac-sha256".into(),
            iterations: PBKDF2_ITERATIONS,
            salt_b64: B64.encode(salt),
        };
        let master_key = derive_master_key(passphrase, &salt, kdf.iterations)?;
        Ok(Self {
            path,
            master_key,
            kdf,
            rng,
            entries: BTreeMap::new(),
        })
    }

    /// Open an existing store file and unseal every entry.
    pub fn open(path: &Path, passphrase: &str) -> Result<Self, StoreError> {
        let raw = std::fs::read_to_string(path)?;
        let file: StoreFile =
            serde_json::from_str(&raw).map_err(|e| StoreError::Format(e.to_string()))?;
        if file.version != STORE_VERSION {
            return Err(StoreError::Format(format!(
                "unsupported store version {}",
                file.version
            )));
        }
        if file.kdf.algo != "pbkdf2-hmac-sha256" {
            return Err(StoreError::Format(format!(
                "unsupported kdf {:?}",
                file.kdf.algo
            )));
        }
        let salt = B64
            .decode(&file.kdf.salt_b64)
            .map_err(|e| StoreError::Format(format!("bad salt: {e}")))?;
        let master_key = derive_master_key(passphrase, &salt, file.kdf.iterations)?;
        let key = aead_key(&master_key)?;

        let mut entries = BTreeMap::new();
        for (name, sealed) in &file.entries {
            let name = CredentialName::new(name).map_err(StoreError::Format)?;
            let nonce_bytes: [u8; NONCE_LEN] = B64
                .decode(&sealed.nonce_b64)
                .map_err(|e| StoreError::Format(format!("bad nonce: {e}")))?
                .try_into()
                .map_err(|_| StoreError::Format("bad nonce length".into()))?;
            let mut buf = B64
                .decode(&sealed.sealed_b64)
                .map_err(|e| StoreError::Format(format!("bad ciphertext: {e}")))?;
            let aad = entry_aad(&name, sealed.kind);
            let plain_len = key
                .open_in_place(
                    Nonce::assume_unique_for_key(nonce_bytes),
                    Aad::from(aad),
                    &mut buf,
                )
                .map_err(|_| StoreError::Unsealable)?
                .len();
            buf.truncate(plain_len);
            entries.insert(
                name,
                Entry {
                    kind: sealed.kind,
                    material: Zeroizing::new(buf),
                    revoked: sealed.revoked,
                    budget: sealed.budget,
                },
            );
        }
        Ok(Self {
            path: Some(path.to_path_buf()),
            master_key,
            kdf: file.kdf,
            rng: SystemRandom::new(),
            entries,
        })
    }

    pub fn entries(&self) -> &BTreeMap<CredentialName, Entry> {
        &self.entries
    }

    pub fn get(&self, name: &CredentialName) -> Option<&Entry> {
        self.entries.get(name)
    }

    /// Register (or replace) material. Admin surface: reachable only by the
    /// principal that holds the store passphrase, never over the custody
    /// protocol.
    pub fn register(
        &mut self,
        name: CredentialName,
        kind: CredentialKind,
        material: Zeroizing<Vec<u8>>,
        budget: Option<u64>,
    ) -> Result<(), StoreError> {
        self.entries.insert(
            name,
            Entry {
                kind,
                material,
                revoked: false,
                budget,
            },
        );
        self.persist()
    }

    pub fn revoke(&mut self, name: &CredentialName) -> Result<bool, StoreError> {
        match self.entries.get_mut(name) {
            Some(e) => {
                e.revoked = true;
                self.persist()?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Reseal every entry and write the store file atomically (tmp + rename).
    pub fn persist(&self) -> Result<(), StoreError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let key = aead_key(&self.master_key)?;
        let mut sealed_entries = BTreeMap::new();
        for (name, entry) in &self.entries {
            let mut nonce_bytes = [0u8; NONCE_LEN];
            self.rng
                .fill(&mut nonce_bytes)
                .map_err(|_| StoreError::Format("rng failure".into()))?;
            let mut buf = entry.material.to_vec();
            key.seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(entry_aad(name, entry.kind)),
                &mut buf,
            )
            .map_err(|_| StoreError::Format("seal failure".into()))?;
            sealed_entries.insert(
                name.as_str().to_string(),
                SealedEntry {
                    kind: entry.kind,
                    nonce_b64: B64.encode(nonce_bytes),
                    sealed_b64: B64.encode(&buf),
                    revoked: entry.revoked,
                    budget: entry.budget,
                },
            );
        }
        let file = StoreFile {
            version: STORE_VERSION,
            kdf: KdfParams {
                algo: self.kdf.algo.clone(),
                iterations: self.kdf.iterations,
                salt_b64: self.kdf.salt_b64.clone(),
            },
            entries: sealed_entries,
        };
        let body =
            serde_json::to_string_pretty(&file).map_err(|e| StoreError::Format(e.to_string()))?;
        let tmp = path.with_extension("tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(body.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> CredentialName {
        CredentialName::new(s).expect("valid name")
    }

    #[test]
    fn store_roundtrips_under_the_passphrase() {
        let dir = std::env::temp_dir().join(format!("whip-custody-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("store.json");

        let mut store = SealedStore::create(Some(path.clone()), "hunter2").expect("create");
        store
            .register(
                name("stripe_api"),
                CredentialKind::Bearer,
                Zeroizing::new(b"sk_live_123".to_vec()),
                Some(10),
            )
            .expect("register");

        let reopened = SealedStore::open(&path, "hunter2").expect("open");
        let entry = reopened.get(&name("stripe_api")).expect("entry");
        assert_eq!(entry.kind, CredentialKind::Bearer);
        assert_eq!(entry.material.as_slice(), b"sk_live_123");
        assert_eq!(entry.budget, Some(10));

        // The stored file never contains material in the clear.
        let raw = std::fs::read_to_string(&path).expect("read");
        assert!(!raw.contains("sk_live_123"));
        let b64_material = B64.encode(b"sk_live_123");
        assert!(!raw.contains(&b64_material));

        // A wrong passphrase does not open it.
        assert!(matches!(
            SealedStore::open(&path, "wrong"),
            Err(StoreError::Unsealable)
        ));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn revocation_persists() {
        let dir = std::env::temp_dir().join(format!("whip-custody-revoke-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("store.json");

        let mut store = SealedStore::create(Some(path.clone()), "pw").expect("create");
        store
            .register(
                name("gone"),
                CredentialKind::Raw,
                Zeroizing::new(b"x".to_vec()),
                None,
            )
            .expect("register");
        assert!(store.revoke(&name("gone")).expect("revoke"));
        assert!(!store.revoke(&name("never-there")).expect("revoke missing"));

        let reopened = SealedStore::open(&path, "pw").expect("open");
        assert!(reopened.get(&name("gone")).expect("entry").revoked);

        std::fs::remove_dir_all(&dir).ok();
    }
}
