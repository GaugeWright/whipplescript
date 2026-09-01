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
    /// Sealed local material. Absent for remote entries — there is no secret
    /// on this box to seal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sealed_b64: Option<String>,
    /// r3 remote reference: `{"remote": {"openbao_transit": "<key_name>"}}`.
    /// Plaintext metadata by design — a key *name* in a transit engine is not
    /// a secret, and sealing it would only pretend otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    remote: Option<RemoteRef>,
    /// r2 PKCS#11: where the key is, and what it was admitted on. Plaintext
    /// metadata for the reason the others are: a module path, a token label and
    /// a set of boolean attributes are not secrets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pkcs11: Option<SealedPkcs11>,
    /// r2 TPM binding: `{"tpm": {"slots": [0, 7], "digest_hex": "..."}}`.
    /// Plaintext metadata by design, for the same reason the remote key name
    /// is: a PCR digest is a measurement of the platform, not a secret, and
    /// sealing it would only pretend otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tpm: Option<crate::tpm::PcrBinding>,
    #[serde(default)]
    revoked: bool,
    /// Optional per-credential use budget (DR-0053 §9), enforced per
    /// custodian process lifetime at r0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    budget: Option<u64>,
    /// Optional lease expiry, epoch seconds (DR-0053 §9's fifth lease
    /// mechanism). A use at or after this instant is refused.
    ///
    /// Durable, unlike the budget beside it. The budget's counts live in
    /// process memory, so a custodian restart resets them — which is fine for
    /// a rate bound and useless for a revocation one. An expiry stored in the
    /// sealed entry survives the restart, so "this credential stops working at
    /// four o'clock" means it, and that difference is why the two coexist
    /// rather than one replacing the other.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lease_expires_at: Option<u64>,
}

/// Where a remote entry's material lives. One variant per remote backend.
#[derive(Serialize, Deserialize, Clone)]
struct RemoteRef {
    /// The key name in an OpenBao transit engine.
    openbao_transit: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct SealedPkcs11 {
    #[serde(flatten)]
    reference: Pkcs11Ref,
    admitted: crate::pkcs11::KeyAttributes,
}

/// Where an entry's material is (DR-0053 §4): held locally under seal, or
/// resident in a remote backend that performs the operations itself.
#[derive(Clone)]
pub enum Material {
    Local(Zeroizing<Vec<u8>>),
    /// r3: the key lives in an OpenBao transit engine; material never exists
    /// on this box.
    OpenBaoTransit {
        key_name: String,
    },
    /// r2: the key is derived inside a TPM 2.0 and signs there, bound to a
    /// platform state. Like the remote variant, this holds no material — only
    /// the binding the rung's freshness half is judged against.
    TpmHmac {
        binding: crate::tpm::PcrBinding,
    },
    /// r2 over PKCS#11: the key is resident on a token and signs there.
    ///
    /// Carries the attributes the key was ADMITTED on, not just where to find
    /// it. The TPM variant can report r2 from what it is — a key the chip made
    /// cannot leave whatever the PCRs say — but a PKCS#11 key is r2 only if the
    /// token says it never left, so the evidence has to travel with the entry
    /// and be re-checked at every use.
    Pkcs11 {
        reference: crate::store::Pkcs11Ref,
        admitted: crate::pkcs11::KeyAttributes,
    },
}

/// Where a PKCS#11 key lives: which module, which token, which object.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Pkcs11Ref {
    /// The vendor module, an operator path. whip does not guess it.
    pub module: String,
    /// The token's LABEL rather than its slot number, which the module assigns
    /// in an order nothing promises to keep across reboots.
    pub token: String,
    /// The key object's label on that token.
    pub key: String,
}

/// One unsealed entry held in custodian memory. Local material zeroizes on
/// drop; remote entries hold only a key name.
pub struct Entry {
    pub kind: CredentialKind,
    pub material: Material,
    pub revoked: bool,
    pub budget: Option<u64>,
    /// Epoch seconds after which this credential refuses use. See the sealed
    /// entry's field for why it is durable where the budget is not.
    pub lease_expires_at: Option<u64>,
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
            // An r2 entry is recognised BEFORE the local/remote split: it has
            // neither ciphertext nor a remote name, so leaving it to the
            // catch-all below would read a perfectly good hardware credential
            // as a malformed one.
            if let Some(token) = &sealed.pkcs11 {
                entries.insert(
                    name,
                    Entry {
                        kind: sealed.kind,
                        material: Material::Pkcs11 {
                            reference: token.reference.clone(),
                            admitted: token.admitted,
                        },
                        revoked: sealed.revoked,
                        budget: sealed.budget,
                        lease_expires_at: sealed.lease_expires_at,
                    },
                );
                continue;
            }
            if let Some(binding) = &sealed.tpm {
                entries.insert(
                    name,
                    Entry {
                        kind: sealed.kind,
                        material: Material::TpmHmac {
                            binding: binding.clone(),
                        },
                        revoked: sealed.revoked,
                        budget: sealed.budget,
                        lease_expires_at: sealed.lease_expires_at,
                    },
                );
                continue;
            }
            let material = match (&sealed.remote, &sealed.nonce_b64, &sealed.sealed_b64) {
                (Some(remote), None, None) => Material::OpenBaoTransit {
                    key_name: remote.openbao_transit.clone(),
                },
                (None, Some(nonce_b64), Some(sealed_b64)) => {
                    let nonce_bytes: [u8; NONCE_LEN] = B64
                        .decode(nonce_b64)
                        .map_err(|e| StoreError::Format(format!("bad nonce: {e}")))?
                        .try_into()
                        .map_err(|_| StoreError::Format("bad nonce length".into()))?;
                    let mut buf = B64
                        .decode(sealed_b64)
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
                    Material::Local(Zeroizing::new(buf))
                }
                _ => {
                    return Err(StoreError::Format(format!(
                        "entry {} must carry sealed material, a remote reference, a TPM binding, or a PKCS#11 key",
                        name.resource_id()
                    )))
                }
            };
            entries.insert(
                name,
                Entry {
                    kind: sealed.kind,
                    material,
                    revoked: sealed.revoked,
                    budget: sealed.budget,
                    lease_expires_at: sealed.lease_expires_at,
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
        lease_expires_at: Option<u64>,
    ) -> Result<(), StoreError> {
        self.entries.insert(
            name,
            Entry {
                kind,
                material: Material::Local(material),
                revoked: false,
                budget,
                lease_expires_at,
            },
        );
        self.persist()
    }

    /// Register (or replace) an r3 remote entry: the material lives in an
    /// OpenBao transit engine under `key_name` and never exists on this box.
    /// Same admin surface as [`Self::register`].
    pub fn register_remote(
        &mut self,
        name: CredentialName,
        kind: CredentialKind,
        key_name: String,
        budget: Option<u64>,
        lease_expires_at: Option<u64>,
    ) -> Result<(), StoreError> {
        self.entries.insert(
            name,
            Entry {
                kind,
                material: Material::OpenBaoTransit { key_name },
                revoked: false,
                budget,
                lease_expires_at,
            },
        );
        self.persist()
    }

    /// Register an r2 credential: no material crosses, because there is none to
    /// cross. The TPM derives the key from a seed it will not disclose, and
    /// this records only which platform state the credential is bound to.
    pub fn register_tpm(
        &mut self,
        name: CredentialName,
        kind: CredentialKind,
        binding: crate::tpm::PcrBinding,
        budget: Option<u64>,
        lease_expires_at: Option<u64>,
    ) -> Result<(), StoreError> {
        self.entries.insert(
            name,
            Entry {
                kind,
                material: Material::TpmHmac { binding },
                revoked: false,
                budget,
                lease_expires_at,
            },
        );
        self.persist()
    }

    /// Register an r2 PKCS#11 credential. No material crosses: the key stays
    /// on the token, and this records where it is plus the attributes it was
    /// admitted on.
    pub fn register_pkcs11(
        &mut self,
        name: CredentialName,
        kind: CredentialKind,
        reference: Pkcs11Ref,
        admitted: crate::pkcs11::KeyAttributes,
        budget: Option<u64>,
        lease_expires_at: Option<u64>,
    ) -> Result<(), StoreError> {
        self.entries.insert(
            name,
            Entry {
                kind,
                material: Material::Pkcs11 {
                    reference,
                    admitted,
                },
                revoked: false,
                budget,
                lease_expires_at,
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
            let sealed = match &entry.material {
                Material::Local(material) => {
                    let mut nonce_bytes = [0u8; NONCE_LEN];
                    self.rng
                        .fill(&mut nonce_bytes)
                        .map_err(|_| StoreError::Format("rng failure".into()))?;
                    let mut buf = material.to_vec();
                    key.seal_in_place_append_tag(
                        Nonce::assume_unique_for_key(nonce_bytes),
                        Aad::from(entry_aad(name, entry.kind)),
                        &mut buf,
                    )
                    .map_err(|_| StoreError::Format("seal failure".into()))?;
                    SealedEntry {
                        kind: entry.kind,
                        nonce_b64: Some(B64.encode(nonce_bytes)),
                        sealed_b64: Some(B64.encode(&buf)),
                        remote: None,
                        pkcs11: None,
                        tpm: None,
                        revoked: entry.revoked,
                        budget: entry.budget,
                        lease_expires_at: entry.lease_expires_at,
                    }
                }
                // Remote entries persist as plaintext metadata: no nonce, no
                // ciphertext — there is no secret to seal.
                Material::OpenBaoTransit { key_name } => SealedEntry {
                    kind: entry.kind,
                    nonce_b64: None,
                    sealed_b64: None,
                    remote: Some(RemoteRef {
                        openbao_transit: key_name.clone(),
                    }),
                    pkcs11: None,
                    tpm: None,
                    revoked: entry.revoked,
                    budget: entry.budget,
                    lease_expires_at: entry.lease_expires_at,
                },
                // Same shape as remote, and for the same reason: an r2 entry
                // has no secret on this box to seal, only the platform state it
                // is bound to.
                Material::TpmHmac { binding } => SealedEntry {
                    kind: entry.kind,
                    nonce_b64: None,
                    sealed_b64: None,
                    remote: None,
                    pkcs11: None,
                    tpm: Some(binding.clone()),
                    revoked: entry.revoked,
                    budget: entry.budget,
                    lease_expires_at: entry.lease_expires_at,
                },
                // Same shape again: no secret on this box, only where the key
                // is and what admitted it.
                Material::Pkcs11 {
                    reference,
                    admitted,
                } => SealedEntry {
                    kind: entry.kind,
                    nonce_b64: None,
                    sealed_b64: None,
                    remote: None,
                    pkcs11: Some(SealedPkcs11 {
                        reference: reference.clone(),
                        admitted: *admitted,
                    }),
                    tpm: None,
                    revoked: entry.revoked,
                    budget: entry.budget,
                    lease_expires_at: entry.lease_expires_at,
                },
            };
            sealed_entries.insert(name.as_str().to_string(), sealed);
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
                None,
            )
            .expect("register");

        let reopened = SealedStore::open(&path, "hunter2").expect("open");
        let entry = reopened.get(&name("stripe_api")).expect("entry");
        assert_eq!(entry.kind, CredentialKind::Bearer);
        let Material::Local(material) = &entry.material else {
            panic!("expected local material");
        };
        assert_eq!(material.as_slice(), b"sk_live_123");
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
    fn remote_entries_roundtrip_as_plaintext_metadata() {
        let dir = std::env::temp_dir().join(format!(
            "whip-custody-remote-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("store.json");

        let mut store = SealedStore::create(Some(path.clone()), "pw").expect("create");
        store
            .register_remote(
                name("release_signing"),
                CredentialKind::Ed25519,
                "whip-release".into(),
                Some(4),
                None,
            )
            .expect("register remote");

        // The reference is plaintext metadata in the exact recorded shape —
        // no nonce, no ciphertext.
        let raw = std::fs::read_to_string(&path).expect("read");
        let file: serde_json::Value = serde_json::from_str(&raw).expect("json");
        let entry = &file["entries"]["release_signing"];
        assert_eq!(entry["remote"]["openbao_transit"], "whip-release");
        assert!(entry.get("nonce_b64").is_none(), "{entry}");
        assert!(entry.get("sealed_b64").is_none(), "{entry}");

        let reopened = SealedStore::open(&path, "pw").expect("open");
        let entry = reopened.get(&name("release_signing")).expect("entry");
        assert_eq!(entry.kind, CredentialKind::Ed25519);
        assert_eq!(entry.budget, Some(4));
        let Material::OpenBaoTransit { key_name } = &entry.material else {
            panic!("expected a remote reference");
        };
        assert_eq!(key_name, "whip-release");

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
