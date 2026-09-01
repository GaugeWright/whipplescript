//! The half of PKCS#11 r2 that talks to a token, behind the `pkcs11` feature.
//!
//! Kept apart from `pkcs11.rs` for the reason the TPM split exists: the rule
//! for what evidences the rung is checked by the ordinary green bar, and only
//! the module conversation needs a device.

use std::collections::BTreeMap;
use std::sync::Arc;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::object::{Attribute, AttributeType, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

use crate::pkcs11::KeyAttributes;

/// Every module this process has loaded, by path.
///
/// PKCS#11 allows exactly ONE `C_Initialize` per module per process: a second
/// call returns CKR_CRYPTOKI_ALREADY_INITIALIZED, so a custodian that loaded
/// the module afresh for each operation would sign once and fail forever after.
/// Found by doing two operations in a row rather than one — the same way the
/// TPM path's session bug surfaced.
///
/// Caching also matches what the module is: a loaded shared library with
/// process-wide state, not a handle to open per call.
static MODULES: std::sync::OnceLock<std::sync::Mutex<BTreeMap<String, Arc<Pkcs11>>>> =
    std::sync::OnceLock::new();

/// Load a PKCS#11 module and initialise it, or return the one already loaded.
///
/// The module path is the operator's: a token is whatever `.so` their vendor
/// ships, and whip has no business guessing. Naming it is also what makes the
/// live smoke able to report WHICH module answered, which is the difference
/// between evidence and plumbing.
pub fn module(path: &str) -> Result<Arc<Pkcs11>, String> {
    let modules = MODULES.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()));
    let mut loaded = modules
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(context) = loaded.get(path) {
        return Ok(Arc::clone(context));
    }
    let context = Pkcs11::new(path)
        .map_err(|error| format!("cannot load the PKCS#11 module at {path}: {error}"))?;
    context
        // OS locking: the custodian serves connections on threads, so the
        // module must tolerate being called from more than one.
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .map_err(|error| format!("cannot initialise the PKCS#11 module at {path}: {error}"))?;
    let context = Arc::new(context);
    loaded.insert(path.to_owned(), Arc::clone(&context));
    Ok(context)
}

/// The slot whose token has `label`.
///
/// By LABEL rather than by index: slot numbers are assigned by the module in an
/// order nothing promises to keep, so a credential bound to slot 0 would follow
/// whichever token happened to enumerate first after a reboot.
pub fn slot_with_token(context: &Pkcs11, label: &str) -> Result<Slot, String> {
    let slots = context
        .get_slots_with_token()
        .map_err(|error| format!("cannot enumerate PKCS#11 slots: {error}"))?;
    let mut labels = Vec::with_capacity(slots.len());
    for slot in &slots {
        let info = context
            .get_token_info(*slot)
            .map_err(|error| format!("cannot read token info: {error}"))?;
        labels.push(info.label().to_string());
    }
    // The CHOICE is a rule over the labels, in `pkcs11.rs`, so the refusal an
    // operator meets when they mistype one is checked without a token.
    let index = crate::pkcs11::slot_for_label(&labels, label)?;
    Ok(slots[index])
}

/// Open a logged-in session on `slot`.
pub fn session(context: &Pkcs11, slot: Slot, pin: &str) -> Result<Session, String> {
    let session = context
        .open_rw_session(slot)
        .map_err(|error| format!("cannot open a PKCS#11 session: {error}"))?;
    session
        .login(UserType::User, Some(&AuthPin::new(pin.into())))
        .map_err(|error| format!("cannot log in to the token: {error}"))?;
    Ok(session)
}

/// The secret key object labelled `label` on this session's token.
pub fn find_key(session: &Session, label: &str) -> Result<ObjectHandle, String> {
    let found = session
        .find_objects(&[Attribute::Label(label.as_bytes().to_vec())])
        .map_err(|error| format!("cannot search the token: {error}"))?;
    crate::pkcs11::one_key(found.len(), label)?;
    Ok(found[0])
}

/// Read the four attributes the rung turns on.
///
/// A token that will not answer is a refusal rather than a default: assuming
/// `false` would read a silent module as a key that may leave, and assuming
/// `true` would hand it the rung for saying nothing.
pub fn key_attributes(session: &Session, key: ObjectHandle) -> Result<KeyAttributes, String> {
    let wanted = [
        AttributeType::Sensitive,
        AttributeType::Extractable,
        AttributeType::AlwaysSensitive,
        AttributeType::NeverExtractable,
    ];
    let values = session
        .get_attributes(key, &wanted)
        .map_err(|error| format!("cannot read the key's attributes: {error}"))?;

    let mut read = KeyAttributes {
        sensitive: false,
        extractable: false,
        always_sensitive: false,
        never_extractable: false,
    };
    let mut seen = 0usize;
    for value in values {
        match value {
            Attribute::Sensitive(v) => {
                read.sensitive = v;
                seen += 1;
            }
            Attribute::Extractable(v) => {
                read.extractable = v;
                seen += 1;
            }
            Attribute::AlwaysSensitive(v) => {
                read.always_sensitive = v;
                seen += 1;
            }
            Attribute::NeverExtractable(v) => {
                read.never_extractable = v;
                seen += 1;
            }
            _ => {}
        }
    }
    crate::pkcs11::complete_attributes(seen, wanted.len())?;
    Ok(read)
}

/// HMAC `payload` with the token's key, on the token.
///
/// The key handle never yields a value: PKCS#11 signs by handle, so the same
/// property the TPM path gets from `fixed_tpm` this one gets from the token
/// refusing to export. What differs is who says so — the TPM makes the key
/// itself, while a token's attributes are its own word, which is why
/// `evidences_r2` insists on the never/always pair rather than today's flags.
pub fn hmac_sha256(
    session: &Session,
    key: ObjectHandle,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    use cryptoki::mechanism::Mechanism;
    session
        .sign(&Mechanism::Sha256Hmac, key, payload)
        .map_err(|error| format!("the token refused to sign: {error}"))
}

/// Open a token, find the key, and check it evidences r2 before using it.
///
/// One entry point so the attribute check cannot be skipped by a caller that
/// only wanted a signature: the rung is a property of the key, and reading it
/// after signing would be asking the question too late.
pub fn admitted_key(
    session: &Session,
    label: &str,
) -> Result<(ObjectHandle, KeyAttributes), String> {
    let key = find_key(session, label)?;
    let attributes = key_attributes(session, key)?;
    crate::pkcs11::evidences_r2(attributes)?;
    Ok((key, attributes))
}
