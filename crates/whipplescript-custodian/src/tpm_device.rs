//! The half of r2 that touches `/dev/tpmrm0`, behind the `tpm` feature.
//!
//! Kept apart from `tpm.rs` on purpose: the RULE lives there and is checked by
//! the ordinary green bar, and only the device conversation lives here. What
//! remains is genuinely untestable without hardware, so it is small, and
//! `scripts/check-tpm-live-smoke.sh` runs it against a real TPM.

use std::str::FromStr;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::{PcrSelectionListBuilder, PcrSlot};

use tss_esapi::{Context, TctiNameConf};

use crate::tpm::{bind, PcrBinding};

/// Open a context against the platform TPM.
///
/// The TCTI comes from the environment when set — the tss2 convention, and what
/// lets a test point at a simulator — and falls back to the kernel resource
/// manager. `/dev/tpmrm0` rather than `/dev/tpm0`: the resource manager
/// multiplexes, so whip does not have to be the only user of the chip.
pub fn context() -> Result<Context, String> {
    let tcti = TctiNameConf::from_environment_variable()
        .or_else(|_| TctiNameConf::from_str("device:/dev/tpmrm0"))
        .map_err(|error| format!("no usable TPM TCTI: {error}"))?;
    Context::new(tcti).map_err(|error| {
        format!(
            "cannot open the TPM: {error} — the device is /dev/tpmrm0 and is \
             owned by the `tss` group, so a process outside it cannot reach the chip"
        )
    })
}

/// Every slot `tpm::supported_slot` admits, in order.
///
/// A table rather than a match with a fall-through arm. The arm would be a
/// refusal nothing can produce — the range check above admits exactly these
/// indices — and the codebase's own rule is that an error nothing can produce
/// is a refusal nothing gates. Indexing a total table has no such arm, and the
/// test below pins the table to the ceiling so raising one without extending
/// the other fails rather than panicking here.
const SLOTS: [PcrSlot; 10] = [
    PcrSlot::Slot0,
    PcrSlot::Slot1,
    PcrSlot::Slot2,
    PcrSlot::Slot3,
    PcrSlot::Slot4,
    PcrSlot::Slot5,
    PcrSlot::Slot6,
    PcrSlot::Slot7,
    PcrSlot::Slot8,
    PcrSlot::Slot9,
];

fn slot_of(number: u32) -> Result<PcrSlot, String> {
    // The RANGE rule lives in `tpm.rs`, which compiles without this feature, so
    // the refusal an operator meets is checked by the ordinary green bar. What
    // is left here is the mapping, and it is total over what that rule admits.
    crate::tpm::supported_slot(number)?;
    Ok(SLOTS[number as usize])
}

/// Read the named PCRs and digest them into a binding.
pub fn read_binding(context: &mut Context, slots: &[u32]) -> Result<PcrBinding, String> {
    let mut selection = PcrSelectionListBuilder::new();
    let resolved: Result<Vec<PcrSlot>, String> = slots.iter().copied().map(slot_of).collect();
    let resolved = resolved?;
    selection = selection.with_selection(HashingAlgorithm::Sha256, &resolved);
    let selection = selection
        .build()
        .map_err(|error| format!("bad PCR selection: {error}"))?;
    let (_count, _selection, digests) = context
        .pcr_read(selection)
        .map_err(|error| format!("PCR read failed: {error}"))?;
    let values: Vec<Vec<u8>> = digests.value().iter().map(|d| d.value().to_vec()).collect();
    // A TPM that answers with fewer digests than the selection asked for is
    // refused by `bind`, which already requires one value per slot — the rule
    // is its, and restating it here was a second copy that only the chip could
    // reach. Binding to a short reading would record a claim about slots nobody
    // read, and it is `bind` that says so.
    bind(slots, &values)
}

/// HMAC `payload` under the key belonging to `credential`, inside the chip.
///
/// **The key is never on this box.** It is a PRIMARY key of the owner
/// hierarchy, so the TPM derives it from a seed that cannot be read out, and
/// `sensitive_data_origin` means the TPM generated the secret itself — it did
/// not exist outside the chip at any point, which is a stronger claim than
/// "material was put in and cannot come out". The custodian holds a template,
/// the way it holds a key NAME for r3; whip holds neither.
///
/// Determinism is what removes the key blob. The same hierarchy seed and the
/// same template yield the same key every time, so nothing has to be stored and
/// there is no wrapped secret at rest to steal. The credential's name goes into
/// the template's unique field, so two credentials are two keys rather than one
/// key used twice.
///
/// The caveat that comes with that, and it is the sibling of the PCR one:
/// clearing the owner hierarchy changes the seed and every key derived from it.
/// That is a platform reset, it is deliberate, and it is documented here rather
/// than designed away.
pub fn hmac_sha256(
    context: &mut Context,
    credential: &str,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    use tss_esapi::attributes::ObjectAttributesBuilder;
    use tss_esapi::constants::SessionType;
    use tss_esapi::interface_types::algorithm::PublicAlgorithm;
    use tss_esapi::interface_types::resource_handles::Hierarchy;
    use tss_esapi::structures::{
        Digest, KeyedHashScheme, MaxBuffer, PublicBuilder, PublicKeyedHashParameters,
        SymmetricDefinition,
    };

    // Scoped with `execute_with_session` rather than `set_sessions`: a session
    // left set on the context makes the NEXT call fail with "inconsistent
    // attributes", so a custodian that signed twice would fail on the second
    // signature. Found by signing twice in a test rather than once.
    let session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(|error| format!("TPM session failed: {error}"))?
        .ok_or("the TPM returned no session")?;

    let attributes = ObjectAttributesBuilder::new()
        .with_sign_encrypt(true)
        // The TPM makes the secret. Nothing is imported, so there is no moment
        // at which the material existed outside the chip.
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        // Neither the key nor its parent may be duplicated off this TPM. This
        // is the attribute that makes "non-extractability is literally true"
        // literally true.
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .build()
        .map_err(|error| format!("bad object attributes: {error}"))?;

    // The credential's identity, so two credentials are two keys. A shared key
    // would make a `sign` grant on one a `sign` grant on every other.
    let unique = ring::digest::digest(&ring::digest::SHA256, credential.as_bytes());
    let unique = Digest::try_from(unique.as_ref().to_vec())
        .map_err(|error| format!("bad unique identifier: {error}"))?;

    let template = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
            KeyedHashScheme::HMAC_SHA_256,
        ))
        .with_keyed_hash_unique_identifier(unique)
        .build()
        .map_err(|error| format!("bad key template: {error}"))?;

    let buffer = MaxBuffer::try_from(payload.to_vec())
        .map_err(|_| "payload is larger than the TPM will accept in one call".to_owned())?;

    let signed = context.execute_with_session(Some(session), |context| {
        let key = context
            .create_primary(Hierarchy::Owner, template, None, None, None, None)
            .map_err(|error| format!("TPM key derivation failed: {error}"))?;
        let signature = context
            .hmac(key.key_handle.into(), buffer, HashingAlgorithm::Sha256)
            .map_err(|error| format!("TPM HMAC failed: {error}"));
        // Flushed whether the HMAC succeeded or not: the handle exists either
        // way, and a custodian that signs for a living would otherwise fill the
        // chip's object slots and start failing for an unrelated-looking reason.
        let _ = context.flush_context(key.key_handle.into());
        signature.map(|signature| signature.value().to_vec())
    })?;

    // The session is a TPM resource too, and the same argument applies.
    let _ = context.flush_context(tss_esapi::handles::SessionHandle::from(session).into());
    Ok(signed)
}

#[cfg(test)]
mod live_tests {
    use super::*;

    /// Skips with a recorded reason when there is no reachable TPM, following
    /// the env-gated live-smoke pattern DR-0053 §8 sets for r3.
    fn context_or_skip() -> Option<Context> {
        match context() {
            Ok(context) => Some(context),
            Err(reason) => {
                eprintln!("SKIP: no reachable TPM ({reason})");
                None
            }
        }
    }

    #[test]
    fn a_real_tpm_reads_the_same_platform_state_twice() {
        // FRESHNESS against the actual chip: nothing moved between two reads a
        // moment apart, so the binding holds. This is the property in its
        // working direction; `tpm.rs` covers the failing one, which cannot be
        // provoked without rebooting the machine.
        let Some(mut context) = context_or_skip() else {
            return;
        };
        let first = read_binding(&mut context, &[0, 7]).expect("PCRs read");
        let second = read_binding(&mut context, &[0, 7]).expect("PCRs read again");
        assert_eq!(
            first.still_fresh(&second),
            Ok(()),
            "a platform that did not move must stay fresh"
        );
        assert_eq!(first.slots, vec![0, 7]);
        assert_eq!(first.digest_hex.len(), 64, "sha256 hex");
    }

    #[test]
    fn a_different_selection_reads_a_different_platform_claim() {
        let Some(mut context) = context_or_skip() else {
            return;
        };
        let boot = read_binding(&mut context, &[0]).expect("PCR 0");
        let wider = read_binding(&mut context, &[0, 7]).expect("PCRs 0 and 7");
        // Not comparable, and refused as such rather than silently equal.
        assert!(boot.still_fresh(&wider).is_err());
    }

    #[test]
    fn a_key_that_never_left_the_chip_signs_deterministically() {
        let Some(mut context) = context_or_skip() else {
            return;
        };
        let once = hmac_sha256(&mut context, "release_signing", b"payload").expect("signed");
        let again = hmac_sha256(&mut context, "release_signing", b"payload").expect("signed again");
        assert_eq!(once.len(), 32, "HMAC-SHA-256");
        // Determinism is what lets the key have no blob at rest: the same seed
        // and template rederive the same key, so nothing needs storing.
        assert_eq!(
            once, again,
            "the same credential must rederive the same key"
        );
    }

    #[test]
    fn two_credentials_are_two_keys() {
        // A shared key would make a `sign` grant on one credential a `sign`
        // grant on every other, which is the confused deputy the per-credential
        // unique identifier exists to prevent.
        let Some(mut context) = context_or_skip() else {
            return;
        };
        let release = hmac_sha256(&mut context, "release_signing", b"payload").expect("signed");
        let webhook = hmac_sha256(&mut context, "webhook_hmac", b"payload").expect("signed");
        assert_ne!(release, webhook);
    }

    #[test]
    fn a_different_payload_signs_differently_under_the_same_key() {
        // The control for the determinism test above: equal outputs there must
        // mean "same key", not "this function ignores its input".
        let Some(mut context) = context_or_skip() else {
            return;
        };
        let first = hmac_sha256(&mut context, "release_signing", b"payload").expect("signed");
        let second = hmac_sha256(&mut context, "release_signing", b"other").expect("signed");
        assert_ne!(first, second);
    }

    #[test]
    fn the_slot_table_covers_exactly_the_supported_range() {
        // `slot_of` indexes `SLOTS` directly, so a ceiling raised without
        // extending the table would panic on a value the rule admits. This
        // fails first, and says which side to change.
        assert_eq!(
            SLOTS.len(),
            crate::tpm::MAX_PCR_SLOT as usize + 1,
            "SLOTS must cover every slot tpm::supported_slot admits"
        );
        assert!(slot_of(crate::tpm::MAX_PCR_SLOT).is_ok());
    }

    #[test]
    fn a_slot_outside_the_supported_range_is_refused() {
        // Needs no device: the refusal is about the request. The RULE and its
        // wording are pinned in `tpm.rs`, which compiles without this feature;
        // what this adds is that the mapping actually consults it.
        assert_eq!(
            slot_of(24).expect_err("out of range"),
            "PCR slot 24 is outside the supported range 0..=9"
        );
        assert!(slot_of(7).is_ok());
    }
}
