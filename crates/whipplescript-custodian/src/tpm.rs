//! r2 `hardware`: a credential whose key lives in a TPM 2.0 and is bound to a
//! platform state (DR-0053 §4).
//!
//! **The decision layer is in this file and always compiles.** Only the Esys
//! calls that touch `/dev/tpmrm0` sit behind the `tpm` feature, so the rule the
//! rung turns on — freshness — is type-checked and tested by the ordinary green
//! bar on a machine with no TPM at all. A property nobody can run is a property
//! nobody checks.
//!
//! `models/maude/credential-rung-evidence.maude` states what r2 requires, and
//! the two halves are independent:
//!
//! - **FRESHNESS.** A binding is taken against a PCR state. Move the PCRs — a
//!   firmware or kernel update — and it stops counting. The model derives r2
//!   only when the bound digest equals the current one, and blessing a stale
//!   binding would bless exactly the case that breaks in production.
//! - **NON-EXTRACTABILITY.** r2 means the key cannot leave, not that hardware
//!   is present. The key is created in the TPM and signs there; the custodian
//!   holds a handle, never material — which is the same relationship whip has
//!   to the custodian one level up.

use serde::{Deserialize, Serialize};

/// The platform state a TPM-held credential is bound to.
///
/// The digest is over the selected PCRs as the TPM reports them. Which slots
/// were selected travels WITH it: the same digest against a different selection
/// is a different claim, and comparing digests alone would silently accept a
/// binding taken over slots nobody chose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcrBinding {
    /// PCR slot numbers, ascending. Stored rather than assumed so a rebinding
    /// that narrows the selection is visible instead of silent.
    pub slots: Vec<u32>,
    /// Hex SHA-256 over the selected PCR values, in slot order.
    pub digest_hex: String,
}

/// Why a TPM-held credential is not at r2 right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaleBinding {
    /// The platform moved: a firmware or kernel update, or a boot with
    /// different measured state.
    DigestMoved { bound: String, current: String },
    /// The current reading covers different slots than the binding did, so the
    /// two digests are not comparable in the first place.
    SelectionMoved { bound: Vec<u32>, current: Vec<u32> },
}

impl std::fmt::Display for StaleBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StaleBinding::DigestMoved { bound, current } => write!(
                f,
                "the platform state moved since this credential was bound \
                 (bound to {bound}, now {current}) — a firmware or kernel update \
                 does this, and re-bind is the operator action"
            ),
            StaleBinding::SelectionMoved { bound, current } => write!(
                f,
                "this credential is bound over PCR slots {bound:?} but the \
                 current reading covers {current:?}, so the two are not \
                 comparable"
            ),
        }
    }
}

impl PcrBinding {
    /// Whether this binding still holds against a current reading.
    ///
    /// The whole of r2's freshness half, and deliberately a total function over
    /// two values rather than something that reads a device: it is the rule,
    /// and the rule is checkable without hardware.
    pub fn still_fresh(&self, current: &PcrBinding) -> Result<(), StaleBinding> {
        if self.slots != current.slots {
            return Err(StaleBinding::SelectionMoved {
                bound: self.slots.clone(),
                current: current.slots.clone(),
            });
        }
        if self.digest_hex != current.digest_hex {
            return Err(StaleBinding::DigestMoved {
                bound: self.digest_hex.clone(),
                current: current.digest_hex.clone(),
            });
        }
        Ok(())
    }
}

/// Digest the selected PCR values into a binding.
///
/// Slot order is the caller's; this hashes values in the order given and
/// records the slots alongside, so a reordering is a different binding rather
/// than the same one by accident.
pub fn bind(slots: &[u32], values: &[Vec<u8>]) -> Result<PcrBinding, String> {
    if slots.len() != values.len() {
        return Err(format!(
            "a PCR binding needs one value per slot: {} slot(s), {} value(s)",
            slots.len(),
            values.len()
        ));
    }
    if slots.is_empty() {
        // A binding over no slots is bound to nothing, and would report fresh
        // forever — the exact failure freshness exists to prevent.
        return Err("a PCR binding must name at least one slot".to_owned());
    }
    let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
    for value in values {
        hasher.update(value);
    }
    let digest = hasher.finish();
    Ok(PcrBinding {
        slots: slots.to_vec(),
        digest_hex: digest.as_ref().iter().map(|b| format!("{b:02x}")).collect(),
    })
}

/// Refuse unless the binding still holds against a current reading.
///
/// The whole freshness decision INCLUDING its message, here rather than in the
/// custodian's feature-gated signing path. That is not tidiness: a refusal
/// reachable only with the `tpm` feature AND a real chip can be pinned by no
/// gate anywhere — hosted runners have no TPM, so even a featured build skips
/// it. Over values it needs neither, so both the rule and the words an operator
/// reads are checked by the ordinary green bar.
///
/// The message is built HERE rather than in a formatter this calls, so the
/// mutation sweep has a literal to rewrite at the site that decides.
pub fn ensure_fresh(
    credential: &str,
    bound: &PcrBinding,
    current: &PcrBinding,
) -> Result<(), String> {
    if let Err(stale) = bound.still_fresh(current) {
        return Err(format!(
            "credential {credential} is no longer at its bound platform state: {stale}"
        ));
    }
    Ok(())
}

/// Which PCR slots whip will bind to.
///
/// A rule rather than a device fact, so it lives with the other rules and is
/// checked without a chip. Refused rather than clamped: a binding over a slot
/// the caller did not name is a different platform claim, and silently
/// substituting one would be the freshness bug wearing a helpful face.
pub fn supported_slot(number: u32) -> Result<(), String> {
    if number > MAX_PCR_SLOT {
        return Err(format!(
            "PCR slot {number} is outside the supported range 0..={MAX_PCR_SLOT}"
        ));
    }
    Ok(())
}

/// The highest PCR slot `supported_slot` admits.
pub const MAX_PCR_SLOT: u32 = 9;

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(slots: &[u32], values: &[&[u8]]) -> PcrBinding {
        let owned: Vec<Vec<u8>> = values.iter().map(|v| v.to_vec()).collect();
        bind(slots, &owned).expect("binding")
    }

    #[test]
    fn an_unchanged_platform_keeps_the_binding_fresh() {
        let bound = binding(&[0, 7], &[b"firmware", b"secureboot"]);
        let now = binding(&[0, 7], &[b"firmware", b"secureboot"]);
        assert_eq!(bound.still_fresh(&now), Ok(()));
    }

    #[test]
    fn a_firmware_update_makes_the_binding_stale() {
        // The operational failure DR-0053 flags under Consequences: PCR seals
        // break on firmware and kernel updates. Documented, not designed away —
        // so the refusal has to say what happened and what to do.
        let bound = binding(&[0, 7], &[b"firmware", b"secureboot"]);
        let now = binding(&[0, 7], &[b"firmware-v2", b"secureboot"]);
        let stale = bound.still_fresh(&now).expect_err("the platform moved");
        assert!(matches!(stale, StaleBinding::DigestMoved { .. }));
        let said = stale.to_string();
        assert!(said.contains("firmware or kernel update"), "{said}");
        assert!(said.contains("re-bind"), "{said}");
    }

    #[test]
    fn a_supported_slot_is_admitted_and_a_higher_one_is_refused_by_number() {
        for ok in [0, 7, MAX_PCR_SLOT] {
            assert_eq!(supported_slot(ok), Ok(()), "slot {ok} is in range");
        }
        assert_eq!(
            supported_slot(MAX_PCR_SLOT + 1).expect_err("out of range"),
            "PCR slot 10 is outside the supported range 0..=9"
        );
        // Named by number, so an operator who typed 24 reads which of their
        // slots was refused rather than that "a slot" was.
        assert!(supported_slot(24).expect_err("out of range").contains("24"));
    }

    #[test]
    fn the_refusal_names_the_credential_the_cause_and_the_action() {
        // What an operator meets after a firmware update. Three things have to
        // survive: which credential stopped, why, and what to do about it.
        let bound = binding(&[0, 7], &[b"firmware", b"secureboot"]);
        let now = binding(&[0, 7], &[b"firmware-v2", b"secureboot"]);
        let said = ensure_fresh("release_signing", &bound, &now).expect_err("moved");
        assert!(said.contains("release_signing"), "{said}");
        assert!(
            said.contains("no longer at its bound platform state"),
            "{said}"
        );
        assert!(said.contains("firmware or kernel update"), "{said}");
        assert!(said.contains("re-bind"), "{said}");
    }

    #[test]
    fn a_binding_over_different_slots_is_not_compared_by_digest() {
        // Two digests over different selections are not the same claim. Without
        // this, narrowing the selection to a slot that never moves would look
        // like a credential that stays fresh.
        let bound = binding(&[0, 7], &[b"a", b"b"]);
        let now = binding(&[7], &[b"b"]);
        assert!(matches!(
            bound.still_fresh(&now),
            Err(StaleBinding::SelectionMoved { .. })
        ));
    }

    #[test]
    fn a_binding_over_no_slots_is_refused_rather_than_fresh_forever() {
        assert!(bind(&[], &[]).is_err());
    }

    #[test]
    fn a_slot_without_a_value_is_refused() {
        assert!(bind(&[0, 7], &[b"only-one".to_vec()]).is_err());
    }

    #[test]
    fn slot_order_is_part_of_the_binding() {
        // Same values, different order: a different platform claim, not the
        // same one. Hashing without the slots would make these agree.
        let one = binding(&[0, 7], &[b"a", b"b"]);
        let other = binding(&[7, 0], &[b"a", b"b"]);
        assert_ne!(one.slots, other.slots);
        assert!(one.still_fresh(&other).is_err());
    }
}
