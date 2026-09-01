//! r2 `hardware` over PKCS#11: a key resident in a token that will not hand it
//! back (DR-0053 §4).
//!
//! The second backend for the same rung the TPM path already reaches, and the
//! same split: the RULE lives here and compiles unconditionally, the device
//! conversation lives behind the `pkcs11` feature. `credential-rung-evidence.maude`
//! states what this half must decide — `derive-r2-pkcs11` admits a token only
//! when its key is non-extractable — and nothing about that decision needs a
//! token to check.
//!
//! **What a token's own attributes can and cannot evidence.** They are the
//! token's word for it. A software module answers exactly as a hardware one
//! does, which is why `scripts/check-pkcs11-live-smoke.sh` says in its own
//! output which module it ran against: the assertions there prove the plumbing,
//! and only a real device proves the rung. That limit is stated rather than
//! designed away, in the same spirit as the PCR-seal caveat beside it.

use serde::{Deserialize, Serialize};

/// The four attributes PKCS#11 uses to say whether a key can leave its token.
///
/// Read from the object rather than taken from configuration — the model's
/// theorem is that configuration is not evidence, and an operator's `.conf`
/// saying "hardware" is exactly the self-assessment it rejects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyAttributes {
    /// `CKA_SENSITIVE`: the value cannot be read off the token in the clear.
    pub sensitive: bool,
    /// `CKA_EXTRACTABLE`: the value may be wrapped out under another key.
    pub extractable: bool,
    /// `CKA_ALWAYS_SENSITIVE`: it has been sensitive for its whole life.
    pub always_sensitive: bool,
    /// `CKA_NEVER_EXTRACTABLE`: it has never been extractable.
    pub never_extractable: bool,
}

/// Whether these attributes evidence r2, and what is missing when they do not.
///
/// Both pairs are required, and the second pair is the one that matters.
/// `!extractable && sensitive` says the key cannot leave TODAY; a key wrapped
/// out last week and re-imported with the flags tightened satisfies exactly
/// that while copies of it exist elsewhere. `never_extractable &&
/// always_sensitive` is the token's statement that it never could, which is
/// what "the key cannot leave" has to mean if the rung is to be worth its
/// place above r1.
///
/// This is the same bar the TPM path meets by construction: `sensitive_data_origin`
/// makes the chip generate the secret, so it never existed outside. A key
/// imported into a token DID exist outside it, and calling that r2 would let an
/// operator reach the rung by moving a key they already had on disk.
pub fn evidences_r2(attributes: KeyAttributes) -> Result<(), String> {
    let mut missing = Vec::new();
    if attributes.extractable {
        missing.push("CKA_EXTRACTABLE is true (the key may be wrapped out)");
    }
    if !attributes.sensitive {
        missing.push("CKA_SENSITIVE is false (the value can be read in the clear)");
    }
    if !attributes.never_extractable {
        missing.push("CKA_NEVER_EXTRACTABLE is false (the key has been extractable before)");
    }
    if !attributes.always_sensitive {
        missing.push("CKA_ALWAYS_SENSITIVE is false (the key has been readable before)");
    }
    if missing.is_empty() {
        return Ok(());
    }
    Err(format!(
        "this key is not evidence of r2 hardware: {}. A key that could leave the token, or that \
         ever could, is not one the token can promise never left",
        missing.join("; ")
    ))
}

/// Where the custodian reads a token's user PIN.
///
/// The environment rather than the store: a PIN is material, and the store is
/// the one place this design is careful never to put material it does not have
/// to. The custodian holds it for the process lifetime exactly as it holds the
/// store passphrase.
pub const PIN_ENV: &str = "WHIPPLESCRIPT_PKCS11_PIN";

/// Whether a key still evidences the rung it was admitted on.
///
/// Re-asked at every use, because a token can be re-provisioned under a running
/// custodian. Recording the attributes at registration and trusting them
/// afterwards would make r2 a claim about the day the operator typed the
/// command.
pub fn still_admitted(
    credential: &str,
    admitted: &KeyAttributes,
    current: &KeyAttributes,
) -> Result<(), String> {
    if admitted == current {
        return Ok(());
    }
    Err(format!(
        "credential {credential} is on a key whose attributes have changed since it was \
         registered (admitted {admitted:?}, now {current:?}) — re-register it if the change was \
         intended"
    ))
}

/// Which of `labels` is the token called `wanted`.
///
/// A rule over the list the module returned, so the refusal an operator meets
/// when they mistype a token label is checked without a token. By LABEL rather
/// than by slot index: a module assigns slot numbers in an order nothing
/// promises to keep, so a credential bound to slot 0 would follow whichever
/// token happened to enumerate first after a reboot.
pub fn slot_for_label(labels: &[String], wanted: &str) -> Result<usize, String> {
    if let Some(index) = labels.iter().position(|label| label.trim() == wanted) {
        return Ok(index);
    }
    Err(format!(
        "no PKCS#11 token is labelled {wanted:?} (this module offers {})",
        if labels.is_empty() {
            "none".to_owned()
        } else {
            labels
                .iter()
                .map(|label| format!("{:?}", label.trim()))
                .collect::<Vec<_>>()
                .join(", ")
        }
    ))
}

/// Whether a label named exactly one key object.
///
/// Two keys under one label is refused rather than resolved by taking the
/// first: the label would then not identify a key, and the credential's
/// identity would depend on the token's enumeration order.
pub fn one_key(found: usize, label: &str) -> Result<(), String> {
    match found {
        1 => Ok(()),
        0 => Err(format!("no key on this token is labelled {label:?}")),
        many => Err(format!(
            "{many} objects on this token are labelled {label:?}, so the label names no single key"
        )),
    }
}

/// Whether the token answered with every attribute the rung is judged on.
///
/// A token that will not answer is a refusal rather than a default: assuming
/// `false` would read a silent module as a key that may leave, and assuming
/// `true` would hand it the rung for saying nothing.
pub fn complete_attributes(seen: usize, wanted: usize) -> Result<(), String> {
    if seen == wanted {
        return Ok(());
    }
    Err(format!(
        "the token answered with {seen} of the {wanted} attributes the rung is judged on, so its evidence is incomplete"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key generated on-token and never exported: every flag the way r2 needs.
    fn resident() -> KeyAttributes {
        KeyAttributes {
            sensitive: true,
            extractable: false,
            always_sensitive: true,
            never_extractable: true,
        }
    }

    #[test]
    fn a_key_that_never_left_the_token_evidences_r2() {
        assert_eq!(evidences_r2(resident()), Ok(()));
    }

    #[test]
    fn a_key_whose_attributes_changed_since_registration_is_refused() {
        // A token can be re-provisioned under a running custodian. Trusting the
        // attributes recorded at registration would make r2 a claim about the
        // day the operator typed the command.
        let admitted = resident();
        assert_eq!(
            still_admitted("release_signing", &admitted, &admitted),
            Ok(())
        );

        let loosened = KeyAttributes {
            extractable: true,
            never_extractable: false,
            ..resident()
        };
        let refused =
            still_admitted("release_signing", &admitted, &loosened).expect_err("it changed");
        assert!(refused.contains("release_signing"), "{refused}");
        assert!(refused.contains("attributes have changed"), "{refused}");
        assert!(refused.contains("re-register"), "and what to do: {refused}");
    }

    #[test]
    fn a_token_is_found_by_label_and_a_miss_says_what_is_there() {
        let labels = vec!["  whip-smoke  ".to_owned(), "other".to_owned()];
        // Trimmed: PKCS#11 pads token labels to 32 bytes, so an operator's
        // exact string would otherwise never match what the module returns.
        assert_eq!(slot_for_label(&labels, "whip-smoke"), Ok(0));
        assert_eq!(slot_for_label(&labels, "other"), Ok(1));

        let refused = slot_for_label(&labels, "typo").expect_err("no such token");
        // The PROSE as well as the interpolated values. A mutation of this
        // message keeps its placeholders, so assertions on `typo` and
        // `whip-smoke` alone would survive the text being rewritten to anything
        // at all — the same hole `is_err()` opens, one layer in.
        assert!(
            refused.starts_with("no PKCS#11 token is labelled"),
            "{refused}"
        );
        assert!(refused.contains("this module offers"), "{refused}");
        assert!(
            refused.contains("typo"),
            "names what was asked for: {refused}"
        );
        assert!(
            refused.contains("whip-smoke") && refused.contains("other"),
            "and what is actually there: {refused}"
        );

        let empty = slot_for_label(&[], "whip-smoke").expect_err("no tokens at all");
        assert!(empty.starts_with("no PKCS#11 token is labelled"), "{empty}");
        assert!(
            empty.contains("offers none"),
            "an empty module says so rather than listing nothing: {empty}"
        );
    }

    #[test]
    fn a_label_must_name_exactly_one_key() {
        assert_eq!(one_key(1, "release-signing"), Ok(()));
        assert!(one_key(0, "release-signing")
            .expect_err("none")
            .contains("no key on this token"));
        // Refused rather than taking the first: the credential's identity would
        // otherwise depend on the token's enumeration order.
        let ambiguous = one_key(2, "release-signing").expect_err("two");
        assert!(ambiguous.contains("2 objects"), "{ambiguous}");
        assert!(ambiguous.contains("no single key"), "{ambiguous}");
    }

    #[test]
    fn a_token_that_answers_partially_is_refused_rather_than_defaulted() {
        assert_eq!(complete_attributes(4, 4), Ok(()));
        let refused = complete_attributes(3, 4).expect_err("incomplete");
        assert!(refused.contains("3 of the 4"), "{refused}");
        assert!(refused.contains("evidence is incomplete"), "{refused}");
    }

    #[test]
    fn a_key_that_can_be_wrapped_out_is_refused() {
        let leavable = KeyAttributes {
            extractable: true,
            never_extractable: false,
            ..resident()
        };
        let refused = evidences_r2(leavable).expect_err("extractable is not r2");
        assert!(refused.contains("CKA_EXTRACTABLE is true"), "{refused}");
    }

    #[test]
    fn a_key_tightened_after_the_fact_is_refused() {
        // THE case the second pair exists for. It cannot leave today, and it
        // could have last week — so copies may exist and the token cannot say
        // otherwise. `!extractable && sensitive` alone would admit this.
        let re_imported = KeyAttributes {
            sensitive: true,
            extractable: false,
            always_sensitive: false,
            never_extractable: false,
        };
        let refused = evidences_r2(re_imported).expect_err("history matters");
        assert!(
            refused.contains("CKA_NEVER_EXTRACTABLE is false"),
            "the refusal must name the history, not just the present: {refused}"
        );
        assert!(
            refused.contains("CKA_ALWAYS_SENSITIVE is false"),
            "{refused}"
        );
        // And it must not claim the present is wrong, because it is not.
        assert!(!refused.contains("CKA_EXTRACTABLE is true"), "{refused}");
    }

    #[test]
    fn a_readable_key_is_refused_even_when_it_cannot_be_wrapped() {
        let readable = KeyAttributes {
            sensitive: false,
            always_sensitive: false,
            ..resident()
        };
        let refused = evidences_r2(readable).expect_err("readable is not r2");
        assert!(refused.contains("CKA_SENSITIVE is false"), "{refused}");
    }

    #[test]
    fn the_refusal_names_every_missing_attribute_at_once() {
        // An operator fixing one flag at a time would otherwise need four runs
        // to learn what is wrong with the key they have.
        let nothing = KeyAttributes {
            sensitive: false,
            extractable: true,
            always_sensitive: false,
            never_extractable: false,
        };
        let refused = evidences_r2(nothing).expect_err("none of it is r2");
        for named in [
            "CKA_EXTRACTABLE",
            "CKA_SENSITIVE",
            "CKA_NEVER_EXTRACTABLE",
            "CKA_ALWAYS_SENSITIVE",
        ] {
            assert!(refused.contains(named), "{named} missing from: {refused}");
        }
    }
}
