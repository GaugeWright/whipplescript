//! Issuer-bound gate certificates (SR-3, WS-232).
//!
//! A certificate row is evidence, not authority: anything that can write the
//! ref store's tables could otherwise mint a passing envelope. The ref CAS
//! therefore accepts a certificate only when an issuer named in the ref
//! store's configured trust root has signed its exact handle at that issuer's
//! current epoch. Rotating an issuer raises its epoch, which retires every
//! signature made under the earlier key without deleting any evidence.
//!
//! The signature is Ed25519 over a domain-separated encoding of the handle,
//! issuer and epoch. The handle is already the digest of every certificate
//! byte, so a swapped digest or a changed certificate cannot keep a signature.
//! Which process holds the private key, and how the fleet reaches it, is the
//! production wiring this module deliberately leaves to its caller.

use serde::{Deserialize, Serialize};

/// One trusted gate issuer as the ref authority's operator configured it.
/// `public_key` is the lowercase hex of a 32-byte Ed25519 verifying key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingGateTrustedIssuer {
    pub issuer_id: String,
    pub epoch: i64,
    pub public_key: String,
    pub configured_at: String,
}

/// An issuer's signature over one certificate handle. `signature` is the
/// lowercase hex of a 64-byte Ed25519 signature over [`signing_bytes`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingGateIssuerSignature {
    pub certificate_handle: String,
    pub issuer_id: String,
    pub issuer_epoch: i64,
    pub signature: String,
}

/// Why the ref authority will not take a certificate as issued.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingGateIssuerRefusal {
    /// No issuer is configured, so no certificate can be authoritative.
    TrustRootMissing,
    /// The certificate carries no issuer signature at all.
    Unsigned,
    /// Every signature names an issuer the trust root does not hold.
    ForeignIssuer,
    /// A trusted issuer signed, but under an epoch it no longer holds.
    IssuerEpochMismatch {
        issuer_id: String,
        signed: i64,
        current: i64,
    },
    /// A trusted issuer at its current epoch is named, but the signature does
    /// not verify over this handle under its configured key.
    BadSignature { issuer_id: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigureFlowingGateIssuerOutcome {
    Configured(FlowingGateTrustedIssuer),
    Existing(FlowingGateTrustedIssuer),
    /// An epoch may only rise; reusing or lowering one would let a retired
    /// key's signatures verify again.
    EpochNotAdvanced {
        current: i64,
    },
    Invalid {
        field: &'static str,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordFlowingGateSignatureOutcome {
    Recorded(FlowingGateIssuerSignature),
    Existing(FlowingGateIssuerSignature),
    CertificateMissing,
    Refused(FlowingGateIssuerRefusal),
    Invalid { field: &'static str },
}

/// The exact bytes an issuer signs. Domain-separated so a signature made for
/// any other purpose with the same key cannot be replayed here.
pub fn signing_bytes(
    certificate_handle: &str,
    issuer_id: &str,
    issuer_epoch: i64,
) -> crate::StoreResult<Vec<u8>> {
    Ok(serde_json::to_vec(&(
        "native-gate-certificate-issuer-signature-v1",
        certificate_handle,
        issuer_id,
        issuer_epoch,
    ))?)
}

fn decode_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let bytes = text.as_bytes();
    if bytes.len() != N * 2 {
        return None;
    }
    let nibble = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; N];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        out[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

fn verifying_key(public_key: &str) -> Option<ed25519_dalek::VerifyingKey> {
    ed25519_dalek::VerifyingKey::from_bytes(&decode_hex::<32>(public_key)?).ok()
}

pub fn validate_issuer(issuer: &FlowingGateTrustedIssuer) -> Result<(), &'static str> {
    if issuer.issuer_id.trim().is_empty() {
        return Err("issuer_id");
    }
    if issuer.configured_at.trim().is_empty() {
        return Err("configured_at");
    }
    if issuer.epoch < 1 {
        return Err("epoch");
    }
    if verifying_key(&issuer.public_key).is_none() {
        return Err("public_key");
    }
    Ok(())
}

/// Decide a configuration change against the row the store already holds.
pub fn configure_outcome(
    current: Option<FlowingGateTrustedIssuer>,
    proposed: &FlowingGateTrustedIssuer,
) -> ConfigureFlowingGateIssuerOutcome {
    use ConfigureFlowingGateIssuerOutcome as O;
    if let Err(field) = validate_issuer(proposed) {
        return O::Invalid { field };
    }
    match current {
        Some(current)
            if current.epoch == proposed.epoch && current.public_key == proposed.public_key =>
        {
            O::Existing(current)
        }
        Some(current) if proposed.epoch <= current.epoch => O::EpochNotAdvanced {
            current: current.epoch,
        },
        _ => O::Configured(proposed.clone()),
    }
}

pub fn validate_signature(signature: &FlowingGateIssuerSignature) -> Result<(), &'static str> {
    if signature.certificate_handle.trim().is_empty() {
        return Err("certificate_handle");
    }
    if signature.issuer_id.trim().is_empty() {
        return Err("issuer_id");
    }
    if signature.issuer_epoch < 1 {
        return Err("issuer_epoch");
    }
    if decode_hex::<64>(&signature.signature).is_none() {
        return Err("signature");
    }
    Ok(())
}

/// Verify that some issuer of `trusted` signed `handle` at its current epoch.
/// When none did, the refusal names the closest miss: a bad signature from a
/// current issuer, then a retired epoch, then a foreign or absent signature.
pub fn verify_issued(
    handle: &str,
    trusted: &[FlowingGateTrustedIssuer],
    signatures: &[FlowingGateIssuerSignature],
) -> Result<(), FlowingGateIssuerRefusal> {
    use ed25519_dalek::Signature;
    use FlowingGateIssuerRefusal as R;
    if trusted.is_empty() {
        return Err(R::TrustRootMissing);
    }
    if signatures.is_empty() {
        return Err(R::Unsigned);
    }
    let mut bad = None;
    let mut retired = None;
    for issuer in trusted {
        for signed in signatures
            .iter()
            .filter(|signed| signed.issuer_id == issuer.issuer_id)
        {
            if signed.issuer_epoch != issuer.epoch {
                retired.get_or_insert(R::IssuerEpochMismatch {
                    issuer_id: issuer.issuer_id.clone(),
                    signed: signed.issuer_epoch,
                    current: issuer.epoch,
                });
                continue;
            }
            let verified = signed.certificate_handle == handle
                && verifying_key(&issuer.public_key).is_some_and(|key| {
                    decode_hex::<64>(&signed.signature).is_some_and(|bytes| {
                        signing_bytes(handle, &issuer.issuer_id, issuer.epoch).is_ok_and(
                            |message| {
                                key.verify_strict(&message, &Signature::from_bytes(&bytes))
                                    .is_ok()
                            },
                        )
                    })
                });
            if verified {
                return Ok(());
            }
            bad.get_or_insert(R::BadSignature {
                issuer_id: issuer.issuer_id.clone(),
            });
        }
    }
    match bad.or(retired) {
        // MUTATION-SUCCESS-EXPR: Ok(())
        Some(refusal) => Err(refusal),
        // MUTATION-SUCCESS-EXPR: Ok(())
        None => Err(R::ForeignIssuer),
    }
}

#[cfg(test)]
pub(crate) mod test_issuer {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    pub(crate) const ISSUER: &str = "fleet-gate";

    pub(crate) fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    pub(crate) fn trusted(issuer_id: &str, epoch: i64, seed: u8) -> FlowingGateTrustedIssuer {
        FlowingGateTrustedIssuer {
            issuer_id: issuer_id.into(),
            epoch,
            public_key: hex(key(seed).verifying_key().as_bytes()),
            configured_at: format!("epoch-{epoch}"),
        }
    }

    pub(crate) fn sign(
        handle: &str,
        issuer_id: &str,
        epoch: i64,
        seed: u8,
    ) -> FlowingGateIssuerSignature {
        let message = signing_bytes(handle, issuer_id, epoch).unwrap();
        FlowingGateIssuerSignature {
            certificate_handle: handle.into(),
            issuer_id: issuer_id.into(),
            issuer_epoch: epoch,
            signature: hex(&key(seed).sign(&message).to_bytes()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_issuer::*;
    use super::*;

    #[test]
    fn only_a_current_trusted_issuer_over_the_exact_handle_verifies() {
        let root = [trusted(ISSUER, 2, 7)];
        let good = sign("sha256:h", ISSUER, 2, 7);
        assert_eq!(
            verify_issued("sha256:h", &root, std::slice::from_ref(&good)),
            Ok(())
        );
        assert_eq!(
            verify_issued("sha256:h", &[], std::slice::from_ref(&good)),
            Err(FlowingGateIssuerRefusal::TrustRootMissing)
        );
        assert_eq!(
            verify_issued("sha256:h", &root, &[]),
            Err(FlowingGateIssuerRefusal::Unsigned)
        );
        // Swapped digest: the signature was made for another handle.
        let mut swapped = sign("sha256:other", ISSUER, 2, 7);
        swapped.certificate_handle = "sha256:h".into();
        assert_eq!(
            verify_issued("sha256:h", &root, &[swapped]),
            Err(FlowingGateIssuerRefusal::BadSignature {
                issuer_id: ISSUER.into()
            })
        );
        // Forged issuer: the trusted name signed with someone else's key.
        assert_eq!(
            verify_issued("sha256:h", &root, &[sign("sha256:h", ISSUER, 2, 9)]),
            Err(FlowingGateIssuerRefusal::BadSignature {
                issuer_id: ISSUER.into()
            })
        );
        assert_eq!(
            verify_issued("sha256:h", &root, &[sign("sha256:h", "elsewhere", 2, 7)]),
            Err(FlowingGateIssuerRefusal::ForeignIssuer)
        );
        assert_eq!(
            verify_issued("sha256:h", &root, &[sign("sha256:h", ISSUER, 1, 7)]),
            Err(FlowingGateIssuerRefusal::IssuerEpochMismatch {
                issuer_id: ISSUER.into(),
                signed: 1,
                current: 2
            })
        );
        // A good signature beside a bad one still admits.
        assert_eq!(
            verify_issued(
                "sha256:h",
                &root,
                &[sign("sha256:h", "elsewhere", 2, 7), good]
            ),
            Ok(())
        );
    }

    #[test]
    fn issuer_configuration_only_moves_forward() {
        use ConfigureFlowingGateIssuerOutcome as O;
        let first = trusted(ISSUER, 1, 7);
        assert_eq!(
            configure_outcome(None, &first),
            O::Configured(first.clone())
        );
        assert_eq!(
            configure_outcome(Some(first.clone()), &first),
            O::Existing(first.clone())
        );
        assert_eq!(
            configure_outcome(Some(first.clone()), &trusted(ISSUER, 1, 8)),
            O::EpochNotAdvanced { current: 1 }
        );
        assert_eq!(
            configure_outcome(Some(trusted(ISSUER, 2, 8)), &first),
            O::EpochNotAdvanced { current: 2 }
        );
        let rotated = trusted(ISSUER, 2, 8);
        assert_eq!(
            configure_outcome(Some(first.clone()), &rotated),
            O::Configured(rotated)
        );
        let mut bad = first.clone();
        bad.public_key = "zz".into();
        assert_eq!(
            configure_outcome(None, &bad),
            O::Invalid {
                field: "public_key"
            }
        );
        let mut bad = first.clone();
        bad.epoch = 0;
        assert_eq!(configure_outcome(None, &bad), O::Invalid { field: "epoch" });
        let mut bad = first.clone();
        bad.issuer_id = " ".into();
        assert_eq!(
            configure_outcome(None, &bad),
            O::Invalid { field: "issuer_id" }
        );
        let mut bad = first;
        bad.configured_at = String::new();
        assert_eq!(
            configure_outcome(None, &bad),
            O::Invalid {
                field: "configured_at"
            }
        );
    }

    #[test]
    fn signature_shape_is_validated_before_storage() {
        let good = sign("sha256:h", ISSUER, 1, 7);
        assert_eq!(validate_signature(&good), Ok(()));
        let mut bad = good.clone();
        bad.signature.pop();
        assert_eq!(validate_signature(&bad), Err("signature"));
        let mut bad = good.clone();
        bad.issuer_epoch = 0;
        assert_eq!(validate_signature(&bad), Err("issuer_epoch"));
        let mut bad = good.clone();
        bad.certificate_handle = String::new();
        assert_eq!(validate_signature(&bad), Err("certificate_handle"));
        let mut bad = good;
        bad.issuer_id = " ".into();
        assert_eq!(validate_signature(&bad), Err("issuer_id"));
    }
}
