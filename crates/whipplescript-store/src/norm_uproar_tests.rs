use super::*;
use sha2::{Digest, Sha256};

const VECTORS: &str = include_str!("../../../contracts/uproar/record-vectors.json");
const PIN: &str = include_str!("../../../contracts/uproar/pin.json");

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

/// The vendored vectors are the owner's, byte for byte, at the pinned revision.
#[test]
fn the_uproar_vectors_are_the_pinned_owners() {
    let pin: serde_json::Value = serde_json::from_str(PIN).unwrap();
    assert_eq!(pin["repository"], "gaugenet");
    assert_eq!(
        hex(&Sha256::digest(VECTORS.as_bytes())),
        pin["sha256"].as_str().unwrap(),
        "contracts/uproar/record-vectors.json differs from the pinned owner's file"
    );
}

/// The codec agrees with gaugenet's frozen wire: every reference record
/// decodes, re-encodes to the same bytes, hashes to its reference, and its
/// key id and Ed25519 signature check out under the vector's repository.
#[test]
fn the_codec_reproduces_the_owners_reference_records() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let vectors: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let repository = vectors["repository"].as_str().unwrap();
    let records = vectors["records"].as_array().unwrap();
    assert!(!records.is_empty());
    for vector in records {
        let bytes = unhex(vector["cbor_hex"].as_str().unwrap());
        let record = Cbor::decode(&bytes).expect("the owner's record decodes");
        assert_eq!(record.encode(), bytes, "re-encoding is byte-identical");
        assert_eq!(hex(&reference(&record)), vector["ref_hex"]);
        let public = unhex(vector["public_key_hex"].as_str().unwrap());
        assert_eq!(key_id(&public), vector["author"]);
        let key = VerifyingKey::from_bytes(&public.clone().try_into().unwrap()).unwrap();
        let signature =
            Signature::from_slice(&unhex(vector["signature_hex"].as_str().unwrap())).unwrap();
        key.verify(&signing_message(&record, repository), &signature)
            .expect("the owner's signature verifies over our signing message");
        // Signatures never validate across repositories.
        assert!(key
            .verify(
                &signing_message(&record, "urn:gaugenet:repo:other"),
                &signature
            )
            .is_err());
    }
}

#[test]
fn the_codec_refuses_what_the_v1_wire_forbids() {
    // Each is refused for its own reason, not for bytes left over after a
    // refusal that did not happen.
    for (bytes, why) in [
        (vec![0xf9, 0x3c, 0x00], "simple value or float 0xf9"),
        (vec![0xf7], "simple value or float 0xf7"),
        (vec![0xc0, 0x60], "tag 0"),
        (vec![0x18, 0x05], "shortest form"),
        (vec![0x5f, 0x40, 0xff], "indefinite or reserved"),
        (vec![0x1c], "indefinite or reserved"),
        (
            vec![0xa2, 0x61, 0x62, 0x01, 0x61, 0x61, 0x02],
            "unsorted or duplicated",
        ),
        (
            vec![0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02],
            "unsorted or duplicated",
        ),
        (vec![0x01, 0x02], "trailing"),
    ] {
        let refused = Cbor::decode(&bytes).expect_err(why);
        assert!(refused.contains(why), "{why}: {refused}");
    }
    // Map entries are ordered by their encoded keys, however they were built.
    let built = Cbor::Map(vec![
        (Cbor::Text("bb".into()), Cbor::Unsigned(1)),
        (Cbor::Text("a".into()), Cbor::Unsigned(2)),
    ]);
    assert_eq!(
        built.encode(),
        vec![0xa2, 0x61, 0x61, 0x02, 0x62, 0x62, 0x62, 0x01]
    );
    assert_eq!(Cbor::Unsigned(500).encode(), vec![0x19, 0x01, 0xf4]);
    assert_eq!(Cbor::Negative(0).encode(), vec![0x20]);
}
