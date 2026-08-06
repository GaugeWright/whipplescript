# Test fixtures

- `rfc7515_a2_key.pk8` — the RSA key from RFC 7515 Appendix A.2, converted
  from the RFC's JWK to PKCS#8 DER. At generation time the conversion was
  verified by reproducing the RFC's published signature exactly
  (RSASSA-PKCS1-v1_5 is deterministic). This is a **published test key**; it
  secures nothing.
- `rfc7515_a2_signature.b64u` — the RFC's published base64url signature for
  the A.2 signing input, the expected value of the `jwt-rs256` differential.
