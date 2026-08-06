# aws-sig-v4-test-suite (vendored subset)

Fifteen cases from the AWS Signature Version 4 test suite as shipped in
[awslabs/aws-c-auth](https://github.com/awslabs/aws-c-auth)
(`tests/aws-signing-test-suite/v4`, Apache-2.0). Each case carries the
original `context.json`, `request.txt`, and the expected
`header-canonical-request.txt` / `header-string-to-sign.txt` /
`header-signature.txt`.

DR-0053 §7 makes canonicalizer correctness a gate: a canonicalizer that
disagrees with the vendor's is a signature bypass. The custody crate's tests
check the secret-free half (canonical request, string-to-sign) — exactly the
half whip computes. The custodian crate's tests drive the same fixtures
end-to-end through the keyed derivation chain and compare the final
signature.
