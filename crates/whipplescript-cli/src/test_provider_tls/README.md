# Synthetic provider transport fixture

These DER certificates and the disposable leaf private key were generated only
for native transport tests. They have no connection to an office, a real model
provider, system trust, or deployment credentials. `provider.test` is a reserved
synthetic DNS name; the tests connect to an ephemeral loopback socket through
the explicit admitted resolver.

The root and leaf expire in October 2036. Certificate time-validation tests
also use explicit times outside the fixture's validity. Regenerate together
when their validity ends; never disable TLS verification to extend the fixture.
