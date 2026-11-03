# ADR-001: Standardized RFC 9180 HPKE over bespoke ECIES

**Date:** 2026-07-01

## Context

The package exists to wrap an AES key to an X25519 public key and recover
it later with the matching private key. The sibling library
`@substrate-system/keys` already does something similar with its own
hand-rolled ECIES-style scheme.

ECIES is a family, not a protocol. Implementations differ in the
Diffie-Hellman variant, the KDF, what goes into the KDF context, how
nonces are chosen, and how the output is encoded. Two "ECIES"
implementations are rarely interoperable, and each one needs its own
security review.

RFC 9180 (HPKE) fixes all of those choices: a KEM, a KDF, and an AEAD
composed through one specified, reviewed key schedule, with an `info`
parameter for domain separation and a fresh ephemeral keypair per
encryption.

## Decision

Implement key wrapping as HPKE base-mode single-shot `Seal` / `Open`
(RFC 9180), where the plaintext is the 16 or 32 raw bytes of the AES
key. Do not design a custom scheme.

- Each wrap generates a fresh ephemeral X25519 keypair (DHKEM), so
  wrapping the same key twice yields different output.
- The DH output goes through HKDF Extract-then-Expand with the RFC's
  labels, never used directly as a key.
- `info` is exposed to callers and bound into the key schedule, so an
  envelope can be tied to a context without changing the wire format.

The repo is named `ecies` historically; the package is `simple-hpke` and
is not ECIES.

## Consequences

- Envelopes are interoperable with any conforming HPKE implementation
  using the same suite (see [ADR-003](ADR-003-one-fixed-cipher-suite.md)).
  This is what makes the known-answer test in
  [ADR-002](ADR-002-first-party-hpke-on-webcrypto.md) possible.
- Security rests on a published analysis rather than on this repo.
- Not wire-compatible with `@substrate-system/keys` `wrap` / `unwrap`,
  although both can use the same X25519 keypair.
- `info` must match between wrap and open; a mismatch is
  indistinguishable from a wrong key (see
  [ADR-008](ADR-008-single-error-class-with-stable-codes.md)).
- The original rationale lived in a "Why HPKE" section of
  `docs/README.md`, which was removed on 2026-07-02. This ADR replaces it.
