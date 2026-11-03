# ADR-002: First-party HPKE on WebCrypto, no HPKE library

**Date:** 2026-07-02

## Context

The first design (2026-07-01) vendored panva's `hpke` v1.1.3 into
`src/vendor/hpke/` to delegate the cryptography to a maintained
implementation while keeping the published package free of runtime
dependencies.

A core requirement is that the recipient's X25519 private key can be
**non-extractable**. Apps keep identity keys non-extractable so their raw
bytes never leave the WebCrypto boundary, and they assert this at
runtime.

Every HPKE library surveyed (`hpke`, `@hpke/core` +
`@hpke/dhkem-x25519`) performs X25519 in JavaScript (via
`@noble/curves`) and so needs the raw private-key bytes. That forces the
private key to be extractable, which defeats the requirement.

WebCrypto's `deriveBits` with `{ name: 'X25519' }` performs the DH step
on a non-extractable key. Everything else HPKE needs (HMAC-SHA256,
AES-256-GCM, random bytes) is also in WebCrypto. The one gap is that
WebCrypto's native HKDF fuses Extract and Expand and cannot accept a
supplied PRK, so RFC 9180's `LabeledExtract` / `LabeledExpand` must be
built on HMAC.

## Decision

Remove the vendored library (commit `06b429d`) and implement the RFC 9180
suite directly on `globalThis.crypto.subtle`:

- DHKEM `Encap` / `Decap` and `ExtractAndExpand` in `src/util.ts`, with
  DH via `deriveBits`.
- HKDF Extract / Expand on HMAC-SHA256 in `src/util.ts`.
- The base-mode key schedule in `src/index.ts`.
- Suite ids, lengths, and labels in `src/constants.ts`.

Do not add an HPKE or crypto library as a runtime dependency, vendored or
otherwise.

## Consequences

- The recipient private key needs only the `deriveBits` usage and may be
  non-extractable. The ephemeral keypair is also generated
  non-extractable.
- Zero crypto dependencies. The only runtime dependency is `uint8arrays`
  (see [ADR-009](ADR-009-flexible-recipient-forms.md)).
- Runs anywhere WebCrypto has X25519: modern browsers and Node.
- This repo owns conformance. A wrong label, suite id, or `kem_context`
  ordering would pass every round-trip test while silently breaking
  interop. The guard is the known-answer test in `test/index.ts`: an
  envelope sealed once by `@hpke/core` that `open.raw` must recover. That
  test covers only the open direction; the seal direction was checked
  manually against `@hpke/core`.
- Upstream security fixes do not arrive automatically. Any change to the
  key schedule needs RFC review by hand.
- A defensive all-zero DH check stays in `dh()` even though the Secure
  Curves spec requires conforming runtimes to throw first.
