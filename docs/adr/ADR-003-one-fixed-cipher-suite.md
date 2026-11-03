# ADR-003: One fixed, non-configurable cipher suite

**Date:** 2026-07-01

## Context

HPKE is parameterized by a KEM, a KDF, an AEAD, and a mode (base, PSK,
auth, auth-PSK). Exposing these as options lets callers create envelopes
that other callers cannot open, multiplies the test matrix, and invites
weak choices. The package's job is narrow: wrap a symmetric key to an
X25519 key.

The first design also allowed a 192-bit generated AES key.

## Decision

Hard-code a single suite in `src/constants.ts`:

- KEM: DHKEM(X25519, HKDF-SHA256), `0x0020`
- KDF: HKDF-SHA256, `0x0001`
- AEAD: AES-256-GCM, `0x0002`
- Mode: base (`0x00`), single-shot (sequence 0 only)

No option selects a different suite or mode. The wrapped AES key (the
plaintext) is 128 or 256 bits; AES-192 is rejected with
`ERR_INVALID_KEYSIZE` / `ERR_INVALID_AES_KEY` rather than silently
accepted by WebCrypto.

## Consequences

- Any two installs of this package can open each other's envelopes.
- Changing any part of the suite is a breaking wire-format change, and
  since envelopes carry no version byte (see
  [ADR-004](ADR-004-minimal-unversioned-wire-formats.md)), old and new
  envelopes would be indistinguishable on the wire.
- No PSK or sender authentication. A recipient cannot tell who wrapped a
  key; callers who need that must sign the envelope themselves.
- The wrapped key is always sealed with AES-256-GCM even when the AES key
  being wrapped is 128-bit.
