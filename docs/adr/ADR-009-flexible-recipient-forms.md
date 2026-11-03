# ADR-009: Several recipient key forms; uint8arrays as sole dependency

**Date:** 2026-07-02

## Context

Senders often hold a recipient's public key as something other than a
`CryptoKey`: raw bytes from a database, or a base64url string from JSON.
Making every caller import the key into WebCrypto first is repetitive and
easy to get wrong (for example, passing an Ed25519 signing key from a
library that exposes both).

Decoding strings requires base-N codecs, and the encrypt-to-string and
`keyId` paths need encoding too. Writing those codecs by hand is
avoidable surface area; `uint8arrays` is small and has no crypto in it.

## Decision

The `recipient` argument of `create`, `encryptKey`, `encrypt`, and
`encrypt.asString` is a `RecipientKey`, one of:

- an X25519 public `CryptoKey`,
- a `CryptoKeyPair` (only `.publicKey` is used),
- 32 raw bytes (`Uint8Array`),
- `{ publicKey:string; encoding?:SupportedEncodings }`, default
  `base64url`.

`resolveRecipientPublicKey` normalizes every form and rejects private
keys, non-X25519 keys, non-extractable public keys (the KEM must export
`pkR`), strings that do not decode, wrong lengths, and unknown shapes
with `ERR_INVALID_RECIPIENT_KEY`.

The receiving side (`open`, `decrypt`) still takes a full
`CryptoKeyPair`, since DHKEM's `Decap` needs the private key and the
recipient's own public key for `kem_context`.

`uint8arrays` is the single runtime dependency. It is used for string
encoding and decoding only: decoding a string recipient,
`decrypt.fromString`, `encrypt.asString`, and `keyId`'s base64url output.
No cryptography comes from it.

## Consequences

- Callers can encrypt straight from stored or transmitted key material.
- Raw-byte recipients are imported extractable (a public key holds no
  secret) because the KEM re-exports `pkR` for its context.
- `RecipientKey` and `SupportedEncodings` live in `src/util.ts` and are
  not re-exported, so consumers cannot yet name the type. Tracked as a
  separate change.
