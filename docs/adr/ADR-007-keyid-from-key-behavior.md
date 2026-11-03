# ADR-007: keyId is derived from a key's behavior, not its bytes

**Date:** 2026-08-21

## Context

With non-extractable keys as the default
([ADR-005](ADR-005-non-extractable-aes-keys-by-default.md)), callers
cannot identify a key by hashing its exported bytes. The consuming app
did exactly that (`commitmentForKey`, plain `base64url(SHA-256(raw))`)
and needed a replacement that works on a non-extractable key, including
one rehydrated from IndexedDB.

The first 0.3.0 design (`notes/0.3.0-spec.md`) planned a
`WeakMap<CryptoKey, string>` registry filled at the moment the library
still held the raw bytes, plus an export-and-hash fallback for foreign
extractable keys. The as-built work order (`docs/spec-0.3.0.md`)
replaced it with the derivation below. The registry design fails
for any key the library did not mint in the current session: a key
loaded from IndexedDB, or recovered in another tab, would have no entry
and could not be fingerprinted.

WebCrypto offers no digest-a-key primitive. HKDF is not an option either:
an AES-GCM key cannot be converted to an HKDF key, and `deriveBits` only
accepts a key imported under HKDF, which needs the raw bytes. Encrypting
under the key is the only operation a non-extractable AES-GCM key still
exposes.

The name `keyId` was chosen over `commitment`, which in the literature
means key-committing AEAD and would mislead a crypto-literate reader.

## Decision

Use AES-GCM as a PRF over a fixed input:

```
LABEL = utf8("simple-hpke/keyId/v1")
N     = SHA-256(LABEL)[0..12]
C     = AES-GCM(key, N, LABEL)        -- ciphertext || 16-byte tag
keyId = base64url(SHA-256(LABEL || C)) -- 43 chars, unpadded
```

- No AAD. AAD feeds only GHASH and leaves the keystream unchanged, so
  "domain separation by AAD" would produce a second ciphertext over an
  identical keystream under the same key and nonce.
- The nonce comes from the label hash, not zeros or a counter, which are
  what a caller using deterministic nonces would pick. A collision there
  would expose the GHASH subkey.
- `C` never leaves the function; only its digest is returned.
- The key must be AES-GCM with the `encrypt` usage; otherwise
  `ERR_INVALID_AES_KEY`. It need not be extractable.
- No registry, and `keyId` is not added to the `create` / `encryptKey`
  return value. Callers call `keyId(result.key)`.

Amended 2026-11-02 (0.4.0): `verifyKeyId(key, expected)` resolves `true`
or `false` with a constant-time comparison (early `false` on length
mismatch, since length is public). Errors from `keyId` propagate rather
than resolving `false`, so "cannot fingerprint this key" is never read as
"wrong key". The planned `ERR_UNKNOWN_KEY` code was dropped: with no
registry there is no unknown-key state.

## Consequences

- Works on any usable AES-GCM key, in any session, without its bytes.
- The derivation and constants in `src/constants.ts` are permanent wire
  format. Changing any of them invalidates every stored `keyId`, with no
  migration path. A new scheme would need a new label (`.../v2`).
- Not byte-compatible with the app's old `commitmentForKey`; persisted
  values had to be recomputed.
- A decrypt-only key cannot be fingerprinted.
- Publishing a `keyId` reveals nothing useful about the key, given the
  key is uniformly random.
