# ADR-005: Returned AES keys are non-extractable by default

**Date:** 2026-08-21

## Context

Before 0.3.0, `create`, `encryptKey`, and `open` always returned an
extractable AES-GCM key because `importAesKey` hardcoded `true`. The
consuming chat app holds a room conversation key, which decrypts every
stored message, in memory for a whole session. It needed that key
extractable only so it could hash it into an identifier. That sat badly
next to the app's own runtime assertion that identity private keys are
non-extractable.

## Decision

`create`, `encryptKey`, and `open` return a **non-extractable** AES-GCM
key unless the caller passes `opts.extractable: true`.

- `opts.extractable` governs only keys the library imports: a generated
  key, a raw `Uint8Array` key, or the key `open` recovers. A supplied
  `CryptoKey` is returned untouched (see
  [ADR-006](ADR-006-supplied-key-returned-by-identity.md)).
- Callers who need bytes have `open.raw`, which returns the raw key and
  takes no `extractable` option, or can opt in explicitly.
- `decrypt` imports its message key non-extractable and decrypt-only,
  since that key never leaves the library.

This is the opposite of the **input** rule: a supplied `aesKey`
`CryptoKey` must be extractable, because its raw bytes are what get
sealed. The two rules must not be conflated.

## Consequences

- A key that never needs to leave the runtime cannot be exported by
  accident or by injected script.
- Callers lose the ability to hash the key's bytes to identify it, which
  motivated `keyId` (see
  [ADR-007](ADR-007-keyid-from-key-behavior.md)).
- Breaking change in 0.3.0 for callers that exported the returned key.
- The non-extractable default does not protect a key wrapped from
  caller-supplied raw bytes; the caller already holds those bytes.
