# ADR-006: A supplied CryptoKey is returned by identity

**Date:** 2026-11-02

## Context

When a caller passed their own `CryptoKey` to `encryptKey` or `encrypt`,
the library exported its bytes, wrapped them, and returned a *different*
key re-imported from those bytes. Once
[ADR-005](ADR-005-non-extractable-aes-keys-by-default.md) made imported
keys non-extractable by default, a caller who passed in an extractable
key got back a downgraded copy. The copy also always carried
`['encrypt', 'decrypt']`, so a decrypt-only key silently gained the
`encrypt` usage. A return value that callers had to know to ignore was
the opposite of what a return value implies.

This was specified in the 0.3.0 spec (Change 2b) but shipped in 0.4.0.

## Decision

When `aesKey` is a `CryptoKey`, `encryptKey` returns `{ wrapped, key }`
with `key === aesKey`: same object, same `extractable`, same usages. No
re-import happens on that path, and `opts.extractable` is ignored for it.

- The input constraints are unchanged: the key must be extractable and
  export to 16 or 32 bytes, and it must be an AES-GCM key. Each violation
  throws `ERR_INVALID_AES_KEY`.
- The library no longer launders usages. `encryptKey` still wraps a
  decrypt-only key, since wrapping never encrypts with it.
- `encrypt` / `encrypt.asString` encrypt the message under the caller's
  own key, so they check for the `encrypt` usage up front and throw
  `ERR_INVALID_AES_KEY` before doing any wrapping work.
- `create` and `open` are unaffected; neither receives a key.

## Consequences

- The key a caller holds and the key the library reports are the same
  object, so there is never a weaker duplicate in memory.
- Breaking for callers who relied on the copy to add an `encrypt` usage
  their key lacked. The consuming app updates in lockstep (see
  [ADR-010](ADR-010-breaking-changes-without-shims.md)), so no shim is
  carried.
- The return type does not tell a caller whether `key` is theirs or
  newly imported; that depends on which `aesKey` form they passed.
