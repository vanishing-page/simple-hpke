# ADR-004: Minimal, unversioned wire formats

**Date:** 2026-07-02

## Context

The package produces two byte formats:

1. A wrapped key, from `create` / `encryptKey`, consumed by `open` /
   `open.raw`.
2. A message envelope, from `encrypt`, consumed by `decrypt`.

HPKE derives the AEAD nonce from the key schedule, so a wrapped key needs
no stored salt or IV. The message envelope holds a wrapped key whose
length depends on the AES key size (64 bytes for 128-bit, 80 for
256-bit), so the reader cannot locate the IV without being told.

## Decision

Wrapped key:

```
enc(32) || ciphertext
```

`enc` is the ephemeral X25519 public key; `ciphertext` is the AEAD output
(key bytes plus a 16-byte tag). Nothing else.

Message envelope:

```
wrappedLen(2, big-endian u16) || wrapped || iv(12) || ciphertext
```

The length prefix lets `decrypt` slice out the wrapped key for either key
size. The message body uses a fresh random 96-bit IV per call.

Neither format has a version byte or suite identifier. The returned field
is named `wrapped`, not `enc`: in RFC 9180 `enc` is the KEM output alone,
and the value returned is `enc || ciphertext` (renamed in 0.3.0).

## Consequences

- Smallest possible output, and a wrapped key is byte-identical to a raw
  RFC 9180 single-shot seal, so other HPKE implementations can open it.
- Wire formats have not changed since 0.2.x; the known-answer fixture
  test in `test/index.ts` must keep passing untouched.
- There is no in-band way to evolve the format. Any future change needs a
  new format that callers distinguish out of band, or a breaking release
  where old envelopes stop opening.
- `decrypt` validates the declared segment lengths up front and throws
  `ERR_MALFORMED_MESSAGE`; `open` throws `ERR_MALFORMED_ENVELOPE` for
  input shorter than `enc` plus a tag.
- Reusing one supplied `aesKey` across many `encrypt` calls carries the
  random-nonce birthday bound (about 2^32 messages, NIST SP 800-38D). The
  default, a fresh key per call, avoids it.
