# ADR-008: One HpkeError class with stable string codes

**Date:** 2026-08-21

## Context

Before 0.3.0, an AEAD tag mismatch escaped as WebCrypto's bare
`OperationError`, with no library identity and nothing for a caller to
branch on. Other failures threw plain `Error`s that callers could only
pattern-match by message text.

The package ships ESM, CJS, and minified builds of each. A consumer can
end up with two copies loaded, in which case `instanceof` against a
subclass from the other copy silently returns `false`.

## Decision

Every error the package throws is an `HpkeError` (in `src/errors.ts`, a
leaf module to avoid deepening the `index.ts` / `util.ts` import cycle)
with `name === 'HpkeError'` and a `readonly code:HpkeErrorCode`:

`ERR_INVALID_RECIPIENT_KEY`, `ERR_INVALID_KEYPAIR`, `ERR_SMALL_ORDER_KEY`,
`ERR_MALFORMED_ENVELOPE`, `ERR_MALFORMED_MESSAGE`, `ERR_INVALID_KEYSIZE`,
`ERR_INVALID_AES_KEY`, `ERR_DECRYPT_FAILED`.

- One class with a code string, not a class per failure, so
  `err.code === '...'` works across duplicate copies.
- Codes are public API; message text is not. Tests assert on codes.
- Inputs are validated up front so WebCrypto errors do not escape.
  Where a WebCrypto failure is wrapped, the original goes on `cause`,
  not in the message.
- Wrong keypair, wrong `info`, and tampered ciphertext all surface as the
  single `ERR_DECRYPT_FAILED`. Distinguishing them would hand an attacker
  a decryption oracle, and WebCrypto reports them identically anyway.

## Consequences

- Callers can switch exhaustively on `HpkeErrorCode`.
- Adding a code is additive; renaming or removing one is breaking.
- A caller cannot tell version skew or a wrong `info` from an attack;
  that is intentional.
- As of 2026-11-02 the invariant had eight known gaps, all on inputs
  that type-check, where a raw `DOMException` or `uint8arrays` error
  escaped instead of an `HpkeError`. They mattered because a
  `DOMException` carries a legacy numeric `code`, so a leaked one looked
  superficially like a coded error while matching no `HpkeErrorCode`.
  On 2026-11-02 all eight were closed, each mapped to an existing code
  with no new codes; see `.scratch/hpke-error-coverage/spec.md`.
- One known gap remains: `encrypt.asString` with an unsupported
  `opts.encoding` still throws the `uint8arrays` `Error`. The option is
  typed as a closed string union, so only untyped callers reach it, and
  no existing code fits a sender-side option error. Adding a code for it
  is a separate decision.
