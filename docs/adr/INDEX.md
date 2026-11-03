# Architecture Decision Records

Each ADR records one decision: its context, what was decided, and the
consequences. Dates are when the decision landed, taken from git history.
Read this index first, then only the ADRs that touch your area.

To add one, take the next number, copy the template from an existing
ADR, and add a row below. To reverse a decision, write a new ADR and note
the replacement in the old one.

| # | Decision | Date |
|---|----------|------|
| [ADR-001](ADR-001-standardized-hpke-over-bespoke-ecies.md) | Standardized RFC 9180 HPKE over bespoke ECIES | 2026-07-01 |
| [ADR-002](ADR-002-first-party-hpke-on-webcrypto.md) | First-party HPKE on WebCrypto, no HPKE library | 2026-07-02 |
| [ADR-003](ADR-003-one-fixed-cipher-suite.md) | One fixed, non-configurable cipher suite | 2026-07-01 |
| [ADR-004](ADR-004-minimal-unversioned-wire-formats.md) | Minimal, unversioned wire formats | 2026-07-02 |
| [ADR-005](ADR-005-non-extractable-aes-keys-by-default.md) | Returned AES keys are non-extractable by default | 2026-08-21 |
| [ADR-006](ADR-006-supplied-key-returned-by-identity.md) | A supplied CryptoKey is returned by identity | 2026-11-02 |
| [ADR-007](ADR-007-keyid-from-key-behavior.md) | keyId is derived from a key's behavior, not its bytes | 2026-08-21 |
| [ADR-008](ADR-008-single-error-class-with-stable-codes.md) | One HpkeError class with stable string codes | 2026-08-21 |
| [ADR-009](ADR-009-flexible-recipient-forms.md) | Several recipient key forms; uint8arrays as sole dependency | 2026-07-02 |
| [ADR-010](ADR-010-breaking-changes-without-shims.md) | Breaking API changes ship without compatibility shims | 2026-08-21 |
