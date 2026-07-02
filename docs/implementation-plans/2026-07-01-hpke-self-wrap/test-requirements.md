# HPKE Self-Wrap — Test Requirements

Maps every acceptance criterion from
`docs/design-plans/2026-07-01-hpke-self-wrap.md` to a specific automated test,
an operational/inspection check, or a documented human review. Automated tests
use tapzero, live in `test/index.ts`, and run in both runtimes: `test/node.ts`
re-imports `test/index.ts` so `npm run test:node` (esbuild-bundle then Node) and
`npm test` (browser/headless via tapout) exercise the same suite.

## Automated tests

All rows below live in `test/index.ts` and are exercised by **both**
`npm test` and `npm run test:node`.

| AC id | Description | Type | Test file | Commands |
|-------|-------------|------|-----------|----------|
| `hpke-self-wrap.AC1.1` | `seal(keypair)` with no `aesKey` round-trips; `open` recovers raw bytes equal to the generated key | unit | `test/index.ts` | `npm test`, `npm run test:node` |
| `hpke-self-wrap.AC1.2` | Sealed `key` and opened key decrypt each other's AES-GCM ciphertext (cross-use) | unit | `test/index.ts` | `npm test`, `npm run test:node` |
| `hpke-self-wrap.AC1.3` | Caller-supplied extractable AES-GCM key is sealed; `open` recovers matching raw bytes | unit | `test/index.ts` | `npm test`, `npm run test:node` |
| `hpke-self-wrap.AC1.4` | `keysize:128` -> 16-byte key, `keysize:256` -> 32-byte key; both round-trip | unit | `test/index.ts` | `npm test`, `npm run test:node` |
| `hpke-self-wrap.AC1.5` | `seal` with a non-extractable supplied `aesKey` throws a clear error (try/catch + assert-threw; before crypto) | unit | `test/index.ts` | `npm test`, `npm run test:node` |
| `hpke-self-wrap.AC1.6` | `seal` with an out-of-range `keysize` throws before any crypto (try/catch + assert-threw) | unit | `test/index.ts` | `npm test`, `npm run test:node` |
| `hpke-self-wrap.AC2.1` | Keypair from `EccKeys.create()` (default non-extractable exchange keys) round-trips through `seal`/`open` | integration | `test/index.ts` | `npm test`, `npm run test:node` |
| `hpke-self-wrap.AC2.2` | Keypair assembled from `publicExchangeKey`/`privateExchangeKey` getters works as the `seal`/`open` keypair | integration | `test/index.ts` | `npm test`, `npm run test:node` |
| `hpke-self-wrap.AC3.1` | Tampered envelope (one flipped byte) causes `open` to reject | unit | `test/index.ts` | `npm test`, `npm run test:node` |
| `hpke-self-wrap.AC3.2` | `open` with a different keypair rejects | unit | `test/index.ts` | `npm test`, `npm run test:node` |
| `hpke-self-wrap.AC3.3` | Mismatched `info` between `seal` and `open` rejects (and matching `info` succeeds) | unit | `test/index.ts` | `npm test`, `npm run test:node` |
| `hpke-self-wrap.AC3.4` | Sealing the same key twice yields two different envelopes (semantic security) | unit | `test/index.ts` | `npm test`, `npm run test:node` |
| `hpke-self-wrap.AC3.5` | Malformed / too-short envelope throws a clear error (length guard, before crypto) | unit | `test/index.ts` | `npm test`, `npm run test:node` |
| `hpke-self-wrap.AC4.1` | The full test suite passes in Node | cross-runtime gate (whole suite) | `test/index.ts` (via `test/node.ts`) | `npm run test:node` |
| `hpke-self-wrap.AC4.2` | The full test suite passes in the browser/headless run | cross-runtime gate (whole suite) | `test/index.ts` | `npm test` |

Notes:
- AC1.5 and AC1.6 are throw-before-crypto cases; the async rejection is asserted
  with a `try/catch` + assert-threw pattern (no assumed `t.rejects`).
- AC3.1–AC3.3 all surface as a single generic HPKE rejection by design; tests
  assert only that `open` threw, not which internal check failed.
- AC4.1/AC4.2 are not distinct tests: they are the cross-runtime gate satisfied
  by running the whole `test/index.ts` suite under `npm run test:node` (AC4.1)
  and `npm test` (AC4.2) respectively.

## Verified operationally / by inspection

| AC id | Description | How it is checked |
|-------|-------------|-------------------|
| `hpke-self-wrap.AC5.1` | `package.json` declares no `hpke` (or other crypto) runtime dependency; HPKE is imported from `src/vendor/hpke/` | Inspect `package.json` — confirm no `hpke`/crypto entry under `dependencies`; confirm `src/index.ts` imports the suite from `./vendor/hpke/index.js`. Build spot-check (`grep -c "vendor/hpke" dist/index.js dist/index.cjs`) confirms the vendored code is inlined, not left as a dangling dependency. |
| `hpke-self-wrap.AC5.2` | The vendored copy retains the upstream MIT `LICENSE.md` / copyright notice | Inspect `src/vendor/hpke/LICENSE.md` — confirm present and non-empty; `PROVENANCE.md` records source, version (1.1.3), and refresh steps. |

These are not unit-testable; they are verified by inspection during Phase 1 and
re-confirmed at the Phase 3 cross-runtime gate.

## Human / review verification

| Deliverable | Description | Verification approach |
|-------------|-------------|-----------------------|
| Phase 4 documentation (`docs/README.md`) | Documents `seal`/`open`, `HpkeOpts`, the wire format (`enc(32) ‖ ciphertext`), a working `@substrate-system/keys` example, and the "why HPKE" rationale | Manual review of `docs/README.md`: confirm it documents `seal(keypair, aesKey?, opts?)` -> `{ wrapped, key }`, `open(keypair, wrapped, opts?)` -> `CryptoKey`, `HpkeOpts` (`keysize`, `info`), the wire format, a runnable `EccKeys`-based example, and the rationale points (ephemeral-static ECDH, HKDF Extract-then-Expand, standardized HPKE over bespoke ECIES, non-extractable private keys, nonce safety, `info` domain separation). No automated tests (documentation phase). |
| Top-level `README.md` example | Example section shows real `seal`/`open` usage, not the removed `example()` placeholder | Manual review: confirm the Example section matches the shipped API and no longer references `example()`. |

This satisfies the design's "Best-practice research on ECC self-encryption is
folded into `docs/`" done-when condition, which carries no numbered AC.

## Coverage check

Every acceptance criterion maps to exactly one row above — no gaps, no
duplicates:

- AC1.1, AC1.2, AC1.3, AC1.4, AC1.5, AC1.6 — Automated tests (unit)
- AC2.1, AC2.2 — Automated tests (integration)
- AC3.1, AC3.2, AC3.3, AC3.4, AC3.5 — Automated tests (unit)
- AC4.1, AC4.2 — Automated tests (cross-runtime gate; whole suite)
- AC5.1, AC5.2 — Verified operationally / by inspection

17 acceptance criteria total (AC1.1–1.6, AC2.1–2.2, AC3.1–3.5, AC4.1–4.2,
AC5.1–5.2), each mapped once. The Phase 4 documentation deliverable is covered
under Human / review verification and is not a numbered AC.
