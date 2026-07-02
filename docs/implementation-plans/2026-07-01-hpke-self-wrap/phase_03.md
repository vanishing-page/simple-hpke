# HPKE Self-Wrap Implementation Plan — Phase 3

**Goal:** Prove the `@substrate-system/keys` integration requirement, cover the
failure/tamper cases, and confirm the whole suite passes in both runtimes.

**Architecture:** No new production code — this phase is tests. It mints the
long-term keypair with `EccKeys.create()`, assembles a `CryptoKeyPair` from the
exchange-key getters, and round-trips it through `seal`/`open`. It adds negative
tests (tamper, wrong keypair, mismatched `info`, malformed envelope) and runs
the full suite under both `npm test` and `npm run test:node`.

**Tech Stack:** TypeScript, WebCrypto, `@substrate-system/keys@^0.2.41`
(devDependency, already installed), tapzero.

**Scope:** Phase 3 of 4 from `docs/design-plans/2026-07-01-hpke-self-wrap.md`.

**Codebase verified:** 2026-07-02

---

## Acceptance Criteria Coverage

This phase implements and tests:

### hpke-self-wrap.AC2: Works with @substrate-system/keys
- **hpke-self-wrap.AC2.1 Success:** A keypair from `EccKeys.create()` (default
  non-extractable exchange keys) round-trips through `seal`/`open`.
- **hpke-self-wrap.AC2.2 Success:** The keypair assembled from the `EccKeys`
  `publicExchangeKey` / `privateExchangeKey` getters works as the `seal`/`open`
  keypair.

### hpke-self-wrap.AC3: Integrity and semantic security
- **hpke-self-wrap.AC3.1 Failure:** A tampered envelope (one flipped byte) causes
  `open` to reject.
- **hpke-self-wrap.AC3.2 Failure:** `open` with a different keypair rejects.
- **hpke-self-wrap.AC3.3 Failure:** A mismatched `info` between `seal` and `open`
  rejects.
- **hpke-self-wrap.AC3.5 Edge:** A malformed or too-short envelope throws a clear
  error.

### hpke-self-wrap.AC4: Cross-runtime
- **hpke-self-wrap.AC4.1:** The test suite passes in Node (`npm run test:node`).
- **hpke-self-wrap.AC4.2:** The test suite passes in the browser/headless run
  (`npm test`).

---

## Verified integration facts (from research, 2026-07-02)

- Import: `import { EccKeys } from '@substrate-system/keys/ecc'`.
- `EccKeys.create(session?:boolean, extractable?:boolean, keys?)` → `Promise`;
  `extractable` defaults to **false** (non-extractable exchange keys).
- Exchange-key getters are **synchronous** and return WebCrypto `CryptoKey`s:
  `keys.publicExchangeKey`, `keys.privateExchangeKey`. The exchange algorithm is
  **X25519** — compatible with the suite's `DHKEM(X25519, HKDF-SHA256)`.
- Assemble directly: `{ publicKey:keys.publicExchangeKey,
  privateKey:keys.privateExchangeKey }`.
- (`EccKeys` also has its own `wrap`/`unwrap`; this package deliberately does
  not use them — interop is at the "same keypair" level only.)

**Style:** test code must follow repo lint — object-literal key colons take **no
space** (`{a:1}`, via `@stylistic/key-spacing`), same as type-annotation colons.

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: `@substrate-system/keys` integration tests

**Verifies:** hpke-self-wrap.AC2.1, hpke-self-wrap.AC2.2.

**Files:**
- Modify: `test/index.ts` (append; runs in both runtimes via `test/node.ts`)
- Test type: integration. Commands: `npm test`, `npm run test:node`.

**Testing:**

Mint the keypair with `EccKeys.create()` and round-trip through `seal`/`open`.
Reference:

```ts
import { EccKeys } from '@substrate-system/keys/ecc'

async function eccKeypair ():Promise<CryptoKeyPair> {
    const keys = await EccKeys.create()          // non-extractable by default
    return {
        publicKey:keys.publicExchangeKey,
        privateKey:keys.privateExchangeKey
    }
}
```

- **AC2.1:** `const kp = await eccKeypair()`; `const { wrapped, key } = await
  seal(kp)`; `const recovered = await open(kp, wrapped)`; assert the recovered
  raw bytes equal `key`'s raw bytes (reuse the `raw`/`bytesEqual` helpers from
  the Phase 2 tests).
- **AC2.2:** Explicitly assemble the pair from the two getters (as
  `eccKeypair` does), seal a caller-supplied extractable AES key with it, open
  it, and assert the recovered raw bytes match — demonstrating the getters'
  `CryptoKey`s are directly usable as the `seal`/`open` keypair.

**Verification:**

```bash
npm test && npm run test:node
```
Expected: the new integration tests pass in both runtimes.

**Commit:** `test: integrate @substrate-system/keys EccKeys with seal/open`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Negative / integrity tests

**Verifies:** hpke-self-wrap.AC3.1, AC3.2, AC3.3, AC3.5.

**Files:**
- Modify: `test/index.ts` (append)
- Test type: unit/integration. Commands: `npm test`, `npm run test:node`.

**Testing:**

Use the `try/catch` + `t.ok(threw)` pattern for every rejection (no assumption
of a `t.rejects` helper). Reuse the Phase 2 `genKeypair` (local X25519) and the
`raw`/`bytesEqual` helpers.

- **AC3.1 (tamper):** `seal(kp)` → copy `wrapped`, flip one byte in the
  ciphertext region (`copy[copy.length - 1] ^= 0xff`) → `open(kp, copy)` inside
  `try/catch` → assert it threw.
- **AC3.2 (wrong keypair):** `seal(kpA)` → `open(kpB, wrapped)` with a second,
  independently-generated keypair inside `try/catch` → assert it threw.
- **AC3.3 (mismatched info):** `seal(kp, null, { info:'context-a' })` →
  `open(kp, wrapped, { info:'context-b' })` inside `try/catch` → assert it
  threw. Also assert the matching-`info` case succeeds (sanity: `info:'context-a'`
  on both sides round-trips).
- **AC3.5 (malformed/too-short):** `open(kp, new Uint8Array(10))` inside
  `try/catch` → assert it threw with the "malformed envelope" error (the length
  guard fires before any crypto).

Do not assert on which internal check failed — tamper / wrong-key / mismatched
`info` all surface as a single generic rejection by design.

**Verification:**

```bash
npm test && npm run test:node
```
Expected: all negative tests pass in both runtimes.

**Commit:** `test: cover tamper, wrong-key, mismatched-info, malformed envelope`
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_TASK_3 -->
### Task 3: Confirm cross-runtime gate

**Verifies:** hpke-self-wrap.AC4.1, hpke-self-wrap.AC4.2 (and re-confirms
AC5.1/AC5.2 from Phase 1).

**No new files.** Operational gate for the phase.

**Verification (all must hold):**

```bash
npm run lint
```
Expected: passes.

```bash
npm test
```
Expected: the full suite (smoke + Phase 2 + Phase 3) passes headless — AC4.2.

```bash
npm run test:node
```
Expected: the full suite passes under Node, exit 0 — AC4.1.

Also re-confirm AC5: `package.json` still declares **no** `hpke` (or other
crypto) runtime dependency, and `src/vendor/hpke/LICENSE.md` is present.

If Node fails only for lack of X25519 WebCrypto, upgrade Node (>= 20.19; stable
>= 23.5) — do not weaken the tests.

**Commit:** none (verification only).
<!-- END_TASK_3 -->
