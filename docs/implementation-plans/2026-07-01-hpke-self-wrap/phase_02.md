# HPKE Self-Wrap Implementation Plan — Phase 2

**Goal:** Implement `seal` and `open` (plus their key/utility helpers) so an AES
key can be wrapped to a keypair's own public key and recovered.

**Architecture:** `seal` resolves raw AES key bytes (generate, or export a
supplied key), calls the vendored `suite.Seal(publicKey, keyBytes, { info })`,
concatenates `enc ‖ ciphertext` into the envelope, and returns both the envelope
and a usable AES-GCM `CryptoKey`. `open` slices the envelope, calls
`suite.Open(privateKey, enc, ciphertext, { info })`, and imports the recovered
bytes as an AES-GCM `CryptoKey`.

**Tech Stack:** TypeScript, WebCrypto (`globalThis.crypto`), the vendored
`hpke` suite from Phase 1, tapzero for tests.

**Scope:** Phase 2 of 4 from `docs/design-plans/2026-07-01-hpke-self-wrap.md`.

**Codebase verified:** 2026-07-02

---

## Acceptance Criteria Coverage

This phase implements and tests:

### hpke-self-wrap.AC1: Wrap and recover an AES key
- **hpke-self-wrap.AC1.1 Success:** `seal(keypair)` with no `aesKey` returns
  `{ wrapped, key }`; `open(keypair, wrapped)` recovers a key whose raw bytes
  equal the generated key's raw bytes.
- **hpke-self-wrap.AC1.2 Success:** The `key` returned by `seal` and the key
  returned by `open` decrypt each other's AES-GCM ciphertext (cross-use).
- **hpke-self-wrap.AC1.3 Success:** `seal(keypair, myKey)` with a caller-supplied
  extractable AES-GCM key seals that key; `open` recovers matching raw bytes.
- **hpke-self-wrap.AC1.4 Edge:** `keysize:128` yields a 16-byte key and
  `keysize:256` a 32-byte key; both round-trip successfully.
- **hpke-self-wrap.AC1.5 Failure:** `seal` with a non-extractable supplied
  `aesKey` throws a clear error (its bytes cannot be exported to be sealed).
- **hpke-self-wrap.AC1.6 Failure:** `seal` with a `keysize` other than
  128/192/256 throws before performing any crypto.

### hpke-self-wrap.AC3: Integrity and semantic security
- **hpke-self-wrap.AC3.4 Success:** Sealing the same key twice yields two
  different envelopes.

---

## Verified API facts (from research, 2026-07-02)

- `suite.Seal(publicKey:CryptoKey, plaintext:Uint8Array, { info?:Uint8Array })`
  → `Promise<{ encapsulatedSecret:Uint8Array; ciphertext:Uint8Array }>`.
- `suite.Open(privateKey:CryptoKey, encapsulatedSecret:Uint8Array,
  ciphertext:Uint8Array, { info?:Uint8Array })` → `Promise<Uint8Array>`; throws
  `OpenError` on auth failure. The private key may be **non-extractable**.
- All byte params are `Uint8Array`. `suite.KEM.Nenc === 32` (X25519 `enc`
  length). AES-GCM auth tag is 16 bytes.
- `info` must be identical on seal and open; default is an empty `Uint8Array`.

---

<!-- START_SUBCOMPONENT_A (tasks 1-4) -->

<!-- START_TASK_1 -->
### Task 1: Key and utility helpers

**Verifies:** supports AC1.1–AC1.6, AC3.4 (no direct tests; exercised via
`seal`/`open` in Task 4).

**Files:**
- Modify: `src/index.ts` (add helpers + a `subtle` alias below the `suite`
  constant, and un-export `suite`)

**Implementation:**

Add these to `src/index.ts`. Keep repo style (4-space indent, no semicolons,
single quotes, `foo:Bar` type colons, **`{a:1}` object-literal colons — no
space after the colon** (`@stylistic/key-spacing`), `A|B` unions, <= 80 cols).

```ts
const subtle = globalThis.crypto.subtle

// X25519 encapsulated-key length (bytes) and AES-GCM auth-tag length (bytes).
const ENC_LENGTH = suite.KEM.Nenc
const AEAD_TAG_LENGTH = 16

function validateKeysize (keysize:number):void {
    if (keysize !== 128 && keysize !== 192 && keysize !== 256) {
        throw new Error(
            `invalid keysize: ${keysize} (expected 128, 192, or 256)`
        )
    }
}

function normalizeInfo (info?:Uint8Array|string):Uint8Array {
    if (info === undefined || info === null) return new Uint8Array(0)
    if (typeof info === 'string') return new TextEncoder().encode(info)
    return info
}

async function exportAesKeyBytes (key:CryptoKey):Promise<Uint8Array> {
    if (!key.extractable) {
        throw new Error(
            'aesKey must be extractable: its raw bytes are what get sealed'
        )
    }
    return new Uint8Array(await subtle.exportKey('raw', key))
}

async function importAesKey (raw:Uint8Array):Promise<CryptoKey> {
    return subtle.importKey(
        'raw',
        raw,
        { name:'AES-GCM' },
        true,
        ['encrypt', 'decrypt']
    )
}

function concat (a:Uint8Array, b:Uint8Array):Uint8Array {
    const out = new Uint8Array(a.length + b.length)
    out.set(a, 0)
    out.set(b, a.length)
    return out
}
```

**Also make `suite` internal.** In `src/index.ts`, change the Phase 1
`export const suite = new CipherSuite(...)` to a plain `const suite =
new CipherSuite(...)` (drop the `export` keyword). It was exported in Phase 1
only to avoid an unused-var lint error before `seal`/`open` existed; now these
helpers/functions consume it. Keeping it internal also keeps the emitted
`dist/index.d.ts` free of the vendored `CipherSuite` type (see the note below).
`seal`/`open` reference only `CryptoKeyPair`, `CryptoKey`, `Uint8Array`, and
`HpkeOpts`, so once `suite` is unexported the public declaration imports nothing
from `./vendor/hpke/`.

Notes:
- `exportAesKeyBytes` checks `extractable` **first**, giving AC1.5 a clear,
  specific error before any crypto call.
- Returned keys are `extractable` and usable for `['encrypt','decrypt']` so a
  recovered key can be cross-used (AC1.2) and re-sealed later.
- **Why unexport `suite`:** if it stayed exported, `tsc --emitDeclarationOnly`
  would put `import { CipherSuite } from './vendor/hpke/index.js'` into
  `dist/index.d.ts`, but the vendored `.d.ts` is never copied into `dist/`
  (esbuild `--bundle` inlines only JS). Internalizing `suite` avoids that
  dangling declaration import entirely.

**Verification:** deferred to Task 4 (helpers are exercised through
`seal`/`open`).

**Commit:** `feat: add key and envelope helpers for seal/open`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: `seal`

**Verifies:** contributes to AC1.1, AC1.3, AC1.4, AC1.5, AC1.6, AC3.4 (tested in
Task 4).

**Files:**
- Modify: `src/index.ts` (add the exported `seal` function)

**Implementation:**

```ts
/**
 * Wrap an AES key to your own public key.
 *
 * @param keypair An X25519 `CryptoKeyPair` (the private key may be
 *   non-extractable).
 * @param aesKey Optional AES-GCM key to seal. Omit to generate a fresh
 *   extractable key of `opts.keysize` bits. If supplied it MUST be extractable
 *   (its raw bytes are sealed).
 * @param opts `keysize` (128/192/256, default 256; ignored when `aesKey` is
 *   supplied) and `info` (bound into the HPKE key schedule; default empty).
 * @returns The envelope bytes and a usable AES-GCM `CryptoKey`.
 */
export async function seal (
    keypair:CryptoKeyPair,
    aesKey?:CryptoKey|null,
    opts?:HpkeOpts
):Promise<{ wrapped:Uint8Array; key:CryptoKey }> {
    const info = normalizeInfo(opts?.info)

    let keyBytes:Uint8Array
    if (aesKey) {
        keyBytes = await exportAesKeyBytes(aesKey)
    } else {
        const keysize = opts?.keysize ?? 256
        validateKeysize(keysize)
        keyBytes = globalThis.crypto.getRandomValues(
            new Uint8Array(keysize / 8)
        )
    }

    const { encapsulatedSecret, ciphertext } = await suite.Seal(
        keypair.publicKey,
        keyBytes,
        { info }
    )

    const wrapped = concat(encapsulatedSecret, ciphertext)
    const key = await importAesKey(keyBytes)
    return { wrapped, key }
}
```

Notes:
- `keysize` is validated **before** generating random bytes, so an invalid
  `keysize` (with no `aesKey`) throws before any crypto (AC1.6). When `aesKey`
  is supplied, `keysize` is ignored (per design).
- Each call produces a fresh ephemeral `enc`, so two seals of the same key
  differ (AC3.4).

**Verification:** deferred to Task 4.

**Commit:** `feat: add seal (wrap an AES key to your own public key)`
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: `open`

**Verifies:** contributes to AC1.1, AC1.2, AC1.3, AC1.4 (tested in Task 4; also
underpins the Phase 3 negative cases).

**Files:**
- Modify: `src/index.ts` (add the exported `open` function)

**Implementation:**

```ts
/**
 * Recover an AES key that was wrapped with `seal`, using your private key.
 *
 * @param keypair The same X25519 `CryptoKeyPair` used to seal.
 * @param wrapped The envelope returned by `seal` (`enc ‖ ciphertext`).
 * @param opts `info` — must match the value passed to `seal`.
 * @returns The recovered AES-GCM `CryptoKey` (extractable).
 */
export async function open (
    keypair:CryptoKeyPair,
    wrapped:Uint8Array,
    opts?:Pick<HpkeOpts, 'info'>
):Promise<CryptoKey> {
    if (wrapped.byteLength < ENC_LENGTH + AEAD_TAG_LENGTH) {
        throw new Error('malformed envelope: too short')
    }

    const info = normalizeInfo(opts?.info)
    const enc = wrapped.slice(0, ENC_LENGTH)
    const ciphertext = wrapped.slice(ENC_LENGTH)

    const keyBytes = await suite.Open(
        keypair.privateKey,
        enc,
        ciphertext,
        { info }
    )
    return importAesKey(keyBytes)
}
```

Notes:
- The length guard is a **loose lower bound** for obviously-malformed input:
  `ENC_LENGTH + AEAD_TAG_LENGTH` = 48, whereas the smallest real envelope is 64
  bytes (128-bit key → 32-byte `enc` + 16-byte plaintext + 16-byte tag). That is
  intentional — it is not a full validity check. It catches the AC3.5 case (a
  10-byte buffer); inputs of 48–63 bytes pass the guard and then fail inside
  `suite.Open` with the generic `OpenError`. Both paths reject; only the message
  differs.
- Tampered bytes / wrong key / mismatched `info` surface as the vendored
  `OpenError` from `suite.Open` (Phase 3's AC3.1–AC3.3).
- `slice` copies out standalone `Uint8Array`s for the vendored call.

**Verification:** deferred to Task 4.

**Commit:** `feat: add open (recover a wrapped AES key)`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Tests for `seal` / `open`

**Verifies:** hpke-self-wrap.AC1.1, AC1.2, AC1.3, AC1.4, AC1.5, AC1.6, AC3.4.

**Files:**
- Modify: `test/index.ts` — **replace** the Phase 1 `suite` smoke test (its
  `import { suite }` no longer resolves now that `suite` is internal) with these
  tests. The new file imports `{ seal, open }` instead of `{ suite }`. They run
  in both runtimes because `test/node.ts` re-imports this file.
- Test type: unit. Test command: `npm test` (browser/headless) and
  `npm run test:node` (Node).

**Testing:**

Tests must verify each AC. `tapzero`'s `t` has `ok`, `equal`, `deepEqual`; for
async rejections use a `try/catch` + `t.ok(threw)` pattern (do not assume a
`t.rejects` helper exists). Use a locally-generated X25519 keypair (this also
exercises non-extractable private keys). Reference implementation:

```ts
import { test } from '@substrate-system/tapzero'
import { seal, open } from '../src/index.js'

const subtle = globalThis.crypto.subtle

async function genKeypair ():Promise<CryptoKeyPair> {
    return subtle.generateKey(
        { name:'X25519' },
        false,                 // non-extractable private key
        ['deriveBits']
    ) as Promise<CryptoKeyPair>
}

async function raw (key:CryptoKey):Promise<Uint8Array> {
    return new Uint8Array(await subtle.exportKey('raw', key))
}

function bytesEqual (a:Uint8Array, b:Uint8Array):boolean {
    if (a.byteLength !== b.byteLength) return false
    for (let i = 0; i < a.byteLength; i++) {
        if (a[i] !== b[i]) return false
    }
    return true
}
```

- **AC1.1:** `const { wrapped, key } = await seal(kp)`; `const recovered = await
  open(kp, wrapped)`; assert `bytesEqual(await raw(key), await raw(recovered))`.
- **AC1.2:** With `key` (from seal) and `recovered` (from open): AES-GCM encrypt
  a plaintext under `key` with a random 12-byte IV, decrypt under `recovered`,
  and assert the plaintext round-trips — then repeat encrypting under
  `recovered` and decrypting under `key`.
- **AC1.3:** Generate an **extractable** AES-GCM key
  (`subtle.generateKey({ name:'AES-GCM', length:256 }, true,
  ['encrypt','decrypt'])`); `seal(kp, myKey)`; `open` it; assert the recovered
  raw bytes equal `await raw(myKey)`.
- **AC1.4:** `seal(kp, null, { keysize:128 })` → open → assert recovered raw
  `byteLength === 16`; `seal(kp, null, { keysize:256 })` → open → assert
  `byteLength === 32`.
- **AC1.5:** Generate a **non-extractable** AES-GCM key (pass `false` as the
  `extractable` arg to `generateKey`); `await seal(kp, myKey)` inside
  `try/catch`; assert it threw (the error is the "must be extractable" message
  from `exportAesKeyBytes`).
- **AC1.6:** `await seal(kp, null, { keysize:100 as any })` inside `try/catch`;
  assert it threw. (Cast is test-only, to pass an out-of-range value past the
  literal type.)
- **AC3.4:** `const a = await seal(kp, myKey)`; `const b = await seal(kp, myKey)`
  (same extractable key); assert `!bytesEqual(a.wrapped, b.wrapped)`.

**Verification:**

```bash
npm run lint
```
Expected: passes (confirms the new `src/index.ts` and `test/index.ts` are
clean — including object-literal `{a:1}` colons — so Phase 2 is lint-green
independently, not only at Phase 3).

```bash
npm test
```
Expected: all Phase 2 tests pass headless.

```bash
npm run test:node
```
Expected: the same tests pass under Node (exit 0). If Node lacks X25519
WebCrypto, upgrade Node (>= 20.19; stable >= 23.5) rather than weakening the
test.

**Commit:** `test: cover seal/open round-trip, sizing, byo key, and rejections`
<!-- END_TASK_4 -->

<!-- END_SUBCOMPONENT_A -->
