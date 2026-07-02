# HPKE Self-Wrap Design

## Summary

HPKE (RFC 9180) standardizes public-key encryption by composing a key
encapsulation mechanism, a key derivation function, and an authenticated
cipher into a single key schedule. This package uses that composition to let
a keypair wrap a symmetric AES key to its own public key — a self-encryption
pattern useful for, say, re-sealing a key to a new device using only the
existing long-term keypair. Rather than reimplement that key schedule by
hand (as the sibling `@substrate-system/keys` library already does
internally), this design vendors panva's audited `hpke` implementation into
`src/vendor/hpke/` and calls it directly. Vendoring — copying the library's
source into this repo instead of adding it to `package.json` — keeps the
published package free of runtime dependencies while still delegating the
actual cryptography to a maintained, RFC-compliant implementation. The
trade-off: security fixes upstream have to be pulled in by hand, which a
`PROVENANCE` note in the vendored directory tracks.

`seal` and `open` are a thin layer on top of that vendored suite. They
resolve or generate the AES key bytes, hand them to HPKE's `Seal`/`Open`, and
pack the result into an envelope of just the encapsulated ephemeral key plus
ciphertext — no separately stored salt or IV, since HPKE derives the AEAD
nonce internally. Both functions take a raw WebCrypto `CryptoKeyPair` rather
than the `EccKeys` class, so a caller can mint a keypair with
`@substrate-system/keys` and pass its exchange keys straight in. The two
libraries can share a keypair, but they are not wire-compatible.

## Definition of Done

- `src/index.ts` exports `seal(keypair, aesKey?, opts?)` and
  `open(keypair, wrapped, opts?)`, operating on a raw WebCrypto **X25519**
  `CryptoKeyPair` (no `EccKeys` instance required).
- `seal` wraps an AES key to the keypair's own public key and returns both the
  envelope bytes and a usable AES-GCM `CryptoKey`; `open` recovers that
  `CryptoKey`.
- An AES key is optional: if omitted, a fresh key is generated. `keysize`
  (128/192/256, default 256) sizes the generated key.
- Runs in modern browsers **and** Node (via `globalThis.crypto.subtle` and a
  vendored copy of the `hpke` library — no runtime dependency).
- Tests cover: wrap/open round-trip, integration with `@substrate-system/keys`
  (used to mint the long-term keypair), 128/256-bit keys, bring-your-own key,
  tamper / wrong-key / mismatched-`info` rejections, and semantic security.
- Best-practice research on ECC self-encryption is folded into `docs/`.

## Acceptance Criteria

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
- **hpke-self-wrap.AC3.4 Success:** Sealing the same key twice yields two
  different envelopes.
- **hpke-self-wrap.AC3.5 Edge:** A malformed or too-short envelope throws a clear
  error.

### hpke-self-wrap.AC4: Cross-runtime
- **hpke-self-wrap.AC4.1:** The test suite passes in Node (`npm run test:node`).
- **hpke-self-wrap.AC4.2:** The test suite passes in the browser/headless run
  (`npm test`).

### hpke-self-wrap.AC5: Self-contained (vendored, no runtime dependency)
- **hpke-self-wrap.AC5.1:** `package.json` declares no `hpke` (or other crypto)
  runtime dependency; HPKE is imported from `src/vendor/hpke/`.
- **hpke-self-wrap.AC5.2:** The vendored copy retains the upstream MIT
  `LICENSE.md` / copyright notice.

## Glossary

- **HPKE (Hybrid Public Key Encryption)**: An IETF standard (RFC 9180) for
  public-key encryption that composes a KEM, a KDF, and an AEAD cipher into
  one key schedule. `seal`/`open` are a thin layer over an HPKE
  implementation.
- **KEM (Key Encapsulation Mechanism)**: The part of HPKE that derives a
  shared secret from a recipient's public key and a fresh ephemeral key
  pair, producing the shared secret plus a public encapsulated key (`enc`)
  the recipient needs to reproduce it.
- **DHKEM**: A KEM built from Diffie-Hellman key exchange. This design uses
  `DHKEM(X25519, HKDF-SHA256)` — X25519 for the DH step, HKDF-SHA256 to turn
  the raw DH output into the shared secret.
- **HKDF (HMAC-based Key Derivation Function)**: Derives one or more keys
  from a secret in two steps, Extract then Expand. HPKE uses it both inside
  the KEM and to derive the final AEAD key.
- **AEAD (Authenticated Encryption with Associated Data)**: A cipher mode
  providing confidentiality and tamper detection in one operation. This
  design's cipher suite uses AES-256-GCM as its AEAD.
- **X25519**: The elliptic curve used for Diffie-Hellman key exchange in
  this design's cipher suite — the curve underlying the `CryptoKeyPair`
  that `seal`/`open` operate on.
- **Cipher suite**: The fixed combination of KEM, KDF, and AEAD algorithms
  HPKE uses for a given operation. This package hard-codes one suite at the
  module level rather than exposing it as a runtime option.
- **CryptoKeyPair**: The WebCrypto API type for a public/private key pair
  (`{ publicKey, privateKey }`). `seal`/`open` take one directly, instead of
  requiring the `EccKeys` wrapper class.
- **Extractable key**: A WebCrypto property on a `CryptoKey` controlling
  whether its raw bytes can ever be exported (e.g. via
  `crypto.subtle.exportKey`). Sealing a caller-supplied AES key requires it
  to be extractable, since its raw bytes are what gets sealed.
- **Envelope**: The byte string `seal` returns and `open` consumes — the
  encapsulated ephemeral key (`enc`) concatenated with the ciphertext, and
  nothing else.
- **Encapsulated key (`enc`)**: The serialized ephemeral public key HPKE's
  KEM step produces. It's public information the recipient needs to redo
  the DH step during `open`, and forms the first 32 bytes of the envelope.
- **`info`**: An HPKE parameter — an arbitrary byte string bound into the
  key schedule. `seal` and `open` must supply the same `info`, or
  decryption fails; it lets callers bind an envelope to a specific context
  without changing the wire format.
- **ECIES (Elliptic Curve Integrated Encryption Scheme)**: An older family
  of hybrid public-key encryption schemes combining ECDH with a symmetric
  cipher. `@substrate-system/keys` implements its own ECIES/HPKE-style
  scheme; this package uses standardized HPKE instead.
- **Ephemeral-static ECDH**: A Diffie-Hellman exchange between a fresh,
  one-time ('ephemeral') key pair and a long-lived ('static') key pair —
  the pattern HPKE's KEM performs against the caller's own keypair for
  self-wrap.
- **Semantic security**: The property that encrypting the same plaintext
  twice produces different ciphertexts, so an observer can't tell whether
  two envelopes hold the same key. AC3.4 verifies this directly.
- **Vendoring**: Copying a third-party library's source directly into this
  repo (`src/vendor/hpke/`) instead of listing it as a `package.json`
  dependency. It keeps the published package dependency-free at the cost of
  manual upstream updates.
- **`@substrate-system/keys` / `EccKeys`**: The sibling library in this
  ecosystem that mints and manages ECC keypairs. `EccKeys.create()`
  produces the non-extractable X25519 keys this design is tested against;
  the class already has its own `wrap`/`unwrap`, which this package
  deliberately doesn't reuse.

## Architecture

A thin self-encryption helper over RFC-9180 HPKE. A **vendored copy** of the
`hpke` library (panva, v1.1.3, MIT) does all cryptography; this package adds a
narrow "wrap an AES key to your own keypair" surface and an envelope format. The
library is copied into `src/vendor/hpke/` rather than taken as a dependency, so
the published package has no runtime dependencies.

**Cipher suite** (module-level constant): DHKEM(X25519, HKDF-SHA256) +
HKDF-SHA256 + AES-256-GCM, built from the vendored module's
`KEM_DHKEM_X25519_HKDF_SHA256`, `KDF_HKDF_SHA256`, and `AEAD_AES_256_GCM`.

**Public surface** (`src/index.ts`):

```ts
export interface HpkeOpts {
    keysize?:128|192|256      // size of the GENERATED key; ignored if aesKey
    info?:Uint8Array|string   // HPKE info; must match on seal + open. default ''
}

// Wrap an AES key to your own public key.
// aesKey omitted  -> generate a fresh extractable AES-GCM key of `keysize`.
// aesKey supplied -> must be extractable (its raw bytes are sealed).
export function seal (
    keypair:CryptoKeyPair,
    aesKey?:CryptoKey|null,
    opts?:HpkeOpts
):Promise<{ wrapped:Uint8Array; key:CryptoKey }>

// Recover the wrapped AES key with your private key.
export function open (
    keypair:CryptoKeyPair,
    wrapped:Uint8Array,
    opts?:Pick<HpkeOpts, 'info'>
):Promise<CryptoKey>
```

**Data flow — `seal`:** resolve key bytes (export a supplied `aesKey` as raw —
requires extractable; or generate `keysize / 8` random bytes) →
`suite.Seal(keypair.publicKey, keyBytes, { info })` →
`{ encapsulatedSecret, ciphertext }` → envelope = `enc ‖ ciphertext` → return
`{ wrapped, key }`, where `key` is the AES-GCM `CryptoKey` imported from the raw
bytes (`extractable`, usages `['encrypt','decrypt']`).

**Data flow — `open`:** slice `enc` (32 bytes) and `ciphertext` →
`suite.Open(keypair.privateKey, enc, ciphertext, { info })` → import the
recovered bytes as an AES-GCM `CryptoKey`.

**Wire format:** `enc(32) ‖ ciphertext`. 80 bytes for a 256-bit key, 64 for
128-bit. No salt or IV is stored — HPKE derives the AEAD nonce internally and
binds both public keys into its key schedule, so the envelope carries only the
encapsulated ephemeral key and the ciphertext.

**System boundary:** the keypair is supplied by the caller. HPKE needs only
`deriveBits` on the private key, so a **non-extractable** X25519 private key
works — verified against `@substrate-system/keys`' default exchange keys.

## Existing Patterns

This is a `@substrate-system` library following the nichoth/template-ts layout
already present in the repo: source in `src/`, `esbuild` producing ESM + CJS +
minified bundles (`npm run build`), and `tapzero` + `@substrate-system/tapout`
for tests. The existing `test/index.ts` is bundled for the browser/headless run
via the `test` script; `test/node.ts` is the Node entry (currently empty).

The sibling library `@substrate-system/keys` (`EccKeys`) already implements an
ECIES/HPKE-style `wrap`/`unwrap` internally on `crypto.subtle`. This package
deliberately diverges: rather than reimplement the key schedule by hand, it
**vendors** the audited `hpke` library (panva, MIT) for RFC-9180 compliance, and
exposes a functional API over a raw `CryptoKeyPair` instead of the `EccKeys`
class. The two are not wire-compatible by design; interop is at the "same
keypair" level only.

`src/index.ts` currently holds a placeholder (`example()` + a `Debug` import)
and will be replaced.

## Implementation Phases

<!-- START_PHASE_1 -->
### Phase 1: Setup and scaffolding
**Goal:** Dependency, suite constant, option types, and a working Node test path.

**Components:**
- `src/vendor/hpke/` — vendored copy of panva `hpke` v1.1.3 (`index.js` +
  `index.d.ts` + upstream `LICENSE.md`), plus a short `PROVENANCE` note (source,
  version, retrieval date, how to refresh). No `hpke` entry is added to
  `package.json`.
- `src/index.ts` — replace the placeholder with the `HpkeOpts` type and the
  module-level `CipherSuite` constant (X25519 / HKDF-SHA256 / AES-256-GCM),
  importing from `./vendor/hpke`.
- Node test wiring — a `test:node` script that runs `test/node.ts` under Node
  (e.g. via the TypeScript-capable runner already available to the toolchain).

**Dependencies:** None (first phase).

**Done when:** `npm run build` succeeds (the vendored module bundles in),
`npm run lint` passes, an empty `test/node.ts` executes green, `package.json`
lists no `hpke` runtime dependency, and the upstream `LICENSE.md` is present in
`src/vendor/hpke/`.
<!-- END_PHASE_1 -->

<!-- START_PHASE_2 -->
### Phase 2: Core seal / open
**Goal:** The two functions and their key handling.

**Components:**
- `seal` in `src/index.ts` — resolve/generate key bytes, `suite.Seal`, assemble
  the envelope, return `{ wrapped, key }`.
- `open` in `src/index.ts` — parse the envelope, `suite.Open`, import and return
  the AES-GCM `CryptoKey`.
- Key helpers — generate `keysize` random bytes, export a supplied key as raw,
  import raw bytes as an AES-GCM `CryptoKey`; `keysize` validation.

**Dependencies:** Phase 1.

**Covers:** `hpke-self-wrap.AC1.1`, `AC1.2`, `AC1.3`, `AC1.4`, `AC1.5`, `AC1.6`,
`AC3.4`.

**Done when:** Tests prove round-trip (generated + bring-your-own key), 128 and
256-bit sizing, cross-use of the returned vs opened key, a non-extractable
supplied key throwing, invalid `keysize` throwing, and two seals of the same key
producing different envelopes.
<!-- END_PHASE_2 -->

<!-- START_PHASE_3 -->
### Phase 3: Keys-module integration, negative cases, cross-runtime
**Goal:** Prove the `@substrate-system/keys` requirement and failure handling in
both runtimes.

**Components:**
- `test/index.ts` / `test/node.ts` — integration test that mints the keypair via
  `EccKeys.create()` and round-trips through `seal`/`open`.
- Negative tests — tampered envelope, wrong keypair, mismatched `info`, malformed
  envelope.

**Dependencies:** Phase 2.

**Covers:** `hpke-self-wrap.AC2.1`, `AC2.2`, `AC3.1`, `AC3.2`, `AC3.3`, `AC3.5`,
`AC4.1`, `AC4.2`.

**Done when:** The full suite passes under both `npm test` (browser/headless)
and `npm run test:node`.
<!-- END_PHASE_3 -->

<!-- START_PHASE_4 -->
### Phase 4: Documentation
**Goal:** Usage docs and folded-in research rationale.

**Components:**
- `docs/README.md` — API usage (`seal`/`open`, options, the
  `@substrate-system/keys` example) and a short "why HPKE" rationale drawn from
  the research (ephemeral-static ECDH, HKDF Extract-then-Expand, non-extractable
  key support, why standardized HPKE over a bespoke ECIES variant).

**Dependencies:** Phase 3.

**Done when:** `docs/README.md` documents the public API and the design
rationale. No tests (documentation phase; verified by review).
<!-- END_PHASE_4 -->

## Additional Considerations

**Error handling:** `open` failures — tampered bytes, wrong keypair, or a
mismatched `info` — all surface as a single generic rejection (HPKE's
`OpenError`/`DecapError`); no branch reveals which check failed. A
non-extractable supplied `aesKey` and an out-of-range `keysize` throw clear,
specific errors before any crypto runs.

**Returned key extractability:** generated and recovered keys are `extractable`.
Extraction is unavoidable when a caller wants to seal an existing key, so it is
kept symmetric, and it allows a recovered key to be re-sealed later (e.g. adding
a device). A future `extractable?:boolean` option could tighten this without an
API break.

**Vendored HPKE:** panva `hpke` (MIT, zero sub-dependencies, WebCrypto-native,
single `index.js` with no external imports) is copied into `src/vendor/hpke/`
rather than depended on, so the published package ships no runtime dependencies.
The upstream `LICENSE.md` and copyright notice are retained for attribution.
Trade-off: security and correctness fixes must be pulled in manually — the
vendored copy is pinned to v1.1.3, and a `PROVENANCE` note records the source and
how to refresh it. A vendored `.js`/`.d.ts` carries a top-of-file
`/* eslint-disable */` so third-party style does not fail `npm run lint` (no
eslint config change).

**Nonce safety:** HPKE derives the AEAD nonce from its key schedule rather than
a transmitted IV; each `seal` uses a fresh ephemeral key, so there is no
nonce-reuse exposure to manage in this package.
