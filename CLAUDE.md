# ecies — HPKE AES-key wrapping

Last verified: 2026-07-02

## Purpose
A dependency-free library for wrapping (sealing) an AES-GCM key to your own
X25519 keypair using RFC 9180 HPKE, then recovering it later with the same
keypair. Despite the repo name, this is not bespoke ECIES: it is standardized
HPKE. Works in modern browsers and Node.js via WebCrypto.

## Tech Stack
- Language: TypeScript, ESM-first (also ships CJS + minified builds)
- Crypto: WebCrypto (`globalThis.crypto.subtle`) + RFC 9180 HPKE
- HPKE impl: vendored panva `hpke` v1.1.3 (MIT) in `src/vendor/hpke/`
- Build/bundle: esbuild; types via `tsc`
- Tests: `@substrate-system/tapzero` + `tapout` (browser), plain node (Node)

## Commands
- `npm run build` — build all dist variants (esm, cjs, both minified)
- `npm test` — build, then bundle `test/index.ts` and run in a browser
  via tapout
- `npm run test:node` — bundle `test/node.ts` for Node and run
  (externalizes `tweetnacl` + `@noble/hashes` for `@substrate-system/keys`)
- `npm run lint` — eslint
- `npm run build-docs` — typedoc from `src/index.ts`

Both test commands run the SAME suite: `test/node.ts` just re-imports
`test/index.ts`. Add tests to `test/index.ts` only.

## Project Structure
- `src/index.ts` — the entire public API (`seal`, `open`, `HpkeOpts`)
- `src/vendor/hpke/` — vendored panva hpke; see its `PROVENANCE.md`
- `test/index.ts` — shared test suite; `test/node.ts` re-imports it
- `docs/README.md` — full API reference + HPKE rationale (source of truth)

## Contracts (public API — `src/index.ts`)
- `seal(keypair, aesKey?, opts?) → { wrapped, key }`: wrap an AES key to
  `keypair.publicKey`. Omit `aesKey` to generate a fresh extractable key of
  `opts.keysize` bits (default 256).
- `open(keypair, wrapped, opts?) → CryptoKey`: recover the sealed key with
  `keypair.privateKey`.
- `HpkeOpts`: `{ keysize?:128|256; info?:Uint8Array|string }`.
- Wire format: `enc(32 bytes) ‖ ciphertext`. No salt/IV stored (HPKE derives
  the AEAD nonce from its key schedule).

## Invariants
- ZERO runtime dependencies. `hpke` is vendored and bundled into every dist
  variant at build time, never listed in `dependencies`. Do NOT `npm install`
  it — refresh via the vendored `PROVENANCE.md` procedure instead.
- One fixed, non-configurable cipher suite: DHKEM(X25519, HKDF-SHA256) +
  HKDF-SHA256 + AES-256-GCM. Changing it is a breaking wire-format change.
- The X25519 private key may be non-extractable (HPKE needs only
  `deriveBits`). A supplied `aesKey` MUST be extractable — its raw bytes are
  what get sealed.
- `info` must match between `seal` and `open` or `open` fails; it is bound
  into the key schedule for domain separation.

## Key Decisions
- Standardized HPKE over hand-rolled ECIES: interoperable, reviewed key
  schedule; `info` gives domain separation. See `docs/README.md` "Why HPKE".
- Vendored (not npm-installed) hpke keeps the package dependency-free and
  auditable. To update it, follow `src/vendor/hpke/PROVENANCE.md` (npm pack,
  copy 3 files, re-add `/* eslint-disable */`, bump version/date, rebuild,
  re-run both test suites).
- Not wire-compatible with `@substrate-system/keys` `wrap`/`unwrap`, though
  they can share a keypair.

## Conventions
- `src/index.ts` follows Functional Core / Imperative Shell: pure helpers for
  normalization/concat; WebCrypto side effects isolated in `seal`/`open`.
- Unusual lint rules enforced by `eslint.config.js`: no space around the
  colon in type annotations and object literals (`x:T`, `{ a:1 }`), and no
  space around `|`/`&` in inline union/intersection types (`A|B`). Run
  `npm run lint`; the vendored hpke files carry `/* eslint-disable */`.
