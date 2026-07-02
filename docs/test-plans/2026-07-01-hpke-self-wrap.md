# HPKE Self-Wrap — Human Test Plan

Covers the `seal`/`open` HPKE self-wrap library. This is a WebCrypto library
with no UI, so "human" verification is running the two test suites, a
fresh-clone/build smoke check, and confirming the inspection and documentation
items. No UI steps.

Branch: `hpke-self-wrap`. Reference commit: `342eb1a`.

## Prerequisites

- Node 20+ with a WebCrypto-capable runtime (stable X25519; Node >= 20.19,
  fully stable >= 23.5); a Chromium install for the headless run (esbuild,
  tapzero, tapout are already dev dependencies in `package.json`).
- Clean checkout on branch `hpke-self-wrap`.
- From `/Users/nick/code/ecies`: `npm ci` completes, then `npm run lint`,
  `npm run test:node`, and `npm test` all pass.

## Phase 1: Automated gates (cross-runtime)

| Step | Action | Expected |
|------|--------|----------|
| 1 | Run `npm run test:node` | TAP output ends `# tests 18 / # pass 18 / # ok`; every AC-labeled line is `ok` (AC4.1) |
| 2 | Run `npm test` | Builds dist, runs in Chromium, ends `# tests 18 / # pass 18 / # ok` (AC4.2) |
| 3 | Confirm the same 18 assertions (AC1.1–AC3.5) appear in both runs | Identical test names and counts under each runtime |

## Phase 2: AC5 inspection (no runtime crypto dependency + vendored license)

| Step | Action | Expected |
|------|--------|----------|
| 1 | Open `package.json` | No `dependencies` key (only `devDependencies`); no `hpke`/crypto runtime entry |
| 2 | `grep -n "vendor/hpke/index.js" src/index.ts` | HPKE suite imported from the vendored path |
| 3 | After `npm run build`, `grep -c "vendor/hpke" dist/index.js dist/index.cjs` and `grep -c CipherSuite dist/index.js` | Only a section-comment reference to the vendored path; `CipherSuite` count non-zero — the code is inlined, not a dangling dependency |
| 4 | Open `src/vendor/hpke/LICENSE.md` | Present, non-empty, MIT text with upstream copyright (Filip Skokan) |
| 5 | Open `src/vendor/hpke/PROVENANCE.md` | Records source repo, version 1.1.3, license, and refresh steps |

## End-to-end: fresh-clone build-and-consume smoke check

Purpose: prove the built `dist/` works for a downstream consumer with no source
tree and no extra installs.

1. Clone the repo (or `npm pack` and extract the tarball) into a scratch dir.
2. `npm ci && npm run build` → `dist/index.js`, `dist/index.cjs`, and the
   `.min` variants are produced with no errors.
3. In a throwaway script that imports `seal`/`open` from the built
   `dist/index.js`: generate an X25519 keypair,
   `const { wrapped, key } = await seal(kp)`,
   `const recovered = await open(kp, wrapped)`, export both to raw and compare
   → the bytes are equal.
4. Confirm the build ran from `dist` alone with no network/runtime crypto
   dependency pulled in.

## Human verification required (documentation deliverables)

| Deliverable | Why manual | Steps |
|-------------|------------|-------|
| `docs/README.md` | Prose/accuracy judgment, not unit-testable | Confirm it documents `seal(keypair, aesKey?, opts?) -> { wrapped, key }`, `open(keypair, wrapped, opts?) -> CryptoKey`, `HpkeOpts` (`keysize` 128/256, `info`), the wire format `enc(32) ‖ ciphertext`, a runnable `@substrate-system/keys` `EccKeys` example, and the rationale (ephemeral-static ECDH, HKDF extract-then-expand, standardized HPKE over bespoke ECIES, non-extractable private keys, nonce safety, `info` domain separation). Verify the documented signatures match `src/index.ts`. |
| Top-level `README.md` example | Must reflect the shipped API, not the removed placeholder | Confirm the Example uses real `seal`/`open` and contains no `example()` reference (`grep -c "example()" README.md` → 0). Optionally copy the snippet into the smoke-check script and confirm it runs. |

## Traceability

| Acceptance Criterion | Automated Test | Manual Step |
|----------------------|----------------|-------------|
| AC1.1–AC1.6 | `test/index.ts` (round-trip, cross-use, BYO key, sizing, non-extractable throw, bad-keysize throw) | Phase 1 steps 1–2 |
| AC2.1–AC2.2 | `test/index.ts` `EccKeys` integration | Phase 1 steps 1–2; E2E step 3 |
| AC3.1–AC3.5 | `test/index.ts` tamper / wrong-key / mismatched-info + positive / semantic-security / malformed | Phase 1 steps 1–2 |
| AC4.1 | whole suite via `test/node.ts` | Phase 1 step 1 |
| AC4.2 | whole suite in Chromium | Phase 1 step 2 |
| AC5.1 | inspection | Phase 2 steps 1–3; E2E step 4 |
| AC5.2 | inspection | Phase 2 steps 4–5 |
| Phase 4 docs (`docs/README.md`) | review | Human verification, row 1 |
| Top-level `README.md` example | review | Human verification, row 2 |

## Relevant paths

- Tests: `test/index.ts`, `test/node.ts`
- Source: `src/index.ts`
- Vendored HPKE: `src/vendor/hpke/LICENSE.md`, `src/vendor/hpke/PROVENANCE.md`
- Docs: `docs/README.md`, `README.md`
- Requirements: `docs/implementation-plans/2026-07-01-hpke-self-wrap/test-requirements.md`
