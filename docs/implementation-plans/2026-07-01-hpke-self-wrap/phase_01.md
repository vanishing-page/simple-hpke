# HPKE Self-Wrap Implementation Plan

**Goal:** Vendor the panva `hpke` library, wire a Node test path, and stand up
the module-level cipher suite + option types so later phases can add `seal` /
`open`.

**Architecture:** A thin self-encryption helper over RFC-9180 HPKE. A vendored
copy of `hpke` (panva v1.1.3, MIT) does all cryptography; `src/index.ts` builds
a single hard-coded cipher suite from it. The library is copied into
`src/vendor/hpke/` rather than depended on, so the published package ships no
runtime dependencies.

**Tech Stack:** TypeScript, esbuild (ESM + CJS + minified bundles), tapzero +
`@substrate-system/tapout` for the browser/headless run, plain `node` for the
Node run. WebCrypto (`globalThis.crypto.subtle`) is the only crypto primitive.

**Scope:** Phase 1 of 4 from `docs/design-plans/2026-07-01-hpke-self-wrap.md`.

**Codebase verified:** 2026-07-02

---

## Acceptance Criteria Coverage

This phase is **infrastructure/scaffolding**. It writes no acceptance-criteria
tests of its own.

**Verifies: None.** (It does lay groundwork for `hpke-self-wrap.AC5.1` /
`AC5.2` — vendored, no runtime dependency — which are re-checked at the end of
Phase 3.)

---

## Codebase reality (verified 2026-07-02)

Facts the executor must rely on (do not re-derive; verify only if a step fails):

- `package.json` has `"type": "module"`, **no** `hpke` dependency, and
  `@substrate-system/keys@^0.2.41`, `@substrate-system/tapout@^0.0.38`,
  `@substrate-system/tapzero@^0.10.15`, `esbuild`, `typescript`, `tap-spec` all
  in `devDependencies`. There is **no `test:node` script** yet.
- Build scripts (verbatim, note **only `build-esm:min` uses `--bundle`**):
  - `build-cjs`: `esbuild src/*.ts --format=cjs --keep-names
    --tsconfig=tsconfig.build.json --outdir=./dist --out-extension:.js=.cjs
    --sourcemap`
  - `build-esm`: `esbuild src/*.ts --format=esm --metafile=dist/meta.json
    --keep-names --tsconfig=tsconfig.build.json --outdir=./dist --sourcemap &&
    tsc --emitDeclarationOnly --project tsconfig.build.json --outDir dist`
  - `build-esm:min`: `esbuild ./src/*.ts --format=esm --keep-names --bundle
    --tsconfig=tsconfig.build.json --minify --out-extension:.js=.min.js
    --outdir=./dist --sourcemap`
  - `build-cjs:min`: `esbuild src/*.ts --format=cjs --minify --keep-names
    --tsconfig=tsconfig.build.json --outdir=./dist --out-extension:.js=.min.cjs
    --sourcemap`
  - `build`: `mkdir -p ./dist && rm -rf ./dist/* && npm run build-cjs && npm run
    build-esm && npm run build-esm:min && npm run build-cjs:min`
- `src/index.ts` is a placeholder importing `@substrate-system/debug` and
  exporting `example()`.
- `test/index.ts` imports `{ example }` from `../src/index.js` (so it breaks the
  moment the placeholder is removed — this phase must update it).
- `test/node.ts` exists and is **empty** (0 bytes).
- ESLint is a **flat config** (`eslint.config.js`, neostandard) enforcing:
  4-space indent, no semicolons, **no spaces around type-annotation colons**
  (`foo:Bar`), **no space after object-literal key colons** (`{a:1}`, via
  `@stylistic/key-spacing` `afterColon:false`), union spacing `A|B` (no
  spaces), and it lints `./**/*.{ts,js}`.
  It ignores only `lib.es5.d.ts`, `dist/**`, `public/**`, `test/*.js`. It will
  lint files under `src/vendor/`, so vendored files need a `/* eslint-disable */`
  header. **Do not change ESLint config.**
- `tsconfig.json`: `strict: true`, `module: ES2022`, `moduleResolution:
  "Bundler"`, `lib: ["ES2024","DOM","WebWorker"]` (WebCrypto types available),
  `allowJs: false`. `tsconfig.build.json` extends it and excludes `example`,
  `test`.

## Design decisions made during planning (read before starting)

1. **`--bundle` is added to `build-cjs`, `build-esm`, and `build-cjs:min`**
   (Task 3). The design's "the vendored module bundles in" only holds when the
   build bundles. Without `--bundle`, esbuild leaves the relative import
   `./vendor/hpke/index.js` untouched in the emitted `dist/index.js` /
   `dist/index.cjs`, and that path does not exist in `dist/` — and the vendored
   file is ESM, so it could not be `require()`d from the CJS output anyway.
   Bundling inlines the vendored code into every dist variant, which is what
   makes the "no runtime dependency" guarantee real.
2. **`src/index.ts` exports the `suite` constant** (not only `HpkeOpts`). The
   design lists `HpkeOpts` + a module-level `CipherSuite` constant for this
   phase. An unexported, unused `const suite` would fail `no-unused-vars` before
   `seal`/`open` exist. Exporting it keeps this phase lint-clean, lets the smoke
   test assert against it, and does not expose suite *selection* as a runtime
   option (the design's actual constraint). `seal`/`open` consume it in Phase 2.
3. **Node test runner = esbuild-bundle-then-`node`.** There is no `tsx`/`ts-node`
   installed, and the browser `test` script already bundles TS with esbuild.
   `test:node` mirrors that: bundle `test/node.ts` for the node platform to a
   gitignored `test/node.mjs`, then run it with `node`. `tapzero` prints TAP and
   sets a non-zero exit code on failure. `test/node.ts` re-imports
   `test/index.ts` so a single set of tests runs in both runtimes (DRY).
   (The design's "done when" says "an empty `test/node.ts` executes green";
   re-importing the browser tests instead is a deliberate improvement — it
   proves the Node path actually runs the suite, not just an empty file.)
4. **Node version:** the Node run needs stable WebCrypto **X25519**
   (Node >= 20.19, fully stable >= 23.5). The executor's Node must support it;
   note it, do not add an `engines` field (out of scope).

---

<!-- START_TASK_1 -->
### Task 1: Vendor the panva `hpke` library into `src/vendor/hpke/`

**Files:**
- Create: `src/vendor/hpke/index.js` (copied from upstream, unmodified except a
  prepended `/* eslint-disable */`)
- Create: `src/vendor/hpke/index.d.ts` (copied from upstream, unmodified except a
  prepended `/* eslint-disable */`)
- Create: `src/vendor/hpke/LICENSE.md` (copied from upstream, unmodified)
- Create: `src/vendor/hpke/PROVENANCE.md`

**Step 1: Fetch the pinned upstream package**

Run from the repo root:

```bash
npm pack hpke@1.1.3
tar -xzf hpke-1.1.3.tgz
mkdir -p src/vendor/hpke
```

The extracted `package/` directory contains (flat layout): `index.js` (ESM,
zero external imports), `index.d.ts`, `LICENSE.md`, plus `README.md`,
`index.ts`, `index.d.ts.map`, `package.json`. Only the first three are
vendored.

**Step 2: Copy the three files into place**

```bash
cp package/index.js    src/vendor/hpke/index.js
cp package/index.d.ts  src/vendor/hpke/index.d.ts
cp package/LICENSE.md   src/vendor/hpke/LICENSE.md
```

Do **not** copy `package.json`, `README.md`, `index.ts`, or the `.map`.

**Step 3: Prepend `/* eslint-disable */` to the two source files**

Add this as the very first line of both `src/vendor/hpke/index.js` and
`src/vendor/hpke/index.d.ts` (leave `LICENSE.md` untouched):

```js
/* eslint-disable */
```

This keeps third-party style out of `npm run lint` without touching the ESLint
config. (`src/vendor/` is not in the ignore list, so the header is required.)

**Step 4: Verify the two files are the only new code and are self-contained**

```bash
grep -nE "require\(|from ['\"][^.]" src/vendor/hpke/index.js | \
  grep -v "globalThis" || echo "no external imports (good)"
```

Expected: no external `import`/`require` lines (the module uses only
`globalThis.crypto.subtle`). Confirm the MIT `LICENSE.md` is present and
non-empty.

**Step 5: Clean up the pack artifacts**

```bash
rm -rf package hpke-1.1.3.tgz
```

**Step 6: Commit**

```bash
git add src/vendor/hpke/index.js src/vendor/hpke/index.d.ts \
  src/vendor/hpke/LICENSE.md
git commit -m "chore: vendor panva hpke v1.1.3 (MIT)"
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Write the `PROVENANCE.md` note

**Files:**
- Create: `src/vendor/hpke/PROVENANCE.md`

**Step 1: Write the file**

```markdown
# Provenance

- Package: `hpke` (panva / Filip Skokan)
- Version: 1.1.3
- License: MIT (see LICENSE.md, retained unmodified)
- Source: https://github.com/panva/hpke (tag v1.1.3) / https://npmjs.com/hpke
- Retrieved: 2026-07-02

## What is vendored

`index.js` (compiled ESM) and `index.d.ts` (types), copied verbatim from the
published package except for a prepended `/* eslint-disable */` on each so the
third-party style does not trip this repo's lint. `LICENSE.md` is retained
unmodified for attribution. Nothing else from the package is included.

## How to refresh

    npm pack hpke@<version>
    tar -xzf hpke-<version>.tgz
    cp package/index.js src/vendor/hpke/index.js
    cp package/index.d.ts src/vendor/hpke/index.d.ts
    cp package/LICENSE.md src/vendor/hpke/LICENSE.md
    # re-add the `/* eslint-disable */` first line to index.js and index.d.ts
    rm -rf package hpke-<version>.tgz

Then bump the version and retrieval date above, re-run `npm run build`,
`npm run lint`, `npm test`, and `npm run test:node`, and review the upstream
changelog for security-relevant fixes.
```

**Step 2: Commit**

```bash
git add src/vendor/hpke/PROVENANCE.md
git commit -m "docs: record vendored hpke provenance"
```
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Bundle the vendored module into every dist variant

**Files:**
- Modify: `package.json` (the `build-cjs`, `build-esm`, `build-cjs:min` scripts)

**Implementation:**

Read `package.json` first, then add the `--bundle` flag immediately after
`src/*.ts` (or `./src/*.ts`) in each of these three scripts. `build-esm:min`
already has `--bundle`; leave it and all other scripts unchanged.

After editing, the three scripts must read:

- `build-cjs`: `esbuild src/*.ts --bundle --format=cjs --keep-names
  --tsconfig=tsconfig.build.json --outdir=./dist --out-extension:.js=.cjs
  --sourcemap`
- `build-esm`: `esbuild src/*.ts --bundle --format=esm --metafile=dist/meta.json
  --keep-names --tsconfig=tsconfig.build.json --outdir=./dist --sourcemap && tsc
  --emitDeclarationOnly --project tsconfig.build.json --outDir dist`
- `build-cjs:min`: `esbuild src/*.ts --bundle --format=cjs --minify --keep-names
  --tsconfig=tsconfig.build.json --outdir=./dist --out-extension:.js=.min.cjs
  --sourcemap`

**Why:** without `--bundle`, esbuild leaves `import ... from
'./vendor/hpke/index.js'` in the emitted `dist/index.js` and `dist/index.cjs`;
that relative path is absent from `dist/`, and the ESM vendored file cannot be
`require()`d from CJS. Bundling inlines the vendored code so each variant is
self-contained and the package stays runtime-dependency-free.

**Verification:** deferred to Task 6 (run once `src/index.ts` imports the
vendored module).

**Commit:** `build: bundle vendored deps into all dist variants`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Replace the `src/index.ts` placeholder with `HpkeOpts` + the suite

**Files:**
- Modify: `src/index.ts` (replace entire contents)

**Implementation:**

Replace the whole file with the option type and the module-level cipher suite,
built from the vendored module. Match repo style: 4-space indent, no
semicolons, single quotes, no space around type-annotation colons, `A|B` union
spacing, lines <= 80 columns.

```ts
import {
    CipherSuite,
    KEM_DHKEM_X25519_HKDF_SHA256,
    KDF_HKDF_SHA256,
    AEAD_AES_256_GCM
} from './vendor/hpke/index.js'

/**
 * Options for `seal` / `open`.
 */
export interface HpkeOpts {
    // Size of the GENERATED AES key. Ignored when an `aesKey` is supplied.
    keysize?:128|192|256
    // HPKE `info`: bound into the key schedule; must match on seal + open.
    info?:Uint8Array|string
}

/**
 * The one fixed HPKE cipher suite this package uses:
 * DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM. Not configurable at
 * runtime. `seal` / `open` (added next) operate through it.
 */
export const suite = new CipherSuite(
    KEM_DHKEM_X25519_HKDF_SHA256,
    KDF_HKDF_SHA256,
    AEAD_AES_256_GCM
)
```

Note: the import specifier ends in `.js` (matches the vendored `index.js`; TS
`Bundler` resolution picks up the sibling `index.d.ts` for types).

**Verification:** deferred to Task 6.

**Commit:** `feat: add HpkeOpts and the module-level HPKE cipher suite`
<!-- END_TASK_4 -->

<!-- START_TASK_5 -->
### Task 5: Wire the Node test path and a smoke test in both runtimes

**Files:**
- Modify: `package.json` (add `test:node` script)
- Modify: `test/index.ts` (replace the `example` smoke test)
- Modify: `test/node.ts` (currently empty)
- Modify/Create: `.gitignore` (ignore the Node bundle artifact)

**Step 1: Add the `test:node` script to `package.json`**

Add this entry to `scripts` (adjacent to the existing `test` script):

```json
"test:node": "esbuild ./test/node.ts --bundle --platform=node --format=esm --outfile=./test/node.mjs && node ./test/node.mjs"
```

**Step 2: Replace `test/index.ts` with a suite smoke test**

The current file imports the now-deleted `example`. Replace it entirely:

```ts
import { test } from '@substrate-system/tapzero'
import { suite } from '../src/index.js'

test('cipher suite is configured', async t => {
    t.equal(suite.KEM.Nenc, 32, 'X25519 encapsulated key is 32 bytes')
})
```

Assert only `suite.KEM.Nenc` — that is the one suite property confirmed by
research (`=== 32` for X25519). (All future tests are added to `test/index.ts`
so they run in both runtimes. Phase 2 makes `suite` internal and replaces this
smoke test with the real `seal`/`open` tests.)

**Step 3: Point `test/node.ts` at the browser tests**

Set `test/node.ts` to a single re-import so one test set runs in both runtimes:

```ts
import './index.js'
```

**Step 4: Ignore the Node bundle artifact**

Ensure `.gitignore` contains a line for the generated bundle (create the file if
it does not exist; otherwise append):

```
test/node.mjs
```

**Step 5: Verify everything operationally**

Run each and confirm the expected result:

```bash
npm run lint
```
Expected: passes (the `/* eslint-disable */` headers keep the vendored files
quiet; `src/index.ts`, `test/index.ts`, `test/node.ts` are clean).

```bash
npm run build
```
Expected: succeeds; `dist/index.js` and `dist/index.cjs` contain the inlined
hpke code (no dangling `./vendor/hpke/index.js` import). Spot-check:
```bash
grep -c "vendor/hpke" dist/index.js dist/index.cjs || \
  echo "no dangling vendor import (good)"
```

```bash
npm test
```
Expected: builds, bundles `test/index.ts`, runs headless, the smoke test
passes.

```bash
npm run test:node
```
Expected: bundles `test/node.ts` to `test/node.mjs`, runs under `node`, prints
TAP with the smoke test passing and exits 0.

**Step 6: Commit**

```bash
git add package.json test/index.ts test/node.ts .gitignore
git commit -m "test: add Node test runner and cipher-suite smoke test"
```
<!-- END_TASK_5 -->

<!-- START_TASK_6 -->
### Task 6: Confirm the Phase 1 "done when" gate

**No new files.** This task is the phase's operational gate; it exists so the
executor confirms the whole scaffold holds together before Phase 2.

**Verification (all must hold):**
- `npm run build` succeeds and the vendored module is inlined into the dist
  bundles (no `./vendor/hpke/` import survives in `dist/index.js` /
  `dist/index.cjs`).
- `npm run lint` passes.
- `npm test` passes (browser/headless smoke test green).
- `npm run test:node` passes (Node smoke test green, exit 0).
- `package.json` lists **no** `hpke` (or other crypto) runtime dependency, and
  `src/vendor/hpke/LICENSE.md` is present.

If any check fails, fix within this phase before proceeding. If the failure is
`hpke` rejecting the WebCrypto keys or an unexpected API shape, STOP and surface
it — later phases depend on the vendored API behaving as researched.

**Commit:** none (verification only).
<!-- END_TASK_6 -->
