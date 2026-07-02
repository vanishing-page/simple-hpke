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
