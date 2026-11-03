<!-- nightralph:start -->
## Agent skills

### Issue tracker

Issues are tracked as local markdown files under `.scratch/`. See `docs/agents/issue-tracker.md`.

### Triage labels

Default label vocabulary. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout. See `docs/agents/domain.md`.
<!-- nightralph:end -->

## Working in this repo

- Architectural decisions live in `docs/adr/`. Read
  `docs/adr/INDEX.md` before changing the crypto, wire formats, key
  handling, or error model, and add an ADR when you make a new decision
  in those areas.
- Tests: one shared suite, `test/index.ts`, run in a browser by
  `npm test` (builds first) and in Node by `npm run test:node` (faster
  for iterating). New tests go before the final `all done` test, which
  signals completion to the browser runner.
- Assert error cases with the `thrownCode` helper in `test/index.ts`
  (compares `HpkeError.code`), never on message text.
- Every error the package throws must be an `HpkeError`. Validate inputs
  up front rather than letting a WebCrypto error escape.
- `encrypt` (`encryptBytes`) and `encrypt.asString` (`encryptToString`)
  live in `src/util.ts` and delegate to `encryptKey` in `src/index.ts`.
  `encryptToString` calls `encryptBytes`, so a check there covers both.
- `CLAUDE.md` is gitignored; do not expect it in a worktree.
- CHANGELOG is regenerated from git history by auto-changelog on
  `npm version`, flagging commits whose message contains
  `BREAKING CHANGE:`. Hand-written CHANGELOG edits are overwritten, so
  a release note must live in a commit subject. Every commit is listed
  (no per-release limit) except subjects starting `nightralph`.
  Preview with the `version` script's flags plus `--stdout`.
- A new public export is re-exported from `src/index.ts`, and also goes
  in the README's ESM import example and, if it gets its own heading,
  the TOC (`npm run toc`).
- `generateKey` always makes the public half of a keypair extractable,
  and the test helper `genKeypair` makes a non-extractable private key.
  To test a non-extractable public key, re-import its raw bytes with
  `extractable: false`; to test other private-key usages, generate an
  extractable pair and re-import its `pkcs8` export.
- Recipient `CryptoKey` checks (type, X25519 algorithm, extractable)
  live in `assertRecipientPublicKey` in `src/util.ts`, shared by the bare
  key and the keypair `.publicKey` forms. Add new recipient checks there
  so both forms get them. The decapsulation side (`decap` in
  `src/util.ts`) runs its own up-front checks on the keypair with
  `ERR_INVALID_KEYPAIR`; keep both halves' checks (type, X25519,
  extractable / usages) in step with the recipient side.
  String recipients wrap the `uint8arrays`
  decoder, which throws `SyntaxError` / `Error` on bad input.
- X25519 `deriveBits` failures are told apart by `err.name`:
  `OperationError` means a small-order public key (all-zero shared
  secret), `InvalidAccessError` means a key lacking the `deriveBits`
  usage. Importing a small-order key succeeds; only `deriveBits` fails.
  Wrapped key layout is `enc(32) || ...`; an envelope is a 2-byte
  wrapped-key length prefix, then the wrapped key, so its `enc` is
  bytes 2..34.
- A supplied AES `CryptoKey` is checked algorithm, then extractable,
  then exported length. Only an AES-GCM-192 key reaches the length
  check, and Chromium cannot generate one, so a test of that branch
  must tolerate the key being unavailable in the browser run.
