# simple-hpke 0.3.0 -- implementation spec

Status: implemented, shipped as 0.3.1 on 2026-08-21. Kept as history.
This work order superseded the earlier design in `notes/0.3.0-spec.md`.
Rationale for these decisions is recorded in `docs/adr/` (ADR-004
through ADR-008); the `docs/changes.md` it originally cited was never
committed. Two items were deferred to 0.4.0 (`notes/0.4.0-spec.md`): a
supplied `CryptoKey` returned by identity, and `verifyKeyId`. Change 6's
hand-written CHANGELOG step no longer applies: the changelog is
regenerated from commits (see `AGENTS.md`).

Self-contained work order. Everything happens in
`/Users/nick/code/simple-hpke`. No other repository is in scope.

## Orientation, because CLAUDE.md is stale here

(Historical: these points were fixed in CLAUDE.md afterward, and `docs/`
has been tracked since 2026-11-02.)

- `CLAUDE.md` says the whole implementation is in `src/index.ts`. It is
  not. Source is split across `src/index.ts` (public API, key schedule,
  open/encryptKey), `src/util.ts` (AEAD, HKDF, DHKEM, recipient
  resolution), and `src/constants.ts` (suite ids and lengths).
- `CLAUDE.md` cites `docs/README.md` as the API reference. That file does
  not exist. The API reference is `README.md` at the repo root.
- `docs/` is gitignored. This spec will not travel with a worktree; copy it
  in if you branch.
- Both test commands run the same suite. `test/node.ts` re-imports
  `test/index.ts`. Add tests to `test/index.ts` only.

## Scope

Five changes, shipped together as `0.3.0`. Two are breaking.

1. Rename the returned `enc` property to `wrapped`. Breaking.
2. Add `keyId()`, a key fingerprint that works on non-extractable keys.
3. Add an `extractable` option, defaulting to `false`. Breaking.
4. Fix an opts type bug on `open` / `open.raw`.
5. Add typed error codes.

Do all five. They touch overlapping lines and splitting them costs more
than it saves.

## Change 1: `enc` -> `wrapped`

`create()` and `encryptKey()` return `{ enc, key }`. The property carries
the encapsulated KEM output *and* the sealed key, so `enc` (which in RFC
9180 means the KEM output alone) sends readers hunting for a second
ciphertext field. `open`'s parameter is already named `wrapped`, so this
makes the two halves agree.

Rename the property to `wrapped`. Do **not** keep `enc` as an alias: an
alias means a consumer can upgrade without noticing the migration is
pending.

Sites:

- `src/index.ts`, `create()`: return type, JSDoc `@returns`, and the
  destructure of `encryptKey`'s result.
- `src/index.ts`, `encryptKey()`: return type, JSDoc `@returns`, and the
  returned object literal (currently `{ enc: wrapped, key: aesGcmKey }`,
  where a local named `wrapped` already exists -- collapse them).
- `test/index.ts`: `grep -n '\benc\b' test/index.ts` finds 43 lines. Most are
  `const { enc } = ...`, which must become `const { wrapped } = ...`.
  Two are property reads: `created128.enc`, `created256.enc` (~line 165,
  171) and `a.enc` / `b.enc` (~line 414).
- `README.md`: the `enc` examples around lines 80-140, including the
  `const encLength = enc.length` example.
- `CLAUDE.md`: the Contracts section describes `{ enc, key }` in four
  places.

Note the wire format does not change. Only the property name does.

## Change 2: `keyId()`

### Why it exists

Callers want a stable identifier for an AES key so they can tell "is this
the key I have?" without holding the bytes. The obvious implementation,
`exportKey('raw') |> SHA-256`, forces every such key to be extractable.
`keyId` gets the same property from behavior instead of bytes, so it works
on a non-extractable key and on one rehydrated from IndexedDB.

HKDF is not an option: WebCrypto cannot convert an AES-GCM key into an
HKDF key, and `deriveBits` only accepts a key imported under `HKDF`, which
needs the raw bytes a non-extractable key withholds. AES-GCM as a PRF is
the only primitive such a key still exposes.

### Definition -- pin these exactly

    LABEL = utf8("simple-hpke/keyId/v1")
    N     = SHA-256(LABEL)[0..12]          // 12-byte fixed nonce
    P     = LABEL                          // fixed plaintext
    C     = AES-GCM(key, N, P)             // ciphertext ‖ 16-byte tag
    keyId = base64url(SHA-256(LABEL ‖ C))

These constants are permanent. Changing any of them changes every `keyId`
a consumer has stored, and there is no migration path, so treat them as
wire format. Put them in `src/constants.ts` next to the existing suite
constants.

Output is the full 32-byte digest, base64url, unpadded (43 chars). Do not
truncate.

### Signature

```ts
export async function keyId (key:CryptoKey):Promise<string>
```

Export it from `src/index.ts` alongside `create` / `encryptKey` / `open`.
Implement the derivation in `src/util.ts` if that keeps `index.ts`
readable; either is fine.

### Rules, each of which is load-bearing

- No AAD. AAD feeds GHASH only and leaves the counter stream untouched, so
  "domain separation by AAD" would produce a second (A, C) pair over an
  identical keystream under the same (K, N). That is nonce reuse with extra
  steps.
- `N` must come from the label hash. Never all-zeros, never a low counter:
  those are the values a caller doing deterministic nonces would pick, and
  a collision there is catastrophic. Callers using random 12-byte IVs
  collide at 2^-96.
- Return only the digest. Never expose `C`: it is a known-plaintext block
  of keystream.
- Validate before deriving. `key.algorithm.name` must be `AES-GCM` and
  `key.usages` must include `encrypt`. Throw a defined error (see Change 5)
  rather than letting WebCrypto surface an opaque `OperationError`.

Why the nonce rules matter: two distinct plaintexts under one (K, IV) let
an attacker solve GHASH for the hash subkey H, and H is nonce-independent.
Recovering it forges under every nonce for that key, not just the one that
collided.

### Tests

Add to `test/index.ts`:

- Same key gives the same `keyId` across calls.
- Two independently generated keys give different `keyId`s.
- A key imported with `extractable: false` and usages `['encrypt']`
  produces a `keyId` (this is the whole point).
- A key from `create()` and the key recovered from `open()` for the same
  envelope produce equal `keyId`s.
- A key with usages `['decrypt']` only throws, and the thrown error has
  code `ERR_INVALID_AES_KEY`.

Assert on error codes, not message text.

## Change 3: `extractable` option, default `false`

`importAesKey` in `src/index.ts` currently hardcodes `extractable: true`
with usages `['encrypt', 'decrypt']`, and both `openBytes` and
`encryptKey` return keys through it. So today every returned key is
extractable and there is no way to ask for anything else.

Add `extractable?:boolean` to the opts of `create`, `encryptKey`, `open`,
defaulting to `false`.

This is a breaking behavior change, not a new knob. It is deliberate:
returning extractable keys by default is the footgun, and 0.3.0 already
breaks on the rename, so consumers read the changelog once instead of
twice. Say so explicitly in the changelog entry.

Consequences to handle:

- `open.raw` returns bytes, not a key. It takes no `extractable` option.
- `importAesKeyDecryptOnly` (the internal helper used by `decryptBytes`)
  is already non-extractable and is unaffected.
- Existing tests export returned keys and will fail. `test/index.ts`
  around line 526 does `await raw(key)` on the key from `create()`, and
  the `raw` helper calls `exportKey`. Find every such site and pass
  `{ extractable: true }` explicitly. Do not weaken the assertions to make
  them pass.
- Add one test that the default really is non-extractable: `create()` with
  no opts returns a key whose `.extractable` is `false` and whose
  `exportKey` rejects.
- Add one test that `{ extractable: true }` round-trips as before.

A supplied `aesKey` `CryptoKey` argument must still be extractable, since
its raw bytes are what get sealed. That is an input constraint and is
unrelated to this option. Do not change it.

## Change 4: opts type fix

`openBytes` and `openRawBytes` in `src/index.ts` declare:

```ts
opts?:{ info:Uint8Array|string }
```

`info` is required inside an optional object, so `open(kp, w)` typechecks
but `open(kp, w, {})` does not. `encryptKey`'s opts are all-optional, so
the two halves of the API disagree.

Change both to `opts?:{ info?:Uint8Array|string }`. This is a widening;
nothing that compiled before stops compiling. Fold the new `extractable`
option from Change 3 into the same object for `openBytes`.

## Change 5: typed error codes

### What is actually wrong today

The library throws at thirteen sites, twelve distinct messages
(`malformed message: too short` appears twice). Every one is a bare
`Error`, distinguishable only by regex on prose.

Worse, the case callers most need to branch on is not thrown by the
library at all. Neither `subtle.decrypt` call is wrapped:

- `aeadOpen` in `src/util.ts` (the wrapped-key AEAD)
- `decryptBytes` in `src/index.ts` (the message body)

So a wrong `info`, a wrong key, or a tampered ciphertext escapes as
WebCrypto's `OperationError` with no message of ours.

### Shape

```ts
export type HpkeErrorCode =
    'ERR_INVALID_RECIPIENT_KEY'|
    'ERR_INVALID_KEYPAIR'|
    'ERR_SMALL_ORDER_KEY'|
    'ERR_MALFORMED_ENVELOPE'|
    'ERR_MALFORMED_MESSAGE'|
    'ERR_INVALID_KEYSIZE'|
    'ERR_INVALID_AES_KEY'|
    'ERR_DECRYPT_FAILED'

export class HpkeError extends Error {
    readonly code:HpkeErrorCode
}
```

Export both from `src/index.ts`. `HpkeError` must remain
`instanceof Error`. Set `name` to `'HpkeError'`. When wrapping a
WebCrypto failure, pass the original through `cause`.

### Mapping

Keep every existing message string **verbatim**. Several current tests
regex on message text (`test/index.ts` around lines 127, 155, 232, 314,
384) and must keep passing untouched. The codes are purely additive at all
thirteen existing sites.

| Code | Existing message(s) |
| --- | --- |
| `ERR_INVALID_RECIPIENT_KEY` | `invalid public key length: …`; `recipient CryptoKey must be a public key`; `recipient keypair publicKey must be a public key`; `unrecognized recipient key form`; plus `assertX25519Algorithm` when its `context` argument names a recipient |
| `ERR_INVALID_KEYPAIR` | `keypair.privateKey must be a private key`; plus `assertX25519Algorithm` when its `context` argument is `keypair.privateKey` |
| `ERR_SMALL_ORDER_KEY` | `X25519 shared secret is all-zero (small-order public key?)` |
| `ERR_MALFORMED_ENVELOPE` | `malformed envelope: too short` (in `openRawBytes`) |
| `ERR_MALFORMED_MESSAGE` | `malformed message: too short` (both length checks in `decryptBytes`) |
| `ERR_INVALID_KEYSIZE` | `invalid keysize: … (expected 128 or 256)` |
| `ERR_INVALID_AES_KEY` | `invalid aesKey length: … (expected 16 or 32)`; `aesKey must be extractable: its raw bytes are what get sealed`; plus the new `keyId` usage check from Change 2, which is a new site and so needs a new message |
| `ERR_DECRYPT_FAILED` | none today; two new wrappers, `src/util.ts` `aeadOpen` and `src/index.ts` `decryptBytes` |

`assertX25519Algorithm` is one function serving two codes. It already
takes a `context` string; thread the code through the same call sites
rather than splitting the function.

### The one non-additive part

Wrapping the two `subtle.decrypt` calls introduces error objects where
none existed, which changes what a mismatched-info failure throws. Nothing
blocks it: the mismatched-info tests (`test/index.ts` around lines 270 and
506) only assert that something threw.

Wrap both. Wrapping only `aeadOpen` still lets a tampered message body
escape as a raw `OperationError`, which is the exact failure this change
exists to fix.

### Tests

Add code assertions for each of the eight codes. For `ERR_DECRYPT_FAILED`,
cover both paths: a wrong `info` on `open` (the `aeadOpen` path) and a
tampered message body on `decrypt` (the `decryptBytes` path). Leave the
existing message-regex tests alone.

## Change 6: version and changelog

Set `version` to `0.3.0` in `package.json` by editing the file directly.

Do **not** run `npm version`. This repo has a `postversion` hook that runs
`git push --follow-tags && npm publish`. Publishing is the user's call.

Write the changelog entry by hand under a `0.3.0` heading, marking the
`enc` rename and the `extractable` default flip as BREAKING. The repo
normally generates `CHANGELOG.md` via `auto-changelog` during
`npm version`; since we are not running that, a hand-written entry is
correct.

## Ordering

Change 4 first, it is a one-line widening. Then 3, then 2 (which depends
on 3 being settled, since `keyId` is what makes a non-extractable default
survivable). Then 5. Then 1, last, because renaming touches 43 test sites
and you do not want that churn under you while the other changes land.
Then 6.

## Verification

Run all four and paste real output. Do not claim completion without it.

```
npm run lint
npm run build
npm run test:node
npm test
```

`npm test` builds first and then runs the suite in a browser via `tapout`.
`npm run test:node` bundles for node and runs it directly. Both execute
the same tests. If the browser run is unavailable in your environment, say
so explicitly rather than reporting three of four as a pass.

## Out of scope

- The consumer application. It pins an older version and is not being
  migrated as part of this work. Do not edit anything outside this repo.
- The HPKE wire format. Both formats stay exactly as they are:
  `enc(32) ‖ ciphertext` for `encryptKey`/`open`, and
  `wrappedLen(2, big-endian) ‖ wrapped ‖ iv(12) ‖ ciphertext` for
  `encrypt`/`decrypt`.
- The cipher suite. DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 +
  AES-256-GCM, fixed and non-configurable.
- Adding any dependency. The single runtime dependency is `uint8arrays`,
  used only to decode a string-form public key. Do not add an HPKE
  library: their X25519 KEMs need raw private-key bytes, which would force
  extractable private keys and break the non-extractable invariant this
  package exists to preserve.

## House rules that apply

- Max 80 columns.
- No space between colon and type annotation (`x:string`,
  `classes?:string[]`), exactly one space after the colon in object
  literals (`{ a: 1 }`), no space around `|` in inline unions (`A|B`).
  `npm run lint` enforces all three.
- No em dashes and no unicode arrow characters in docs or comments. Use
  the ASCII `--` and `->` instead.
- No emojis in file names or code comments.
- Do not write brittle tests. Assert on error codes and byte equality, not
  on prose.
