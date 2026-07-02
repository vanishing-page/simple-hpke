# HPKE Self-Wrap Implementation Plan — Phase 4

**Goal:** Document the public API and fold in the "why HPKE" rationale.

**Architecture:** Documentation only. `docs/README.md` currently describes the
old hand-rolled ECIES protocol; this phase replaces it with `seal`/`open` usage
plus a concise, sourced rationale. The stale top-level `README.md` example
(which referenced the removed `example()`) is refreshed to match.

**Tech Stack:** Markdown.

**Scope:** Phase 4 of 4 from `docs/design-plans/2026-07-01-hpke-self-wrap.md`.

**Codebase verified:** 2026-07-02

---

## Acceptance Criteria Coverage

**Verifies: None** (documentation phase — verified by review, no tests). This
phase completes the design's "Best-practice research on ECC self-encryption is
folded into `docs/`" done-when.

---

## Writing guidance

- Follow the `ed3d-house-style:writing-for-a-technical-audience` conventions:
  plain, direct prose; no AI-slop filler; short examples over walls of text.
- Do **not** copy prose from the design plan; write fresh, accurate docs from
  the implemented API.
- **Read `package.json` and use the real `"name"` field** in all import
  examples (do not guess the package name).
- Keep code samples consistent with the shipped API: `seal(keypair, aesKey?,
  opts?)` → `{ wrapped, key }`; `open(keypair, wrapped, opts?)` → `CryptoKey`;
  `HpkeOpts` = `{ keysize?:128|192|256, info?:Uint8Array|string }`.
- Write samples in the repo's TS style (no-space colons in both type
  annotations and object literals, e.g. `{ keysize:256 }`) so copy-pasted code
  matches the codebase.

---

<!-- START_TASK_1 -->
### Task 1: Rewrite `docs/README.md`

**Files:**
- Modify: `docs/README.md` (replace the ECIES-protocol content)

**Implementation:**

Write `docs/README.md` covering, in this order:

1. **What it does** — one short paragraph: wraps a symmetric AES key to a
   keypair's own X25519 public key using RFC-9180 HPKE (a self-encryption /
   self-wrap pattern, e.g. re-sealing a key to a new device using only the
   existing long-term keypair). Note it operates on a raw WebCrypto
   `CryptoKeyPair` and runs in modern browsers and Node.

2. **API reference** —
   - `seal(keypair:CryptoKeyPair, aesKey?:CryptoKey|null, opts?:HpkeOpts)` →
     `Promise<{ wrapped:Uint8Array; key:CryptoKey }>`. Document: `aesKey`
     omitted generates a fresh extractable AES-GCM key of `opts.keysize` bits;
     `aesKey` supplied must be **extractable** (its raw bytes are sealed);
     `keysize` defaults to 256 and is ignored when `aesKey` is supplied.
   - `open(keypair:CryptoKeyPair, wrapped:Uint8Array, opts?:{ info? })` →
     `Promise<CryptoKey>`. `info` must match the `seal` call.
   - `HpkeOpts` — `keysize?:128|192|256`, `info?:Uint8Array|string` (default
     empty; bound into the HPKE key schedule).
   - **Wire format:** `enc(32) ‖ ciphertext` — 80 bytes for a 256-bit key, 64
     for 128-bit. No stored salt or IV (HPKE derives the AEAD nonce internally).

3. **Usage example with `@substrate-system/keys`** — mint the keypair with
   `EccKeys.create()`, assemble `{ publicKey:keys.publicExchangeKey,
   privateKey:keys.privateExchangeKey }`, `seal` it, `open` it. Show a
   generated-key example and a bring-your-own-key example. Mention the returned
   `key` is a usable AES-GCM `CryptoKey`.

4. **Why HPKE (rationale)** — a short section drawn from the research. Cover,
   each in 2–4 sentences, and cite the referenced RFCs/sources inline:
   - **Ephemeral-static ECDH:** HPKE's KEM uses a fresh ephemeral key pair per
     seal against the recipient's static key, giving forward-secrecy-like
     properties and semantic security (same key sealed twice → different
     envelopes; verified by AC3.4). [RFC 9180 §7.1.3]
   - **HKDF Extract-then-Expand:** why the raw DH output is run through
     HKDF-SHA256 rather than used directly as a key. [RFC 5869 §2; RFC 9180
     §7.1.3]
   - **Standardized HPKE over bespoke ECIES:** interoperability, security
     review, a defined key schedule, and `info`-based domain separation vs. the
     older, non-interoperable ECIES family. [RFC 9180]
   - **Non-extractable private keys:** HPKE needs only `deriveBits` on the
     private key, so the X25519 private key can be non-extractable and never
     leave the WebCrypto boundary. [W3C WebCrypto / WICG Secure Curves]
   - **Nonce safety:** the AEAD nonce is derived from the key schedule (no
     transmitted IV) and each seal uses a fresh ephemeral, so there is no
     AES-GCM nonce-reuse exposure. [RFC 9180 §7.2.2]
   - **`info`:** binding context into the key schedule gives domain separation
     without changing the wire format. [RFC 9180 §7.2.1]

5. **Relationship to `@substrate-system/keys`** — one short paragraph: the two
   can share a keypair but are **not wire-compatible**; this package uses
   standardized HPKE (vendored panva `hpke`, MIT) rather than the `EccKeys`
   built-in `wrap`/`unwrap`.

**Reference sources** (cite as appropriate; do not dump the full list unless it
reads well): RFC 9180 (HPKE), RFC 5869 (HKDF), RFC 8452 (nonce-misuse context),
W3C WebCrypto / WICG Secure Curves, panva/hpke.

**Verification:** none automated. Confirm the file documents `seal`, `open`,
`HpkeOpts`, the wire format, a working `@substrate-system/keys` example, and the
rationale points above.

**Commit:** `docs: document seal/open API and the HPKE rationale`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Refresh the top-level `README.md` example

**Files:**
- Modify: `README.md` (the "Example" section)

**Implementation:**

Phase 1 removed the `example()` placeholder that the top-level README's Example
section referenced. Read `README.md`, and replace the stale example with a
minimal `seal`/`open` snippet (generated-key round-trip) using the real package
`name` from `package.json`. Keep the existing Install and Modules sections
intact. Optionally add a one-line link to `docs/README.md` for the full API and
rationale.

**Verification:** none automated. Confirm the Example section no longer
references `example()` and shows real `seal`/`open` usage that matches the
shipped API.

**Commit:** `docs: update README example to seal/open`
<!-- END_TASK_2 -->
