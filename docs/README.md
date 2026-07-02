# seal / open: AES-GCM Key Wrapping with HPKE

Wrap a symmetric AES key to your own X25519 keypair using RFC 9180 HPKE.
This is a self-encryption pattern: you seal a key now, unseal it later with
the same keypair (e.g., re-sealing a key to a new device). The API works in
modern browsers and Node.js via WebCrypto.

## API

### seal

```ts
seal(
    keypair:CryptoKeyPair,
    aesKey?:CryptoKey|null,
    opts?:HpkeOpts
):Promise<{ wrapped:Uint8Array; key:CryptoKey }>
```

Wrap an AES key to your public key.

**Parameters:**
- `keypair`: An X25519 `CryptoKeyPair` (private key may be non-extractable).
- `aesKey`: Optional AES-GCM key to seal. Omit to generate a fresh
  extractable key of `opts.keysize` bits. If supplied, it MUST be extractable
  (its raw bytes are sealed).
- `opts`: `HpkeOpts` — optional `keysize` and `info`.

**Returns:** An object with `wrapped` (the envelope bytes) and `key` (the
AES-GCM `CryptoKey` — same as input if provided, or newly generated).

### open

```ts
open(
    keypair:CryptoKeyPair,
    wrapped:Uint8Array,
    opts?:{ info? }
):Promise<CryptoKey>
```

Recover an AES key that was wrapped with `seal`, using your private key.

**Parameters:**
- `keypair`: The same X25519 `CryptoKeyPair` used to seal.
- `wrapped`: The envelope returned by `seal` (`enc ‖ ciphertext`).
- `opts`: Optional `info` — must match the value passed to `seal`.

**Returns:** The recovered AES-GCM `CryptoKey` (extractable).

### HpkeOpts

```ts
type HpkeOpts = {
    keysize?:128|192|256
    info?:Uint8Array|string
}
```

- `keysize`: Size in bits of the generated AES key. Defaults to 256. Ignored
  when an `aesKey` is supplied to `seal`.
- `info`: Bound into the HPKE key schedule for domain separation. Defaults to
  empty. Must match between `seal` and `open`.

### Wire Format

The wrapped output is 80 bytes (for a 256-bit key) or 64 bytes (for a 128-bit
key):

```
enc(32 bytes) ‖ ciphertext
```

- `enc`: The 32-byte X25519 encapsulated secret (ephemeral public key).
- `ciphertext`: The AES-256-GCM ciphertext (key bytes + 16-byte auth tag).

No salt or IV is stored; HPKE derives the AEAD nonce internally from the key
schedule.

## Usage

### Generate a new key

```ts
import { seal, open } from '@substrate-system/ecies'
import { EccKeys } from '@substrate-system/keys'

// Create a fresh keypair
const keys = await EccKeys.create()
const keypair = {
    publicKey:keys.publicExchangeKey,
    privateKey:keys.privateExchangeKey
}

// Seal a fresh key (no aesKey parameter)
const { wrapped, key } = await seal(keypair)

// Later: unseal it with the same keypair
const recovered = await open(keypair, wrapped)

// Both key and recovered are usable AES-GCM CryptoKeys
```

### Bring your own AES key

```ts
import { seal, open } from '@substrate-system/ecies'

// Suppose you have an existing AES-GCM key
const myKey = await crypto.subtle.importKey(
    'raw',
    new Uint8Array(32),
    { name:'AES-GCM' },
    true,  // Must be extractable
    ['encrypt', 'decrypt']
)

// Seal it with a specific keysize (ignored when aesKey is supplied)
const { wrapped, key } = await seal(keypair, myKey, { keysize:256 })

// Recover the same key later
const recovered = await open(keypair, wrapped)
```

### With domain separation (info)

```ts
const { wrapped } = await seal(keypair, aesKey, {
    info:'my-app:v1'
})

// info must match on unseal
const key = await open(keypair, wrapped, { info:'my-app:v1' })
```

## Why HPKE

### Ephemeral-static ECDH

HPKE's KEM uses a fresh ephemeral key pair per seal against your static
public key. Each seal produces a different envelope for the same input,
giving semantic security (RFC 9180 §7.1.3). The encapsulated secret travels
unencrypted; only the key bytes are sealed.

### HKDF Extract-then-Expand

The raw ECDH output is fragile. Running it through HKDF-SHA256 (Extract →
Expand) stretches the shared secret, adds entropy, and derives distinct
keys for different purposes without single-output reuse attacks (RFC 5869
§2; RFC 9180 §7.1.3).

### Standardized over bespoke ECIES

RFC 9180 HPKE defines a single, interoperable cipher suite with rigorous
security review. Older ECIES implementations vary widely (Diffie-Hellman
variant, KDF choice, encoding). A standard key schedule and domain separation
via `info` prevent misuse.

### Non-extractable private keys

HPKE needs only `deriveBits` on the private key. Your X25519 private key
never leaves the WebCrypto boundary and can stay non-extractable (W3C
WebCrypto / WICG Secure Curves). This hardens key isolation.

### Nonce safety

The AEAD nonce is derived from the key schedule, not stored or transmitted.
Each seal uses a fresh ephemeral, so there's no AES-GCM nonce-reuse window
(RFC 9180 §7.2.2).

### info binding

Passing `info` to both `seal` and `open` binds context (e.g., an application
name or version) into the key schedule without changing the wire format. This
provides domain separation and prevents key material from leaking across
application boundaries (RFC 9180 §7.2.1).

## Relationship to @substrate-system/keys

`@substrate-system/keys` (via `EccKeys`) can create keypairs you can pass
here. The two share a keypair, but they're **not wire-compatible**: the
`EccKeys` `wrap`/`unwrap` methods use a different internal protocol than this
package's standardized HPKE. This package uses a vendored panva `hpke`
implementation (MIT license).
