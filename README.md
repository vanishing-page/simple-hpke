# Simple HPKE
[![tests](https://img.shields.io/github/actions/workflow/status/vanishing-page/simple-hpke/nodejs.yml?style=flat-square)](https://github.com/vanishing-page/simple-hpke/actions/workflows/nodejs.yml)
[![types](https://img.shields.io/npm/types/simple-hpke?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM%2FCJS-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![Common Changelog](https://nichoth.github.io/badge/common-changelog.svg)](./CHANGELOG.md)
[![install size](https://flat.badgen.net/packagephobia/install/simple-hpke)](https://packagephobia.com/result?p=simple-hpke)
[![gzip size](https://flat.badgen.net/bundlephobia/minzip/simple-hpke)](https://bundlephobia.com/package/simple-hpke)
[![license](https://img.shields.io/badge/license-Big_Time-blue?style=flat-square)](LICENSE)


Hybrid Public Key Encryption
([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html))

1 dependency -- `uint8arrays`.

On every `create`/`encrypt` call, we generate a fresh ephemeral X25519 keypair,
do Diffie-Hellman against the recipient public key, and the key schedule derives
an AES-256-GCM key from that shared secret.

That DH-derived key is the wrapping key. The AES key the API hands back is a
second, independently random key, and the wrapping key encrypts its raw
bytes. *Key wrapping* here just means "HPKE seal where the plaintext
happens to be 16 or 32 bytes of key material." The RFC doesn't care what
the plaintext is.

<details><summary><h2>Contents</h2></summary>

<!-- toc -->

- [Install](#install)
- [Examples](#examples)
  * [Key Wrapping](#key-wrapping)
    + [`open.raw`](#openraw)
  * [Hybrid Encryption](#hybrid-encryption)
    + [Encrypt / Decrypt](#encrypt--decrypt)
      - [`encrypt`](#encrypt)
      - [`encrypt.asString`](#encryptasstring)
      - [`decrypt`](#decrypt)
      - [`decrypt.asString`](#decryptasstring)
      - [`decrypt.fromString`](#decryptfromstring)
- [Extractable keys](#extractable-keys)
- [`keyId`](#keyid)
  * [`verifyKeyId`](#verifykeyid)
- [Errors](#errors)
- [Modules](#modules)
  * [ESM](#esm)
  * [Common JS](#common-js)
  * [pre-built JS](#pre-built-js)
    + [copy](#copy)
    + [HTML](#html)

<!-- tocstop -->

</details>

## Install

```sh
npm i -S simple-hpke
```

## Examples

Create an AES key, or encrypt a message.

### Key Wrapping

Encrypt an AES key, then recover it later.

```ts
import { create, encryptKey, open } from 'simple-hpke'

// An X25519 keypair. (asymmetric keypair).
// The private key can be non-extractable.
// HPKE only needs `deriveBits`.
const keypair = await crypto.subtle.generateKey(
    { name: 'X25519' },
    false,  // not extractable
    ['deriveBits']
)

// Create a new AES key and encrypt it to your public key.
// `key` is the unencrypted new AES key
// `wrapped` is the AES key encrypted to the given public key
const { wrapped, key } = await create(keypair.publicKey)  // or bytes or string

// `key` is non-extractable by default. It still encrypts and decrypts;
// it just cannot be exported. Pass `{ extractable: true }` if you need
// the raw bytes. See [Extractable keys](#extractable-keys).

//
// Or wrap an existing AES key. The supplied AES key must be extractable.
//
const aesKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,  // extractable -- its raw bytes are what get sealed
    ['encrypt', 'decrypt']
)

// Wrap the existing key. The returned key is your own `aesKey` object,
// untouched (`sameKey === aesKey`): same `extractable`, same usages.
const { wrapped: wrappedKey, key: sameKey } = await encryptKey(
    keypair,
    aesKey
)

// or pass in just a public key

// Later, recover the same key with your private key.
const recoveredKey = await open(keypair, wrappedKey)

// `recoveredKey` holds the same key material as `aesKey`
```

#### `open.raw`

Recover the wrapped key as raw bytes instead of a `CryptoKey`. Returns a
`Uint8Array` of 16 or 32 bytes, matching the key that was wrapped. It
takes the same `info` option as `open`, and no `extractable` option.

```ts
const keyBytes = await open.raw(keypair, wrappedKey)
```


------------------------------------------------------


### Hybrid Encryption

Encrypt a message with AES-GCM, then encrypt the AES key to a given
public key. The encrypted key is concatenated with the cipher text,
along with the IV. The recipient uses their private key to open the AES key and
decrypt the message.

```ts
import { create, open } from 'simple-hpke'

const recipient = await crypto.subtle.generateKey(
    { name: 'X25519' },
    false,  // not extractable
    ['deriveBits']
)

// Create a fresh AES-GCM key, and encrypt a message with it.
const { wrapped, key } = await create(recipient)
const iv = crypto.getRandomValues(new Uint8Array(12))
const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode('attack at dawn')
)

// Send `wrapped`, `iv`, and `ciphertext` together. `create(...)` defaults
// to a 256-bit AES key, so `wrapped.length` is 80 bytes in this example.
//
// If your protocol allows different wrapped-key sizes, prefix
// `wrapped.length` (or otherwise transmit it) so the recipient can split
// the payload safely.
const ciphertext = new Uint8Array(ciphertextBuffer)
const wrappedLength = wrapped.length
const message = new Uint8Array(
    wrappedLength + iv.length + ciphertext.length
)
message.set(wrapped, 0)
message.set(iv, wrappedLength)
message.set(ciphertext, wrappedLength + iv.length)

// On the other side, split the payload back into its parts.
const wrapped2 = message.subarray(0, wrappedLength)
const iv2 = message.subarray(wrappedLength, wrappedLength + 12)
const ciphertext2 = message.subarray(wrappedLength + 12)

// Recover the key, then decrypt the message.
const recovered = await open(recipient, wrapped2)
const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv2 },
    recovered,
    ciphertext2
)

new TextDecoder().decode(plaintext)  // => 'attack at dawn'
```

#### Encrypt / Decrypt

So that was a lot of code to encrypt and decrypt a message...
This package exposes functions `encrypt` and `decrypt` that do the same thing.

`encrypt` wraps an AES key to the recipient, encrypts the message under
that key, and returns a single envelope:
`wrappedLen + wrappedKey + iv + ciphertext`
(a 2-byte length prefix, the wrapped key, the 12-byte AES-GCM IV, and the
cipher text). `decrypt` reverses it, returning the plaintext bytes.

>
> [!NOTE]  
> See [`decrypt.asString`](#decryptasstring) &
> [`decrypt.fromString`](#decryptfromstring) below for a convenient way
> to decrypt from a string.
>
> See [`encrypt.asString`](#encryptasstring) for encrypting and encoding to a
> string.
>


```ts
import { toString } from 'uint8arrays'
import { encrypt, decrypt } from 'simple-hpke'

// ----------------------
// Encrypt
// ----------------------

// need a public key for the recipient
const recipient = await crypto.subtle.generateKey(
    { name: 'X25519' },
    false,  // not extractable
    ['deriveBits']
)

// create a new AES key, encrypt a message, and get back an "envelope"
const encryptedMessage = await encrypt(recipient.publicKey, 'hello encryption')

// encrypt to a public key as Uint8Array
const publicBytes = new Uint8Array(
    await crypto.subtle.exportKey('raw', recipient.publicKey)
)
const envelope = await encrypt(publicBytes, 'hello again')

// encrypt to a stringified public key
// create a string with `uint8arrays.toString`
const publicString = toString(publicBytes, 'base64url')
const envelopeAgain = await encrypt({
    publicKey: publicString,
    encoding: 'base64url'  // <-- this is the default
}, 'hello again, string version')

//
// encrypt with an existing AES key
// (a key not generated by this module)
//

const existingKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,  // extractable
    ['encrypt', 'decrypt']
)

const anotherEncryptedMsg = await encrypt(
    recipient,
    'hello again',
    existingKey
)

// ----------------------
// Decrypt
// ----------------------

// the recipient recovers the message with their private key
const text = await decrypt.asString(recipient, encryptedMessage)

// use `decrypt` to get a Uint8Array
const bytes = await decrypt(recipient, encryptedMessage)

// get a string
const plaintext = await decrypt.asString(recipient, envelope)
```

---

##### `encrypt`

The recipient can be a public crypto key, a keypair (only its public key
is used), a Uint8Array, or a string public key. `SupportedEncodings` is
the encoding type from `uint8arrays`.

```ts
type RecipientKey =
    | CryptoKey
    | CryptoKeyPair
    | Uint8Array
    | { publicKey:string; encoding?:SupportedEncodings }

async function encrypt (
    recipient:RecipientKey,
    message:Uint8Array|string,
    aesKey?:CryptoKey|Uint8Array|null,
    opts?:{
        size?:128|256
        info?:Uint8Array|string
    }
):Promise<Uint8Array>
```

A supplied `aesKey` `CryptoKey` must be extractable and must have the
`encrypt` usage, because the message is encrypted under that key directly.
A key without it rejects with `ERR_INVALID_AES_KEY` before any work is
done. The key is used as-is, never re-imported.

##### `encrypt.asString`

`encrypt.asString` is `encrypt` with the envelope encoded to a string, useful
for transports that carry text (JSON, URLs, headers). `opts.encoding` sets the
string encoding. Default encoding is `base64url`.

```ts
import { encrypt, decrypt } from 'simple-hpke'
import { fromString } from 'uint8arrays'

// recipient is any RecipientKey; keypair holds the matching private key
const encryptedString = await encrypt.asString(
    recipient,
    'message for them',
    null,  // an AES key if you want
    { encoding: 'base64url' }
)

// Decode it back to bytes before decrypting.
const message = fromString(encryptedString, 'base64url')
const plaintext = await decrypt.asString(keypair, message)
// 'message for them'
```

The returned string encodes the same envelope `encrypt` returns, so the
recipient decodes it with a matching decoder (here `fromString`) and passes the
bytes to `decrypt` / `decrypt.asString`.


##### `decrypt`

Decrypt the given data, return a `Uint8Array`.

```ts
async function decrypt (
    keypair:CryptoKeyPair,
    message:Uint8Array,
    opts?:{ info?:Uint8Array|string }
):Promise<Uint8Array>
```

##### `decrypt.asString`

Take a `Uint8Array`, return a string.

```ts
decrypt.asString = async function decryptToString (
    keypair:CryptoKeyPair,
    message:Uint8Array,
    opts?:{ info?:Uint8Array|string }
):Promise<string>
```

##### `decrypt.fromString`

Take a `base64url` string as input (as returned by `encrypt.asString` with
the default encoding). Return either a string, or if `opts.buffer` is true,
a `Uint8Array`.

```ts
decrypt.fromString = async function decryptFromString (
    keypair:CryptoKeyPair,
    message:string,
    opts?:{ info?:Uint8Array|string, buffer?:boolean }
):Promise<string|Uint8Array>
```

---------------------------------------------------------------

## Extractable keys

`create`, `encryptKey`, and `open` return a **non-extractable** AES-GCM
`CryptoKey` by default. It encrypts and decrypts normally; it just cannot
be exported, so its raw bytes cannot leak out of the runtime.

Opt in when you genuinely need the bytes:

```ts
const { wrapped, key } = await create(recipient, { extractable: true })
const bytes = new Uint8Array(await crypto.subtle.exportKey('raw', key))

// same option on the way back out
const recovered = await open(keypair, wrapped, { extractable: true })
```

This is separate from the `aesKey` you may pass **in** to `encryptKey` /
`encrypt`. That one must always be extractable, because its raw bytes are
what get sealed.

A supplied `CryptoKey` is returned **as-is**: `encryptKey` gives back the
same object you passed in, with its own `extractable` flag and usages.
`opts.extractable` does not apply to it; it only governs a key the library
imports (a generated key, or raw `Uint8Array` bytes). Because the library
does not re-import your key, it does not add usages either. `encryptKey`
will wrap a decrypt-only key, but `encrypt` needs the `encrypt` usage.

```ts
const myKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
)
const { key } = await encryptKey(recipient, myKey, { extractable: false })
key === myKey  // true, and still extractable
```

If you only need to tell two keys apart, you do not need the bytes --
use [`keyId`](#keyid).

## `keyId`

A stable fingerprint for an AES-GCM key, so you can ask "is this the key I
have?" without holding its bytes.

```ts
async function keyId (key:CryptoKey):Promise<string>
```

```ts
import { create, open, keyId } from 'simple-hpke'

const { wrapped, key } = await create(recipient)
const id = await keyId(key)     // 43-char base64url string

const recovered = await open(keypair, wrapped)
await keyId(recovered) === id   // true
```

It works on a **non-extractable** key -- including one rehydrated from
IndexedDB -- which is the whole point: the obvious implementation
(`exportKey('raw')` then SHA-256) would force every key you want to
identify to be extractable.

The derivation is fixed, and is treated as wire format:

```
LABEL = utf8("simple-hpke/keyId/v1")
N     = SHA-256(LABEL)[0..12]        // fixed nonce
C     = AES-GCM(key, N, LABEL)       // ciphertext || 16-byte tag
keyId = base64url(SHA-256(LABEL || C))
```

`key` must be an AES-GCM key with the `encrypt` usage; anything else
throws [`ERR_INVALID_AES_KEY`](#errors).

### `verifyKeyId`

Check a key against a `keyId` you stored earlier.

```ts
async function verifyKeyId (
    key:CryptoKey,
    expected:string
):Promise<boolean>
```

```ts
import { open, verifyKeyId } from 'simple-hpke'

const recovered = await open(keypair, wrapped)
if (!(await verifyKeyId(recovered, storedId))) {
    // not the key you expected
}
```

It resolves `true` or `false`, comparing in constant time. A key that
`keyId` cannot fingerprint (not AES-GCM, or no `encrypt` usage) rejects
with [`ERR_INVALID_AES_KEY`](#errors) rather than resolving `false`, so
"cannot check this key" is never confused with "wrong key". Do not catch
that error and return `false`.

## Errors

Every error this package throws is an `HpkeError`: an ordinary `Error`
with a stable `code`. Branch on the code, not on the message text -- the
codes are part of the API, the prose is not. Where a WebCrypto failure is
being wrapped, the original is kept on `cause`.

```ts
import { decrypt, HpkeError } from 'simple-hpke'

try {
    await decrypt(keypair, envelope)
} catch (err) {
    if (err instanceof HpkeError && err.code === 'ERR_DECRYPT_FAILED') {
        // wrong keypair, wrong `info`, or a tampered envelope
    }
    throw err
}
```

| Code | Raised when |
| --- | --- |
| `ERR_INVALID_RECIPIENT_KEY` | The recipient is not a usable X25519 public key: wrong length, a private key, the wrong algorithm, a non-extractable public key, a string that does not decode, or an unrecognized form. |
| `ERR_INVALID_KEYPAIR` | `keypair.privateKey` is not an X25519 private key or lacks the `deriveBits` usage, or `keypair.publicKey` is not an extractable X25519 public key. |
| `ERR_SMALL_ORDER_KEY` | A small-order X25519 public key (for example all zeros), as the recipient or as the `enc` in a tampered envelope. Raised on conforming runtimes, which reject it inside `deriveBits`, and on nonconforming ones, where the shared secret comes out all-zero. |
| `ERR_MALFORMED_ENVELOPE` | An `open` / `open.raw` envelope is too short to hold `enc` plus an AEAD tag. |
| `ERR_MALFORMED_MESSAGE` | A `decrypt` envelope is too short to hold its own declared segments, or a `decrypt.fromString` input is not valid `base64url`. |
| `ERR_INVALID_KEYSIZE` | `opts.size` is neither `128` nor `256`. |
| `ERR_INVALID_AES_KEY` | A supplied `aesKey` is the wrong length, non-extractable, or not an AES-GCM key, `encrypt` got an `aesKey` without the `encrypt` usage, or `keyId` / `verifyKeyId` got a key it cannot use. |
| `ERR_DECRYPT_FAILED` | AES-GCM authentication failed: wrong keypair, wrong `info`, or a tampered ciphertext. |

`HpkeErrorCode` is exported as a type if you want to switch exhaustively.

---------------------------------------------------------------

## Modules

This exposes ESM and common JS via
[package.json `exports` field](https://nodejs.org/api/packages.html#exports).

### ESM
```js
import {
    create,
    encryptKey,
    open,
    encrypt,
    decrypt,
    keyId,
    verifyKeyId,
    HpkeError
} from 'simple-hpke'
```

### Common JS
```js
require('simple-hpke')
```

### pre-built JS
This package exposes minified JS files too. Copy them to a location that is
accessible to your web server, then link to them in HTML.

#### copy
```sh
cp ./node_modules/simple-hpke/dist/index.min.js ./public/hpke.min.js
```

#### HTML
```html
<script type="module" src="./hpke.min.js"></script>
```
