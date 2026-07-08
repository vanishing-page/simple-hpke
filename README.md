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

<details><summary><h2>Contents</h2></summary>

<!-- toc -->

- [Install](#install)
- [Example](#example)
  * [Key Wrapping](#key-wrapping)
  * [Hybrid Encryption](#hybrid-encryption)
    + [Encrypt / Decrypt](#encrypt--decrypt)
      - [`encrypt`](#encrypt)
      - [`encrypt.asString`](#encryptasstring)
      - [`decrypt`](#decrypt)
      - [`decrypt.asString`](#decryptasstring)
      - [`decrypt.fromString`](#decryptfromstring)
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

## Example

Wrap an AES key, or encrypt a message.

### Key Wrapping

Encrypt an AES key to yourself, then recover it later.

```ts
import { create, seal, open } from 'simple-hpke'

// An X25519 keypair. (asymmetric keypair).
// The private key can be non-extractable.
// HPKE only needs `deriveBits`.
const keypair = await crypto.subtle.generateKey(
    { name: 'X25519' },
    false,  // extractable
    ['deriveBits']
)

// Create a new AES key and encrypt it to your public key.
const { enc, key } = await create(keypair)

// Or wrap an existing AES key. The supplied AES key must be extractable.
const aesKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,  // extractable
    ['encrypt', 'decrypt']
)

// Wrap an existing key.
const { enc: sealedKey } = await seal(keypair, aesKey)

// Later, recover the same key with your private key.
const recoveredKey = await open(keypair, sealedKey)

// `recoveredKey` is equal to `aesKey`
```

See [docs/README.md](./docs/README.md) for the full API and rationale.


------------------------------------------------------


### Hybrid Encryption

Encrypt a message with AES-GCM, then encrypt the AES key to a given
public key. The wrapped key is concattenated with the cipher text,
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
const { enc, key } = await create(recipient)
const iv = crypto.getRandomValues(new Uint8Array(12))
const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode('attack at dawn')
)

// Send `enc`, `iv`, and `ciphertext` together. `enc` is a fixed
// 80 bytes for this suite, and the AES-GCM IV is 12 bytes, so the recipient
// can slice the payload back apart at known offsets.
const ciphertext = new Uint8Array(ciphertextBuffer)
const message = new Uint8Array(enc.length + iv.length + ciphertext.length)
message.set(enc, 0)
message.set(iv, enc.length)
message.set(ciphertext, enc.length + iv.length)

// On the other side, split the payload back into its parts.
const enc2 = message.subarray(0, 80)
const iv2 = message.subarray(80, 80 + 12)
const ciphertext2 = message.subarray(80 + 12)

// Recover the key, then decrypt the message.
const recovered = await open(recipient, enc2)
const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv2 },
    recovered,
    ciphertext2
)

new TextDecoder().decode(plaintext)  // => 'attack at dawn'
```

#### Encrypt / Decrypt

So that was a lot of code to encrypt and decrypt a message...
This package exposes functions `encrypt` and `decrypt` which do the same thing.

`encrypt` seals an AES key to the recipient, encrypts the message under
that key, and returns a single envelope:
`wrappedLen + wrapped + iv + ciphertext`
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
import { encrypt, decrypt } from 'simple-hpke'

// need a public key for the recipient
const recipient = await crypto.subtle.generateKey(
    { name: 'X25519' },
    false,
    ['deriveBits']
)

// create a new AES key, encrypt a message, and get back one envelope
const encryptedMessage = await encrypt(recipient, 'hello encryption')

// the recipient recovers the message with their private key
const text = await decrypt.asString(recipient, encryptedMessage)

// use `decrypt` to get a Uint8Array
const bytes = await decrypt(recipient, encryptedMessage)

//
// use an existing AES key
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
```

##### `encrypt`

The recipient can be a crypto key, a Uint8Array, or a string public key.

```ts
type RecipientKey =
    | CryptoKey
    | CryptoKeyPair
    | Uint8Array
    | { publicKey:string; encoding?:Uint8ArrayEncodings }

async function encrypt (
    recipient:RecipientKey,
    message:Uint8Array|string,
    aesKey?:CryptoKey|Uint8Array|null,
    opts?:{
        keysize?:128|256
        info?:Uint8Array|string
    }
):Promise<Uint8Array>
```

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

Take a `string` as input. Return either a string, or if `opts.buffer` is true,
a`Uint8Array`.

```ts
decrypt.fromString = async function decryptFromString (
    keypair:CryptoKeyPair,
    message:string,
    opts?:{ info?:Uint8Array|string, buffer?:boolean }
):Promise<string|Uint8Array>
```

---------------------------------------------------------------

## Modules

This exposes ESM and common JS via
[package.json `exports` field](https://nodejs.org/api/packages.html#exports).

### ESM
```js
import { create, seal, open, encrypt, decrypt } from 'simple-hpke'
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
