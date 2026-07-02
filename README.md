# HPKE
[![tests](https://img.shields.io/github/actions/workflow/status/nichoth/simple-hpke/nodejs.yml?style=flat-square)](https://github.com/nichoth/simple-hpke/actions/workflows/nodejs.yml)
[![types](https://img.shields.io/npm/types/@substrate-system/simple-hpke?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM%2FCJS-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![Common Changelog](https://nichoth.github.io/badge/common-changelog.svg)](./CHANGELOG.md)
[![install size](https://flat.badgen.net/packagephobia/install/@substrate-system/simple-hpke)](https://packagephobia.com/result?p=@substrate-system/simple-hpke)
[![gzip size](https://flat.badgen.net/bundlephobia/minzip/@substrate-system/simple-hpke)](https://bundlephobia.com/package/@substrate-system/simple-hpke)
[![license](https://img.shields.io/badge/license-Big_Time-blue?style=flat-square)](LICENSE)


Hybrid Public Key Encryption
([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html))


<details><summary><h2>Contents</h2></summary>

<!-- toc -->

- [Install](#install)
- [Example](#example)
  * [Key Wrapping](#key-wrapping)
  * [Hybrid Encryption](#hybrid-encryption)
    + [Encrypt / Decrypt](#encrypt--decrypt)
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
npm i -S @substrate-system/simple-hpke
```

## Example

Wrap an AES key, or encrypt a message.

### Key Wrapping

Encapsulate an AES key to yourself, then recover it later.

```ts
import { seal, open } from '@substrate-system/simple-hpke'

// An X25519 keypair. The private key can be non-extractable.
// HPKE needs only `deriveBits`.
const keypair = await crypto.subtle.generateKey(
    { name:'X25519' },
    false,  // extractable
    ['deriveBits']
)

// create a new AES key, and encapsulate it to your public key.
const { wrapped, key } = await seal(keypair)

// Or wrap an existing AES key. The supplied key must be extractable
const aesKey = await crypto.subtle.generateKey(
    { name:'AES-GCM', length:256 },
    true,  // extractable
    ['encrypt', 'decrypt']
)
const { wrapped } = await seal(keypair, aesKey)

// Later, recover the same key with your private key.
const recovered = await open(keypair, wrapped)
```

See [docs/README.md](./docs/README.md) for the full API and rationale.

### Hybrid Encryption

Seal a key, then use it to encrypt a message with AES-GCM.
The wrapped key is concattenated with the cipher text, along with the
IV. The recipient uses their private key to open the AES key and decrypt
the message.

```ts
import { seal, open } from '@substrate-system/simple-hpke'

const recipient = await crypto.subtle.generateKey(
    { name:'X25519' },
    false,
    ['deriveBits']
)

// Seal a fresh AES-GCM key, then encrypt a message under it.
const { wrapped, key } = await seal(recipient)
const iv = crypto.getRandomValues(new Uint8Array(12))
const ciphertext = await crypto.subtle.encrypt(
    { name:'AES-GCM', iv },
    key,
    new TextEncoder().encode('attack at dawn')
)

// Send `wrapped`, `iv`, and `ciphertext` together. `wrapped` is a fixed
// 80 bytes for this suite, and the AES-GCM IV is 12 bytes, so the recipient
// can slice the payload back apart at known offsets.
const ct = new Uint8Array(ciphertext)
const message = new Uint8Array(wrapped.length + iv.length + ct.length)
message.set(wrapped, 0)
message.set(iv, wrapped.length)
message.set(ct, wrapped.length + iv.length)

// On the other side, split the payload back into its parts.
const wrapped2 = message.subarray(0, 80)
const iv2 = message.subarray(80, 80 + 12)
const ciphertext2 = message.subarray(80 + 12)

// Recover the key, then decrypt the message.
const recovered = await open(recipient, wrapped2)
const plaintext = await crypto.subtle.decrypt(
    { name:'AES-GCM', iv:iv2 },
    recovered,
    ciphertext2
)

new TextDecoder().decode(plaintext)  // => 'attack at dawn'
```

#### Encrypt / Decrypt

So that was a lot of code to encrypt and decrypt a message...
This package exposes functions `encrypt` and `decrypt` which do the same thing.

`encrypt` seals an AES key to the recipient, encrypts the message under
it, and returns a single envelope: `wrappedLen + wrapped + iv + ciphertext`
(a 2-byte length prefix, the wrapped key, the 12-byte AES-GCM IV, and the
cipher text). `decrypt` reverses it, returning the plaintext bytes;
`decryptText` is a convenient way to decrypt to a string.

```ts
import {
    encrypt,
    decrypt,
    decryptText
} from '@substrate-system/simple-hpke'

// need a public key for the recipient
const recipient = await crypto.subtle.generateKey(
    { name:'X25519' },
    false,
    ['deriveBits']
)

// create a new AES key, encrypt a message, and get back one envelope
const encryptedMessage = await encrypt(recipient, 'hello encryption')

// the recipient recovers the message with their private key
const text = await decryptText(recipient, encryptedMessage)

// use `decrypt` to get a Uint8Array
const bytes = await decrypt(recipient, encryptedMessage)

//
// use an existing AES key
//
const existingKey = await crypto.subtle.generateKey(
    { name:'AES-GCM', length:256 },
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

Encrypt can take a crypto key, a Uint8Array, or a string public key as
the recipient.

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

##### Encrypt to a string

`encryptText` is `encrypt` with the envelope encoded to a string, handy for
transports that carry text (JSON, URLs, headers). `opts.encoding` sets the
string encoding. Default encoding is `base64url`.

```ts
import { encryptText, decryptText } from '@substrate-system/ecies'
import { fromString } from 'uint8arrays'

// recipient is any RecipientKey; keypair holds the matching private key
const encryptedString = await encryptText(recipient, 'message for them', null, {
    encoding:'base64url'
})

// Decode it back to bytes before decrypting.
const message = fromString(encryptedString, 'base64url')
const plaintext = await decryptText(keypair, message)
// 'message for them'
```

The returned string encodes the same envelope `encrypt` returns, so the
recipient decodes it with a matching decoder (here `fromString`) and passes the
bytes to `decrypt` / `decryptText`.


## Modules

This exposes ESM and common JS via
[package.json `exports` field](https://nodejs.org/api/packages.html#exports).

### ESM
```js
import { seal, open, encrypt, decrypt } from '@substrate-system/simple-hpke'
```

### Common JS
```js
require('@substrate-system/simple-hpke')
```

### pre-built JS
This package exposes minified JS files too. Copy them to a location that is
accessible to your web server, then link to them in HTML.

#### copy
```sh
cp ./node_modules/@substrate-system/simple-hpke/dist/index.min.js ./public/hpke.min.js
```

#### HTML
```html
<script type="module" src="./hpke.min.js"></script>
```
