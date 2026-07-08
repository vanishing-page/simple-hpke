# create / seal / open

Wrap AES keys to an X25519 recipient with HPKE
([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html)).

Use:

- `create(...)` when you want this package to generate a fresh AES-GCM key.
- `seal(...)` when you already have the AES key bytes you want to wrap.
- `open(...)` or `open.raw(...)` to recover that key later.

The API works in modern browsers and in Node.js via WebCrypto.

## API

### create

```ts
create(
    recipient:RecipientKey,
    opts?:{
        size?:128|256
        info?:Uint8Array|string
    }
):Promise<{ enc:Uint8Array; key:CryptoKey }>
```

Generate a fresh AES-GCM key, wrap it to `recipient`, and return both:

- `enc`: the wrapped envelope bytes to store or send
- `key`: the generated AES-GCM `CryptoKey`

`size` defaults to `256`.

### seal

```ts
seal(
    recipient:RecipientKey,
    aesKey:CryptoKey|Uint8Array|null,
    opts?:{ info?:Uint8Array|string }
):Promise<{ enc:Uint8Array; key:CryptoKey }>
```

Wrap an existing AES key to `recipient`.

- `aesKey` may be an extractable AES-GCM `CryptoKey`
- `aesKey` may also be raw key bytes as a `Uint8Array`
- Raw keys must be 16 or 32 bytes

Returns:

- `enc`: the wrapped envelope bytes to store or send
- `key`: a usable AES-GCM `CryptoKey` with the same raw bytes

### open

```ts
open(
    keypair:CryptoKeyPair,
    enc:Uint8Array,
    opts?:{ info?:Uint8Array|string }
):Promise<CryptoKey>
```

Recover an AES-GCM `CryptoKey` from the `enc` bytes returned by `create` or
`seal`.

### open.raw

```ts
open.raw(
    keypair:CryptoKeyPair,
    enc:Uint8Array,
    opts?:{ info?:Uint8Array|string }
):Promise<Uint8Array>
```

Like `open(...)`, but returns raw key bytes instead of importing them as a
`CryptoKey`.

### RecipientKey

```ts
type RecipientKey =
    | CryptoKey
    | CryptoKeyPair
    | Uint8Array
    | { publicKey:string; encoding?:Uint8ArrayEncodings }
```

`create`, `seal`, and `encrypt` all accept the same recipient forms:

- an X25519 public `CryptoKey`
- a full `CryptoKeyPair` where only `.publicKey` is used
- 32 raw X25519 public-key bytes
- an encoded public-key string, defaulting to `base64url`

`open` and `decrypt` still require the full recipient `CryptoKeyPair`.

## Examples

### Generate and wrap a new key

```ts
import { create, open } from 'simple-hpke'

const keypair = await crypto.subtle.generateKey(
    { name: 'X25519' },
    false,
    ['deriveBits']
)

const { enc, key } = await create(keypair, { size: 256 })
const recovered = await open(keypair, enc)

// `key` and `recovered` hold the same AES key bytes.
```

### Wrap an existing AES key

```ts
import { seal, open } from 'simple-hpke'

const myKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
)

const { enc } = await seal(keypair, myKey)
const recovered = await open(keypair, enc)
```

### Wrap raw AES key bytes

```ts
import { seal, open } from 'simple-hpke'

const rawKey = crypto.getRandomValues(new Uint8Array(32))
const { enc } = await seal(keypair, rawKey)
const recovered = await open.raw(keypair, enc)
```

### Bind context with info

```ts
const { enc } = await create(keypair, { info: 'my-app:v1' })
const recovered = await open(keypair, enc, { info: 'my-app:v1' })
```

`info` must match on both sides.

## Wire Format

The `enc` value returned by `create` and `seal` is the HPKE envelope:

```txt
encapsulated_public_key(32 bytes) || ciphertext
```

Its length is:

- 64 bytes for a 128-bit AES key
- 80 bytes for a 256-bit AES key

## Related APIs

- `encrypt(...)` and `decrypt(...)` build on the same wrapping logic, but
  also AES-GCM encrypt a message payload.
- `encrypt.asString(...)` and `decrypt.fromString(...)` add string encoding
  helpers for transport.
