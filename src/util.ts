import {
    toString,
    fromString,
    type SupportedEncodings
} from 'uint8arrays'
import { create, seal } from './index.js'
import {
    WRAPPED_LEN_PREFIX,
    NN,
    NSECRET,
    HPKE_V1,
    ENC_LENGTH,
    KEM_SUITE_ID
} from './constants.js'
const subtle = globalThis.crypto.subtle

/**
 * A recipient's X25519 public key, in any of four forms:
 * - `CryptoKey`: an X25519 public key.
 * - `CryptoKeyPair`: its `.publicKey` is used (encryption never needs the
 *   private half).
 * - `Uint8Array`: 32 raw X25519 public-key bytes.
 * - `{ publicKey, encoding? }`: the public key as an encoded string;
 *   `encoding` defaults to `base64url`.
 */
export type RecipientKey =
    | CryptoKey
    | CryptoKeyPair
    | Uint8Array
    | { publicKey:string; encoding?:SupportedEncodings }

/**
 * AEAD (AES-256-GCM), single-shot at sequence 0
 */
export async function aeadSeal (
    key:Uint8Array,
    nonce:Uint8Array,
    plaintext:Uint8Array
):Promise<Uint8Array> {
    const k = await subtle.importKey(
        'raw',
        key as BufferSource,
        { name: 'AES-GCM' },
        false,
        ['encrypt']
    )
    const ct = await subtle.encrypt(
        { name: 'AES-GCM', iv: nonce as BufferSource },
        k,
        plaintext as BufferSource
    )
    return new Uint8Array(ct)
}

export async function aeadOpen (
    key:Uint8Array,
    nonce:Uint8Array,
    ciphertext:Uint8Array
):Promise<Uint8Array> {
    const k = await subtle.importKey(
        'raw',
        key as BufferSource,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    )
    const pt = await subtle.decrypt(
        { name: 'AES-GCM', iv: nonce as BufferSource },
        k,
        ciphertext as BufferSource
    )
    return new Uint8Array(pt)
}

/**
 * Seal a fresh (or supplied) AES key to `recipient`, then AES-GCM encrypt a
 * message under it. The wrapped key, IV, and ciphertext are concatenated
 * into a single self-describing envelope.
 *
 * Wire format: `wrappedLen(2, big-endian) ‖ wrapped ‖ iv(12) ‖ ciphertext`.
 * The length prefix lets `decrypt` slice the segments apart for either
 * 128- or 256-bit wrapped keys.
 *
 * @param recipient The recipient's X25519 public key, as a `CryptoKey`,
 *   `CryptoKeyPair` (its `.publicKey` is used), 32 raw bytes (`Uint8Array`),
 *   or `{ publicKey:string, encoding? }` (encoding defaults to `base64url`).
 * @param message Plaintext to encrypt. A `string` is UTF-8 encoded.
 * @param aesKey Optional key, as either an AES-GCM `CryptoKey` or its raw
 *   bytes (`Uint8Array`, 16 or 32 bytes). Omit to generate a fresh key of
 *   `opts.size` bits. A supplied `CryptoKey` MUST be extractable. Each
 *   call picks a fresh random 96-bit IV for the message ciphertext, so
 *   reusing the same `aesKey` across many calls carries the standard
 *   birthday bound for random nonces (collision risk becomes
 *   non-negligible around 2^32 messages under one key, NIST SP 800-38D) --
 *   prefer a fresh key per call (the default) over reusing one at scale.
 * @param opts `size` (128/256, default 256; ignored when `aesKey` is
 *   supplied) and `info` (bound into the HPKE key schedule).
 * @returns The concatenated envelope bytes.
 *
 * `encrypt.asString(...)` returns the same envelope as an encoded string.
 */
export async function encryptBytes (
    recipient:RecipientKey,
    message:Uint8Array|string,
    aesKey?:CryptoKey|Uint8Array|null,
    opts?:{
        size?:128|256
        info?:Uint8Array|string
    }
):Promise<Uint8Array> {
    const plaintext = typeof message === 'string' ?
        new TextEncoder().encode(message) :
        message

    let enc:Uint8Array<ArrayBufferLike>
    let key:CryptoKey
    if (!aesKey) {
        const keys = await create(recipient, opts)
        enc = keys.enc
        key = keys.key
    } else {
        const keys = await seal(recipient, aesKey, opts)
        enc = keys.enc
        key = keys.key
    }

    // const { enc, key } = await seal(recipient, aesKey, opts)
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(NN))
    const ct = new Uint8Array(await subtle.encrypt(
        { name: 'AES-GCM', iv: iv as BufferSource },
        key,
        plaintext as BufferSource
    ))

    return concat(i2osp(enc.length, WRAPPED_LEN_PREFIX), enc, iv, ct)
}

/**
 * Like `encrypt`, but encodes the envelope bytes to a string — handy for
 * transports that carry text (JSON, URLs, headers). Decode with
 * `fromString(...)` (or any matching decoder) and pass the bytes to
 * `decrypt` / `decrypt.asString`. Exposed as `encrypt.asString`.
 *
 * @param recipient The recipient's X25519 public key, as a `CryptoKey`,
 *   `CryptoKeyPair` (its `.publicKey` is used), 32 raw bytes (`Uint8Array`),
 *   or `{ publicKey:string, encoding? }` (encoding defaults to `base64url`).
 * @param message Plaintext to encrypt. A `string` is UTF-8 encoded.
 * @param aesKey Optional key, as either an AES-GCM `CryptoKey` or its raw
 *   bytes (`Uint8Array`, 16 or 32 bytes). Omit to generate a fresh key of
 *   `opts.size` bits. A supplied `CryptoKey` MUST be extractable. Each
 *   call picks a fresh random 96-bit IV for the message ciphertext, so
 *   reusing the same `aesKey` across many calls carries the standard
 *   birthday bound for random nonces (collision risk becomes
 *   non-negligible around 2^32 messages under one key, NIST SP 800-38D) --
 *   prefer a fresh key per call (the default) over reusing one at scale.
 * @param opts `size` (128/256, default 256; ignored when `aesKey` is
 *   supplied), `info` (bound into the HPKE key schedule), and `encoding`
 *   (the string encoding of the returned envelope; default `base64url`).
 * @returns The encoded envelope string.
 */
export async function encryptToString (
    recipient:RecipientKey,
    message:Uint8Array|string,
    aesKey?:CryptoKey|Uint8Array|null,
    opts?:{
        size?:128|256
        info?:Uint8Array|string
        encoding?:SupportedEncodings
    }
):Promise<string> {
    const envelope = await encryptBytes(recipient, message, aesKey, opts)
    return toString(envelope, opts?.encoding ?? 'base64url')
}

// ----- HKDF via HMAC-SHA256 (imperative shell) -----
//
// WebCrypto's native HKDF fuses extract+expand and cannot take a supplied
// PRK, so RFC 9180's LabeledExtract / LabeledExpand are built directly on
// HMAC-SHA256.

export async function hmac (key:Uint8Array, data:Uint8Array):Promise<Uint8Array> {
    const k = await subtle.importKey(
        'raw',
        key as BufferSource,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    )
    return new Uint8Array(await subtle.sign('HMAC', k, data as BufferSource))
}

// HKDF-Extract(salt, ikm) = HMAC(salt, ikm). Empty salt becomes 32 zero
// bytes (RFC 5869: salt defaults to HashLen zeros).
async function extract (
    salt:Uint8Array,
    ikm:Uint8Array
):Promise<Uint8Array> {
    const key = salt.length === 0 ? new Uint8Array(NSECRET) : salt
    return hmac(key, ikm)
}

// HKDF-Expand(prk, info, L).
async function expand (
    prk:Uint8Array,
    info:Uint8Array,
    length:number
):Promise<Uint8Array> {
    const out = new Uint8Array(length)
    let t:Uint8Array = new Uint8Array(0)
    let offset = 0
    let counter = 1
    while (offset < length) {
        t = await hmac(prk, concat(t, info, i2osp(counter, 1)))
        const take = Math.min(t.length, length - offset)
        out.set(t.subarray(0, take), offset)
        offset += take
        counter++
    }
    return out
}

// LabeledExtract(salt, label, ikm) with a given suite_id.
export async function labeledExtract (
    suiteId:Uint8Array,
    salt:Uint8Array,
    label:string,
    ikm:Uint8Array
):Promise<Uint8Array> {
    const labeledIkm = concat(
        HPKE_V1,
        suiteId,
        new TextEncoder().encode(label),
        ikm
    )
    return extract(salt, labeledIkm)
}

// LabeledExpand(prk, label, info, L) with a given suite_id.
export async function labeledExpand (
    suiteId:Uint8Array,
    prk:Uint8Array,
    label:string,
    info:Uint8Array,
    length:number
):Promise<Uint8Array> {
    const labeledInfo = concat(
        i2osp(length, 2),
        HPKE_V1,
        suiteId,
        new TextEncoder().encode(label),
        info
    )
    return expand(prk, labeledInfo, length)
}

// ----- DHKEM(X25519, HKDF-SHA256) -----

async function exportRawPublic (key:CryptoKey):Promise<Uint8Array> {
    return new Uint8Array(await subtle.exportKey('raw', key))
}

// Import 32 raw bytes as an X25519 public key. Imported extractable: the KEM
// re-exports the recipient public key for its context, and a public key holds
// no secret.
async function importRawPublic (raw:Uint8Array):Promise<CryptoKey> {
    if (raw.length !== ENC_LENGTH) {
        throw new Error(
            `invalid public key length: ${raw.length} bytes ` +
            `(expected ${ENC_LENGTH})`
        )
    }
    return subtle.importKey(
        'raw',
        raw as BufferSource,
        { name: 'X25519' },
        true,
        []
    )
}

// Resolve any accepted recipient form to an X25519 public `CryptoKey`.
// Encryption only ever needs the recipient's public key, so a supplied
// `CryptoKeyPair` contributes only its `.publicKey`.
export async function resolveRecipientPublicKey (
    recipient:RecipientKey
):Promise<CryptoKey> {
    // Raw 32-byte X25519 public key.
    if (recipient instanceof Uint8Array) {
        return importRawPublic(recipient)
    }

    // A single public CryptoKey.
    if (recipient instanceof CryptoKey) {
        if (recipient.type !== 'public') {
            throw new Error('recipient CryptoKey must be a public key')
        }
        assertX25519Algorithm(recipient, 'recipient CryptoKey')
        return recipient
    }

    // String form: { publicKey, encoding? }, encoding defaults to base64url.
    if (typeof (recipient as { publicKey?:unknown }).publicKey === 'string') {
        const { publicKey, encoding } =
            recipient as { publicKey:string; encoding?:SupportedEncodings }
        return importRawPublic(fromString(publicKey, encoding ?? 'base64url'))
    }

    // CryptoKeyPair: use its public half.
    const pair = recipient as CryptoKeyPair
    if (pair.publicKey instanceof CryptoKey) {
        if (pair.publicKey.type !== 'public') {
            throw new Error('recipient keypair publicKey must be a public key')
        }
        assertX25519Algorithm(pair.publicKey, 'recipient keypair publicKey')
        return pair.publicKey
    }

    throw new Error('unrecognized recipient key form')
}

// Guards against an easy mistake (e.g. passing an Ed25519 signing key from
// a library that exposes both): fail with a clear message here rather than
// an opaque WebCrypto error later inside deriveBits.
function assertX25519Algorithm (key:CryptoKey, context:string):void {
    if (key.algorithm.name !== 'X25519') {
        throw new Error(
            `${context} must be an X25519 key (got ${key.algorithm.name})`
        )
    }
}

// X25519 Diffie-Hellman via WebCrypto deriveBits (works with a
// non-extractable private key).
async function dh (
    priv:CryptoKey,
    pub:CryptoKey
):Promise<Uint8Array> {
    const bits = await subtle.deriveBits(
        { name: 'X25519', public: pub },
        priv,
        256
    )
    const bytes = new Uint8Array(bits)

    // The Secure Curves spec requires deriveBits to throw on an all-zero
    // output (a small-order public key); conforming runtimes never reach
    // here. Kept as defense-in-depth against a nonconforming runtime.
    if (bytes.every(b => b === 0)) {
        throw new Error(
            'X25519 shared secret is all-zero (small-order public key?)'
        )
    }

    return bytes
}

// DHKEM ExtractAndExpand: derive the KEM shared secret from the DH output
// and the KEM context (enc || pkRm).
async function extractAndExpand (
    dhBytes:Uint8Array,
    kemContext:Uint8Array
):Promise<Uint8Array> {
    const eaePrk = await labeledExtract(
        KEM_SUITE_ID,
        new Uint8Array(0),
        'eae_prk',
        dhBytes
    )
    return labeledExpand(
        KEM_SUITE_ID,
        eaePrk,
        'shared_secret',
        kemContext,
        NSECRET
    )
}

// Encap(pkR): generate an ephemeral keypair, run DH, and derive the shared
// secret. Returns the shared secret and the encapsulated public key (enc).
export async function encap (
    pkR:CryptoKey
):Promise<{ sharedSecret:Uint8Array; enc:Uint8Array }> {
    const eph = await subtle.generateKey(
        { name: 'X25519' },
        false,
        ['deriveBits']
    ) as CryptoKeyPair

    const dhBytes = await dh(eph.privateKey, pkR)
    const enc = await exportRawPublic(eph.publicKey)
    const pkRm = await exportRawPublic(pkR)
    const kemContext = concat(enc, pkRm)
    const sharedSecret = await extractAndExpand(dhBytes, kemContext)
    return { sharedSecret, enc }
}

// Decap(enc, skR): recover the shared secret from an encapsulated public
// key and the recipient keypair.
export async function decap (
    enc:Uint8Array,
    keypair:CryptoKeyPair
):Promise<Uint8Array> {
    if (keypair.privateKey.type !== 'private') {
        throw new Error('keypair.privateKey must be a private key')
    }
    assertX25519Algorithm(keypair.privateKey, 'keypair.privateKey')

    const pkE = await subtle.importKey(
        'raw',
        enc as BufferSource,
        { name: 'X25519' },
        false,
        []
    )
    const dhBytes = await dh(keypair.privateKey, pkE)
    const pkRm = await exportRawPublic(keypair.publicKey)
    const kemContext = concat(enc, pkRm)
    return extractAndExpand(dhBytes, kemContext)
}

// ----- Pure byte helpers  -----

// I2OSP(n, len): big-endian encode a non-negative integer into `len` bytes.
export function i2osp (n:number, len:number):Uint8Array {
    const out = new Uint8Array(len)
    let v = n
    for (let i = len - 1; i >= 0; i--) {
        out[i] = v & 0xff
        v = Math.floor(v / 256)
    }
    return out
}

export function concat (...arrays:Uint8Array[]):Uint8Array {
    let total = 0
    for (const a of arrays) total += a.length
    const out = new Uint8Array(total)
    let offset = 0
    for (const a of arrays) {
        out.set(a, offset)
        offset += a.length
    }
    return out
}
