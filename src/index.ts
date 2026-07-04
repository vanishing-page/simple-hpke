// RFC 9180 HPKE cipher suite
// (DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM, base mode, single-shot)
// - Pure helpers build the labeled byte strings
// - all crypto runs through WebCrypto's subtle API so the X25519 private
//   key can stay non-extractable (HPKE needs only `deriveBits`).

import { fromString, toString, type SupportedEncodings } from 'uint8arrays'

const subtle = globalThis.crypto.subtle

// String-key encodings, re-exported from `uint8arrays` (the only runtime
// dependency). Named `Uint8ArrayEncodings` here for the public API.
export type Uint8ArrayEncodings = SupportedEncodings

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
    | { publicKey:string; encoding?:Uint8ArrayEncodings }

// RFC 9180 suite identifiers for the one suite this package implements:
// DHKEM(X25519, HKDF-SHA256) = 0x0020, HKDF-SHA256 = 0x0001,
// AES-256-GCM = 0x0002.
const KEM_ID = 0x0020
const KDF_ID = 0x0001
const AEAD_ID = 0x0002

// Lengths (bytes). Nsecret/Nk/Nh follow SHA-256; Nn/Nenc/tag are the
// AES-256-GCM nonce, X25519 encapsulated-key, and GCM tag sizes.
const NSECRET = 32
const NK = 32
const NN = 12
const ENC_LENGTH = 32
const AEAD_TAG_LENGTH = 16

// HPKE base mode.
const MODE_BASE = 0x00

const HPKE_V1 = new TextEncoder().encode('HPKE-v1')

// suite_id for KEM labeled calls: "KEM" || I2OSP(kem_id, 2).
const KEM_SUITE_ID = concat(
    new TextEncoder().encode('KEM'),
    i2osp(KEM_ID, 2)
)

// suite_id for key-schedule labeled calls:
// "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2).
const HPKE_SUITE_ID = concat(
    new TextEncoder().encode('HPKE'),
    i2osp(KEM_ID, 2),
    i2osp(KDF_ID, 2),
    i2osp(AEAD_ID, 2)
)

/**
 * Wrap an AES key to a recipient's public key.
 *
 * @param recipient The recipient's X25519 public key, as a `CryptoKey`,
 *   `CryptoKeyPair` (its `.publicKey` is used), 32 raw bytes (`Uint8Array`),
 *   or `{ publicKey:string, encoding? }` (encoding defaults to `base64url`).
 * @param aesKey Optional key to seal, as either an AES-GCM `CryptoKey` or its
 *   raw bytes (`Uint8Array`, 16 or 32 bytes). Omit to generate a fresh
 *   extractable key of `opts.keysize` bits. A supplied `CryptoKey` MUST be
 *   extractable (its raw bytes are sealed).
 * @param opts `keysize` (128/256, default 256; ignored when `aesKey` is
 *   supplied) and `info` (bound into the HPKE key schedule; default empty).
 * @returns { wrapped:Uint8Array, key:CryptoKey } The envelope bytes and a
 *   usable AES-GCM `CryptoKey`.
 */
export async function seal (
    recipient:RecipientKey,
    aesKey?:CryptoKey|Uint8Array|null,
    opts?:{
        // Size of the GENERATED AES key. Ignored when an `aesKey` is supplied.
        keysize?:128|256
        // HPKE `info`: bound into the key schedule; must match on seal + open.
        info?:Uint8Array|string
    }
):Promise<{ wrapped:Uint8Array; key:CryptoKey }> {
    const info = normalizeInfo(opts?.info)

    let keyBytes:Uint8Array
    if (aesKey instanceof Uint8Array) {
        validateRawKeyBytes(aesKey)
        keyBytes = aesKey
    } else if (aesKey) {
        keyBytes = await exportAesKeyBytes(aesKey)
    } else {
        const keysize = opts?.keysize ?? 256
        validateKeysize(keysize)
        keyBytes = globalThis.crypto.getRandomValues(
            new Uint8Array(keysize / 8)
        )
    }

    const publicKey = await resolveRecipientPublicKey(recipient)
    const { sharedSecret, enc } = await encap(publicKey)
    const { key, baseNonce } = await keySchedule(sharedSecret, info)
    const ciphertext = await aeadSeal(key, baseNonce, keyBytes)

    const wrapped = concat(enc, ciphertext)
    const aesGcmKey = await importAesKey(keyBytes)
    return { wrapped, key: aesGcmKey }
}

/**
 * Recover an AES key that was wrapped with `seal`, using your private key.
 *
 * @param keypair The same X25519 `CryptoKeyPair` used to seal.
 * @param wrapped The envelope returned by `seal` (`enc ‖ ciphertext`).
 * @param opts `info` — must match the value passed to `seal`.
 * @returns The recovered AES-GCM `CryptoKey` (extractable).
 */
async function openBytes (
    keypair:CryptoKeyPair,
    wrapped:Uint8Array,
    opts?:{ info:Uint8Array|string }
):Promise<CryptoKey> {
    const keyBytes = await openRawBytes(keypair, wrapped, opts)
    return importAesKey(keyBytes)
}

/**
 * Like `open`, but returns the recovered key as raw bytes instead of
 * importing it as an AES-GCM `CryptoKey`. Exposed as `open.raw`.
 *
 * @param keypair The same X25519 `CryptoKeyPair` used to seal.
 * @param wrapped The envelope returned by `seal` (`enc ‖ ciphertext`).
 * @param opts `info` — must match the value passed to `seal`.
 * @returns The recovered key bytes (16 or 32 bytes, matching whatever
 *   was sealed).
 */
async function openRawBytes (
    keypair:CryptoKeyPair,
    wrapped:Uint8Array,
    opts?:{ info:Uint8Array|string }
):Promise<Uint8Array> {
    if (wrapped.byteLength < ENC_LENGTH + AEAD_TAG_LENGTH) {
        throw new Error('malformed envelope: too short')
    }

    const info = normalizeInfo(opts?.info)
    const enc = wrapped.slice(0, ENC_LENGTH)
    const ciphertext = wrapped.slice(ENC_LENGTH)

    const sharedSecret = await decap(enc, keypair)
    const { key, baseNonce } = await keySchedule(sharedSecret, info)
    return aeadOpen(key, baseNonce, ciphertext)
}

/**
 * Recover the AES key wrapped by `seal`. Call `open(...)` for a usable
 * AES-GCM `CryptoKey`, or `open.raw(...)` for the raw key bytes.
 */
export const open = Object.assign(openBytes, {
    raw: openRawBytes
})

// Length of the encrypt/decrypt length prefix, in bytes. The prefix is a
// big-endian u16 giving the byte length of the `wrapped` segment, which
// varies with the wrapped AES key size (64 bytes for 128-bit, 80 for 256).
const WRAPPED_LEN_PREFIX = 2

/**
 * Seal an AES key to `recipient` and AES-GCM encrypt a message under it.
 * Call `encrypt(...)` for the raw envelope bytes, or `encrypt.asString(...)`
 * for the same envelope as an encoded string.
 */
export const encrypt = Object.assign(encryptBytes, {
    asString: encryptToString
})

/**
 * Recover the AES key from an `encrypt` envelope and AES-GCM decrypt the
 * message. Call `decrypt(...)` for the plaintext bytes, or
 * `decrypt.asString(...)` to UTF-8 decode them to a string.
 */
export const decrypt = Object.assign(decryptBytes, {
    asString: decryptToString
})

/**
 * Recover the AES key from an envelope produced by `encrypt`, then AES-GCM
 * decrypt the message.
 *
 * @param keypair The same recipient `CryptoKeyPair` used to `encrypt`.
 * @param message The envelope returned by `encrypt`.
 * @param opts `info` — must match the value passed to `encrypt`.
 * @returns The decrypted plaintext bytes. Use `decrypt.asString` for a string.
 */
async function decryptBytes (
    keypair:CryptoKeyPair,
    message:Uint8Array,
    opts?:{ info?:Uint8Array|string }
):Promise<Uint8Array> {
    if (message.byteLength < WRAPPED_LEN_PREFIX) {
        throw new Error('malformed message: too short')
    }

    const wrappedLen = (message[0] << 8) | message[1]
    const ivStart = WRAPPED_LEN_PREFIX + wrappedLen
    const ctStart = ivStart + NN
    if (message.byteLength < ctStart + AEAD_TAG_LENGTH) {
        throw new Error('malformed message: too short')
    }

    const wrapped = message.slice(WRAPPED_LEN_PREFIX, ivStart)
    const iv = message.slice(ivStart, ctStart)
    const ciphertext = message.slice(ctStart)

    const key = await open(
        keypair,
        wrapped,
        opts?.info !== undefined ? { info: opts.info } : undefined
    )
    const pt = await subtle.decrypt(
        { name: 'AES-GCM', iv: iv as BufferSource },
        key,
        ciphertext as BufferSource
    )
    return new Uint8Array(pt)
}

/**
 * Like `decrypt`, but UTF-8 decodes the plaintext to a string. Only use this
 * when the original message was text. Exposed as `decrypt.asString`.
 *
 * @param keypair The same recipient `CryptoKeyPair` used to `encrypt`.
 * @param message The envelope returned by `encrypt`.
 * @param opts `info` — must match the value passed to `encrypt`.
 * @returns The decrypted plaintext as a string.
 */
async function decryptToString (
    keypair:CryptoKeyPair,
    message:Uint8Array,
    opts?:{ info?:Uint8Array|string }
):Promise<string> {
    const bytes = await decryptBytes(keypair, message, opts)
    return new TextDecoder().decode(bytes)
}

function validateKeysize (keysize:number):void {
    if (keysize !== 128 && keysize !== 256) {
        throw new Error(
            `invalid keysize: ${keysize} (expected 128 or 256)`
        )
    }
}

// Raw AES key bytes must be a 128- or 256-bit key: this suite does not
// support AES-192, so anything but 16 or 32 bytes is rejected (rather than
// letting WebCrypto silently accept a 24-byte key later).
function validateRawKeyBytes (raw:Uint8Array):void {
    if (raw.length !== 16 && raw.length !== 32) {
        throw new Error(
            `invalid aesKey length: ${raw.length} bytes ` +
            '(expected 16 or 32)'
        )
    }
}

function normalizeInfo (info?:Uint8Array|string):Uint8Array {
    if (info === undefined || info === null) return new Uint8Array(0)
    if (typeof info === 'string') return new TextEncoder().encode(info)
    return info
}

async function exportAesKeyBytes (key:CryptoKey):Promise<Uint8Array> {
    if (!key.extractable) {
        throw new Error(
            'aesKey must be extractable: its raw bytes are what get sealed'
        )
    }
    return new Uint8Array(await subtle.exportKey('raw', key))
}

async function importAesKey (raw:Uint8Array):Promise<CryptoKey> {
    return subtle.importKey(
        'raw',
        raw as BufferSource,
        { name: 'AES-GCM' },
        true,
        ['encrypt', 'decrypt']
    )
}

// ----- Pure byte helpers (functional core) -----

// I2OSP(n, len): big-endian encode a non-negative integer into `len` bytes.
function i2osp (n:number, len:number):Uint8Array {
    const out = new Uint8Array(len)
    let v = n
    for (let i = len - 1; i >= 0; i--) {
        out[i] = v & 0xff
        v = Math.floor(v / 256)
    }
    return out
}

function concat (...arrays:Uint8Array[]):Uint8Array {
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

// ----- HKDF via HMAC-SHA256 (imperative shell) -----
//
// WebCrypto's native HKDF fuses extract+expand and cannot take a supplied
// PRK, so RFC 9180's LabeledExtract / LabeledExpand are built directly on
// HMAC-SHA256.

async function hmac (key:Uint8Array, data:Uint8Array):Promise<Uint8Array> {
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
async function labeledExtract (
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
async function labeledExpand (
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
async function resolveRecipientPublicKey (
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
        return recipient
    }

    // String form: { publicKey, encoding? }, encoding defaults to base64url.
    if (typeof (recipient as { publicKey?:unknown }).publicKey === 'string') {
        const { publicKey, encoding } =
            recipient as { publicKey:string; encoding?:Uint8ArrayEncodings }
        return importRawPublic(fromString(publicKey, encoding ?? 'base64url'))
    }

    // CryptoKeyPair: use its public half.
    const pair = recipient as CryptoKeyPair
    if (pair.publicKey instanceof CryptoKey) {
        if (pair.publicKey.type !== 'public') {
            throw new Error('recipient keypair publicKey must be a public key')
        }
        return pair.publicKey
    }

    throw new Error('unrecognized recipient key form')
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
    return new Uint8Array(bits)
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
async function encap (
    pkR:CryptoKey
):Promise<{ sharedSecret:Uint8Array; enc:Uint8Array }> {
    const eph = await subtle.generateKey(
        { name: 'X25519' },
        true,
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
async function decap (
    enc:Uint8Array,
    keypair:CryptoKeyPair
):Promise<Uint8Array> {
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

// ----- Key schedule (base mode) -----

// KeySchedule for base mode with empty psk / psk_id: derive the AEAD key and
// base nonce from the KEM shared secret and `info`.
async function keySchedule (
    sharedSecret:Uint8Array,
    info:Uint8Array
):Promise<{ key:Uint8Array; baseNonce:Uint8Array }> {
    const empty = new Uint8Array(0)
    const pskIdHash = await labeledExtract(
        HPKE_SUITE_ID,
        empty,
        'psk_id_hash',
        empty
    )
    const infoHash = await labeledExtract(
        HPKE_SUITE_ID,
        empty,
        'info_hash',
        info
    )
    const ksContext = concat(new Uint8Array([MODE_BASE]), pskIdHash, infoHash)

    const secret = await labeledExtract(
        HPKE_SUITE_ID,
        sharedSecret,
        'secret',
        empty
    )
    const key = await labeledExpand(
        HPKE_SUITE_ID,
        secret,
        'key',
        ksContext,
        NK
    )
    const baseNonce = await labeledExpand(
        HPKE_SUITE_ID,
        secret,
        'base_nonce',
        ksContext,
        NN
    )
    return { key, baseNonce }
}

// ----- AEAD (AES-256-GCM), single-shot at sequence 0 -----

async function aeadSeal (
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

async function aeadOpen (
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
 *   `opts.keysize` bits. A supplied `CryptoKey` MUST be extractable.
 * @param opts `keysize` (128/256, default 256; ignored when `aesKey` is
 *   supplied) and `info` (bound into the HPKE key schedule).
 * @returns The concatenated envelope bytes.
 *
 * `encrypt.asString(...)` returns the same envelope as an encoded string.
 */
async function encryptBytes (
    recipient:RecipientKey,
    message:Uint8Array|string,
    aesKey?:CryptoKey|Uint8Array|null,
    opts?:{
        keysize?:128|256
        info?:Uint8Array|string
    }
):Promise<Uint8Array> {
    const plaintext = typeof message === 'string' ?
        new TextEncoder().encode(message) :
        message

    const { wrapped, key } = await seal(recipient, aesKey, opts)
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(NN))
    const ct = new Uint8Array(await subtle.encrypt(
        { name: 'AES-GCM', iv: iv as BufferSource },
        key,
        plaintext as BufferSource
    ))

    return concat(i2osp(wrapped.length, WRAPPED_LEN_PREFIX), wrapped, iv, ct)
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
 *   `opts.keysize` bits. A supplied `CryptoKey` MUST be extractable.
 * @param opts `keysize` (128/256, default 256; ignored when `aesKey` is
 *   supplied), `info` (bound into the HPKE key schedule), and `encoding`
 *   (the string encoding of the returned envelope; default `base64url`).
 * @returns The encoded envelope string.
 */
async function encryptToString (
    recipient:RecipientKey,
    message:Uint8Array|string,
    aesKey?:CryptoKey|Uint8Array|null,
    opts?:{
        keysize?:128|256
        info?:Uint8Array|string
        encoding?:SupportedEncodings
    }
):Promise<string> {
    const envelope = await encryptBytes(recipient, message, aesKey, opts)
    return toString(envelope, opts?.encoding ?? 'base64url')
}
