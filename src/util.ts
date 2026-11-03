import {
    toString,
    fromString,
    type SupportedEncodings
} from 'uint8arrays'
import { encryptKey } from './index.js'
import { HpkeError, type HpkeErrorCode } from './errors.js'
import {
    WRAPPED_LEN_PREFIX,
    NN,
    NSECRET,
    HPKE_V1,
    ENC_LENGTH,
    KEM_SUITE_ID,
    KEY_ID_LABEL,
    KEY_ID_NONCE_LENGTH
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
    let pt:ArrayBuffer
    try {
        pt = await subtle.decrypt(
            { name: 'AES-GCM', iv: nonce as BufferSource },
            k,
            ciphertext as BufferSource
        )
    } catch (err) {
        // AES-GCM authentication failed. WebCrypto reports every cause
        // as the same opaque `OperationError`, so this is deliberately
        // the one error for all of them.
        throw new HpkeError(
            'ERR_DECRYPT_FAILED',
            'failed to decrypt the wrapped key: wrong keypair, ' +
            'wrong info, or a tampered envelope',
            { cause: err }
        )
    }
    return new Uint8Array(pt)
}

/**
 * Wrap a fresh (or supplied) AES key to `recipient`, then AES-GCM encrypt a
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
 *   `opts.size` bits. A supplied `CryptoKey` MUST be extractable and
 *   MUST have the `encrypt` usage (the message is encrypted under it
 *   directly; otherwise this throws `ERR_INVALID_AES_KEY`). It is used
 *   as-is and never re-imported, so the `opts.extractable` setting that
 *   `encryptKey` takes does not apply to it. Each
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
    // The body is encrypted under the caller's own key (no re-import, so
    // no usage widening). Fail before any wrapping work, as an HpkeError
    // rather than an opaque WebCrypto error from `subtle.encrypt`.
    if (
        aesKey instanceof CryptoKey &&
        !aesKey.usages.includes('encrypt')
    ) {
        throw new HpkeError(
            'ERR_INVALID_AES_KEY',
            'aesKey is missing the "encrypt" usage, ' +
            'which encrypt needs to encrypt the message'
        )
    }

    const plaintext = typeof message === 'string' ?
        new TextEncoder().encode(message) :
        message

    const { wrapped, key } = await encryptKey(recipient, aesKey, opts)

    const iv = globalThis.crypto.getRandomValues(new Uint8Array(NN))
    const ct = new Uint8Array(await subtle.encrypt(
        { name: 'AES-GCM', iv: iv as BufferSource },
        key,
        plaintext as BufferSource
    ))

    return concat(
        i2osp(wrapped.length, WRAPPED_LEN_PREFIX),
        wrapped,
        iv,
        ct
    )
}

/**
 * Like `encrypt`, but encodes the envelope bytes to a string -- handy for
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
 *   `opts.size` bits. A supplied `CryptoKey` MUST be extractable and
 *   MUST have the `encrypt` usage (the message is encrypted under it
 *   directly; otherwise this throws `ERR_INVALID_AES_KEY`). It is used
 *   as-is and never re-imported, so the `opts.extractable` setting that
 *   `encryptKey` takes does not apply to it. Each
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
        throw new HpkeError(
            'ERR_INVALID_RECIPIENT_KEY',
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
        return assertRecipientPublicKey(recipient, 'recipient CryptoKey')
    }

    // String form: { publicKey, encoding? }, encoding defaults to base64url.
    if (typeof (recipient as { publicKey?:unknown }).publicKey === 'string') {
        const { publicKey, encoding } =
            recipient as { publicKey:string; encoding?:SupportedEncodings }
        let decoded:Uint8Array
        try {
            decoded = fromString(publicKey, encoding ?? 'base64url')
        } catch (err) {
            // Invalid characters, a bad length, or an unknown encoding
            // name all surface here as a uint8arrays SyntaxError / Error.
            throw new HpkeError(
                'ERR_INVALID_RECIPIENT_KEY',
                'recipient publicKey string does not decode as ' +
                `${encoding ?? 'base64url'}`,
                { cause: err }
            )
        }
        return importRawPublic(decoded)
    }

    // CryptoKeyPair: use its public half.
    const pair = recipient as CryptoKeyPair
    if (pair.publicKey instanceof CryptoKey) {
        return assertRecipientPublicKey(
            pair.publicKey,
            'recipient keypair publicKey'
        )
    }

    throw new HpkeError(
        'ERR_INVALID_RECIPIENT_KEY',
        'unrecognized recipient key form'
    )
}

// Check a caller-supplied recipient public CryptoKey up front, so an
// unusable key fails as an HpkeError rather than a WebCrypto error later.
// It must be extractable: the KEM exports the recipient public key for its
// context, and WebCrypto offers no other way to get those bytes.
function assertRecipientPublicKey (
    key:CryptoKey,
    context:string
):CryptoKey {
    if (key.type !== 'public') {
        throw new HpkeError(
            'ERR_INVALID_RECIPIENT_KEY',
            `${context} must be a public key`
        )
    }
    assertX25519Algorithm(key, context, 'ERR_INVALID_RECIPIENT_KEY')
    if (!key.extractable) {
        throw new HpkeError(
            'ERR_INVALID_RECIPIENT_KEY',
            `${context} must be extractable (the KEM exports it)`
        )
    }
    return key
}

// Guards against an easy mistake (e.g. passing an Ed25519 signing key from
// a library that exposes both): fail with a clear message here rather than
// an opaque WebCrypto error later inside deriveBits.
function assertX25519Algorithm (
    key:CryptoKey,
    context:string,
    code:HpkeErrorCode
):void {
    if (key.algorithm.name !== 'X25519') {
        throw new HpkeError(
            code,
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
    let bits:ArrayBuffer
    try {
        bits = await subtle.deriveBits(
            { name: 'X25519', public: pub },
            priv,
            256
        )
    } catch (err) {
        // Per the Secure Curves spec, OperationError from X25519
        // deriveBits at 256 bits means an all-zero shared secret (a
        // small-order public key). Match on `name` only: a key missing
        // the deriveBits usage throws InvalidAccessError from this same
        // call, and that is not a small-order key. Anything else is
        // rethrown unchanged.
        if ((err as { name?:string })?.name === 'OperationError') {
            throw new HpkeError(
                'ERR_SMALL_ORDER_KEY',
                'X25519 deriveBits rejected a small-order public key',
                { cause: err }
            )
        }
        throw err
    }
    const bytes = new Uint8Array(bits)

    // Conforming runtimes reject an all-zero output inside deriveBits
    // (handled above) and never reach here. Kept as defense-in-depth
    // against a nonconforming runtime.
    if (bytes.every(b => b === 0)) {
        throw new HpkeError(
            'ERR_SMALL_ORDER_KEY',
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
        throw new HpkeError(
            'ERR_INVALID_KEYPAIR',
            'keypair.privateKey must be a private key'
        )
    }
    assertX25519Algorithm(
        keypair.privateKey,
        'keypair.privateKey',
        'ERR_INVALID_KEYPAIR'
    )
    if (!keypair.privateKey.usages.includes('deriveBits')) {
        throw new HpkeError(
            'ERR_INVALID_KEYPAIR',
            'keypair.privateKey must have the deriveBits usage'
        )
    }
    // The KEM context needs the raw public key bytes, and WebCrypto only
    // gives those up for an extractable key.
    if (
        keypair.publicKey.type !== 'public' ||
        !keypair.publicKey.extractable
    ) {
        throw new HpkeError(
            'ERR_INVALID_KEYPAIR',
            'keypair.publicKey must be an extractable public key'
        )
    }
    assertX25519Algorithm(
        keypair.publicKey,
        'keypair.publicKey',
        'ERR_INVALID_KEYPAIR'
    )

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

// ----- keyId -----

/**
 * A stable fingerprint for an AES-GCM key: the same key bytes always give
 * the same string, and two different keys effectively never collide.
 *
 * Derived from the key's *behavior* rather than its bytes, so it works on
 * a non-extractable key -- including one rehydrated from IndexedDB, and
 * the keys `create` / `encryptKey` / `open` return by default. The obvious
 * implementation, `exportKey('raw')` then SHA-256, would force every such
 * key to be extractable. HKDF is not an option either: WebCrypto cannot
 * convert an AES-GCM key into an HKDF key, and `deriveBits` only accepts a
 * key imported under HKDF, which needs the raw bytes a non-extractable key
 * withholds. AES-GCM as a PRF is the only primitive such a key still
 * exposes.
 *
 * The derivation is fixed forever (see `src/constants.ts`):
 *
 * ```
 * LABEL = utf8("simple-hpke/keyId/v1")
 * N     = SHA-256(LABEL)[0..12]        // fixed nonce
 * C     = AES-GCM(key, N, LABEL)       // ciphertext || 16-byte tag
 * keyId = base64url(SHA-256(LABEL || C))
 * ```
 *
 * @param key An AES-GCM `CryptoKey` with the `encrypt` usage. It does not
 *   need to be extractable.
 * @returns The fingerprint: the full 32-byte digest, base64url, unpadded
 *   (43 characters).
 * @throws {HpkeError} `ERR_INVALID_AES_KEY` if `key` is not an AES-GCM key
 *   or cannot encrypt.
 */
export async function keyId (key:CryptoKey):Promise<string> {
    if (key.algorithm.name !== 'AES-GCM') {
        throw new HpkeError(
            'ERR_INVALID_AES_KEY',
            'keyId needs an AES-GCM key ' +
            `(got ${key.algorithm.name})`
        )
    }

    if (!key.usages.includes('encrypt')) {
        throw new HpkeError(
            'ERR_INVALID_AES_KEY',
            "keyId needs a key with the 'encrypt' usage"
        )
    }

    const labelHash = new Uint8Array(
        await subtle.digest('SHA-256', KEY_ID_LABEL as BufferSource)
    )
    const nonce = labelHash.slice(0, KEY_ID_NONCE_LENGTH)

    // No AAD. AAD feeds GHASH only and leaves the counter stream
    // untouched, so "domain separation by AAD" would produce a second
    // (A, C) pair over an identical keystream under the same (K, N).
    // That is nonce reuse with extra steps.
    const ciphertext = new Uint8Array(await subtle.encrypt(
        { name: 'AES-GCM', iv: nonce as BufferSource },
        key,
        KEY_ID_LABEL as BufferSource
    ))

    // Only the digest is returned. `ciphertext` is a known-plaintext
    // block of keystream and must never escape.
    const digest = await subtle.digest(
        'SHA-256',
        concat(KEY_ID_LABEL, ciphertext) as BufferSource
    )

    return toString(new Uint8Array(digest), 'base64url')
}

/**
 * Check whether `key` matches a stored `keyId`.
 *
 * Compares in constant time over the string. Errors from `keyId`
 * propagate: a key that cannot be fingerprinted rejects rather than
 * resolving `false`, so "cannot check" never reads as "wrong key".
 *
 * @param key An AES-GCM `CryptoKey` with the `encrypt` usage.
 * @param expected A `keyId` string recorded earlier.
 * @returns `true` if `keyId(key)` equals `expected`, else `false`.
 * @throws {HpkeError} `ERR_INVALID_AES_KEY` if `key` is not an AES-GCM key
 *   or cannot encrypt.
 */
export async function verifyKeyId (
    key:CryptoKey,
    expected:string
):Promise<boolean> {
    const actual = await keyId(key)
    // Length is public: a valid id is always 43 characters.
    if (actual.length !== expected.length) return false

    let diff = 0
    for (let i = 0; i < actual.length; i++) {
        diff |= actual.charCodeAt(i) ^ expected.charCodeAt(i)
    }

    return diff === 0
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
