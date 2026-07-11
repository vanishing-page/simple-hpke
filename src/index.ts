import { fromString } from 'uint8arrays'
import {
    type RecipientKey,
    aeadSeal,
    aeadOpen,
    encryptToString,
    encryptBytes,
    resolveRecipientPublicKey,
    concat,
    encap,
    decap,
    labeledExtract,
    labeledExpand,
} from './util'
import {
    AEAD_TAG_LENGTH,
    ENC_LENGTH,
    NN,
    NK,
    MODE_BASE,
    WRAPPED_LEN_PREFIX,
    HPKE_SUITE_ID,
} from './constants'

// RFC 9180 HPKE cipher suite
// (DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM,
// base mode, single-shot)
// - Pure helpers build the labeled byte strings
// - all crypto runs through WebCrypto's subtle API so the X25519 private
//   key can stay non-extractable (HPKE needs only `deriveBits`).

const subtle = globalThis.crypto.subtle

/**
 * Create a new AES key for the given public key.
 *
 * @param recipient Public key for decryptor
 * @param opts `size` and `info`
 * @returns {{ enc, key }} The wrapped envelope bytes and the generated
 *   AES-GCM key.
 */
export async function create (
    recipient:RecipientKey,
    opts?:{
        // Size of the GENERATED AES key. Ignored when an `aesKey` is supplied.
        size?:128|256
        // HPKE `info`: bound into the key schedule; must match on open.
        info?:Uint8Array|string
    }
):Promise<{ enc:Uint8Array<ArrayBufferLike>, key:CryptoKey }> {
    const { enc, key } = await encryptKey(recipient, null, opts)
    return { enc, key }
}

/**
 * Recover the AES key wrapped by `create` or `encryptKey`. Call `open(...)`
 * for a usable AES-GCM `CryptoKey`, or `open.raw(...)` for the raw key bytes.
 */
export const open = Object.assign(openBytes, {
    raw: openRawBytes
})

/**
 * Wrap an AES key to `recipient` and AES-GCM encrypt a message under it.
 * Call `encrypt(...)` for the raw envelope bytes, or `encrypt.asString(...)`
 * for the same envelope as an encoded string.
 */
export const encrypt = Object.assign(encryptBytes, {
    asString: encryptToString
})

/**
 * Recover the AES key from an `encrypt` envelope and AES-GCM decrypt the
 * message. Call `decrypt(...)` for the plaintext bytes,
 * `decrypt.asString(...)` to UTF-8 decode them to a string, or
 * `decrypt.fromString(...)` to decrypt a `base64url`-encoded envelope
 * string (from `encrypt.asString`).
 */
export const decrypt = Object.assign(decryptBytes, {
    asString: decryptToString,
    fromString: decryptFromString
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

    const keyBytes = await openRawBytes(
        keypair,
        wrapped,
        opts?.info !== undefined ? { info: opts.info } : undefined
    )
    const key = await importAesKeyDecryptOnly(keyBytes)
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

/**
 * Decode a `base64url` string envelope (from `encrypt.asString`),
 * recover the AES key, and AES-GCM decrypt the message. Exposed as
 * `decrypt.fromString`.
 *
 * @param keypair The same recipient `CryptoKeyPair` used to `encrypt`.
 * @param message The `base64url`-encoded envelope string, as returned
 *   by `encrypt.asString`.
 * @param opts `info` (must match `encrypt`), and `buffer` -- if true,
 *   return the raw plaintext `Uint8Array` instead of a UTF-8 decoded
 *   string.
 * @returns The decrypted plaintext, as a string (default) or
 *   `Uint8Array` (if `opts.buffer` is true).
 */
async function decryptFromString (
    keypair:CryptoKeyPair,
    message:string,
    opts?:{ info?:Uint8Array|string, buffer?:false }
):Promise<string>

async function decryptFromString (
    keypair:CryptoKeyPair,
    message:string,
    opts:{ info?:Uint8Array|string, buffer:true }
):Promise<Uint8Array>

async function decryptFromString (
    keypair:CryptoKeyPair,
    message:string,
    opts?:{ info?:Uint8Array|string, buffer?:boolean }
):Promise<string|Uint8Array> {
    const bytes = fromString(message, 'base64url')
    const plaintext = await decryptBytes(
        keypair,
        bytes,
        opts?.info !== undefined ? { info: opts.info } : undefined
    )

    return opts?.buffer ? plaintext : new TextDecoder().decode(plaintext)
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

// Used by `decryptBytes` instead of `importAesKey`: the message key never
// leaves the library there, so it can be imported non-extractable and
// decrypt-only rather than the extractable, both-usages key `open` returns
// for general use.
async function importAesKeyDecryptOnly (raw:Uint8Array):Promise<CryptoKey> {
    return subtle.importKey(
        'raw',
        raw as BufferSource,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    )
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

/**
 * Like `open`, but returns the recovered key as raw bytes instead of
 * importing it as an AES-GCM `CryptoKey`. Exposed as `open.raw`.
 *
 * @param keypair The same X25519 `CryptoKeyPair` used to create or encryptKey.
 * @param wrapped The `enc` bytes returned by `create` or `encryptKey`.
 * @param opts `info` — must match the value passed to `create` or `encryptKey`.
 * @returns The recovered key bytes (16 or 32 bytes, matching whatever
 *   was wrapped).
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
 * Recover an AES key that was wrapped with `create` or `encryptKey`.
 *
 * @param keypair The same X25519 `CryptoKeyPair` used to create or encryptKey.
 * @param wrapped The `enc` bytes returned by `create` or `encryptKey`.
 * @param opts `info` — must match the value passed to `create` or `encryptKey`.
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
 * Wrap an AES key to a recipient's public key. `create(...)` calls this
 * helper with no `aesKey`, so it generates a fresh AES key first.
 *
 * @param recipient The recipient's X25519 public key, as a `CryptoKey`,
 *   `CryptoKeyPair` (its `.publicKey` is used), 32 raw bytes (`Uint8Array`),
 *   or `{ publicKey:string, encoding? }` (encoding defaults to `base64url`).
 * @param aesKey Optional key to wrap, as either an AES-GCM `CryptoKey` or its
 *   raw bytes (`Uint8Array`, 16 or 32 bytes). Omit to generate a fresh
 *   extractable key of `opts.size` bits. A supplied `CryptoKey` MUST be
 *   extractable (its raw bytes are wrapped).
 * @param opts `size` (128/256, default 256; ignored when `aesKey` is
 *   supplied) and `info` (bound into the HPKE key schedule; default empty).
 * @returns { enc:Uint8Array, key:CryptoKey } The wrapped envelope bytes
 *   and a usable AES-GCM `CryptoKey`.
 */
export async function encryptKey (
    recipient:RecipientKey,
    aesKey?:CryptoKey|Uint8Array|null,
    opts?:{
        // Size of the GENERATED AES key. Ignored when an `aesKey` is supplied.
        size?:128|256
        // HPKE `info`: bound into the key schedule; must match on open.
        info?:Uint8Array|string
    }
):Promise<{ enc:Uint8Array; key:CryptoKey }> {
    const info = normalizeInfo(opts?.info)

    let keyBytes:Uint8Array
    if (aesKey instanceof Uint8Array) {
        validateRawKeyBytes(aesKey)
        keyBytes = aesKey
    } else if (aesKey) {  // if given a CryptoKey
        keyBytes = await exportAesKeyBytes(aesKey)
        validateRawKeyBytes(keyBytes)
    } else {  // generate a key
        const keysize = opts?.size ?? 256
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

    return { enc: wrapped, key: aesGcmKey }
}
