// pattern: Functional Core + Imperative Shell (WebCrypto side effects)
// Functions performing key derivation, validation, and cryptographic
// operations through WebCrypto's subtle API. Pure helpers for key/info
// normalization and envelope concatenation.
import {
    CipherSuite,
    KEM_DHKEM_X25519_HKDF_SHA256,
    KDF_HKDF_SHA256,
    AEAD_AES_256_GCM
} from './vendor/hpke/index.js'

/**
 * Options for `seal` / `open`.
 */
export type HpkeOpts = {
    // Size of the GENERATED AES key. Ignored when an `aesKey` is supplied.
    keysize?:128|256
    // HPKE `info`: bound into the key schedule; must match on seal + open.
    info?:Uint8Array|string
}

/**
 * The one fixed HPKE cipher suite this package uses:
 * DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM. Not configurable at
 * runtime. `seal` / `open` operate through it.
 */
const suite = new CipherSuite(
    KEM_DHKEM_X25519_HKDF_SHA256,
    KDF_HKDF_SHA256,
    AEAD_AES_256_GCM
)

const subtle = globalThis.crypto.subtle

// X25519 encapsulated-key length (bytes) and AES-GCM auth-tag length (bytes).
const ENC_LENGTH = suite.KEM.Nenc
const AEAD_TAG_LENGTH = 16

function validateKeysize (keysize:number):void {
    if (keysize !== 128 && keysize !== 256) {
        throw new Error(
            `invalid keysize: ${keysize} (expected 128 or 256)`
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
        { name:'AES-GCM' },
        true,
        ['encrypt', 'decrypt']
    )
}

function concat (a:Uint8Array, b:Uint8Array):Uint8Array {
    const out = new Uint8Array(a.length + b.length)
    out.set(a, 0)
    out.set(b, a.length)
    return out
}

/**
 * Wrap an AES key to your own public key.
 *
 * @param keypair An X25519 `CryptoKeyPair` (the private key may be
 *   non-extractable).
 * @param aesKey Optional AES-GCM key to seal. Omit to generate a fresh
 *   extractable key of `opts.keysize` bits. If supplied it MUST be extractable
 *   (its raw bytes are sealed).
 * @param opts `keysize` (128/256, default 256; ignored when `aesKey` is
 *   supplied) and `info` (bound into the HPKE key schedule; default empty).
 * @returns The envelope bytes and a usable AES-GCM `CryptoKey`.
 */
export async function seal (
    keypair:CryptoKeyPair,
    aesKey?:CryptoKey|null,
    opts?:HpkeOpts
):Promise<{ wrapped:Uint8Array; key:CryptoKey }> {
    const info = normalizeInfo(opts?.info)

    let keyBytes:Uint8Array
    if (aesKey) {
        keyBytes = await exportAesKeyBytes(aesKey)
    } else {
        const keysize = opts?.keysize ?? 256
        validateKeysize(keysize)
        keyBytes = globalThis.crypto.getRandomValues(
            new Uint8Array(keysize / 8)
        )
    }

    const { encapsulatedSecret, ciphertext } = await suite.Seal(
        keypair.publicKey,
        keyBytes,
        { info }
    )

    const wrapped = concat(encapsulatedSecret, ciphertext)
    const key = await importAesKey(keyBytes)
    return { wrapped, key }
}

/**
 * Recover an AES key that was wrapped with `seal`, using your private key.
 *
 * @param keypair The same X25519 `CryptoKeyPair` used to seal.
 * @param wrapped The envelope returned by `seal` (`enc ‖ ciphertext`).
 * @param opts `info` — must match the value passed to `seal`.
 * @returns The recovered AES-GCM `CryptoKey` (extractable).
 */
export async function open (
    keypair:CryptoKeyPair,
    wrapped:Uint8Array,
    opts?:Pick<HpkeOpts, 'info'>
):Promise<CryptoKey> {
    if (wrapped.byteLength < ENC_LENGTH + AEAD_TAG_LENGTH) {
        throw new Error('malformed envelope: too short')
    }

    const info = normalizeInfo(opts?.info)
    const enc = wrapped.slice(0, ENC_LENGTH)
    const ciphertext = wrapped.slice(ENC_LENGTH)

    const keyBytes = await suite.Open(
        keypair,
        enc,
        ciphertext,
        { info }
    )
    return importAesKey(keyBytes)
}
