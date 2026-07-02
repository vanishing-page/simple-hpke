// pattern: Functional Core + Imperative Shell (WebCrypto side effects)
// A first-party implementation of one fixed RFC 9180 HPKE cipher suite,
// DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM, base mode,
// single-shot. Pure helpers build the labeled byte strings; all crypto runs
// through WebCrypto's subtle API so the X25519 private key may stay
// non-extractable (HPKE needs only `deriveBits`).

/**
 * Options for `seal` / `open`.
 */
export type HpkeOpts = {
    // Size of the GENERATED AES key. Ignored when an `aesKey` is supplied.
    keysize?:128|256
    // HPKE `info`: bound into the key schedule; must match on seal + open.
    info?:Uint8Array|string
}

const subtle = globalThis.crypto.subtle

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
        { name:'HMAC', hash:'SHA-256' },
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

// X25519 Diffie-Hellman via WebCrypto deriveBits (works with a
// non-extractable private key).
async function dh (
    priv:CryptoKey,
    pub:CryptoKey
):Promise<Uint8Array> {
    const bits = await subtle.deriveBits(
        { name:'X25519', public:pub },
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
        { name:'X25519' },
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
        { name:'X25519' },
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
        { name:'AES-GCM' },
        false,
        ['encrypt']
    )
    const ct = await subtle.encrypt(
        { name:'AES-GCM', iv:nonce as BufferSource },
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
        { name:'AES-GCM' },
        false,
        ['decrypt']
    )
    const pt = await subtle.decrypt(
        { name:'AES-GCM', iv:nonce as BufferSource },
        k,
        ciphertext as BufferSource
    )
    return new Uint8Array(pt)
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

    const { sharedSecret, enc } = await encap(keypair.publicKey)
    const { key, baseNonce } = await keySchedule(sharedSecret, info)
    const ciphertext = await aeadSeal(key, baseNonce, keyBytes)

    const wrapped = concat(enc, ciphertext)
    const aesGcmKey = await importAesKey(keyBytes)
    return { wrapped, key:aesGcmKey }
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

    const sharedSecret = await decap(enc, keypair)
    const { key, baseNonce } = await keySchedule(sharedSecret, info)
    const keyBytes = await aeadOpen(key, baseNonce, ciphertext)
    return importAesKey(keyBytes)
}
