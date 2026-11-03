import { i2osp, concat } from './util.js'

// RFC 9180 suite identifiers for the one suite this package implements:
// DHKEM(X25519, HKDF-SHA256) = 0x0020, HKDF-SHA256 = 0x0001,
// AES-256-GCM = 0x0002.
export const KEM_ID = 0x0020
export const KDF_ID = 0x0001
export const AEAD_ID = 0x0002

// Lengths (bytes). Nsecret/Nk/Nh follow SHA-256; Nn/Nenc/tag are the
// AES-256-GCM nonce, X25519 encapsulated-key, and GCM tag sizes.
export const NSECRET = 32
export const NK = 32
export const NN = 12
export const ENC_LENGTH = 32
export const AEAD_TAG_LENGTH = 16

// HPKE base mode.
export const MODE_BASE = 0x00

export const HPKE_V1 = new TextEncoder().encode('HPKE-v1')

// Length of the encrypt/decrypt length prefix, in bytes. The prefix is a
// big-endian u16 giving the byte length of the `wrapped` segment, which
// varies with the wrapped AES key size (64 bytes for 128-bit, 80 for 256).
export const WRAPPED_LEN_PREFIX = 2

// suite_id for KEM labeled calls: "KEM" || I2OSP(kem_id, 2).
export const KEM_SUITE_ID = concat(
    new TextEncoder().encode('KEM'),
    i2osp(KEM_ID, 2)
)

// suite_id for key-schedule labeled calls:
// "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2).
export const HPKE_SUITE_ID = concat(
    new TextEncoder().encode('HPKE'),
    i2osp(KEM_ID, 2),
    i2osp(KDF_ID, 2),
    i2osp(AEAD_ID, 2)
)

// ----- keyId derivation -----
//
// These constants are permanent. Changing any of them changes every
// `keyId` a consumer has already stored, and there is no migration path,
// so treat them exactly like the wire format.
//
// The label is both the fixed plaintext and the input the fixed nonce is
// derived from: N = SHA-256(KEY_ID_LABEL)[0..KEY_ID_NONCE_LENGTH].
export const KEY_ID_LABEL = new TextEncoder()
    .encode('simple-hpke/keyId/v1')

// AES-GCM's standard nonce size, in bytes. The nonce comes from the label
// hash rather than a counter or zeros: those are the values a caller
// doing deterministic nonces would pick, and a collision there would let
// an attacker solve GHASH for the nonce-independent hash subkey.
export const KEY_ID_NONCE_LENGTH = 12
