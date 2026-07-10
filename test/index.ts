import { test } from '@substrate-system/tapzero'
import { toString, fromString } from 'uint8arrays'
import { EccKeys } from '@substrate-system/keys/ecc'
import { create, seal, open, encrypt, decrypt } from '../src/index.js'

const subtle = globalThis.crypto.subtle

test('create and open round-trip', async t => {
    const kp = await genKeypair()
    const { enc, key } = await create(kp)
    const recovered = await open(kp, enc)

    const keyRaw = await raw(key)
    const recoveredRaw = await raw(recovered)

    t.ok(
        bytesEqual(keyRaw, recoveredRaw),
        'create and open produce equal raw bytes'
    )
})

test('create and open keys are cross-usable', async t => {
    const kp = await genKeypair()
    const { enc, key } = await create(kp)
    const recovered = await open(kp, enc)

    // Encrypt under key, decrypt under recovered
    const plaintext1 = new TextEncoder().encode('hello')
    const iv1 = globalThis.crypto.getRandomValues(new Uint8Array(12))
    const ciphertext1 = await subtle.encrypt(
        { name: 'AES-GCM', iv: iv1 },
        key,
        plaintext1
    )
    const decrypted1 = await subtle.decrypt(
        { name: 'AES-GCM', iv: iv1 },
        recovered,
        ciphertext1
    )
    const matches1 = bytesEqual(
        plaintext1,
        new Uint8Array(decrypted1)
    )
    t.ok(matches1, 'key→recovered round-trip works')

    // Encrypt under recovered, decrypt under key
    const plaintext2 = new TextEncoder().encode('world')
    const iv2 = globalThis.crypto.getRandomValues(new Uint8Array(12))
    const ciphertext2 = await subtle.encrypt(
        { name: 'AES-GCM', iv: iv2 },
        recovered,
        plaintext2
    )
    const decrypted2 = await subtle.decrypt(
        { name: 'AES-GCM', iv: iv2 },
        key,
        ciphertext2
    )
    const matches2 = bytesEqual(
        plaintext2,
        new Uint8Array(decrypted2)
    )
    t.ok(matches2, 'recovered→key round-trip works')
})

test('seal/open with caller-supplied key', async t => {
    const kp = await genKeypair()
    const myKey = await subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    )

    const { enc } = await seal(kp, myKey)
    const recovered = await open(kp, enc)

    const myRaw = await raw(myKey)
    const recoveredRaw = await raw(recovered)

    t.ok(
        bytesEqual(myRaw, recoveredRaw),
        'supplied key round-trips with correct bytes'
    )
})

test('seal/open with raw Uint8Array key', async t => {
    const kp = await genKeypair()
    const rawKey = globalThis.crypto.getRandomValues(new Uint8Array(32))

    const { enc } = await seal(kp, rawKey)
    const recovered = await open(kp, enc)

    t.ok(
        bytesEqual(rawKey, await raw(recovered)),
        'raw key bytes round-trip through seal/open'
    )
})

test('seal with 16-byte raw key round-trips', async t => {
    const kp = await genKeypair()
    const rawKey = globalThis.crypto.getRandomValues(new Uint8Array(16))

    const { enc } = await seal(kp, rawKey)
    const recovered = await open(kp, enc)

    t.ok(
        bytesEqual(rawKey, await raw(recovered)),
        '16-byte raw key round-trips'
    )
})

test('raw key of invalid length throws', async t => {
    const kp = await genKeypair()
    const badKey = globalThis.crypto.getRandomValues(new Uint8Array(24))

    let threw = false
    let errorMessage = ''
    try {
        await seal(kp, badKey)
    } catch (e) {
        threw = true
        if (e instanceof Error) errorMessage = e.message
    }

    t.ok(threw, '24-byte raw key throws during seal')
    t.ok(
        /invalid aesKey length/.test(errorMessage),
        'error message names the invalid length (not a WebCrypto error)'
    )
})

test('CryptoKey exporting to invalid-length bytes throws', async t => {
    const kp = await genKeypair()
    // An HMAC key is a convenient cross-runtime way to get an
    // extractable CryptoKey whose raw export is neither 16 nor 32
    // bytes (AES-192 CryptoKey support is inconsistent across
    // runtimes, so this exercises the same code path more reliably).
    const badKey = await subtle.generateKey(
        { name: 'HMAC', hash: 'SHA-256', length: 192 },
        true,
        ['sign', 'verify']
    )

    let threw = false
    let errorMessage = ''
    try {
        await seal(kp, badKey as unknown as CryptoKey)
    } catch (e) {
        threw = true
        if (e instanceof Error) errorMessage = e.message
    }

    t.ok(threw, '24-byte CryptoKey throws during seal')
    t.ok(
        /invalid aesKey length/.test(errorMessage),
        'error message names the invalid length (not a WebCrypto error)'
    )
})

test('size 128 and 256 produce correct byte lengths', async t => {
    const kp = await genKeypair()

    // size: 128
    const created128 = await create(kp, { size: 128 })
    const recovered128 = await open(kp, created128.enc)
    const raw128 = await raw(recovered128)
    t.equal(raw128.byteLength, 16, 'size 128 -> 16 bytes')

    // size: 256
    const created256 = await create(kp, { size: 256 })
    const recovered256 = await open(kp, created256.enc)
    const raw256 = await raw(recovered256)
    t.equal(raw256.byteLength, 32, 'size 256 -> 32 bytes')
})

test('open.raw returns raw bytes for 32-byte key', async t => {
    const kp = await genKeypair()
    const originalKey = globalThis.crypto.getRandomValues(new Uint8Array(32))

    const { enc } = await seal(kp, originalKey)
    const recoveredBytes = await open.raw(kp, enc)

    t.ok(
        bytesEqual(originalKey, recoveredBytes),
        '32-byte key round-trips via open.raw'
    )
})

test('open.raw returns raw bytes for 16-byte key', async t => {
    const kp = await genKeypair()
    const originalKey = globalThis.crypto.getRandomValues(new Uint8Array(16))

    const { enc } = await seal(kp, originalKey)
    const recoveredBytes = await open.raw(kp, enc)

    t.ok(
        bytesEqual(originalKey, recoveredBytes),
        '16-byte key round-trips via open.raw'
    )
})

test('open.raw and open return equivalent key bytes', async t => {
    const kp = await genKeypair()
    const { enc } = await create(kp)

    const recoveredViaCryptoKey = await open(kp, enc)
    const recoveredViaRawBytes = await open.raw(kp, enc)
    const cryptoKeyAsRaw = await raw(recoveredViaCryptoKey)

    t.ok(
        bytesEqual(cryptoKeyAsRaw, recoveredViaRawBytes),
        'open.raw and open export to identical bytes'
    )
})

test('open.raw with malformed envelope throws', async t => {
    const kp = await genKeypair()

    let threw = false
    let errorMessage = ''
    try {
        await open.raw(kp, new Uint8Array(10))
    } catch (e) {
        threw = true
        if (e instanceof Error) {
            errorMessage = e.message
        }
    }

    t.ok(threw, 'malformed envelope rejected by open.raw')
    t.ok(
        /malformed envelope/.test(errorMessage),
        'error message contains "malformed envelope"'
    )
})

test('open.raw with wrong keypair throws', async t => {
    const kpA = await genKeypair()
    const kpB = await genKeypair()

    const { enc } = await create(kpA)

    let threw = false
    try {
        await open.raw(kpB, enc)
    } catch (_e) {
        threw = true
    }

    t.ok(threw, 'wrong keypair rejected by open.raw')
})

test('open.raw with tampered ciphertext throws', async t => {
    const kp = await genKeypair()
    const { enc } = await create(kp)

    const copy = new Uint8Array(enc)
    copy[copy.length - 1] ^= 1

    let threw = false
    try {
        await open.raw(kp, copy)
    } catch (_e) {
        threw = true
    }

    t.ok(threw, 'tampered ciphertext rejected by open.raw')
})

test('open.raw with mismatched info throws',
    async t => {
        const kp = await genKeypair()

        // Seal with 'abc'
        const { enc } = await create(kp, { info: 'abc' })

        // Attempt open.raw with mismatched 'xyz'
        let threw = false
        try {
            await open.raw(kp, enc, { info: 'xyz' })
        } catch (_e) {
            threw = true
        }

        t.ok(threw, 'mismatched info rejected by open.raw')

        // Verify matching info succeeds
        const recovered = await open.raw(kp, enc, { info: 'abc' })
        t.ok(recovered.byteLength > 0, 'matching info round-trips')
    }
)

test('non-extractable key throws', async t => {
    const kp = await genKeypair()
    const nonExtractable = await subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    )

    let threw = false
    let errorMessage = ''
    try {
        await seal(kp, nonExtractable)
    } catch (e) {
        threw = true
        if (e instanceof Error) {
            errorMessage = e.message
        }
    }

    t.ok(threw, 'non-extractable key throws during seal')
    t.ok(
        /raw bytes are what get sealed/.test(errorMessage),
        'error message contains guard message (not WebCrypto error)'
    )
})

test('ephemeral encap keypair is generated non-extractable', async t => {
    const kp = await genKeypair()
    const originalGenerateKey = subtle.generateKey.bind(subtle)
    let ephExtractable:boolean|null = null

    // Spy on the real WebCrypto call (still delegates to it) to observe
    // the `extractable` flag `seal` passes when generating the ephemeral
    // X25519 keypair inside `encap`. That keypair never leaves the
    // library, so this is the only way to check the flag from outside.
    subtle.generateKey = (async (
        alg:unknown,
        extractable:boolean,
        usages:string[]
    ) => {
        if (alg && (alg as { name?:string }).name === 'X25519') {
            ephExtractable = extractable
        }
        return originalGenerateKey(alg as any, extractable, usages as any)
    }) as typeof subtle.generateKey

    try {
        await create(kp)
    } finally {
        subtle.generateKey = originalGenerateKey
    }

    t.equal(
        ephExtractable,
        false,
        'ephemeral X25519 keypair is generated with extractable:false'
    )
})

test('all-zero DH output is rejected', async t => {
    const kp = await genKeypair()
    const originalDeriveBits = subtle.deriveBits.bind(subtle)

    // Simulate a nonconforming runtime returning an all-zero X25519
    // shared secret (the Secure Curves spec requires deriveBits to throw
    // on this small-order-point case; conforming runtimes never hit this
    // path, so it can only be exercised by spying on deriveBits).
    subtle.deriveBits = (async (
        algorithm:unknown,
        key:CryptoKey,
        length:number
    ) => {
        if ((algorithm as { name?:string })?.name === 'X25519') {
            return new ArrayBuffer(32)
        }
        return originalDeriveBits(algorithm as any, key, length)
    }) as typeof subtle.deriveBits

    let threw = false
    let errorMessage = ''
    try {
        await create(kp)
    } catch (e) {
        threw = true
        if (e instanceof Error) errorMessage = e.message
    } finally {
        subtle.deriveBits = originalDeriveBits
    }

    t.ok(threw, 'all-zero shared secret is rejected')
    t.ok(
        /all-zero/.test(errorMessage),
        'error message explains the all-zero shared secret'
    )
})

test('invalid size throws', async t => {
    const kp = await genKeypair()

    let threw = false
    try {
        await create(kp, { size: 100 as any })
    } catch (_e) {
        threw = true
    }

    t.ok(threw, 'invalid size throws during create')
})

test('sealing the same key twice yields different envelopes',
    async t => {
        const kp = await genKeypair()
        const myKey = await subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        )

        const a = await seal(kp, myKey)
        const b = await seal(kp, myKey)

        const same = bytesEqual(a.enc, b.enc)
        t.ok(!same, 'two seals of same key produce different envelopes')
    }
)

// ===== TASK 1: @substrate-system/keys EccKeys integration tests =====

async function eccKeypair ():Promise<CryptoKeyPair> {
    const keys = await EccKeys.create()
    return {
        publicKey: keys.publicExchangeKey,
        privateKey: keys.privateExchangeKey
    }
}

test('EccKeys keypair round-trip create/open', async t => {
    const kp = await eccKeypair()
    const { enc, key } = await create(kp)
    const recovered = await open(kp, enc)

    const keyRaw = await raw(key)
    const recoveredRaw = await raw(recovered)

    t.ok(
        bytesEqual(keyRaw, recoveredRaw),
        'EccKeys keypair round-trips with correct bytes'
    )
})

test('EccKeys getters assemble working keypair',
    async t => {
        const keys = await EccKeys.create()
        const kp = {
            publicKey: keys.publicExchangeKey,
            privateKey: keys.privateExchangeKey
        }

        const myKey = await subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        )

        const { enc } = await seal(kp, myKey)
        const recovered = await open(kp, enc)

        const myRaw = await raw(myKey)
        const recoveredRaw = await raw(recovered)

        t.ok(
            bytesEqual(myRaw, recoveredRaw),
            'EccKeys getters form valid keypair for seal/open'
        )
    }
)

// ===== TASK 2: Negative / integrity tests =====

test('tampered envelope causes open to reject', async t => {
    const kp = await genKeypair()
    const { enc } = await create(kp)

    const copy = new Uint8Array(enc)
    copy[copy.length - 1] ^= 0xff

    let threw = false
    try {
        await open(kp, copy)
    } catch (_e) {
        threw = true
    }

    t.ok(threw, 'tampered envelope rejected')
})

test('wrong keypair causes open to reject', async t => {
    const kpA = await genKeypair()
    const kpB = await genKeypair()

    const { enc } = await create(kpA)

    let threw = false
    try {
        await open(kpB, enc)
    } catch (_e) {
        threw = true
    }

    t.ok(threw, 'wrong keypair rejected')
})

test('mismatched info causes rejection, matching succeeds',
    async t => {
        const kp = await genKeypair()

        // Seal with 'context-a'
        const { enc, key } = await create(kp, { info: 'context-a' })

        // Attempt open with mismatched 'context-b'
        let threw = false
        try {
            await open(kp, enc, { info: 'context-b' })
        } catch (_e) {
            threw = true
        }

        t.ok(threw, 'mismatched info rejected')

        // Verify matching info succeeds
        const recovered = await open(kp, enc, { info: 'context-a' })
        t.ok(bytesEqual(await raw(key), await raw(recovered)),
            'matching info round-trips to identical bytes'
        )
    }
)

test('malformed envelope causes clear error', async t => {
    const kp = await genKeypair()

    let threw = false
    let errorMessage = ''
    try {
        await open(kp, new Uint8Array(10))
    } catch (e) {
        threw = true
        if (e instanceof Error) {
            errorMessage = e.message
        }
    }

    t.ok(threw, 'malformed envelope rejected')
    t.ok(
        /malformed envelope/.test(errorMessage),
        'error message contains "malformed envelope"'
    )
})

// ===== encrypt / decrypt =====

test('encrypt/decrypt round-trip with a string', async t => {
    const kp = await genKeypair()
    const envelope = await encrypt(kp, 'hello encryption')
    const plaintext = await decrypt.asString(kp, envelope)
    t.equal(plaintext, 'hello encryption', 'string round-trips')
})

test('encrypt/decrypt round-trip with bytes', async t => {
    const kp = await genKeypair()
    const bytes = globalThis.crypto.getRandomValues(new Uint8Array(64))
    const envelope = await encrypt(kp, bytes)
    const recovered = await decrypt(kp, envelope)
    t.ok(bytesEqual(bytes, recovered), 'raw bytes round-trip')
})

test('encrypt with a caller-supplied AES key', async t => {
    const kp = await genKeypair()
    const existingKey = await subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    )
    const envelope = await encrypt(kp, 'hello again', existingKey)
    const plaintext = await decrypt.asString(kp, envelope)
    t.equal(plaintext, 'hello again', 'supplied-key round-trips')
})

test('encrypt with a raw Uint8Array AES key', async t => {
    const kp = await genKeypair()
    const rawKey = globalThis.crypto.getRandomValues(new Uint8Array(32))

    const envelope = await encrypt(kp, 'raw key message', rawKey)
    const plaintext = await decrypt.asString(kp, envelope)
    t.equal(plaintext, 'raw key message', 'raw-key encrypt round-trips')
})

test('encrypt/decrypt round-trip with 128-bit key', async t => {
    const kp = await genKeypair()
    const envelope = await encrypt(kp, 'small key', null, { size: 128 })
    const plaintext = await decrypt.asString(kp, envelope)
    t.equal(plaintext, 'small key', '128-bit wrapped key round-trips')
})

test('encrypt honors the size option for the wrapped-key length',
    async t => {
        const kp = await genKeypair()
        const envelope = await encrypt(kp, 'small key', null, { size: 128 })
        const wrappedLen = (envelope[0] << 8) | envelope[1]
        t.equal(
            wrappedLen,
            64,
            'size:128 -> 64-byte wrapped-key prefix (32-byte enc + ' +
            '16-byte key + 16-byte AEAD tag)'
        )
    }
)

test('encrypt/decrypt honors matching info, rejects mismatch',
    async t => {
        const kp = await genKeypair()
        const envelope = await encrypt(kp, 'bound', null, { info: 'ctx-a' })

        const plaintext = await decrypt.asString(
            kp,
            envelope,
            { info: 'ctx-a' }
        )
        t.equal(plaintext, 'bound', 'matching info decrypts')

        let threw = false
        try {
            await decrypt(kp, envelope, { info: 'ctx-b' })
        } catch (_e) {
            threw = true
        }
        t.ok(threw, 'mismatched info rejected')
    }
)

test('tampered encrypt envelope causes decrypt to reject', async t => {
    const kp = await genKeypair()
    const envelope = await encrypt(kp, 'secret')

    const copy = new Uint8Array(envelope)
    copy[copy.length - 1] ^= 0xff

    let threw = false
    try {
        await decrypt(kp, copy)
    } catch (_e) {
        threw = true
    }
    t.ok(threw, 'tampered envelope rejected')
})

test('wrong keypair causes decrypt to reject', async t => {
    const kpA = await genKeypair()
    const kpB = await genKeypair()
    const envelope = await encrypt(kpA, 'secret')

    let threw = false
    try {
        await decrypt(kpB, envelope)
    } catch (_e) {
        threw = true
    }
    t.ok(threw, 'wrong keypair rejected')
})

test('malformed encrypt envelope causes clear error', async t => {
    const kp = await genKeypair()

    let threw = false
    let errorMessage = ''
    try {
        await decrypt(kp, new Uint8Array(3))
    } catch (e) {
        threw = true
        if (e instanceof Error) errorMessage = e.message
    }
    t.ok(threw, 'malformed envelope rejected')
    t.ok(
        /malformed message/.test(errorMessage),
        'error message contains "malformed message"'
    )
})

test('encrypting the same message twice yields different envelopes',
    async t => {
        const kp = await genKeypair()
        const a = await encrypt(kp, 'secret')
        const b = await encrypt(kp, 'secret')
        t.ok(!bytesEqual(a, b), 'two encrypts produce different envelopes')
    }
)

test('decrypt imports the message key non-extractable, decrypt-only',
    async t => {
        const kp = await genKeypair()
        const envelope = await encrypt(kp, 'inspect me')

        const originalImportKey = subtle.importKey.bind(subtle)
        const aesImports:{ extractable:boolean; usages:string[] }[] = []

        // Spy on the real WebCrypto call (still delegates to it) to observe
        // every AES-GCM key import made while decrypting. The message key
        // recovered inside `decryptBytes` never leaves the library, so this
        // is the only way to check its extractable/usages flags from
        // outside.
        subtle.importKey = (async (
            format:string,
            keyData:BufferSource,
            algorithm:unknown,
            extractable:boolean,
            usages:string[]
        ) => {
            if ((algorithm as { name?:string })?.name === 'AES-GCM') {
                aesImports.push({ extractable, usages: [...usages] })
            }
            return originalImportKey(
                format as any,
                keyData,
                algorithm as any,
                extractable,
                usages as any
            )
        }) as typeof subtle.importKey

        try {
            await decrypt(kp, envelope)
        } finally {
            subtle.importKey = originalImportKey
        }

        t.ok(aesImports.length > 0, 'decrypt imports at least one AES-GCM key')
        t.ok(
            aesImports.every(i => i.extractable === false),
            'every AES-GCM key imported during decrypt is non-extractable'
        )
        t.ok(
            aesImports.every(i =>
                i.usages.length === 1 && i.usages[0] === 'decrypt'
            ),
            'every AES-GCM key imported during decrypt is decrypt-only'
        )
    }
)

test(
    'encrypt.asString round-trips through fromString and decrypt ' +
    '(default encoding)',
    async t => {
        const kp = await genKeypair()
        const str = await encrypt.asString(kp, 'hello asString')

        const envelope = fromString(str, 'base64url')
        const plaintext = await decrypt.asString(kp, envelope)
        t.equal(
            plaintext,
            'hello asString',
            'default base64url-encoded envelope round-trips'
        )
    }
)

test('encrypt.asString honors opts.encoding', async t => {
    const kp = await genKeypair()
    const str = await encrypt.asString(
        kp,
        'hex-encoded envelope',
        null,
        { encoding: 'hex' }
    )

    const envelope = fromString(str, 'hex')
    const plaintext = await decrypt.asString(kp, envelope)
    t.equal(
        plaintext,
        'hex-encoded envelope',
        'hex-encoded envelope round-trips'
    )
})

test('decrypt.fromString round-trips an encrypt.asString envelope',
    async t => {
        const kp = await genKeypair()
        const str = await encrypt.asString(kp, 'hello fromString')

        const plaintext = await decrypt.fromString(kp, str)
        t.equal(
            plaintext,
            'hello fromString',
            'base64url envelope string decrypts to the original text'
        )
    }
)

test('decrypt.fromString honors opts.buffer', async t => {
    const kp = await genKeypair()
    const str = await encrypt.asString(kp, 'hello buffer')

    const bytes = await decrypt.fromString(kp, str, { buffer: true })
    t.ok(bytes instanceof Uint8Array, 'returns a Uint8Array')
    t.equal(
        new TextDecoder().decode(bytes),
        'hello buffer',
        'raw bytes decode to the original text'
    )
})

// ===== recipient key forms (public key, bytes, string) =====

test('encrypt to a bare public CryptoKey', async t => {
    const kp = await genKeypair()
    const envelope = await encrypt(kp.publicKey, 'to a public key')
    const plaintext = await decrypt.asString(kp, envelope)
    t.equal(plaintext, 'to a public key', 'public-key recipient round-trips')
})

test('create to a bare public CryptoKey', async t => {
    const kp = await genKeypair()
    const { enc, key } = await create(kp.publicKey)
    const recovered = await open(kp, enc)
    t.ok(
        bytesEqual(await raw(key), await raw(recovered)),
        'creating to a public key round-trips'
    )
})

test('encrypt to raw public-key bytes', async t => {
    const kp = await genKeypair()
    const pubBytes = await raw(kp.publicKey)
    t.equal(pubBytes.byteLength, 32, 'X25519 public key is 32 bytes')

    const envelope = await encrypt(pubBytes, 'to raw bytes')
    const plaintext = await decrypt.asString(kp, envelope)
    t.equal(plaintext, 'to raw bytes', 'raw-bytes recipient round-trips')
})

test('encrypt to a base64url string public key (default encoding)',
    async t => {
        const kp = await genKeypair()
        const pubStr = toString(await raw(kp.publicKey), 'base64url')

        const envelope = await encrypt({ publicKey: pubStr }, 'to a string')
        const plaintext = await decrypt.asString(kp, envelope)
        t.equal(plaintext, 'to a string', 'default-encoding string round-trips')
    }
)

test('encrypt to a hex string public key (explicit encoding)', async t => {
    const kp = await genKeypair()
    const pubStr = toString(await raw(kp.publicKey), 'hex')

    const envelope = await encrypt(
        { publicKey: pubStr, encoding: 'hex' },
        'hex recipient'
    )
    const plaintext = await decrypt.asString(kp, envelope)
    t.equal(plaintext, 'hex recipient', 'hex-encoded string round-trips')
})

test('recipient bytes of wrong length throw', async t => {
    let threw = false
    let errorMessage = ''
    try {
        await encrypt(new Uint8Array(16), 'nope')
    } catch (e) {
        threw = true
        if (e instanceof Error) errorMessage = e.message
    }
    t.ok(threw, 'short recipient bytes throw')
    t.ok(
        /invalid public key length/.test(errorMessage),
        'error names the invalid public key length'
    )
})

test('a private key as recipient throws', async t => {
    const kp = await genKeypair()
    let threw = false
    let errorMessage = ''
    try {
        await encrypt(kp.privateKey, 'nope')
    } catch (e) {
        threw = true
        if (e instanceof Error) errorMessage = e.message
    }
    t.ok(threw, 'private-key recipient throws')
    t.ok(
        /must be a public key/.test(errorMessage),
        'error explains a public key is required'
    )
})

test('a mismatched-encoding string recipient throws', async t => {
    const kp = await genKeypair()
    // Encode as base64url but claim it is hex: decodes to the wrong length.
    const pubStr = toString(await raw(kp.publicKey), 'base64url')

    let threw = false
    try {
        await encrypt({ publicKey: pubStr, encoding: 'hex' }, 'nope')
    } catch (_e) {
        threw = true
    }
    t.ok(threw, 'wrong-encoding string recipient rejected')
})

test('recipient with non-X25519 public key throws a clear error',
    async t => {
        const wrongAlgKeyPair = await subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['sign', 'verify']
        ) as CryptoKeyPair

        let threw = false
        let errorMessage = ''
        try {
            await encrypt(wrongAlgKeyPair.publicKey, 'nope')
        } catch (e) {
            threw = true
            if (e instanceof Error) errorMessage = e.message
        }

        t.ok(threw, 'non-X25519 public key throws')
        t.ok(
            /X25519/.test(errorMessage),
            'error message names the expected algorithm'
        )
    }
)

test('open with a non-X25519 private key throws a clear error',
    async t => {
        const kp = await genKeypair()
        const { enc } = await create(kp)

        const wrongAlgKeyPair = await subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['sign', 'verify']
        ) as CryptoKeyPair

        let threw = false
        let errorMessage = ''
        try {
            await open(wrongAlgKeyPair, enc)
        } catch (e) {
            threw = true
            if (e instanceof Error) errorMessage = e.message
        }

        t.ok(threw, 'non-X25519 private key throws')
        t.ok(
            /X25519/.test(errorMessage),
            'error message names the expected algorithm'
        )
    }
)

// ===== known-answer (fixture) conformance test =====
//
// This fixture was generated once by an independent HPKE implementation
// (@hpke/core, DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM,
// base mode): a fixed X25519 keypair sealing a fixed 32-byte plaintext.
// Every other test here is a round-trip against this library's own
// seal/open, which cannot catch conformance drift (a wrong label, suite
// ID, or kem_context ordering would pass every round-trip test while
// silently breaking wire compatibility with every other HPKE
// implementation). This test would catch that.
const FIXTURE_PRIVATE_KEY_HEX =
    '68a48becb31d1f341c665c50f99662a2a72a1127327c162a1931de6a4d096b46'
const FIXTURE_PUBLIC_KEY_HEX =
    '2a074c504427ec1c33beabb1d34a7dd2a16d5f5794cd089bebac02cefa2d5f1e'
const FIXTURE_WRAPPED_HEX = (
    'f67896035d433e451d5af78a1ac6693d06eca6ebec4ca7851fd06f85f7923079e' +
    'd946ba24d1c0d3bbbe1438c8db7a4a966ea7c3a12e46ec4ecd06f0dc2483796a1' +
    '64f01e1c9978614da7ef99b75039aa'
)
const FIXTURE_PLAINTEXT_HEX =
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'

async function fixtureKeypair ():Promise<CryptoKeyPair> {
    const publicKeyBytes = fromString(FIXTURE_PUBLIC_KEY_HEX, 'hex')
    const privateJwk = {
        kty: 'OKP',
        crv: 'X25519',
        d: toString(fromString(FIXTURE_PRIVATE_KEY_HEX, 'hex'), 'base64url'),
        x: toString(publicKeyBytes, 'base64url')
    }

    const privateKey = await subtle.importKey(
        'jwk',
        privateJwk,
        { name: 'X25519' },
        false,
        ['deriveBits']
    )
    const publicKey = await subtle.importKey(
        'raw',
        publicKeyBytes as BufferSource,
        { name: 'X25519' },
        true,
        []
    )

    return { privateKey, publicKey }
}

test('known-answer: open.raw recovers a fixture envelope sealed by ' +
    '@hpke/core',
async t => {
    const kp = await fixtureKeypair()
    const wrapped = fromString(FIXTURE_WRAPPED_HEX, 'hex')
    const recovered = await open.raw(kp, wrapped)

    t.ok(
        bytesEqual(recovered, fromString(FIXTURE_PLAINTEXT_HEX, 'hex')),
        'recovers the known plaintext from an independently-generated ' +
        'envelope'
    )
})

test('all done', () => {
    if (typeof window !== 'undefined') {
        // @ts-expect-error tests
        window.testsFinished = true
    }
})

async function genKeypair ():Promise<CryptoKeyPair> {
    return subtle.generateKey(
        { name: 'X25519' },
        false,                 // non-extractable private key
        ['deriveBits']
    ) as Promise<CryptoKeyPair>
}

async function raw (key:CryptoKey):Promise<Uint8Array> {
    return new Uint8Array(await subtle.exportKey('raw', key))
}

function bytesEqual (a:Uint8Array, b:Uint8Array):boolean {
    if (a.byteLength !== b.byteLength) return false
    for (let i = 0; i < a.byteLength; i++) {
        if (a[i] !== b[i]) return false
    }
    return true
}
