import { test } from '@substrate-system/tapzero'
import { seal, open } from '../src/index.js'

const subtle = globalThis.crypto.subtle

async function genKeypair ():Promise<CryptoKeyPair> {
    return subtle.generateKey(
        { name:'X25519' },
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

test('AC1.1: seal and open round-trip', async t => {
    const kp = await genKeypair()
    const { wrapped, key } = await seal(kp)
    const recovered = await open(kp, wrapped)

    const keyRaw = await raw(key)
    const recoveredRaw = await raw(recovered)

    t.ok(
        bytesEqual(keyRaw, recoveredRaw),
        'seal and open produce equal raw bytes'
    )
})

test('AC1.2: seal and open keys are cross-usable', async t => {
    const kp = await genKeypair()
    const { wrapped, key } = await seal(kp)
    const recovered = await open(kp, wrapped)

    // Encrypt under key, decrypt under recovered
    const plaintext1 = new TextEncoder().encode('hello')
    const iv1 = globalThis.crypto.getRandomValues(new Uint8Array(12))
    const ciphertext1 = await subtle.encrypt(
        { name:'AES-GCM', iv:iv1 },
        key,
        plaintext1
    )
    const decrypted1 = await subtle.decrypt(
        { name:'AES-GCM', iv:iv1 },
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
        { name:'AES-GCM', iv:iv2 },
        recovered,
        plaintext2
    )
    const decrypted2 = await subtle.decrypt(
        { name:'AES-GCM', iv:iv2 },
        key,
        ciphertext2
    )
    const matches2 = bytesEqual(
        plaintext2,
        new Uint8Array(decrypted2)
    )
    t.ok(matches2, 'recovered→key round-trip works')
})

test('AC1.3: seal/open with caller-supplied key', async t => {
    const kp = await genKeypair()
    const myKey = await subtle.generateKey(
        { name:'AES-GCM', length:256 },
        true,
        ['encrypt', 'decrypt']
    )

    const { wrapped } = await seal(kp, myKey)
    const recovered = await open(kp, wrapped)

    const myRaw = await raw(myKey)
    const recoveredRaw = await raw(recovered)

    t.ok(
        bytesEqual(myRaw, recoveredRaw),
        'supplied key round-trips with correct bytes'
    )
})

test('AC1.4: keysize 128 and 256 produce correct byte lengths', async t => {
    const kp = await genKeypair()

    // keysize: 128
    const sealed128 = await seal(kp, null, { keysize:128 })
    const recovered128 = await open(kp, sealed128.wrapped)
    const raw128 = await raw(recovered128)
    t.equal(raw128.byteLength, 16, 'keysize 128 → 16 bytes')

    // keysize: 256
    const sealed256 = await seal(kp, null, { keysize:256 })
    const recovered256 = await open(kp, sealed256.wrapped)
    const raw256 = await raw(recovered256)
    t.equal(raw256.byteLength, 32, 'keysize 256 → 32 bytes')
})

test('AC1.5: non-extractable key throws', async t => {
    const kp = await genKeypair()
    const nonExtractable = await subtle.generateKey(
        { name:'AES-GCM', length:256 },
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
        /extractable/.test(errorMessage),
        'error message mentions extractable guard'
    )
})

test('AC1.6: invalid keysize throws', async t => {
    const kp = await genKeypair()

    let threw = false
    try {
        await seal(kp, null, { keysize:100 as any })
    } catch (_e) {
        threw = true
    }

    t.ok(threw, 'invalid keysize throws during seal')
})

test('AC3.4: sealing the same key twice yields different envelopes',
    async t => {
        const kp = await genKeypair()
        const myKey = await subtle.generateKey(
            { name:'AES-GCM', length:256 },
            true,
            ['encrypt', 'decrypt']
        )

        const a = await seal(kp, myKey)
        const b = await seal(kp, myKey)

        const same = bytesEqual(a.wrapped, b.wrapped)
        t.ok(!same, 'two seals of same key produce different envelopes')
    }
)
