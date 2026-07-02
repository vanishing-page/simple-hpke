import { test } from '@substrate-system/tapzero'
import { suite } from '../src/index.js'

test('cipher suite is configured', async t => {
    t.equal(suite.KEM.Nenc, 32, 'X25519 encapsulated key is 32 bytes')
})
