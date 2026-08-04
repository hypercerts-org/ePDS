import { describe, expect, it } from 'vitest'
import * as nodeCrypto from 'node:crypto'
import { verifySignature, parseDidKey } from '@atproto/crypto'
import { secp256k1 } from '@noble/curves/secp256k1'
import {
  deriveIdentityPublicKey,
  deriveRepoPrivateKey,
  deriveRepoPublicKey,
  signRepoDigest,
} from '../derive.js'
import { getRepoKeyInfo } from '../keys.js'

const seed = Buffer.alloc(32, 7)
const otherSeed = Buffer.alloc(32, 8)
const did = 'did:plc:abc123xyz'

describe('deriveRepoPrivateKey', () => {
  it('is deterministic for the same (seed, did)', () => {
    const a = deriveRepoPrivateKey(seed, did)
    const b = deriveRepoPrivateKey(seed, did)
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true)
  })

  it('separates keys by did and seed', () => {
    const repo = deriveRepoPrivateKey(seed, did)
    const otherDid = deriveRepoPrivateKey(seed, 'did:plc:other')
    const otherRoot = deriveRepoPrivateKey(otherSeed, did)
    const all = [repo, otherDid, otherRoot].map((k) =>
      Buffer.from(k).toString('hex'),
    )
    expect(new Set(all).size).toBe(all.length)
  })

  it('produces valid secp256k1 scalars', () => {
    const priv = deriveRepoPrivateKey(seed, did)
    expect(secp256k1.utils.isValidSecretKey(priv)).toBe(true)
  })
})

describe('deriveRepoPublicKey', () => {
  it('matches the private key (secp256k1, compressed)', () => {
    const priv = deriveRepoPrivateKey(seed, did)
    const pub = deriveRepoPublicKey(seed, did)
    expect(
      Buffer.from(pub).equals(Buffer.from(secp256k1.getPublicKey(priv, true))),
    ).toBe(true)
    expect(pub.length).toBe(33)
  })
})

describe('signRepoDigest', () => {
  it('produces a low-S signature ATProto accepts (via did:key verify)', async () => {
    const msg = new TextEncoder().encode('a dag-cbor commit, allegedly')
    const digest = nodeCrypto.createHash('sha256').update(msg).digest()
    const signature = signRepoDigest(seed, did, digest)
    expect(signature.length).toBe(64)

    // low-S: s <= n/2
    const s = BigInt('0x' + Buffer.from(signature.subarray(32)).toString('hex'))
    expect(s <= secp256k1.Point.CURVE().n / 2n).toBe(true)

    // @atproto/crypto verifies against the did:key (strict low-S mode)
    const { didKey } = getRepoKeyInfo(seed, did)
    expect(didKey).toMatch(/^did:key:z/)
    expect(parseDidKey(didKey).jwtAlg).toBe('ES256K')
    await expect(verifySignature(didKey, msg, signature)).resolves.toBe(true)
  })

  it('rejects non-32-byte digests', () => {
    expect(() => signRepoDigest(seed, did, new Uint8Array(31))).toThrow(
      /32 bytes/,
    )
  })
})

describe('deriveIdentityPublicKey', () => {
  it('is deterministic and distinct from user keys', () => {
    const a = deriveIdentityPublicKey(seed)
    const b = deriveIdentityPublicKey(seed)
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true)
    expect(a.length).toBe(33)
    const userPub = deriveRepoPublicKey(seed, did)
    expect(Buffer.from(a).equals(Buffer.from(userPub))).toBe(false)
  })
})
