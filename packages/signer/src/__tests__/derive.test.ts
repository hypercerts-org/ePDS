import { describe, expect, it } from 'vitest'
import * as nodeCrypto from 'node:crypto'
import { verifySignature, parseDidKey } from '@atproto/crypto'
import { secp256k1 } from '@noble/curves/secp256k1'
import { ed25519 } from '@noble/curves/ed25519'
import {
  deriveIdentityPublicKey,
  derivePrivateKey,
  derivePublicKey,
  signEd25519Message,
  signSecp256k1Digest,
} from '../derive.js'
import { getKeyInfo } from '../keys.js'

const seed = Buffer.alloc(32, 7)
const otherSeed = Buffer.alloc(32, 8)
const did = 'did:plc:abc123xyz'

describe('derivePrivateKey', () => {
  it('is deterministic for the same (seed, did, purpose)', () => {
    const a = derivePrivateKey(seed, did, 'atproto/signing')
    const b = derivePrivateKey(seed, did, 'atproto/signing')
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true)
  })

  it('separates keys by purpose, did, and seed', () => {
    const repo = derivePrivateKey(seed, did, 'atproto/signing')
    const evm = derivePrivateKey(seed, did, 'wallet/evm')
    const sol = derivePrivateKey(seed, did, 'wallet/sol')
    const otherDid = derivePrivateKey(seed, 'did:plc:other', 'atproto/signing')
    const otherRoot = derivePrivateKey(otherSeed, did, 'atproto/signing')
    const all = [repo, evm, sol, otherDid, otherRoot].map((k) =>
      Buffer.from(k).toString('hex'),
    )
    expect(new Set(all).size).toBe(all.length)
  })

  it('produces valid secp256k1 scalars', () => {
    const priv = derivePrivateKey(seed, did, 'wallet/evm')
    expect(secp256k1.utils.isValidSecretKey(priv)).toBe(true)
  })
})

describe('derivePublicKey', () => {
  it('matches the private key (secp256k1, compressed)', () => {
    const priv = derivePrivateKey(seed, did, 'atproto/signing')
    const pub = derivePublicKey(seed, did, 'atproto/signing')
    expect(
      Buffer.from(pub).equals(Buffer.from(secp256k1.getPublicKey(priv, true))),
    ).toBe(true)
    expect(pub.length).toBe(33)
  })

  it('matches the private key (ed25519)', () => {
    const priv = derivePrivateKey(seed, did, 'wallet/sol')
    const pub = derivePublicKey(seed, did, 'wallet/sol')
    expect(
      Buffer.from(pub).equals(Buffer.from(ed25519.getPublicKey(priv))),
    ).toBe(true)
    expect(pub.length).toBe(32)
  })
})

describe('signSecp256k1Digest', () => {
  it('produces a low-S signature ATProto accepts (via did:key verify)', async () => {
    const msg = new TextEncoder().encode('a dag-cbor commit, allegedly')
    const digest = nodeCrypto.createHash('sha256').update(msg).digest()
    const { signature } = signSecp256k1Digest(
      seed,
      did,
      'atproto/signing',
      digest,
    )
    expect(signature.length).toBe(64)

    // low-S: s <= n/2
    const s = BigInt('0x' + Buffer.from(signature.subarray(32)).toString('hex'))
    expect(s <= secp256k1.Point.CURVE().n / 2n).toBe(true)

    // @atproto/crypto verifies against the did:key (strict low-S mode)
    const { didKey } = getKeyInfo(seed, did, 'atproto/signing')
    expect(didKey).toMatch(/^did:key:z/)
    expect(parseDidKey(didKey!).jwtAlg).toBe('ES256K')
    await expect(verifySignature(didKey!, msg, signature)).resolves.toBe(true)
  })

  it('rejects non-32-byte digests and wrong-curve purposes', () => {
    expect(() =>
      signSecp256k1Digest(seed, did, 'atproto/signing', new Uint8Array(31)),
    ).toThrow(/32 bytes/)
    expect(() =>
      signSecp256k1Digest(seed, did, 'wallet/sol', new Uint8Array(32)),
    ).toThrow(/not a secp256k1 key/)
  })
})

describe('signEd25519Message', () => {
  it('signs a message verifiable with the derived pubkey', () => {
    const msg = new TextEncoder().encode('a solana transaction message')
    const sig = signEd25519Message(seed, did, 'wallet/sol', msg)
    expect(sig.length).toBe(64)
    const pub = derivePublicKey(seed, did, 'wallet/sol')
    expect(ed25519.verify(sig, msg, pub)).toBe(true)
  })

  it('rejects wrong-curve purposes', () => {
    expect(() =>
      signEd25519Message(seed, did, 'wallet/evm', new Uint8Array(1)),
    ).toThrow(/not an ed25519 key/)
  })
})

describe('deriveIdentityPublicKey', () => {
  it('is deterministic and distinct from user keys', () => {
    const a = deriveIdentityPublicKey(seed)
    const b = deriveIdentityPublicKey(seed)
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true)
    expect(a.length).toBe(33)
    const userPub = derivePublicKey(seed, did, 'atproto/signing')
    expect(Buffer.from(a).equals(Buffer.from(userPub))).toBe(false)
  })
})
