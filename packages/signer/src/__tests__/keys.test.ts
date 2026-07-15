import { describe, expect, it } from 'vitest'
import { secp256k1 } from '@noble/curves/secp256k1'
import { base58Encode } from '../base58.js'
import {
  evmAddressFromCompressedPubkey,
  getKeyInfo,
  toChecksumAddress,
} from '../keys.js'

describe('base58Encode', () => {
  it('matches known vectors', () => {
    expect(base58Encode(new Uint8Array())).toBe('')
    expect(base58Encode(Uint8Array.from([0x61]))).toBe('2g')
    expect(base58Encode(Uint8Array.from([0x62, 0x62, 0x62]))).toBe('a3gV')
    expect(
      base58Encode(Uint8Array.from(Buffer.from('Hello World!', 'ascii'))),
    ).toBe('2NEpo7TZRRrLZSi2U')
    // leading zeros become literal '1's
    expect(base58Encode(Uint8Array.from([0, 0, 1]))).toBe('112')
  })
})

describe('toChecksumAddress', () => {
  it('matches the EIP-55 reference vector', () => {
    const addr = Buffer.from('5aaeb6053f3e94c9b9a09f33669435e7ef1beaed', 'hex')
    expect(toChecksumAddress(Uint8Array.from(addr))).toBe(
      '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
    )
  })
})

describe('evmAddressFromCompressedPubkey', () => {
  it('derives the canonical address for private key 0x...01', () => {
    const pub = secp256k1.getPublicKey(
      Uint8Array.from(Buffer.alloc(32, 0).fill(1, 31)),
      true,
    )
    expect(evmAddressFromCompressedPubkey(pub)).toBe(
      '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf',
    )
  })
})

describe('getKeyInfo', () => {
  const seed = Buffer.alloc(32, 9)
  const did = 'did:plc:keyinfo'

  it('returns a did:key for the repo purpose, no address', () => {
    const info = getKeyInfo(seed, did, 'atproto/signing')
    expect(info.curve).toBe('secp256k1')
    expect(info.didKey).toMatch(/^did:key:z/)
    expect(info.address).toBeUndefined()
    expect(info.keyId).toBe(`${did}#atproto/signing`)
  })

  it('returns an EIP-55 address for wallet/evm, no didKey', () => {
    const info = getKeyInfo(seed, did, 'wallet/evm')
    expect(info.address).toMatch(/^0x[0-9a-fA-F]{40}$/)
    expect(info.didKey).toBeUndefined()
  })

  it('returns a base58 address for wallet/sol', () => {
    const info = getKeyInfo(seed, did, 'wallet/sol')
    expect(info.curve).toBe('ed25519')
    expect(info.address).toMatch(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/)
  })
})
