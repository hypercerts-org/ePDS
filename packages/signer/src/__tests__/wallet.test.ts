/**
 * Unit tests for the 2-of-3 wallet key model: per-wallet entropy,
 * BIP-39/BIP-32/SLIP-10 derivation, Shamir split/combine, server-share
 * encryption, and JWE share transport in both directions.
 */
import { describe, expect, it } from 'vitest'
import { secp256k1 } from '@noble/curves/secp256k1'
import { ed25519 } from '@noble/curves/ed25519'
import { p256 } from '@noble/curves/nist.js'
import { CompactEncrypt, compactDecrypt, importJWK, type JWK } from 'jose'
import {
  WALLET_ENTROPY_BYTES,
  buildExportPayload,
  combineWalletShares,
  decryptJweToEnclave,
  decryptPregenEntropy,
  decryptServerShare,
  deriveChainKeys,
  deriveShareKek,
  encryptPregenEntropy,
  encryptServerShare,
  encryptToRequestKey,
  generateWalletEntropy,
  getWalletEncryptionPublicJwk,
  isCompactJwe,
  isValidP256PublicKeyHex,
  signEvmDigestWithKey,
  signSolMessageWithKey,
  splitWalletEntropy,
} from '../wallet.js'

const rootSeed = Buffer.alloc(32, 3)
const did = 'did:plc:wallettest'

function userP256Jwk(priv: Uint8Array): { publicHex: string; privJwk: JWK } {
  const uncompressed = p256.getPublicKey(priv, false)
  const jwk: JWK = {
    kty: 'EC',
    crv: 'P-256',
    x: Buffer.from(uncompressed.subarray(1, 33)).toString('base64url'),
    y: Buffer.from(uncompressed.subarray(33, 65)).toString('base64url'),
    d: Buffer.from(priv).toString('base64url'),
  }
  return {
    publicHex: Buffer.from(p256.getPublicKey(priv, true)).toString('hex'),
    privJwk: jwk,
  }
}

describe('generateWalletEntropy', () => {
  it('returns 128 bits and never repeats', () => {
    const a = generateWalletEntropy()
    const b = generateWalletEntropy()
    expect(a.length).toBe(WALLET_ENTROPY_BYTES)
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false)
  })
})

describe('deriveChainKeys', () => {
  it('derives the canonical EVM address for the BIP-39 test mnemonic', () => {
    // entropy 0x00*16 = "abandon ... about"; m/44'/60'/0'/0/0 is the
    // well-known reference address for that mnemonic.
    const keys = deriveChainKeys(new Uint8Array(16))
    expect(keys.mnemonic).toBe(
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    )
    expect(keys.evmAddress).toBe('0x9858EfFD232B4033E47d90003D41EC34EcaEda94')
  })

  it('is deterministic and internally consistent', () => {
    const entropy = generateWalletEntropy()
    const a = deriveChainKeys(entropy)
    const b = deriveChainKeys(entropy)
    expect(a.evmAddress).toBe(b.evmAddress)
    expect(a.solAddress).toBe(b.solAddress)
    expect(
      Buffer.from(secp256k1.getPublicKey(a.evmPrivateKey, true)).equals(
        Buffer.from(a.evmPublicKey),
      ),
    ).toBe(true)
    expect(
      Buffer.from(ed25519.getPublicKey(a.solPrivateKey)).equals(
        Buffer.from(a.solPublicKey),
      ),
    ).toBe(true)
    expect(a.solAddress).toMatch(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/)
  })

  it('different entropy yields different wallets', () => {
    const a = deriveChainKeys(generateWalletEntropy())
    const b = deriveChainKeys(generateWalletEntropy())
    expect(a.evmAddress).not.toBe(b.evmAddress)
    expect(a.solAddress).not.toBe(b.solAddress)
  })
})

describe('splitWalletEntropy / combineWalletShares', () => {
  it('any two of three shares reconstruct; shares are not the secret', async () => {
    const entropy = generateWalletEntropy()
    const [server, device, recovery] = await splitWalletEntropy(entropy)
    for (const pair of [
      [server, device],
      [server, recovery],
      [device, recovery],
    ] as const) {
      const rec = await combineWalletShares(pair[0], pair[1])
      expect(Buffer.from(rec).equals(Buffer.from(entropy))).toBe(true)
    }
    for (const share of [server, device, recovery]) {
      expect(Buffer.from(share).equals(Buffer.from(entropy))).toBe(false)
    }
  })

  it('fresh coefficients: re-splitting yields unrelated shares', async () => {
    const entropy = generateWalletEntropy()
    const first = await splitWalletEntropy(entropy)
    const second = await splitWalletEntropy(entropy)
    expect(Buffer.from(first[0]).equals(Buffer.from(second[0]))).toBe(false)
    // Shares from different polynomial sets must not combine correctly.
    const cross = await combineWalletShares(first[0], second[1])
    expect(Buffer.from(cross).equals(Buffer.from(entropy))).toBe(false)
  })
})

describe('server share encryption (measurement-bound KEK)', () => {
  const kek = deriveShareKek(rootSeed)

  it('round-trips and binds the DID as AAD', async () => {
    const [share] = await splitWalletEntropy(generateWalletEntropy())
    const cipherHex = encryptServerShare(kek, did, share)
    expect(
      Buffer.from(decryptServerShare(kek, did, cipherHex)).equals(
        Buffer.from(share),
      ),
    ).toBe(true)
    expect(() =>
      decryptServerShare(kek, 'did:plc:someoneelse', cipherHex),
    ).toThrow()
  })

  it('rejects tampered and truncated ciphertext', async () => {
    const [share] = await splitWalletEntropy(generateWalletEntropy())
    const cipherHex = encryptServerShare(kek, did, share)
    const tampered =
      cipherHex.slice(0, -2) + (cipherHex.endsWith('00') ? '01' : '00')
    expect(() => decryptServerShare(kek, did, tampered)).toThrow()
    expect(() => decryptServerShare(kek, did, 'abcd')).toThrow(/too short/)
  })

  it('kek differs per root seed', () => {
    expect(
      Buffer.from(deriveShareKek(Buffer.alloc(32, 4))).equals(Buffer.from(kek)),
    ).toBe(false)
  })
})

describe('pregenerated entropy encryption (defer-split)', () => {
  const kek = deriveShareKek(rootSeed)

  it('round-trips and binds the DID as AAD', () => {
    const entropy = generateWalletEntropy()
    const cipherHex = encryptPregenEntropy(kek, did, entropy)
    expect(
      Buffer.from(decryptPregenEntropy(kek, did, cipherHex)).equals(
        Buffer.from(entropy),
      ),
    ).toBe(true)
    expect(() =>
      decryptPregenEntropy(kek, 'did:plc:someoneelse', cipherHex),
    ).toThrow()
  })

  it('is domain-separated from server-share ciphertext', () => {
    const entropy = generateWalletEntropy()
    // A pregen blob must never decrypt as a server share, nor a
    // server-share blob as pregen entropy — the AAD domains differ.
    const pregenCipher = encryptPregenEntropy(kek, did, entropy)
    expect(() => decryptServerShare(kek, did, pregenCipher)).toThrow()
    const shareCipher = encryptServerShare(kek, did, entropy)
    expect(() => decryptPregenEntropy(kek, did, shareCipher)).toThrow()
  })
})

describe('JWE transport', () => {
  it('encryptToRequestKey → user decrypts with their P-256 key', async () => {
    const user = userP256Jwk(p256.utils.randomSecretKey())
    const secret = new TextEncoder().encode('a device share')
    const jwe = await encryptToRequestKey(user.publicHex, secret)
    expect(isCompactJwe(jwe)).toBe(true)
    const { plaintext } = await compactDecrypt(
      jwe,
      await importJWK(user.privJwk, 'ECDH-ES'),
    )
    expect(Buffer.from(plaintext).equals(Buffer.from(secret))).toBe(true)
  })

  it('client → enclave: encrypt to the published JWK, enclave decrypts', async () => {
    const enclaveJwk = getWalletEncryptionPublicJwk(rootSeed)
    expect(enclaveJwk.crv).toBe('P-256')
    expect(enclaveJwk.d).toBeUndefined()
    const secret = new TextEncoder().encode('a recovery share')
    const jwe = await new CompactEncrypt(secret)
      .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
      .encrypt(await importJWK(enclaveJwk, 'ECDH-ES'))
    const out = await decryptJweToEnclave(rootSeed, jwe)
    expect(Buffer.from(out).equals(Buffer.from(secret))).toBe(true)
  })

  it('a different root seed cannot decrypt', async () => {
    const enclaveJwk = getWalletEncryptionPublicJwk(rootSeed)
    const jwe = await new CompactEncrypt(new Uint8Array(8))
      .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
      .encrypt(await importJWK(enclaveJwk, 'ECDH-ES'))
    await expect(
      decryptJweToEnclave(Buffer.alloc(32, 9), jwe),
    ).rejects.toThrow()
  })
})

describe('validators', () => {
  it('isCompactJwe accepts 5-part tokens with empty key segment', () => {
    expect(isCompactJwe('AAAA..BBBB.CCCC.DDDD')).toBe(true)
    expect(isCompactJwe('AAAA.KEY.BBBB.CCCC.DDDD')).toBe(true)
    expect(isCompactJwe('AAAA.BBBB.CCCC')).toBe(false)
    expect(isCompactJwe('')).toBe(false)
    expect(isCompactJwe(42)).toBe(false)
    expect(isCompactJwe('A'.repeat(9000) + '..B.C.D')).toBe(false)
  })

  it('isValidP256PublicKeyHex checks the point is on the curve', () => {
    const good = Buffer.from(
      p256.getPublicKey(p256.utils.randomSecretKey(), true),
    ).toString('hex')
    expect(isValidP256PublicKeyHex(good)).toBe(true)
    expect(isValidP256PublicKeyHex('02' + 'ff'.repeat(32))).toBe(false)
    expect(isValidP256PublicKeyHex('zz')).toBe(false)
  })
})

describe('chain signing with reconstructed keys', () => {
  const keys = deriveChainKeys(generateWalletEntropy())

  it('signs an EVM digest (low-S, recoverable)', () => {
    const digest = Buffer.alloc(32, 0xcd)
    const { signature, recovery } = signEvmDigestWithKey(
      keys.evmPrivateKey,
      digest,
    )
    expect(signature.length).toBe(64)
    expect(recovery === 0 || recovery === 1).toBe(true)
    expect(
      secp256k1.verify(signature, digest, keys.evmPublicKey, {
        prehash: false,
      }),
    ).toBe(true)
    expect(() =>
      signEvmDigestWithKey(keys.evmPrivateKey, new Uint8Array(16)),
    ).toThrow(/32 bytes/)
  })

  it('signs a Solana message (ed25519)', () => {
    const msg = new TextEncoder().encode('solana message')
    const sig = signSolMessageWithKey(keys.solPrivateKey, msg)
    expect(ed25519.verify(sig, msg, keys.solPublicKey)).toBe(true)
  })
})

describe('buildExportPayload', () => {
  it('contains everything a leaving user needs', () => {
    const entropy = generateWalletEntropy()
    const keys = deriveChainKeys(entropy)
    const parsed = JSON.parse(
      new TextDecoder().decode(buildExportPayload(entropy, keys)),
    ) as {
      entropyHex: string
      mnemonic: string
      evm: { privateKeyHex: string; address: string }
      sol: { privateKeyHex: string; address: string }
    }
    expect(parsed.entropyHex).toBe(Buffer.from(entropy).toString('hex'))
    expect(parsed.mnemonic).toBe(keys.mnemonic)
    expect(parsed.evm.address).toBe(keys.evmAddress)
    expect(parsed.evm.privateKeyHex).toBe(
      Buffer.from(keys.evmPrivateKey).toString('hex'),
    )
    expect(parsed.sol.address).toBe(keys.solAddress)
    expect(parsed.sol.privateKeyHex).toBe(
      Buffer.from(keys.solPrivateKey).toString('hex'),
    )
  })
})
