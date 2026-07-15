/**
 * Public key material helpers.
 *
 * `getRepoKeyInfo` covers the only root-derivable key — the repo
 * signing key. Wallet public material is per-wallet state (created at
 * wallet creation, cached in the store); the address-encoding helpers
 * for it live here so wallet.ts and tests share one implementation.
 */
import { formatDidKey } from '@atproto/crypto'
import { secp256k1 } from '@noble/curves/secp256k1'
import { keccak_256 } from '@noble/hashes/sha3'
import { deriveRepoPublicKey } from './derive.js'
import { REPO_SIGNING_PURPOSE } from './purposes.js'

export interface RepoKeyInfo {
  keyId: string
  purpose: typeof REPO_SIGNING_PURPOSE
  curve: 'secp256k1'
  /** Compressed public key, hex. */
  publicKeyHex: string
  /** did:key of the public key. */
  didKey: string
}

export function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex')
}

export function hexToBytes(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex, 'hex'))
}

/** EIP-55 mixed-case checksum encoding of a 20-byte EVM address. */
export function toChecksumAddress(addressBytes: Uint8Array): string {
  const lower = bytesToHex(addressBytes)
  const hash = bytesToHex(keccak_256(new TextEncoder().encode(lower)))
  let out = '0x'
  for (let i = 0; i < lower.length; i++) {
    out += parseInt(hash[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i]
  }
  return out
}

/** keccak256(uncompressed pubkey minus prefix byte), last 20 bytes. */
export function evmAddressFromCompressedPubkey(compressed: Uint8Array): string {
  const uncompressed = secp256k1.Point.fromHex(compressed).toBytes(false)
  const addressBytes = keccak_256(uncompressed.subarray(1)).subarray(-20)
  return toChecksumAddress(addressBytes)
}

export function getRepoKeyInfo(rootSeed: Uint8Array, did: string): RepoKeyInfo {
  const publicKey = deriveRepoPublicKey(rootSeed, did)
  return {
    keyId: `${did}#${REPO_SIGNING_PURPOSE}`,
    purpose: REPO_SIGNING_PURPOSE,
    curve: 'secp256k1',
    publicKeyHex: bytesToHex(publicKey),
    didKey: formatDidKey('ES256K', publicKey),
  }
}
