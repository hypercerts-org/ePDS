/**
 * Public key material for a (did, purpose) pair — everything a caller
 * may learn about a key without asking it to sign anything.
 */
import { formatDidKey } from '@atproto/crypto'
import { secp256k1 } from '@noble/curves/secp256k1'
import { keccak_256 } from '@noble/hashes/sha3'
import { base58Encode } from './base58.js'
import { curveForPurpose, derivePublicKey } from './derive.js'
import { REPO_SIGNING_PURPOSE, type KeyPurpose } from './purposes.js'

export interface KeyInfo {
  keyId: string
  purpose: KeyPurpose
  curve: 'secp256k1' | 'ed25519'
  /** Compressed (secp256k1) or raw (ed25519) public key, hex. */
  publicKeyHex: string
  /** did:key of the public key — only for the repo signing purpose. */
  didKey?: string
  /** Chain address — only for wallet purposes. */
  address?: string
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

export function getKeyInfo(
  rootSeed: Uint8Array,
  did: string,
  purpose: KeyPurpose,
): KeyInfo {
  const publicKey = derivePublicKey(rootSeed, did, purpose)
  const curve = curveForPurpose(purpose)
  const info: KeyInfo = {
    keyId: `${did}#${purpose}`,
    purpose,
    curve,
    publicKeyHex: bytesToHex(publicKey),
  }
  if (purpose === REPO_SIGNING_PURPOSE) {
    info.didKey = formatDidKey('ES256K', publicKey)
  } else if (purpose === 'wallet/evm') {
    info.address = evmAddressFromCompressedPubkey(publicKey)
  } else {
    info.address = base58Encode(publicKey)
  }
  return info
}
