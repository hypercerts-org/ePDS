/**
 * Deterministic per-(did, purpose) key derivation from the root seed.
 *
 *   secret = HKDF-SHA256(ikm = rootSeed,
 *                        salt = SHA256('epds-signer:v1'),
 *                        info = `${did}\0${purpose}\0${counter}`)
 *
 * The DID and purpose are both baked into the HKDF info string, so a
 * user's repo-signing key, EVM wallet key, and Solana wallet key are
 * cryptographically unrelated even though two of them share a curve.
 * The counter is 0 except in the astronomically unlikely case that the
 * derived 32 bytes are not a valid secp256k1 scalar, in which case we
 * re-derive with counter+1 (standard hash-to-scalar retry loop).
 *
 * Derivation is pure — no key material is ever stored. A fresh signer
 * instance holding the same root seed (e.g. a failover CVM that passed
 * attestation and received the seed from the KMS) derives identical keys.
 */
import { secp256k1 } from '@noble/curves/secp256k1'
import { ed25519 } from '@noble/curves/ed25519'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { REPO_SIGNING_PURPOSE, type KeyPurpose } from './purposes.js'

const HKDF_SALT = sha256(new TextEncoder().encode('epds-signer:v1'))
const MAX_DERIVE_ATTEMPTS = 16

export type Curve = 'secp256k1' | 'ed25519'

export function curveForPurpose(purpose: KeyPurpose): Curve {
  switch (purpose) {
    case REPO_SIGNING_PURPOSE:
    case 'wallet/evm':
      return 'secp256k1'
    case 'wallet/sol':
      return 'ed25519'
  }
}

function deriveBytes(
  rootSeed: Uint8Array,
  did: string,
  purpose: KeyPurpose,
  counter: number,
): Uint8Array {
  const info = new TextEncoder().encode(`${did}\0${purpose}\0${counter}`)
  return hkdf(sha256, rootSeed, HKDF_SALT, info, 32)
}

/**
 * Derive the 32-byte private key for (did, purpose). For secp256k1 the
 * result is guaranteed to be a valid scalar; for ed25519 any 32 bytes
 * are a valid seed.
 */
export function derivePrivateKey(
  rootSeed: Uint8Array,
  did: string,
  purpose: KeyPurpose,
): Uint8Array {
  const curve = curveForPurpose(purpose)
  if (curve === 'ed25519') {
    return deriveBytes(rootSeed, did, purpose, 0)
  }
  for (let counter = 0; counter < MAX_DERIVE_ATTEMPTS; counter++) {
    const candidate = deriveBytes(rootSeed, did, purpose, counter)
    if (secp256k1.utils.isValidSecretKey(candidate)) return candidate
  }
  /* v8 ignore next 4 -- probability ~2^-2048, unreachable in practice */
  throw new Error(
    `Failed to derive a valid secp256k1 key for ${did}/${purpose}`,
  )
}

/** Derive the public key for (did, purpose). Compressed for secp256k1. */
export function derivePublicKey(
  rootSeed: Uint8Array,
  did: string,
  purpose: KeyPurpose,
): Uint8Array {
  const priv = derivePrivateKey(rootSeed, did, purpose)
  return curveForPurpose(purpose) === 'ed25519'
    ? ed25519.getPublicKey(priv)
    : secp256k1.getPublicKey(priv, true)
}

/**
 * Sign a 32-byte digest with the (did, purpose) secp256k1 key.
 * Returns the compact 64-byte `r || s` signature, low-S normalized —
 * exactly what ATProto commit signatures require (and what EVM needs
 * before appending the recovery byte).
 */
export function signSecp256k1Digest(
  rootSeed: Uint8Array,
  did: string,
  purpose: KeyPurpose,
  digest: Uint8Array,
): { signature: Uint8Array; recovery: number } {
  if (curveForPurpose(purpose) !== 'secp256k1') {
    throw new Error(`purpose ${purpose} is not a secp256k1 key`)
  }
  if (digest.length !== 32) {
    throw new Error('digest must be exactly 32 bytes')
  }
  const priv = derivePrivateKey(rootSeed, did, purpose)
  // prehash: false — the caller supplies the digest; hash exactly once.
  const sig = secp256k1.sign(digest, priv, { lowS: true, prehash: false })
  return { signature: sig.toBytes('compact'), recovery: sig.recovery }
}

/**
 * The signer's own identity key — bound into the attestation quote
 * (report_data = SHA-256 of this public key). Not a user key; derived
 * from the root seed with a reserved, non-DID label so it can never
 * collide with a per-user derivation.
 */
export function deriveIdentityPublicKey(rootSeed: Uint8Array): Uint8Array {
  const info = new TextEncoder().encode('epds-signer-identity\0v1')
  for (let counter = 0; counter < MAX_DERIVE_ATTEMPTS; counter++) {
    const candidate = hkdf(
      sha256,
      rootSeed,
      HKDF_SALT,
      new Uint8Array([...info, counter]),
      32,
    )
    if (secp256k1.utils.isValidSecretKey(candidate)) {
      return secp256k1.getPublicKey(candidate, true)
    }
  }
  /* v8 ignore next 2 -- probability ~2^-2048, unreachable in practice */
  throw new Error('Failed to derive signer identity key')
}

/**
 * Sign an arbitrary message with the (did, 'wallet/sol') ed25519 key.
 * Solana signs the full serialized message bytes, not a digest.
 */
export function signEd25519Message(
  rootSeed: Uint8Array,
  did: string,
  purpose: KeyPurpose,
  message: Uint8Array,
): Uint8Array {
  if (curveForPurpose(purpose) !== 'ed25519') {
    throw new Error(`purpose ${purpose} is not an ed25519 key`)
  }
  const priv = derivePrivateKey(rootSeed, did, purpose)
  return ed25519.sign(message, priv)
}
