/**
 * Deterministic derivation from the root seed — REPO SIGNING KEYS ONLY.
 *
 *   secret = HKDF-SHA256(ikm = rootSeed,
 *                        salt = SHA256('epds-signer:v1'),
 *                        info = `${did}\0atproto/signing\0${counter}`)
 *
 * The repo signing key is disposable (§13.1 of the design): if it is
 * ever lost, a fresh key is minted and the DID's `#atproto` method is
 * rotated to it. So root-derivation is exactly right here — a failover
 * enclave holding the same root seed re-derives identical keys, and no
 * user-facing recovery is needed.
 *
 * Wallet keys are deliberately NOT derivable from the root seed. They
 * are independent per-wallet secrets under a 2-of-3 Shamir share
 * scheme (see wallet.ts) so their durability and the user's exit path
 * never depend on a single enclave root. This module cannot produce a
 * wallet key by construction.
 *
 * The counter is 0 except in the astronomically unlikely case that the
 * derived 32 bytes are not a valid secp256k1 scalar, in which case we
 * re-derive with counter+1 (standard hash-to-scalar retry loop).
 */
import { secp256k1 } from '@noble/curves/secp256k1'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { REPO_SIGNING_PURPOSE } from './purposes.js'

const HKDF_SALT = sha256(new TextEncoder().encode('epds-signer:v1'))
const MAX_DERIVE_ATTEMPTS = 16

function deriveBytes(
  rootSeed: Uint8Array,
  did: string,
  counter: number,
): Uint8Array {
  const info = new TextEncoder().encode(
    `${did}\0${REPO_SIGNING_PURPOSE}\0${counter}`,
  )
  return hkdf(sha256, rootSeed, HKDF_SALT, info, 32)
}

/**
 * Derive the 32-byte repo-signing private key for a DID. The result is
 * guaranteed to be a valid secp256k1 scalar.
 */
export function deriveRepoPrivateKey(
  rootSeed: Uint8Array,
  did: string,
): Uint8Array {
  for (let counter = 0; counter < MAX_DERIVE_ATTEMPTS; counter++) {
    const candidate = deriveBytes(rootSeed, did, counter)
    if (secp256k1.utils.isValidSecretKey(candidate)) return candidate
  }
  /* v8 ignore next 2 -- probability ~2^-2048, unreachable in practice */
  throw new Error(`Failed to derive a valid secp256k1 key for ${did}`)
}

/** Derive the compressed repo-signing public key for a DID. */
export function deriveRepoPublicKey(
  rootSeed: Uint8Array,
  did: string,
): Uint8Array {
  return secp256k1.getPublicKey(deriveRepoPrivateKey(rootSeed, did), true)
}

/**
 * Sign a 32-byte repo-commit digest with the DID's signing key.
 * Returns the compact 64-byte `r || s` signature, low-S normalized —
 * exactly what ATProto commit signatures require.
 */
export function signRepoDigest(
  rootSeed: Uint8Array,
  did: string,
  digest: Uint8Array,
): Uint8Array {
  if (digest.length !== 32) {
    throw new Error('digest must be exactly 32 bytes')
  }
  const priv = deriveRepoPrivateKey(rootSeed, did)
  // prehash: false — the caller supplies the digest; hash exactly once.
  const sig = secp256k1.sign(digest, priv, { lowS: true, prehash: false })
  return sig.toBytes('compact')
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
