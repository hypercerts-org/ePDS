/**
 * Wallet key material — the Privy-style 2-of-3 share model.
 *
 * Unlike the repo signing key (disposable, re-derivable from the root
 * seed — see derive.ts), a wallet key is NOT derived from the enclave
 * root. Each wallet is an independent secret:
 *
 *   entropy  = CSPRNG(128 bits)              generated in-enclave
 *   mnemonic = BIP-39(entropy)               standard HD wallet
 *   keys     = BIP-32  m/44'/60'/0'/0/0      (EVM, secp256k1)
 *              SLIP-10 m/44'/501'/0'/0'      (Solana, ed25519)
 *   shares   = SSS-split(entropy, k=2, n=3)  server / device / recovery
 *
 * Share custody (the §13 invariant — no single party holds ≥ 2 shares,
 * the user independently controls ≥ 2):
 *
 *   - SERVER share: kept by the signer, encrypted at rest under a KEK
 *     derived from the root seed (the measurement-bound key — only an
 *     attested enclave that received the seed from the KMS can use it).
 *   - DEVICE share: returned to the user at creation, encrypted to
 *     their enrolled P-256 request key (JWE ECDH-ES). Never persisted
 *     server-side; the PDS only ever transports ciphertext.
 *   - RECOVERY share: same delivery; the client must re-protect it
 *     under a user-controlled recovery factor (password / cloud
 *     backup). The operator cannot read it.
 *
 * Signing reconstructs the entropy transiently inside the enclave from
 * the server share + the device share (sent JWE-encrypted to the
 * enclave's own encryption key, so the PDS in the middle never sees a
 * second share), derives the chain key, signs, and wipes everything.
 * Recovery re-splits with fresh SSS coefficients, so post-recovery
 * shares carry no correlation to the old set (forward secrecy).
 *
 * Cryptography is upstream throughout: shamir-secret-sharing (Privy's
 * audited SSS), @scure/bip39 + @scure/bip32, micro-key-producer's
 * SLIP-10, @noble/curves, and jose for JWE — nothing hand-rolled.
 */
import * as crypto from 'node:crypto'
import { combine, split } from 'shamir-secret-sharing'
import { entropyToMnemonic, mnemonicToSeedSync } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english'
import { HDKey } from '@scure/bip32'
import { derivePath as deriveSlip10Path } from 'ed25519-hd-key'
import { secp256k1 } from '@noble/curves/secp256k1'
import { ed25519 } from '@noble/curves/ed25519'
import { p256 } from '@noble/curves/nist.js'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { CompactEncrypt, compactDecrypt, importJWK, type JWK } from 'jose'
import { base58Encode } from './base58.js'
import { bytesToHex, evmAddressFromCompressedPubkey } from './keys.js'

const WALLET_HKDF_SALT = sha256(new TextEncoder().encode('epds-wallet:v1'))
const MAX_DERIVE_ATTEMPTS = 16

/** 128 bits of entropy — a 12-word BIP-39 mnemonic. */
export const WALLET_ENTROPY_BYTES = 16
export const SSS_SHARES = 3
export const SSS_THRESHOLD = 2

const EVM_DERIVATION_PATH = "m/44'/60'/0'/0/0"
const SOL_DERIVATION_PATH = "m/44'/501'/0'/0'"

/** JWE algorithms accepted/produced for share transport. */
const JWE_ALG = 'ECDH-ES'
const JWE_ENC = 'A256GCM'

export interface WalletChainKeys {
  mnemonic: string
  evmPrivateKey: Uint8Array
  /** Compressed secp256k1 public key (33 bytes). */
  evmPublicKey: Uint8Array
  evmAddress: string
  solPrivateKey: Uint8Array
  /** Raw ed25519 public key (32 bytes). */
  solPublicKey: Uint8Array
  solAddress: string
}

/** Best-effort zeroization of transient secret buffers. */
export function wipe(...buffers: Array<Uint8Array | undefined>): void {
  for (const buf of buffers) buf?.fill(0)
}

/** shamir-secret-sharing insists on exact Uint8Array (not Buffer). */
function toPlainUint8Array(bytes: Uint8Array): Uint8Array {
  return bytes.constructor === Uint8Array ? bytes : Uint8Array.from(bytes)
}

export function generateWalletEntropy(): Uint8Array {
  return Uint8Array.from(crypto.randomBytes(WALLET_ENTROPY_BYTES))
}

/**
 * Derive the per-chain HD keys from wallet entropy. Deterministic:
 * the same entropy always yields the same addresses, which is how a
 * reconstructed wallet is integrity-checked against stored public
 * material before any signature is issued.
 */
export function deriveChainKeys(entropy: Uint8Array): WalletChainKeys {
  const mnemonic = entropyToMnemonic(entropy, wordlist)
  const seed = mnemonicToSeedSync(mnemonic)
  try {
    const evm = HDKey.fromMasterSeed(seed).derive(EVM_DERIVATION_PATH)
    /* v8 ignore next 3 -- @scure/bip32 always yields a key for this path */
    if (!evm.privateKey) {
      throw new Error('BIP-32 derivation yielded no EVM private key')
    }
    const evmPrivateKey = Uint8Array.from(evm.privateKey)
    const evmPublicKey = secp256k1.getPublicKey(evmPrivateKey, true)
    const sol = deriveSlip10Path(
      SOL_DERIVATION_PATH,
      Buffer.from(seed).toString('hex'),
    )
    const solPrivateKey = Uint8Array.from(sol.key)
    const solPublicKey = ed25519.getPublicKey(solPrivateKey)
    return {
      mnemonic,
      evmPrivateKey,
      evmPublicKey,
      evmAddress: evmAddressFromCompressedPubkey(evmPublicKey),
      solPrivateKey,
      solPublicKey,
      solAddress: base58Encode(solPublicKey),
    }
  } finally {
    wipe(seed)
  }
}

/** Split wallet entropy 2-of-3: [server, device, recovery]. */
export async function splitWalletEntropy(
  entropy: Uint8Array,
): Promise<[Uint8Array, Uint8Array, Uint8Array]> {
  const shares = await split(
    toPlainUint8Array(entropy),
    SSS_SHARES,
    SSS_THRESHOLD,
  )
  return [shares[0], shares[1], shares[2]]
}

/** Reconstruct wallet entropy from any two shares. */
export async function combineWalletShares(
  a: Uint8Array,
  b: Uint8Array,
): Promise<Uint8Array> {
  return combine([toPlainUint8Array(a), toPlainUint8Array(b)])
}

// ── KEK encryption at rest (measurement-bound KEK) ──────────────────

/**
 * KEK for at-rest wallet secrets (server shares and pregenerated
 * whole entropy), derived from the root seed. The root seed is what
 * the measurement-bound KMS releases to an attested enclave, so
 * ciphertext under this KEK is opaque to the operator and storage
 * admins, yet re-accessible by any fresh enclave passing attestation.
 */
export function deriveShareKek(rootSeed: Uint8Array): Uint8Array {
  const info = new TextEncoder().encode('epds-wallet-share-kek\0v1')
  return hkdf(sha256, rootSeed, WALLET_HKDF_SALT, info, 32)
}

/** AES-256-GCM under the KEK. Output hex: iv ‖ tag ‖ ciphertext. */
function kekEncrypt(
  kek: Uint8Array,
  aad: string,
  plaintext: Uint8Array,
): string {
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', kek, iv)
  cipher.setAAD(Buffer.from(aad, 'utf8'))
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()])
  return Buffer.concat([iv, cipher.getAuthTag(), ct]).toString('hex')
}

function kekDecrypt(
  kek: Uint8Array,
  aad: string,
  cipherHex: string,
): Uint8Array {
  const raw = Buffer.from(cipherHex, 'hex')
  if (raw.length < 12 + 16 + 1) {
    throw new Error('server share ciphertext too short')
  }
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    kek,
    raw.subarray(0, 12),
  )
  decipher.setAAD(Buffer.from(aad, 'utf8'))
  decipher.setAuthTag(raw.subarray(12, 28))
  return Uint8Array.from(
    Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]),
  )
}

/** Server share at rest, DID bound in as AAD. */
export function encryptServerShare(
  kek: Uint8Array,
  did: string,
  share: Uint8Array,
): string {
  return kekEncrypt(kek, did, share)
}

export function decryptServerShare(
  kek: Uint8Array,
  did: string,
  cipherHex: string,
): Uint8Array {
  return kekDecrypt(kek, did, cipherHex)
}

/**
 * AAD domain for pregenerated (defer-split) whole wallet entropy at
 * rest. Distinct from the server-share AAD (the bare DID) so a pregen
 * blob can never be presented as a server share or vice versa — the
 * GCM tag check fails across domains.
 */
const PREGEN_AAD_PREFIX = 'epds-pregen\0v1\0'

/**
 * Pregenerated wallet entropy at rest — the ONE case where whole
 * (unsplit) entropy is persisted: a wallet provisioned for a DID
 * before its first login, receive-only until claimed. Claiming
 * splits it 2-of-3 and deletes this blob (see service.ts).
 */
export function encryptPregenEntropy(
  kek: Uint8Array,
  did: string,
  entropy: Uint8Array,
): string {
  return kekEncrypt(kek, PREGEN_AAD_PREFIX + did, entropy)
}

export function decryptPregenEntropy(
  kek: Uint8Array,
  did: string,
  cipherHex: string,
): Uint8Array {
  return kekDecrypt(kek, PREGEN_AAD_PREFIX + did, cipherHex)
}

// ── Enclave wallet-encryption key (shares sent TO the enclave) ──────

function p256JwkFromPoint(point: Uint8Array): JWK {
  // Uncompressed SEC1 point: 0x04 ‖ x ‖ y
  const uncompressed = p256.Point.fromHex(point).toBytes(false)
  return {
    kty: 'EC',
    crv: 'P-256',
    x: Buffer.from(uncompressed.subarray(1, 33)).toString('base64url'),
    y: Buffer.from(uncompressed.subarray(33, 65)).toString('base64url'),
  }
}

function deriveWalletEncryptionSecretKey(rootSeed: Uint8Array): Uint8Array {
  const label = new TextEncoder().encode('epds-wallet-encryption\0v1')
  for (let counter = 0; counter < MAX_DERIVE_ATTEMPTS; counter++) {
    const candidate = hkdf(
      sha256,
      rootSeed,
      WALLET_HKDF_SALT,
      new Uint8Array([...label, counter]),
      32,
    )
    if (p256.utils.isValidSecretKey(candidate)) return candidate
  }
  /* v8 ignore next 2 -- probability ~2^-2048, unreachable in practice */
  throw new Error('Failed to derive wallet encryption key')
}

/**
 * Public JWK clients use to encrypt shares destined for the enclave
 * (device share on sign/export, recovery share on recover). Because
 * the private half is derived from the root seed, only an attested
 * enclave can decrypt — the PDS relaying the request cannot.
 */
export function getWalletEncryptionPublicJwk(rootSeed: Uint8Array): JWK {
  const secret = deriveWalletEncryptionSecretKey(rootSeed)
  try {
    return p256JwkFromPoint(p256.getPublicKey(secret, true))
  } finally {
    wipe(secret)
  }
}

/** Decrypt a compact JWE addressed to the enclave's encryption key. */
export async function decryptJweToEnclave(
  rootSeed: Uint8Array,
  jwe: string,
): Promise<Uint8Array> {
  const secret = deriveWalletEncryptionSecretKey(rootSeed)
  try {
    const jwk: JWK = {
      ...p256JwkFromPoint(p256.getPublicKey(secret, true)),
      d: Buffer.from(secret).toString('base64url'),
    }
    const key = await importJWK(jwk, JWE_ALG)
    const { plaintext } = await compactDecrypt(jwe, key, {
      keyManagementAlgorithms: [JWE_ALG],
      contentEncryptionAlgorithms: [JWE_ENC],
    })
    return plaintext
  } finally {
    wipe(secret)
  }
}

/**
 * Encrypt bytes to the user's enrolled compressed-P-256 request key as
 * a compact JWE (ECDH-ES + A256GCM). Used for everything the signer
 * hands BACK to the user — device/recovery shares and key export — so
 * the PDS in the middle only ever sees ciphertext.
 */
export async function encryptToRequestKey(
  requestPubkeyHex: string,
  plaintext: Uint8Array,
): Promise<string> {
  const jwk = p256JwkFromPoint(Buffer.from(requestPubkeyHex, 'hex'))
  const key = await importJWK(jwk, JWE_ALG)
  return new CompactEncrypt(plaintext)
    .setProtectedHeader({ alg: JWE_ALG, enc: JWE_ENC })
    .encrypt(key)
}

/** True iff `hex` decodes to a valid point on the P-256 curve. */
export function isValidP256PublicKeyHex(hex: string): boolean {
  try {
    p256.Point.fromHex(Buffer.from(hex, 'hex'))
    return true
  } catch {
    return false
  }
}

/** Compact JWE shape (5 dot-separated parts; empty encrypted-key for ECDH-ES). */
export function isCompactJwe(value: unknown, maxLen = 8192): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= maxLen &&
    /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(
      value,
    )
  )
}

// ── Chain signing with explicit (reconstructed) keys ────────────────

export function signEvmDigestWithKey(
  privateKey: Uint8Array,
  digest: Uint8Array,
): { signature: Uint8Array; recovery: number } {
  if (digest.length !== 32) throw new Error('digest must be exactly 32 bytes')
  const sig = secp256k1.sign(digest, privateKey, {
    lowS: true,
    prehash: false,
  })
  return { signature: sig.toBytes('compact'), recovery: sig.recovery }
}

export function signSolMessageWithKey(
  privateKey: Uint8Array,
  message: Uint8Array,
): Uint8Array {
  return ed25519.sign(message, privateKey)
}

/** Plaintext of the export JWE — everything a leaving user needs. */
export function buildExportPayload(
  entropy: Uint8Array,
  keys: WalletChainKeys,
): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({
      entropyHex: bytesToHex(entropy),
      mnemonic: keys.mnemonic,
      evm: {
        privateKeyHex: bytesToHex(keys.evmPrivateKey),
        address: keys.evmAddress,
      },
      sol: {
        privateKeyHex: bytesToHex(keys.solPrivateKey),
        address: keys.solAddress,
      },
    }),
  )
}
