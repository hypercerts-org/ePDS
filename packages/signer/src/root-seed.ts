/**
 * Root seed management.
 *
 * The root seed is the single secret everything else is derived from.
 * In production the signer runs inside a confidential VM (dstack) and
 * the seed is provisioned by the dstack KMS, bound to the measured code
 * image — it exists only inside the TEE. In development it can be set
 * via env or generated into a local file.
 *
 * Sources, in priority order:
 *   1. SIGNER_ROOT_SEED_HEX  — 64 hex chars (32 bytes). Dev / KMS-injected.
 *   2. SIGNER_ROOT_SEED_FILE — path to a 32-byte binary or 64-hex-char file.
 *      When the file does not exist AND SIGNER_ALLOW_DEV_SEED=1, a fresh
 *      seed is generated and persisted there with mode 0600.
 *
 * Anything else is a hard startup failure — the signer must never run
 * with an ambiguous key source.
 */
import * as crypto from 'node:crypto'
import * as fs from 'node:fs'
import * as path from 'node:path'

export const ROOT_SEED_BYTES = 32

export class RootSeedError extends Error {}

function parseHexSeed(hex: string, source: string): Buffer {
  const trimmed = hex.trim()
  if (!/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    throw new RootSeedError(
      `${source} must be exactly ${ROOT_SEED_BYTES * 2} hex characters`,
    )
  }
  return Buffer.from(trimmed, 'hex')
}

export function loadRootSeed(env: {
  SIGNER_ROOT_SEED_HEX?: string
  SIGNER_ROOT_SEED_FILE?: string
  SIGNER_ALLOW_DEV_SEED?: string
}): Buffer {
  if (env.SIGNER_ROOT_SEED_HEX) {
    return parseHexSeed(env.SIGNER_ROOT_SEED_HEX, 'SIGNER_ROOT_SEED_HEX')
  }

  const file = env.SIGNER_ROOT_SEED_FILE
  if (!file) {
    throw new RootSeedError(
      'No root seed configured: set SIGNER_ROOT_SEED_HEX or SIGNER_ROOT_SEED_FILE',
    )
  }

  if (fs.existsSync(file)) {
    const raw = fs.readFileSync(file)
    if (raw.length === ROOT_SEED_BYTES) return Buffer.from(raw)
    return parseHexSeed(raw.toString('utf8'), `seed file ${file}`)
  }

  if (env.SIGNER_ALLOW_DEV_SEED !== '1') {
    throw new RootSeedError(
      `Seed file ${file} does not exist and SIGNER_ALLOW_DEV_SEED is not set. ` +
        'Refusing to generate a seed implicitly — in production the seed must ' +
        'be provisioned by the TEE KMS.',
    )
  }

  const seed = crypto.randomBytes(ROOT_SEED_BYTES)
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, seed, { mode: 0o600 })
  return seed
}
