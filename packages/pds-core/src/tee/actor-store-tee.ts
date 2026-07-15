/**
 * TEE repo signing — actor-store integration and account adoption.
 *
 * The stock `@atproto/pds` ActorStore creates a per-account signing
 * keypair on disk and reads it back for every repo write. There is no
 * config hook to change that, so we patch the single seam every write
 * path goes through — `actorStore.keypair(did)` — on the live instance:
 *
 *   - If the actor's directory contains a `tee.json` marker, the actor
 *     has been adopted into the TEE: return a TeeKeypair that delegates
 *     signing to the enclave.
 *   - Otherwise fall back to the original loader (local key file). The
 *     normal ATProto read/write path is untouched for those accounts.
 *
 * Adoption (`adoptAccountIntoTee`) is the migration step that moves an
 * account's repo signing into the enclave:
 *
 *   1. Ask the signer to derive the account's `atproto/signing` key and
 *      return its did:key.
 *   2. Publish a PLC operation rotating the DID document's `#atproto`
 *      verification method to that did:key. The op is signed by the
 *      PLC rotation key, which never touches the signer — rotation
 *      authority and signing authority stay separate (see threat model).
 *   3. Only after PLC accepts the op, write the `tee.json` marker so
 *      subsequent commits are signed in the enclave.
 *   4. Sequence an identity event so relays pick up the new key.
 *
 * The old local key file is intentionally left in place (adoption-time
 * rollback = delete the marker + rotate PLC back). Adoption is
 * idempotent: an existing marker short-circuits.
 */
import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import type { SignerClient } from '@certified-app/shared'
import { TeeKeypair } from './tee-keypair.js'

export const TEE_MARKER_FILENAME = 'tee.json'

export interface TeeMarker {
  v: 1
  keyDid: string
  adoptedAt: string
}

/** The slice of ActorStore this module needs (structural — avoids deep imports). */
export interface ActorStoreLike {
  getLocation(did: string): Promise<{ directory: string }>
  keypair(did: string): Promise<unknown>
}

/** The slice of `pds.ctx` adoption needs. */
export interface AdoptionCtx {
  actorStore: ActorStoreLike
  plcClient: {
    updateAtprotoKey(
      did: string,
      signer: unknown,
      atprotoKey: string,
    ): Promise<void>
  }
  plcRotationKey: unknown
  sequencer: {
    sequenceIdentityEvt(did: string, handle?: string): Promise<number>
  }
}

interface LoggerLike {
  info: (obj: unknown, msg?: string) => void
  warn: (obj: unknown, msg?: string) => void
  error: (obj: unknown, msg?: string) => void
}

export async function readTeeMarker(
  directory: string,
): Promise<TeeMarker | null> {
  try {
    const raw = await fs.readFile(
      path.join(directory, TEE_MARKER_FILENAME),
      'utf8',
    )
    const parsed: unknown = JSON.parse(raw)
    if (typeof parsed !== 'object' || parsed === null) return null
    const candidate = parsed as Record<string, unknown>
    if (candidate.v === 1 && typeof candidate.keyDid === 'string') {
      return parsed as TeeMarker
    }
    return null
  } catch {
    return null
  }
}

export async function writeTeeMarker(
  directory: string,
  marker: TeeMarker,
): Promise<void> {
  await fs.writeFile(
    path.join(directory, TEE_MARKER_FILENAME),
    JSON.stringify(marker),
    { mode: 0o600 },
  )
}

/**
 * Patch `actorStore.keypair` on the live instance so TEE-adopted actors
 * sign in the enclave and everyone else keeps the stock local-key path.
 */
export function installTeeRepoSigning(opts: {
  actorStore: ActorStoreLike
  signer: SignerClient
  logger: LoggerLike
}): void {
  const { actorStore, signer, logger } = opts
  const originalKeypair = actorStore.keypair.bind(actorStore)

  actorStore.keypair = async (did: string) => {
    const { directory } = await actorStore.getLocation(did)
    const marker = await readTeeMarker(directory)
    if (marker) {
      return new TeeKeypair(did, marker.keyDid, signer)
    }
    return originalKeypair(did)
  }

  logger.info(
    'TEE repo signing installed: actorStore.keypair patched (marker-gated)',
  )
}

/**
 * Adopt an account into the TEE: rotate its `#atproto` key to the
 * enclave-derived key via PLC, then persist the marker. Idempotent.
 */
export async function adoptAccountIntoTee(opts: {
  ctx: AdoptionCtx
  signer: SignerClient
  did: string
  logger: LoggerLike
}): Promise<TeeMarker> {
  const { ctx, signer, did, logger } = opts

  const { directory } = await ctx.actorStore.getLocation(did)
  const existing = await readTeeMarker(directory)
  if (existing) {
    return existing
  }

  const keyInfo = await signer.deriveKey(did, 'atproto/signing')
  if (!keyInfo.didKey) {
    throw new Error(`signer returned no didKey for ${did}`)
  }

  // Rotate the DID document's signing key. Signed by the PLC rotation
  // key — the recoverable authority the signer never holds.
  await ctx.plcClient.updateAtprotoKey(did, ctx.plcRotationKey, keyInfo.didKey)

  const marker: TeeMarker = {
    v: 1,
    keyDid: keyInfo.didKey,
    adoptedAt: new Date().toISOString(),
  }
  // Marker is written only after PLC accepted the rotation — a failed
  // rotation must never leave the actor signing with a key that isn't
  // in its DID document.
  await writeTeeMarker(directory, marker)

  try {
    await ctx.sequencer.sequenceIdentityEvt(did)
  } catch (err) {
    // Non-fatal: the PLC op is authoritative; relays will converge.
    logger.warn(
      { err, did },
      'failed to sequence identity event after TEE adoption',
    )
  }

  logger.info(
    { did, keyDid: keyInfo.didKey },
    'account adopted into TEE signing',
  )
  return marker
}
