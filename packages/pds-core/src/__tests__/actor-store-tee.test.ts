import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import type { SignerClient } from '@certified-app/shared'
import {
  TEE_MARKER_FILENAME,
  adoptAccountIntoTee,
  installTeeRepoSigning,
  readTeeMarker,
  writeTeeMarker,
  type ActorStoreLike,
  type AdoptionCtx,
} from '../tee/actor-store-tee.js'
import { TeeKeypair } from '../tee/tee-keypair.js'

const KEY_DID = 'did:key:zQ3shEnclaveKey'
const logger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
}

let dir: string

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'epds-tee-test-'))
  vi.clearAllMocks()
})

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true })
})

function makeActorStore(): ActorStoreLike & {
  keypair: ReturnType<typeof vi.fn>
} {
  return {
    getLocation: (did: string) => {
      const directory = path.join(dir, did.replaceAll(':', '_'))
      fs.mkdirSync(directory, { recursive: true })
      return Promise.resolve({ directory })
    },
    keypair: vi.fn(() => Promise.resolve({ local: true })),
  }
}

function makeSigner(): SignerClient {
  return {
    deriveKey: vi.fn(() =>
      Promise.resolve({
        keyId: 'did:plc:a#atproto/signing',
        purpose: 'atproto/signing',
        curve: 'secp256k1',
        publicKeyHex: '02ab',
        didKey: KEY_DID,
      }),
    ),
  } as unknown as SignerClient
}

describe('TEE marker read/write', () => {
  it('round-trips a marker', async () => {
    const marker = {
      v: 1 as const,
      keyDid: KEY_DID,
      adoptedAt: '2026-07-15T00:00:00Z',
    }
    await writeTeeMarker(dir, marker)
    await expect(readTeeMarker(dir)).resolves.toEqual(marker)
  })

  it('returns null for a missing or malformed marker', async () => {
    await expect(readTeeMarker(dir)).resolves.toBeNull()
    fs.writeFileSync(path.join(dir, TEE_MARKER_FILENAME), 'not json')
    await expect(readTeeMarker(dir)).resolves.toBeNull()
    fs.writeFileSync(
      path.join(dir, TEE_MARKER_FILENAME),
      JSON.stringify({ v: 2 }),
    )
    await expect(readTeeMarker(dir)).resolves.toBeNull()
  })
})

describe('installTeeRepoSigning', () => {
  it('returns a TeeKeypair for adopted actors', async () => {
    const actorStore = makeActorStore()
    installTeeRepoSigning({ actorStore, signer: makeSigner(), logger })

    const { directory } = await actorStore.getLocation('did:plc:adopted')
    await writeTeeMarker(directory, {
      v: 1,
      keyDid: KEY_DID,
      adoptedAt: new Date().toISOString(),
    })

    const kp = await actorStore.keypair('did:plc:adopted')
    expect(kp).toBeInstanceOf(TeeKeypair)
    expect((kp as TeeKeypair).did()).toBe(KEY_DID)
  })

  it('falls back to the original loader for non-adopted actors', async () => {
    const actorStore = makeActorStore()
    const original = actorStore.keypair
    installTeeRepoSigning({ actorStore, signer: makeSigner(), logger })

    const kp = await actorStore.keypair('did:plc:legacy')
    expect(kp).toEqual({ local: true })
    expect(original).toHaveBeenCalledWith('did:plc:legacy')
  })
})

describe('adoptAccountIntoTee', () => {
  function makeCtx(actorStore: ActorStoreLike): AdoptionCtx & {
    plcClient: { updateAtprotoKey: ReturnType<typeof vi.fn> }
    sequencer: { sequenceIdentityEvt: ReturnType<typeof vi.fn> }
  } {
    return {
      actorStore,
      plcClient: {
        updateAtprotoKey: vi.fn(() => Promise.resolve()),
      },
      plcRotationKey: { rotation: true },
      sequencer: { sequenceIdentityEvt: vi.fn(() => Promise.resolve(1)) },
    }
  }

  it('rotates the PLC key, writes the marker, and sequences identity', async () => {
    const actorStore = makeActorStore()
    const ctx = makeCtx(actorStore)
    const marker = await adoptAccountIntoTee({
      ctx,
      signer: makeSigner(),
      did: 'did:plc:newbie',
      logger,
    })

    expect(marker.keyDid).toBe(KEY_DID)
    expect(ctx.plcClient.updateAtprotoKey).toHaveBeenCalledExactlyOnceWith(
      'did:plc:newbie',
      { rotation: true },
      KEY_DID,
    )
    expect(ctx.sequencer.sequenceIdentityEvt).toHaveBeenCalledWith(
      'did:plc:newbie',
    )

    const { directory } = await actorStore.getLocation('did:plc:newbie')
    await expect(readTeeMarker(directory)).resolves.toEqual(marker)
  })

  it('is idempotent — an existing marker short-circuits', async () => {
    const actorStore = makeActorStore()
    const ctx = makeCtx(actorStore)
    const signer = makeSigner()

    const first = await adoptAccountIntoTee({
      ctx,
      signer,
      did: 'did:plc:x',
      logger,
    })
    const second = await adoptAccountIntoTee({
      ctx,
      signer,
      did: 'did:plc:x',
      logger,
    })
    expect(second).toEqual(first)
    expect(ctx.plcClient.updateAtprotoKey).toHaveBeenCalledTimes(1)
  })

  it('does NOT write the marker when the PLC rotation fails', async () => {
    const actorStore = makeActorStore()
    const ctx = makeCtx(actorStore)
    ctx.plcClient.updateAtprotoKey.mockImplementation(() =>
      Promise.reject(new Error('plc down')),
    )

    await expect(
      adoptAccountIntoTee({
        ctx,
        signer: makeSigner(),
        did: 'did:plc:y',
        logger,
      }),
    ).rejects.toThrow('plc down')

    const { directory } = await actorStore.getLocation('did:plc:y')
    await expect(readTeeMarker(directory)).resolves.toBeNull()
  })

  it('throws when the signer returns no didKey', async () => {
    const actorStore = makeActorStore()
    const ctx = makeCtx(actorStore)
    const signer = {
      deriveKey: vi.fn(() => Promise.resolve({ publicKeyHex: '02ab' })),
    } as unknown as SignerClient

    await expect(
      adoptAccountIntoTee({ ctx, signer, did: 'did:plc:z', logger }),
    ).rejects.toThrow(/no didKey/)
    expect(ctx.plcClient.updateAtprotoKey).not.toHaveBeenCalled()
  })

  it('treats a sequencer failure as non-fatal', async () => {
    const actorStore = makeActorStore()
    const ctx = makeCtx(actorStore)
    ctx.sequencer.sequenceIdentityEvt.mockImplementation(() =>
      Promise.reject(new Error('sequencer sad')),
    )

    const marker = await adoptAccountIntoTee({
      ctx,
      signer: makeSigner(),
      did: 'did:plc:w',
      logger,
    })
    expect(marker.keyDid).toBe(KEY_DID)
    expect(logger.warn).toHaveBeenCalled()
  })
})
