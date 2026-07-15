import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Server } from 'node:http'
import express from 'express'
import type { SignerClient, SignerClientOptions } from '@certified-app/shared'
import { setupTeeIntegration, type PdsLike } from '../tee/setup.js'
import { createUserDidVerifier } from '../tee/user-auth.js'

const logger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
}

function makeSignerStub(mode: 'dstack' | 'dev' = 'dev') {
  return {
    attestation: vi.fn(() =>
      Promise.resolve({
        mode,
        reportData: 'ab'.repeat(32),
        quote: mode === 'dstack' ? 'deadbeef' : null,
        identityPublicKeyHex: '02' + 'cd'.repeat(32),
      }),
    ),
    deriveKey: vi.fn(() =>
      Promise.resolve({ didKey: 'did:key:zQ3shAdopted', publicKeyHex: '02ab' }),
    ),
  }
}

function makePds(): PdsLike {
  return {
    app: express(),
    ctx: {
      actorStore: {
        getLocation: vi.fn(() =>
          Promise.resolve({ directory: '/tmp/nowhere' }),
        ),
        keypair: vi.fn(() => Promise.resolve({ local: true })),
      },
      plcClient: { updateAtprotoKey: vi.fn(() => Promise.resolve()) },
      plcRotationKey: {},
      sequencer: { sequenceIdentityEvt: vi.fn(() => Promise.resolve(1)) },
      authVerifier: {},
    },
  }
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('setupTeeIntegration', () => {
  it('is fully disabled without EPDS_SIGNER_URL', async () => {
    const tee = await setupTeeIntegration({ pds: makePds(), logger, env: {} })
    expect(tee.enabled).toBe(false)
    expect(tee.signer).toBeNull()
    expect(() => {
      tee.adoptOnSignup('did:plc:x')
    }).not.toThrow()
  })

  it('requires EPDS_SIGNER_SECRET when the URL is set', async () => {
    await expect(
      setupTeeIntegration({
        pds: makePds(),
        logger,
        env: { EPDS_SIGNER_URL: 'http://signer:3010' },
      }),
    ).rejects.toThrow(/EPDS_SIGNER_SECRET/)
  })

  it('refuses an unattested signer when attestation is required', async () => {
    const stub = makeSignerStub('dev')
    await expect(
      setupTeeIntegration({
        pds: makePds(),
        logger,
        env: {
          EPDS_SIGNER_URL: 'http://signer:3010',
          EPDS_SIGNER_SECRET: 's',
          EPDS_SIGNER_REQUIRE_ATTESTATION: '1',
        },
        signerFactory: () => stub as unknown as SignerClient,
      }),
    ).rejects.toThrow(/no hardware quote/)
  })

  it('accepts an attested signer when attestation is required', async () => {
    const stub = makeSignerStub('dstack')
    const tee = await setupTeeIntegration({
      pds: makePds(),
      logger,
      env: {
        EPDS_SIGNER_URL: 'http://signer:3010',
        EPDS_SIGNER_SECRET: 's',
        EPDS_SIGNER_REQUIRE_ATTESTATION: '1',
      },
      signerFactory: () => stub as unknown as SignerClient,
    })
    expect(tee.enabled).toBe(true)
  })

  it('warns (but proceeds) on an unattested signer in dev', async () => {
    const stub = makeSignerStub('dev')
    const tee = await setupTeeIntegration({
      pds: makePds(),
      logger,
      env: { EPDS_SIGNER_URL: 'http://signer:3010', EPDS_SIGNER_SECRET: 's' },
      signerFactory: () => stub as unknown as SignerClient,
    })
    expect(tee.enabled).toBe(true)
    expect(logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({ mode: 'dev' }),
      expect.stringContaining('UNATTESTED'),
    )
  })

  it('passes the base URL and secret to the signer factory', async () => {
    const stub = makeSignerStub()
    let seen: SignerClientOptions | undefined
    await setupTeeIntegration({
      pds: makePds(),
      logger,
      env: { EPDS_SIGNER_URL: 'http://signer:3010', EPDS_SIGNER_SECRET: 'sec' },
      signerFactory: (options) => {
        seen = options
        return stub as unknown as SignerClient
      },
    })
    expect(seen).toEqual({ baseUrl: 'http://signer:3010', secret: 'sec' })
  })

  it('keeps adoptOnSignup a noop without EPDS_TEE_REPO_SIGNING', async () => {
    const stub = makeSignerStub()
    const pds = makePds()
    const tee = await setupTeeIntegration({
      pds,
      logger,
      env: {
        EPDS_SIGNER_URL: 'http://signer:3010',
        EPDS_SIGNER_SECRET: 's',
        EPDS_TEE_ADOPT_ON_SIGNUP: '1',
      },
      signerFactory: () => stub as unknown as SignerClient,
    })
    tee.adoptOnSignup('did:plc:x')
    // eslint-disable-next-line @typescript-eslint/unbound-method -- vi.fn() method access for assertion, not a call
    expect(pds.ctx.plcClient.updateAtprotoKey).not.toHaveBeenCalled()
    expect(logger.warn).toHaveBeenCalledWith(
      expect.stringContaining('no effect without EPDS_TEE_REPO_SIGNING'),
    )
  })

  describe('with repo signing + wallet enabled', () => {
    const env = {
      EPDS_SIGNER_URL: 'http://signer:3010',
      EPDS_SIGNER_SECRET: 's',
      EPDS_TEE_REPO_SIGNING: '1',
      EPDS_TEE_ADOPT_ON_SIGNUP: '1',
      EPDS_WALLET_ENABLED: '1',
    }

    let pds: PdsLike
    let server: Server
    let base: string

    beforeEach(async () => {
      pds = makePds()
      await setupTeeIntegration({
        pds,
        logger,
        env,
        signerFactory: () => makeSignerStub() as unknown as SignerClient,
        userDidVerifier: () => Promise.resolve(null),
      })
      await new Promise<void>((resolve) => {
        server = pds.app.listen(0, () => {
          resolve()
        })
      })
      const address = server.address()
      if (typeof address === 'object' && address) {
        base = `http://127.0.0.1:${address.port}`
      }
    })

    afterEach(async () => {
      await new Promise<void>((resolve) => {
        server.close(() => {
          resolve()
        })
      })
    })

    it('patches actorStore.keypair', () => {
      // the patched function is a new assignment, not the original mock
      // eslint-disable-next-line @typescript-eslint/unbound-method -- vi.fn() method access for assertion, not a call
      expect(vi.isMockFunction(pds.ctx.actorStore.keypair)).toBe(false)
    })

    it('mounts /wallet routes (401 without auth)', async () => {
      const res = await fetch(`${base}/wallet/info`)
      expect(res.status).toBe(401)
    })

    it('gates /_internal/tee/adopt on the internal secret', async () => {
      const res = await fetch(`${base}/_internal/tee/adopt`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ did: 'did:plc:x' }),
      })
      expect(res.status).toBe(401)
    })

    it('validates the did on /_internal/tee/adopt', async () => {
      const original = process.env.EPDS_INTERNAL_SECRET
      process.env.EPDS_INTERNAL_SECRET = 'internal-secret'
      try {
        const res = await fetch(`${base}/_internal/tee/adopt`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-internal-secret': 'internal-secret',
          },
          body: JSON.stringify({ did: 'garbage' }),
        })
        expect(res.status).toBe(400)
      } finally {
        if (original === undefined) delete process.env.EPDS_INTERNAL_SECRET
        else process.env.EPDS_INTERNAL_SECRET = original
      }
    })
  })
})

describe('createUserDidVerifier', () => {
  const req = {} as never
  const res = {} as never

  it('returns the did from the verifier credentials', async () => {
    const pds = {
      ctx: {
        authVerifier: {
          authorization: () => () =>
            Promise.resolve({ credentials: { did: 'did:plc:me' } }),
        },
      },
    }
    const verify = createUserDidVerifier(pds, logger)
    await expect(verify(req, res)).resolves.toBe('did:plc:me')
  })

  it('returns null when verification throws', async () => {
    const pds = {
      ctx: {
        authVerifier: {
          authorization: () => () => Promise.reject(new Error('bad token')),
        },
      },
    }
    const verify = createUserDidVerifier(pds, logger)
    await expect(verify(req, res)).resolves.toBeNull()
    expect(logger.debug).toHaveBeenCalled()
  })

  it('returns null for non-string dids', async () => {
    const pds = {
      ctx: {
        authVerifier: {
          authorization: () => () => Promise.resolve({ credentials: {} }),
        },
      },
    }
    const verify = createUserDidVerifier(pds, logger)
    await expect(verify(req, res)).resolves.toBeNull()
  })
})
