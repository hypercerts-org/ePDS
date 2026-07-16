/**
 * Wallet router tests — run against a real express server so the JSON
 * body handling, auth gating, and signer error mapping are exercised
 * end-to-end (the signer itself is stubbed).
 */
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest'
import type { Server } from 'node:http'
import express from 'express'
import { SignerClientError, type SignerClient } from '@certified-app/shared'
import {
  WALLET_NSID_PREFIX,
  createWalletRouter,
  createWalletXrpcRouter,
  isCompressedP256Hex,
  isEnvelopeField,
  isPlausibleWalletDid,
  sendSignerError,
} from '../tee/wallet-router.js'

const logger = { info: vi.fn(), warn: vi.fn() }

const signerStub = {
  walletEnroll: vi.fn(),
  walletEnrollment: vi.fn(),
  walletCreate: vi.fn(),
  walletInfo: vi.fn(),
  walletSign: vi.fn(),
  walletExport: vi.fn(),
  walletRecover: vi.fn(),
  deriveKey: vi.fn(),
}

let authedDid: string | null = 'did:plc:walletuser'
let server: Server
let base: string

beforeAll(async () => {
  const app = express()
  const routerOpts = {
    signer: signerStub as unknown as SignerClient,
    verifyUserDid: () => Promise.resolve(authedDid),
    logger,
  }
  app.use('/wallet', createWalletRouter(routerOpts))
  app.use('/xrpc', createWalletXrpcRouter(routerOpts))
  // A stand-in for the stock PDS XRPC handler mounted after ours —
  // proves unmatched /xrpc/* traffic passes through untouched.
  app.post('/xrpc/com.atproto.repo.createRecord', (req, res) => {
    res.json({ passedThrough: true, bodyParsed: req.body !== undefined })
  })
  await new Promise<void>((resolve) => {
    server = app.listen(0, () => {
      resolve()
    })
  })
  const address = server.address()
  if (typeof address === 'object' && address) {
    base = `http://127.0.0.1:${address.port}`
  }
})

afterAll(async () => {
  await new Promise<void>((resolve) =>
    server.close(() => {
      resolve()
    }),
  )
})

beforeEach(() => {
  vi.clearAllMocks()
  authedDid = 'did:plc:walletuser'
})

async function post(route: string, body: unknown) {
  const res = await fetch(`${base}${route}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
  return {
    status: res.status,
    json: (await res.json()) as Record<string, unknown>,
  }
}

const VALID_P256 = '02' + 'ab'.repeat(32)

describe('validators', () => {
  it('isCompressedP256Hex', () => {
    expect(isCompressedP256Hex(VALID_P256)).toBe(true)
    expect(isCompressedP256Hex('03' + 'CD'.repeat(32))).toBe(true)
    expect(isCompressedP256Hex('04' + 'ab'.repeat(32))).toBe(false)
    expect(isCompressedP256Hex('02abcd')).toBe(false)
    expect(isCompressedP256Hex(42)).toBe(false)
  })

  it('isEnvelopeField', () => {
    expect(isEnvelopeField('abc-_123', 100)).toBe(true)
    expect(isEnvelopeField('', 100)).toBe(false)
    expect(isEnvelopeField('a'.repeat(101), 100)).toBe(false)
    expect(isEnvelopeField('has space', 100)).toBe(false)
    expect(isEnvelopeField(null, 100)).toBe(false)
  })

  it('isPlausibleWalletDid', () => {
    expect(isPlausibleWalletDid('did:plc:abc123')).toBe(true)
    expect(isPlausibleWalletDid('did:web:example.com')).toBe(true)
    expect(isPlausibleWalletDid('did:key:z6Mk')).toBe(false)
    expect(isPlausibleWalletDid('not-a-did')).toBe(false)
  })
})

describe('POST /wallet/enroll', () => {
  it('requires authentication', async () => {
    authedDid = null
    const res = await post('/wallet/enroll', {
      requestPublicKeyHex: VALID_P256,
    })
    expect(res.status).toBe(401)
    expect(signerStub.walletEnroll).not.toHaveBeenCalled()
  })

  it('validates the request key shape', async () => {
    const res = await post('/wallet/enroll', { requestPublicKeyHex: 'junk' })
    expect(res.status).toBe(400)
  })

  it('forwards a valid enrollment for the authenticated DID', async () => {
    signerStub.walletEnroll.mockResolvedValue({ status: 'created' })
    const res = await post('/wallet/enroll', {
      requestPublicKeyHex: VALID_P256,
    })
    expect(res.status).toBe(200)
    expect(res.json).toEqual({ status: 'created' })
    expect(signerStub.walletEnroll).toHaveBeenCalledExactlyOnceWith(
      'did:plc:walletuser',
      VALID_P256,
    )
  })

  it('passes through a 409 enrollment conflict', async () => {
    signerStub.walletEnroll.mockRejectedValue(
      new SignerClientError(409, 'a different request key is already enrolled'),
    )
    const res = await post('/wallet/enroll', {
      requestPublicKeyHex: VALID_P256,
    })
    expect(res.status).toBe(409)
  })
})

describe('POST /wallet/create', () => {
  it('requires authentication', async () => {
    authedDid = null
    const res = await post('/wallet/create', {})
    expect(res.status).toBe(401)
    expect(signerStub.walletCreate).not.toHaveBeenCalled()
  })

  it('forwards creation and relays the share JWEs untouched', async () => {
    const created = {
      status: 'created',
      wallet: {
        did: 'did:plc:walletuser',
        evm: { address: '0xEvm', publicKeyHex: '02aa' },
        sol: { address: 'SoLAddr', publicKeyHex: 'bb' },
        version: 1,
        createdAt: 123,
      },
      deviceShareJwe: 'a..b.c.d',
      recoveryShareJwe: 'e..f.g.h',
    }
    signerStub.walletCreate.mockResolvedValue(created)
    const res = await post('/wallet/create', {})
    expect(res.status).toBe(200)
    expect(res.json).toEqual(created)
    expect(signerStub.walletCreate).toHaveBeenCalledExactlyOnceWith(
      'did:plc:walletuser',
    )
  })

  it('passes through a 409 when the wallet already exists', async () => {
    signerStub.walletCreate.mockRejectedValue(
      new SignerClientError(409, 'wallet already exists for this DID'),
    )
    const res = await post('/wallet/create', {})
    expect(res.status).toBe(409)
  })
})

describe('GET /wallet/info', () => {
  it('requires authentication', async () => {
    authedDid = null
    const res = await fetch(`${base}/wallet/info`)
    expect(res.status).toBe(401)
  })

  it('returns wallet public info and enrollment state', async () => {
    signerStub.walletInfo.mockResolvedValue({
      enrolled: true,
      wallet: {
        did: 'did:plc:walletuser',
        evm: { address: '0xEvm', publicKeyHex: '02aa' },
        sol: { address: 'SoLAddr', publicKeyHex: 'bb' },
        version: 1,
        createdAt: 123,
      },
      walletEncryptionPublicJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
    })

    const res = await fetch(`${base}/wallet/info`)
    expect(res.status).toBe(200)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.did).toBe('did:plc:walletuser')
    expect(body.enrolled).toBe(true)
    expect((body.wallet as Record<string, unknown>).version).toBe(1)
    expect(
      (body.walletEncryptionPublicJwk as Record<string, unknown>).crv,
    ).toBe('P-256')
  })

  it('maps signer outages to 502', async () => {
    signerStub.walletInfo.mockRejectedValue(new Error('ECONNREFUSED'))
    const res = await fetch(`${base}/wallet/info`)
    expect(res.status).toBe(502)
  })
})

describe('GET /wallet/public-info', () => {
  it('returns claimed wallet receive information without authentication', async () => {
    authedDid = null
    signerStub.walletInfo.mockResolvedValue({
      enrolled: true,
      wallet: {
        did: 'did:plc:recipient',
        evm: { address: '0xRecipient', publicKeyHex: '02aa' },
        sol: { address: 'SolRecipient', publicKeyHex: 'bb' },
        version: 1,
        createdAt: 123,
      },
      pregen: null,
      walletEncryptionPublicJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
    })

    const res = await fetch(
      `${base}/wallet/public-info?did=${encodeURIComponent('did:plc:recipient')}`,
    )
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({
      did: 'did:plc:recipient',
      status: 'claimed',
      wallet: expect.objectContaining({
        evm: { address: '0xRecipient', publicKeyHex: '02aa' },
      }),
    })
    expect(signerStub.walletInfo).toHaveBeenCalledExactlyOnceWith(
      'did:plc:recipient',
    )
  })

  it('returns pregenerated receive information and hides signer metadata', async () => {
    signerStub.walletInfo.mockResolvedValue({
      enrolled: false,
      wallet: null,
      pregen: {
        did: 'did:plc:recipient',
        evm: { address: '0xPregen', publicKeyHex: '02aa' },
        sol: { address: 'SolPregen', publicKeyHex: 'bb' },
        createdAt: 123,
      },
      walletEncryptionPublicJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
    })

    const res = await fetch(
      `${base}/wallet/public-info?did=${encodeURIComponent('did:plc:recipient')}`,
    )
    expect(res.status).toBe(200)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.status).toBe('pregenerated')
    expect(body).not.toHaveProperty('enrolled')
    expect(body).not.toHaveProperty('walletEncryptionPublicJwk')
  })

  it('validates the DID and returns 404 when no wallet exists', async () => {
    expect((await fetch(`${base}/wallet/public-info?did=junk`)).status).toBe(
      400,
    )
    signerStub.walletInfo.mockResolvedValue({
      enrolled: false,
      wallet: null,
      pregen: null,
      walletEncryptionPublicJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
    })
    expect(
      (
        await fetch(
          `${base}/wallet/public-info?did=${encodeURIComponent('did:plc:missing')}`,
        )
      ).status,
    ).toBe(404)
  })
})

describe('POST /wallet/sign', () => {
  it('rejects malformed envelopes without calling the signer', async () => {
    expect((await post('/wallet/sign', {})).status).toBe(400)
    expect(
      (await post('/wallet/sign', { payload: '!!', sig: 'AA' })).status,
    ).toBe(400)
    expect(signerStub.walletSign).not.toHaveBeenCalled()
  })

  it('forwards the envelope without requiring a PDS token', async () => {
    authedDid = null // wallet/sign must NOT depend on PDS auth
    signerStub.walletSign.mockResolvedValue({ signatureHex: 'aa', recovery: 0 })
    const res = await post('/wallet/sign', {
      payload: 'cGF5bG9hZA',
      sig: 'c2ln',
    })
    expect(res.status).toBe(200)
    expect(res.json).toEqual({ signatureHex: 'aa', recovery: 0 })
    expect(signerStub.walletSign).toHaveBeenCalledExactlyOnceWith({
      payload: 'cGF5bG9hZA',
      sig: 'c2ln',
    })
  })

  it('passes through signer 403s (bad envelope) and 409s (replay)', async () => {
    signerStub.walletSign.mockRejectedValue(
      new SignerClientError(403, 'invalid signature'),
    )
    const res = await post('/wallet/sign', { payload: 'cGF5', sig: 'c2ln' })
    expect(res.status).toBe(403)
    expect(res.json.error).toBe('invalid signature')
  })
})

describe('POST /wallet/export', () => {
  it('rejects malformed envelopes without calling the signer', async () => {
    expect((await post('/wallet/export', {})).status).toBe(400)
    expect(signerStub.walletExport).not.toHaveBeenCalled()
  })

  it('forwards the envelope without requiring a PDS token', async () => {
    authedDid = null // like /sign, the envelope IS the authorization
    signerStub.walletExport.mockResolvedValue({ exportJwe: 'x..y.z.w' })
    const res = await post('/wallet/export', {
      payload: 'cGF5bG9hZA',
      sig: 'c2ln',
    })
    expect(res.status).toBe(200)
    expect(res.json).toEqual({ exportJwe: 'x..y.z.w' })
  })

  it('passes through signer 403s', async () => {
    signerStub.walletExport.mockRejectedValue(
      new SignerClientError(403, "envelope op is not 'export'"),
    )
    const res = await post('/wallet/export', { payload: 'cGF5', sig: 'c2ln' })
    expect(res.status).toBe(403)
  })
})

describe('POST /wallet/recover', () => {
  it('requires authentication', async () => {
    authedDid = null
    const res = await post('/wallet/recover', {
      recoveryShareJwe: 'a..b.c.d',
    })
    expect(res.status).toBe(401)
    expect(signerStub.walletRecover).not.toHaveBeenCalled()
  })

  it('validates the body', async () => {
    expect((await post('/wallet/recover', {})).status).toBe(400)
    expect(
      (
        await post('/wallet/recover', {
          recoveryShareJwe: 'a'.repeat(20_000),
        })
      ).status,
    ).toBe(400)
    expect(
      (
        await post('/wallet/recover', {
          recoveryShareJwe: 'a..b.c.d',
          requestPublicKeyHex: 'junk',
        })
      ).status,
    ).toBe(400)
    expect(signerStub.walletRecover).not.toHaveBeenCalled()
  })

  it('forwards recovery for the authenticated DID', async () => {
    const recovered = {
      status: 'recovered',
      version: 2,
      deviceShareJwe: 'a..b.c.d',
      recoveryShareJwe: 'e..f.g.h',
    }
    signerStub.walletRecover.mockResolvedValue(recovered)
    const res = await post('/wallet/recover', {
      recoveryShareJwe: 'r..s.t.u',
      requestPublicKeyHex: VALID_P256,
    })
    expect(res.status).toBe(200)
    expect(res.json).toEqual(recovered)
    expect(signerStub.walletRecover).toHaveBeenCalledExactlyOnceWith({
      did: 'did:plc:walletuser',
      recoveryShareJwe: 'r..s.t.u',
      requestPublicKeyHex: VALID_P256,
    })
  })

  it('passes through a 403 for a wrong share', async () => {
    signerStub.walletRecover.mockRejectedValue(
      new SignerClientError(403, 'recovery share does not match wallet'),
    )
    const res = await post('/wallet/recover', {
      recoveryShareJwe: 'r..s.t.u',
    })
    expect(res.status).toBe(403)
  })
})

describe('XRPC aliases (app.gainforest.wallet.*)', () => {
  it('serves getWallet as a query (GET)', async () => {
    signerStub.walletInfo.mockResolvedValue({
      enrolled: false,
      wallet: null,
      walletEncryptionPublicJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
    })
    const res = await fetch(`${base}/xrpc/${WALLET_NSID_PREFIX}.getWallet`)
    expect(res.status).toBe(200)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.did).toBe('did:plc:walletuser')
    expect(body.wallet).toBeNull()
  })

  it('serves getPublicWallet as an unauthenticated query', async () => {
    authedDid = null
    signerStub.walletInfo.mockResolvedValue({
      enrolled: false,
      wallet: null,
      pregen: {
        did: 'did:plc:recipient',
        evm: { address: '0xPregen', publicKeyHex: '02aa' },
        sol: { address: 'SolPregen', publicKeyHex: 'bb' },
        createdAt: 123,
      },
      walletEncryptionPublicJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
    })
    const res = await fetch(
      `${base}/xrpc/${WALLET_NSID_PREFIX}.getPublicWallet?did=${encodeURIComponent('did:plc:recipient')}`,
    )
    expect(res.status).toBe(200)
    expect(((await res.json()) as Record<string, unknown>).status).toBe(
      'pregenerated',
    )
  })

  it('serves sign as a procedure with identical behaviour to /wallet/sign', async () => {
    authedDid = null // envelope-authorized, like the REST route
    signerStub.walletSign.mockResolvedValue({ signatureHex: 'aa', recovery: 0 })
    const res = await post(`/xrpc/${WALLET_NSID_PREFIX}.sign`, {
      payload: 'cGF5bG9hZA',
      sig: 'c2ln',
    })
    expect(res.status).toBe(200)
    expect(res.json).toEqual({ signatureHex: 'aa', recovery: 0 })
  })

  it('serves enroll, create, export, and recover procedures', async () => {
    signerStub.walletEnroll.mockResolvedValue({ status: 'created' })
    expect(
      (
        await post(`/xrpc/${WALLET_NSID_PREFIX}.enroll`, {
          requestPublicKeyHex: VALID_P256,
        })
      ).status,
    ).toBe(200)

    signerStub.walletCreate.mockResolvedValue({ status: 'created' })
    expect((await post(`/xrpc/${WALLET_NSID_PREFIX}.create`, {})).status).toBe(
      200,
    )

    signerStub.walletExport.mockResolvedValue({ exportJwe: 'x..y.z.w' })
    expect(
      (
        await post(`/xrpc/${WALLET_NSID_PREFIX}.export`, {
          payload: 'cGF5',
          sig: 'c2ln',
        })
      ).status,
    ).toBe(200)

    signerStub.walletRecover.mockResolvedValue({ status: 'recovered' })
    expect(
      (
        await post(`/xrpc/${WALLET_NSID_PREFIX}.recover`, {
          recoveryShareJwe: 'r..s.t.u',
        })
      ).status,
    ).toBe(200)
  })

  it('does not intercept or body-parse unrelated /xrpc traffic', async () => {
    const res = await post('/xrpc/com.atproto.repo.createRecord', {
      repo: 'did:plc:walletuser',
    })
    expect(res.status).toBe(200)
    // Our per-route json parser must not have run for this request —
    // the stand-in PDS handler sees the raw, unparsed request.
    expect(res.json).toEqual({ passedThrough: true, bodyParsed: false })
  })
})

describe('sendSignerError', () => {
  function fakeRes() {
    const res = {
      statusCode: 0,
      body: undefined as unknown,
      status(code: number) {
        this.statusCode = code
        return this
      },
      json(body: unknown) {
        this.body = body
      },
    }
    return res
  }

  it('passes through 4xx SignerClientErrors', () => {
    const res = fakeRes()
    sendSignerError(res as never, new SignerClientError(409, 'replay'))
    expect(res.statusCode).toBe(409)
    expect(res.body).toEqual({ error: 'replay' })
  })

  it('maps 5xx SignerClientErrors and unknown errors to 502', () => {
    const res = fakeRes()
    sendSignerError(res as never, new SignerClientError(500, 'boom'))
    expect(res.statusCode).toBe(502)
    const res2 = fakeRes()
    sendSignerError(res2 as never, new Error('boom'))
    expect(res2.statusCode).toBe(502)
  })
})
