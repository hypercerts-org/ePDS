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
  createWalletRouter,
  isCompressedP256Hex,
  isEnvelopeField,
  sendSignerError,
} from '../tee/wallet-router.js'

const logger = { info: vi.fn(), warn: vi.fn() }

const signerStub = {
  walletEnroll: vi.fn(),
  walletEnrollment: vi.fn(),
  walletSign: vi.fn(),
  deriveKey: vi.fn(),
}

let authedDid: string | null = 'did:plc:walletuser'
let server: Server
let base: string

beforeAll(async () => {
  const app = express()
  app.use(
    '/wallet',
    createWalletRouter({
      signer: signerStub as unknown as SignerClient,
      verifyUserDid: () => Promise.resolve(authedDid),
      logger,
    }),
  )
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

describe('GET /wallet/info', () => {
  it('requires authentication', async () => {
    authedDid = null
    const res = await fetch(`${base}/wallet/info`)
    expect(res.status).toBe(401)
  })

  it('returns both wallet addresses and enrollment state', async () => {
    signerStub.deriveKey.mockImplementation((_did: string, purpose: string) =>
      Promise.resolve(
        purpose === 'wallet/evm'
          ? { address: '0xEvm', publicKeyHex: '02aa' }
          : { address: 'SoLAddr', publicKeyHex: 'bb' },
      ),
    )
    signerStub.walletEnrollment.mockResolvedValue({ enrolled: true })

    const res = await fetch(`${base}/wallet/info`)
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({
      did: 'did:plc:walletuser',
      enrolled: true,
      evm: { address: '0xEvm', publicKeyHex: '02aa' },
      sol: { address: 'SoLAddr', publicKeyHex: 'bb' },
    })
  })

  it('maps signer outages to 502', async () => {
    signerStub.deriveKey.mockRejectedValue(new Error('ECONNREFUSED'))
    signerStub.walletEnrollment.mockRejectedValue(new Error('ECONNREFUSED'))
    const res = await fetch(`${base}/wallet/info`)
    expect(res.status).toBe(502)
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
