import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { SignerClient, SignerClientError } from '../signer-client.js'

const originalFetch = globalThis.fetch

function mockFetchOnce(
  status: number,
  body: unknown,
): ReturnType<typeof vi.fn> {
  const mock = vi.fn((_url: string | URL | Request, _init?: RequestInit) =>
    Promise.resolve(
      new Response(JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json' },
      }),
    ),
  )
  globalThis.fetch = mock as unknown as typeof fetch
  return mock
}

let client: SignerClient

beforeEach(() => {
  client = new SignerClient({
    baseUrl: 'http://signer.internal:3010/',
    secret: 's3cret',
  })
})

afterEach(() => {
  globalThis.fetch = originalFetch
  vi.restoreAllMocks()
})

describe('SignerClient', () => {
  it('strips trailing slashes and sends the internal secret', async () => {
    const mock = mockFetchOnce(200, { status: 'ok', service: 'epds-signer' })
    await client.health()
    const [url, init] = mock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('http://signer.internal:3010/health')
    expect((init.headers as Record<string, string>)['x-internal-secret']).toBe(
      's3cret',
    )
  })

  it('deriveKey posts did and purpose', async () => {
    const mock = mockFetchOnce(200, {
      keyId: 'did:plc:x#atproto/signing',
      purpose: 'atproto/signing',
      curve: 'secp256k1',
      publicKeyHex: '02ab',
      didKey: 'did:key:zQ3s',
    })
    const info = await client.deriveKey('did:plc:x', 'atproto/signing')
    expect(info.didKey).toBe('did:key:zQ3s')
    const [url, init] = mock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('http://signer.internal:3010/v1/keys/derive')
    expect(JSON.parse(init.body as string)).toEqual({
      did: 'did:plc:x',
      purpose: 'atproto/signing',
    })
  })

  it('signRepoDigest decodes the signature hex to bytes', async () => {
    mockFetchOnce(200, { signatureHex: 'aabb' })
    const sig = await client.signRepoDigest('did:plc:x', 'cd'.repeat(32))
    expect(Buffer.from(sig).toString('hex')).toBe('aabb')
  })

  it('walletSign forwards the envelope untouched', async () => {
    const mock = mockFetchOnce(200, { signatureHex: '00', recovery: 1 })
    const result = await client.walletSign({ payload: 'cGF5', sig: 'c2ln' })
    expect(result.recovery).toBe(1)
    const [, init] = mock.mock.calls[0] as [string, RequestInit]
    expect(JSON.parse(init.body as string)).toEqual({
      payload: 'cGF5',
      sig: 'c2ln',
    })
  })

  it('walletEnrollment URL-encodes the did', async () => {
    const mock = mockFetchOnce(200, { enrolled: false })
    await client.walletEnrollment('did:plc:abc')
    const [url] = mock.mock.calls[0] as [string]
    expect(url).toBe(
      'http://signer.internal:3010/v1/wallet/enrollment/did%3Aplc%3Aabc',
    )
  })

  it('walletCreate posts the did and returns share JWEs verbatim', async () => {
    const mock = mockFetchOnce(200, {
      status: 'created',
      wallet: {
        did: 'did:plc:x',
        evm: { address: '0x1', publicKeyHex: '02ab' },
        sol: { address: 'So1', publicKeyHex: 'cd' },
        version: 1,
        createdAt: 123,
      },
      deviceShareJwe: 'a..b.c.d',
      recoveryShareJwe: 'e..f.g.h',
    })
    const result = await client.walletCreate('did:plc:x')
    expect(result.deviceShareJwe).toBe('a..b.c.d')
    expect(result.wallet.evm.address).toBe('0x1')
    const [url, init] = mock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('http://signer.internal:3010/v1/wallet/create')
    expect(JSON.parse(init.body as string)).toEqual({ did: 'did:plc:x' })
  })

  it('walletInfo URL-encodes the did', async () => {
    const mock = mockFetchOnce(200, {
      enrolled: true,
      wallet: null,
      walletEncryptionPublicJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
    })
    const info = await client.walletInfo('did:plc:abc')
    expect(info.wallet).toBeNull()
    const [url] = mock.mock.calls[0] as [string]
    expect(url).toBe(
      'http://signer.internal:3010/v1/wallet/info/did%3Aplc%3Aabc',
    )
  })

  it('walletExport forwards the envelope to the export route', async () => {
    const mock = mockFetchOnce(200, { exportJwe: 'x..y.z.w' })
    const result = await client.walletExport({ payload: 'cGF5', sig: 'c2ln' })
    expect(result.exportJwe).toBe('x..y.z.w')
    const [url] = mock.mock.calls[0] as [string]
    expect(url).toBe('http://signer.internal:3010/v1/wallet/export')
  })

  it('walletRecover posts share and optional new request key', async () => {
    const mock = mockFetchOnce(200, {
      status: 'recovered',
      version: 2,
      deviceShareJwe: 'a..b.c.d',
      recoveryShareJwe: 'e..f.g.h',
    })
    const result = await client.walletRecover({
      did: 'did:plc:x',
      recoveryShareJwe: 'r..s.t.u',
      requestPublicKeyHex: '02ab',
    })
    expect(result.version).toBe(2)
    const [url, init] = mock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('http://signer.internal:3010/v1/wallet/recover')
    expect(JSON.parse(init.body as string)).toEqual({
      did: 'did:plc:x',
      recoveryShareJwe: 'r..s.t.u',
      requestPublicKeyHex: '02ab',
    })
  })

  it('throws SignerClientError with the server error message', async () => {
    mockFetchOnce(409, { error: 'nonce replayed or out of order' })
    await expect(
      client.walletSign({ payload: 'x', sig: 'y' }),
    ).rejects.toMatchObject({
      name: 'SignerClientError',
      status: 409,
      message: 'nonce replayed or out of order',
    })
  })

  it('throws a generic message for non-JSON error bodies', async () => {
    globalThis.fetch = vi.fn(() =>
      Promise.resolve(new Response('boom', { status: 500 })),
    ) as unknown as typeof fetch
    await expect(client.health()).rejects.toThrow(
      new SignerClientError(500, 'signer request failed with status 500'),
    )
  })
})
