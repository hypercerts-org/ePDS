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
      keyId: 'did:plc:x#wallet/evm',
      purpose: 'wallet/evm',
      curve: 'secp256k1',
      publicKeyHex: '02ab',
      address: '0x1',
    })
    const info = await client.deriveKey('did:plc:x', 'wallet/evm')
    expect(info.address).toBe('0x1')
    const [url, init] = mock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('http://signer.internal:3010/v1/keys/derive')
    expect(JSON.parse(init.body as string)).toEqual({
      did: 'did:plc:x',
      purpose: 'wallet/evm',
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
