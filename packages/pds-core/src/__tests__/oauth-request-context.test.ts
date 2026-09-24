import { describe, expect, it, vi } from 'vitest'
import { resolveOAuthClientIdFromQuery } from '../lib/oauth-request-context.js'

const CLIENT_ID = 'https://app.example/client.json'
const REQUEST_URI = 'urn:ietf:params:oauth:request_uri:req-123'

describe('resolveOAuthClientIdFromQuery', () => {
  it('prefers an explicit client_id query parameter', async () => {
    const resolver = vi.fn()

    await expect(
      resolveOAuthClientIdFromQuery({ client_id: CLIENT_ID }, resolver),
    ).resolves.toBe(CLIENT_ID)
    // The PAR round-trip is skipped entirely when the id is already present.
    expect(resolver).not.toHaveBeenCalled()
  })

  it('prefers client_id even when a request_uri is also present', async () => {
    const resolver = vi.fn().mockResolvedValue('https://other.example/c.json')

    await expect(
      resolveOAuthClientIdFromQuery(
        { client_id: CLIENT_ID, request_uri: REQUEST_URI },
        resolver,
      ),
    ).resolves.toBe(CLIENT_ID)
    expect(resolver).not.toHaveBeenCalled()
  })

  it('falls back to resolving the PAR request_uri', async () => {
    const resolver = vi.fn().mockResolvedValue(CLIENT_ID)

    await expect(
      resolveOAuthClientIdFromQuery({ request_uri: REQUEST_URI }, resolver),
    ).resolves.toBe(CLIENT_ID)
    expect(resolver).toHaveBeenCalledWith(REQUEST_URI)
  })

  it('returns undefined when the resolver finds no client for the request_uri', async () => {
    const resolver = vi.fn().mockResolvedValue(undefined)

    await expect(
      resolveOAuthClientIdFromQuery({ request_uri: REQUEST_URI }, resolver),
    ).resolves.toBeUndefined()
  })

  it('returns undefined when no resolver is supplied', async () => {
    await expect(
      resolveOAuthClientIdFromQuery({ request_uri: REQUEST_URI }),
    ).resolves.toBeUndefined()
  })

  it('returns undefined for an empty query', async () => {
    const resolver = vi.fn()

    await expect(
      resolveOAuthClientIdFromQuery({}, resolver),
    ).resolves.toBeUndefined()
    expect(resolver).not.toHaveBeenCalled()
  })

  it.each([
    { name: 'non-string client_id', query: { client_id: 42 } },
    { name: 'non-string request_uri', query: { request_uri: 42 } },
  ])('ignores a $name', async ({ query }) => {
    const resolver = vi.fn().mockResolvedValue(CLIENT_ID)

    await expect(
      resolveOAuthClientIdFromQuery(query, resolver),
    ).resolves.toBeUndefined()
    expect(resolver).not.toHaveBeenCalled()
  })

  it('propagates resolver rejections to the caller', async () => {
    // Deliberate: the module leaves error handling to each middleware so
    // they can choose their own logging and fallback behaviour.
    const resolver = vi.fn().mockRejectedValue(new Error('PAR lookup failed'))

    await expect(
      resolveOAuthClientIdFromQuery({ request_uri: REQUEST_URI }, resolver),
    ).rejects.toThrow('PAR lookup failed')
  })
})
