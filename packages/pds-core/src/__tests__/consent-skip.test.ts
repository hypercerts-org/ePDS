import { describe, expect, it, vi } from 'vitest'
import {
  issueConsentSkipRedirect,
  type ConsentSkipProvider,
} from '../lib/consent-skip.js'

type Params = Record<string, unknown>

function makeProvider(parameters: Params, code = 'cod-abc123') {
  const calls: string[] = []
  const get = vi.fn((_uri: string, _deviceId: unknown) => {
    calls.push('get')
    return Promise.resolve({ parameters })
  })
  const setAuthorizedClient = vi.fn(() => {
    calls.push('setAuthorizedClient')
    return Promise.resolve()
  })
  const provider: ConsentSkipProvider = {
    requestManager: {
      get,
      // oauth-provider >= 0.27 returns { code, parameters }, not the bare code
      setAuthorized: vi.fn(() => {
        calls.push('setAuthorized')
        return Promise.resolve({ code, parameters })
      }),
    },
    accountManager: {
      setAuthorizedClient,
    },
  }
  return { provider, calls, get, setAuthorizedClient }
}

const args = {
  requestUri: 'urn:ietf:params:oauth:request_uri:req-1',
  client: {} as never,
  account: { sub: 'did:plc:abc' } as never,
  deviceId: 'dev-1' as never,
  deviceMetadata: {} as never,
  pdsUrl: 'https://pds.example',
}

describe('issueConsentSkipRedirect', () => {
  it('redirects with the authorization code as a plain string', async () => {
    const { provider } = makeProvider({
      redirect_uri: 'https://app.example/cb',
      state: 'xyz',
      scope: 'atproto transition:generic',
    })

    const result = await issueConsentSkipRedirect(provider, args)

    expect(result.kind).toBe('redirect')
    if (result.kind !== 'redirect') return
    expect(result.url.searchParams.get('code')).toBe('cod-abc123')
    expect(result.url.searchParams.get('iss')).toBe('https://pds.example')
    expect(result.url.searchParams.get('state')).toBe('xyz')
  })

  it('binds the device before issuing the code, then records the client with its scopes', async () => {
    const { provider, calls, get, setAuthorizedClient } = makeProvider({
      redirect_uri: 'https://app.example/cb',
      scope: 'atproto transition:generic',
    })

    await issueConsentSkipRedirect(provider, args)

    expect(calls).toEqual(['get', 'setAuthorized', 'setAuthorizedClient'])
    expect(get).toHaveBeenCalledWith(args.requestUri, args.deviceId)
    expect(setAuthorizedClient).toHaveBeenCalledWith(
      args.account,
      args.client,
      { authorizedScopes: ['atproto', 'transition:generic'] },
    )
  })

  it('puts the parameters in the fragment for response_mode=fragment', async () => {
    const { provider } = makeProvider({
      redirect_uri: 'https://app.example/cb',
      response_mode: 'fragment',
    })

    const result = await issueConsentSkipRedirect(provider, args)

    if (result.kind !== 'redirect') throw new Error('expected redirect')
    expect(result.url.search).toBe('')
    expect(new URLSearchParams(result.url.hash.slice(1)).get('code')).toBe(
      'cod-abc123',
    )
  })

  it('reports a missing redirect_uri without issuing a code', async () => {
    const { provider, calls } = makeProvider({ scope: 'atproto' })

    const result = await issueConsentSkipRedirect(provider, args)

    expect(result).toEqual({ kind: 'missing-redirect-uri' })
    // No code is issued and no client is recorded as authorized.
    expect(calls).toEqual(['get'])
  })
})
