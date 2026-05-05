import { describe, expect, it } from 'vitest'
import { buildEpdsCallbackAuthorizeUrl } from '../lib/epds-callback-authorize.js'

describe('buildEpdsCallbackAuthorizeUrl', () => {
  it('preserves a valid display-only epds_handle_mode on the final authorize redirect', () => {
    const url = buildEpdsCallbackAuthorizeUrl({
      pdsUrl: 'https://pds.example',
      requestUri: 'urn:ietf:params:oauth:request_uri:req-123',
      clientId: 'https://app.example/client.json',
      handleMode: 'random',
    })

    expect(url.pathname).toBe('/oauth/authorize')
    expect(url.searchParams.get('request_uri')).toBe(
      'urn:ietf:params:oauth:request_uri:req-123',
    )
    expect(url.searchParams.get('client_id')).toBe(
      'https://app.example/client.json',
    )
    expect(url.searchParams.get('epds_handle_mode')).toBe('random')
  })

  it('drops invalid epds_handle_mode values from the final authorize redirect', () => {
    const url = buildEpdsCallbackAuthorizeUrl({
      pdsUrl: 'https://pds.example',
      requestUri: 'urn:ietf:params:oauth:request_uri:req-123',
      clientId: 'https://app.example/client.json',
      handleMode: 'garbage',
    })

    expect(url.searchParams.has('epds_handle_mode')).toBe(false)
  })
})
