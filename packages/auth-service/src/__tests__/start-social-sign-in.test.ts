/**
 * The check GET /oauth/authorize makes on the provider URL better-auth
 * returns before redirecting the browser there: an https URL on the
 * provider's own authorization server, and nothing else. The login page's
 * button makes the same check in the browser (login-page-social-buttons).
 */
import { describe, expect, it } from 'vitest'
import {
  providerAuthorizationUrl,
  providerOrigins,
} from '../lib/start-social-sign-in.js'

const GOOGLE_URL =
  'https://accounts.google.com/o/oauth2/v2/auth?client_id=google-id&state=s'

describe('providerAuthorizationUrl', () => {
  it('accepts an https URL on Google’s authorization server', () => {
    expect(providerAuthorizationUrl('google', GOOGLE_URL)).toBe(GOOGLE_URL)
  })

  it.each([
    ['an http URL', 'http://accounts.google.com/o/oauth2/v2/auth'],
    ['another host', 'https://evil.example/o/oauth2/v2/auth'],
    [
      'a look-alike host',
      'https://accounts.google.com.evil.example/o/oauth2/v2/auth',
    ],
    [
      'userinfo before another host',
      'https://accounts.google.com@evil.example/',
    ],
    ['an explicit port', 'https://accounts.google.com:8443/o/oauth2/v2/auth'],
    ['a javascript: URL', 'javascript:alert(1)'],
    ['a relative URL', '/o/oauth2/v2/auth'],
    ['a protocol-relative URL', '//accounts.google.com/o/oauth2/v2/auth'],
    ['a non-string URL', { href: GOOGLE_URL }],
    ['no URL', undefined],
  ])('refuses %s', (_label, url) => {
    expect(providerAuthorizationUrl('google', url)).toBeNull()
  })

  it.each(['github', 'toString', '__proto__'])(
    'refuses an unknown provider (%s)',
    (provider) => {
      expect(providerAuthorizationUrl(provider, GOOGLE_URL)).toBeNull()
    },
  )
})

describe('providerAuthorizationUrl for OpenStreetMap', () => {
  const OSM_URL = 'https://www.openstreetmap.org/oauth2/authorize?state=s'
  const DEV_URL =
    'https://master.apis.dev.openstreetmap.org/oauth2/authorize?state=s'

  it('accepts the production issuer by default', () => {
    expect(providerAuthorizationUrl('openstreetmap', OSM_URL, {})).toBe(OSM_URL)
    expect(providerAuthorizationUrl('openstreetmap', DEV_URL, {})).toBeNull()
  })

  it('follows OSM_ISSUER, and only it', () => {
    const env = { OSM_ISSUER: 'https://master.apis.dev.openstreetmap.org' }
    expect(providerAuthorizationUrl('openstreetmap', DEV_URL, env)).toBe(
      DEV_URL,
    )
    expect(providerAuthorizationUrl('openstreetmap', OSM_URL, env)).toBeNull()
  })

  it('does not accept Google’s server for OpenStreetMap or vice versa', () => {
    expect(
      providerAuthorizationUrl(
        'openstreetmap',
        'https://accounts.google.com/o/oauth2/v2/auth',
        {},
      ),
    ).toBeNull()
    expect(providerAuthorizationUrl('google', OSM_URL, {})).toBeNull()
  })

  it('lists one origin per provider', () => {
    expect(providerOrigins({})).toEqual({
      google: 'https://accounts.google.com',
      openstreetmap: 'https://www.openstreetmap.org',
    })
  })
})
