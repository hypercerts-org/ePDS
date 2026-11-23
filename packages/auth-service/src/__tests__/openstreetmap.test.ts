/**
 * OpenStreetMap provider config: env gating, issuer handling, and the
 * profile mapping that keeps an OpenStreetMap identity from ever carrying
 * a real or verified email (see lib/openstreetmap.ts).
 */
import { describe, expect, it } from 'vitest'
import {
  buildOpenStreetMapConfig,
  DEFAULT_OSM_ISSUER,
  mapOsmProfileToUser,
  OSM_PROVIDER_ID,
  osmIssuer,
  osmPlaceholderEmail,
} from '../lib/openstreetmap.js'

describe('buildOpenStreetMapConfig', () => {
  it('is off without both client id and secret', () => {
    expect(buildOpenStreetMapConfig({})).toBeNull()
    expect(buildOpenStreetMapConfig({ OSM_CLIENT_ID: 'id' })).toBeNull()
    expect(buildOpenStreetMapConfig({ OSM_CLIENT_SECRET: 's' })).toBeNull()
    expect(
      buildOpenStreetMapConfig({ OSM_CLIENT_ID: '', OSM_CLIENT_SECRET: 's' }),
    ).toBeNull()
  })

  it('configures an OIDC provider that never signs anyone up', () => {
    const config = buildOpenStreetMapConfig({
      OSM_CLIENT_ID: 'id',
      OSM_CLIENT_SECRET: 'secret',
    })
    expect(config).toMatchObject({
      providerId: OSM_PROVIDER_ID,
      clientId: 'id',
      clientSecret: 'secret',
      discoveryUrl: `${DEFAULT_OSM_ISSUER}/.well-known/openid-configuration`,
      requireIdTokenVerification: true,
      scopes: ['openid'],
      pkce: true,
      disableSignUp: true,
      mapProfileToUser: mapOsmProfileToUser,
    })
  })

  it('discovers from OSM_ISSUER, e.g. the OSM dev server', () => {
    expect(
      buildOpenStreetMapConfig({
        OSM_CLIENT_ID: 'id',
        OSM_CLIENT_SECRET: 'secret',
        OSM_ISSUER: 'https://master.apis.dev.openstreetmap.org/',
      })?.discoveryUrl,
    ).toBe(
      'https://master.apis.dev.openstreetmap.org/.well-known/openid-configuration',
    )
  })
})

describe('osmIssuer', () => {
  it.each([
    [undefined, DEFAULT_OSM_ISSUER],
    ['', DEFAULT_OSM_ISSUER],
    ['  ', DEFAULT_OSM_ISSUER],
    ['http://master.apis.dev.openstreetmap.org', DEFAULT_OSM_ISSUER],
    ['not a url', DEFAULT_OSM_ISSUER],
    ['javascript:alert(1)', DEFAULT_OSM_ISSUER],
    [
      'https://master.apis.dev.openstreetmap.org/path?q',
      'https://master.apis.dev.openstreetmap.org',
    ],
  ])('%j -> %s', (value, expected) => {
    expect(osmIssuer({ OSM_ISSUER: value })).toBe(expected)
  })
})

describe('osmPlaceholderEmail', () => {
  it('is a reserved .invalid address unique to the sub', () => {
    expect(osmPlaceholderEmail('1001')).toBe('1001@users.openstreetmap.invalid')
    expect(osmPlaceholderEmail(1001)).toBe('1001@users.openstreetmap.invalid')
  })

  it.each([undefined, null, '', 'alice', '1@x', '-1', '1.5', {}, ['1']])(
    'is undefined for sub %j',
    (sub) => {
      expect(osmPlaceholderEmail(sub)).toBeUndefined()
    },
  )
})

describe('mapOsmProfileToUser', () => {
  it('never maps a real or verified email, even if OSM sends one', () => {
    expect(
      mapOsmProfileToUser({
        sub: '1001',
        preferred_username: 'alice',
        email: 'alice@example.com',
        email_verified: true,
      } as Parameters<typeof mapOsmProfileToUser>[0]),
    ).toEqual({
      email: '1001@users.openstreetmap.invalid',
      emailVerified: false,
      name: 'alice',
    })
  })

  it('has an empty name without a username', () => {
    expect(mapOsmProfileToUser({ sub: '1' }).name).toBe('')
  })
})
