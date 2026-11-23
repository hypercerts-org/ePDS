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
  osmAccountSubject,
  osmIssuer,
  osmPlaceholderEmail,
  parseOsmAccountId,
} from '../lib/openstreetmap.js'

const PLACEHOLDER = /^[0-9a-f-]{36}@users\.openstreetmap\.invalid$/

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
      accountSubject: expect.any(Function),
    })
  })

  it('keys accounts by the issuer host and the sub', async () => {
    const subject = (env: NodeJS.ProcessEnv) =>
      buildOpenStreetMapConfig({
        OSM_CLIENT_ID: 'id',
        OSM_CLIENT_SECRET: 'secret',
        ...env,
      })?.accountSubject?.({
        profile: { sub: '1001' },
      } as Parameters<
        NonNullable<
          NonNullable<
            ReturnType<typeof buildOpenStreetMapConfig>
          >['accountSubject']
        >
      >[0])
    expect(await subject({})).toBe('www.openstreetmap.org:1001')
    expect(
      await subject({
        OSM_ISSUER: 'https://master.apis.dev.openstreetmap.org',
      }),
    ).toBe('master.apis.dev.openstreetmap.org:1001')
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

describe('osmAccountSubject', () => {
  it('qualifies the sub with the issuer host', () => {
    expect(osmAccountSubject('https://www.openstreetmap.org', '1001')).toBe(
      'www.openstreetmap.org:1001',
    )
    expect(osmAccountSubject('https://osm.example:8443', 1001)).toBe(
      'osm.example:8443:1001',
    )
  })

  it.each([undefined, null, '', 'alice', '1@x', '-1', {}])(
    'is empty, which better-auth rejects, for sub %j',
    (sub) => {
      expect(osmAccountSubject('https://www.openstreetmap.org', sub)).toBe('')
    },
  )
})

describe('parseOsmAccountId', () => {
  it('splits off the instance host for display', () => {
    expect(parseOsmAccountId('www.openstreetmap.org:30869')).toEqual({
      userId: '30869',
      host: 'www.openstreetmap.org',
    })
    expect(parseOsmAccountId('osm.example:8443:7')).toEqual({
      userId: '7',
      host: 'osm.example:8443',
    })
    expect(parseOsmAccountId('30869')).toEqual({ userId: '30869', host: null })
  })
})

describe('osmPlaceholderEmail', () => {
  it('is a fresh, unpredictable reserved .invalid address', () => {
    const first = osmPlaceholderEmail('1001')
    expect(first).toMatch(PLACEHOLDER)
    expect(osmPlaceholderEmail(1001)).toMatch(PLACEHOLDER)
    expect(osmPlaceholderEmail('1001')).not.toBe(first)
    expect(first).not.toContain('1001')
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
      email: expect.stringMatching(PLACEHOLDER),
      emailVerified: false,
      name: 'alice',
    })
  })

  it('has an empty name without a username', () => {
    expect(mapOsmProfileToUser({ sub: '1' }).name).toBe('')
  })
})
