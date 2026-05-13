/**
 * Tests for client metadata resolution (resolveClientName, resolveClientMetadata)
 * and CSS extraction (getClientCss).
 *
 * The SSRF-hardened safeFetch (backed by @atproto-labs/fetch-node) uses a
 * custom undici dispatcher that bypasses globalThis.fetch mocks. Tests that
 * need specific metadata responses seed the cache directly via
 * _seedClientMetadataCacheForTest instead of mocking fetch.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import {
  resolveClientName,
  resolveClientMetadata,
  clearClientMetadataCache,
  _seedClientMetadataCacheForTest,
  getClientCss,
  getClientFaviconUrl,
  getClientFaviconUrlDark,
} from '../client-metadata.js'

beforeEach(() => {
  clearClientMetadataCache()
})

describe('resolveClientMetadata', () => {
  it('returns client_name for non-URL client_id', async () => {
    const metadata = await resolveClientMetadata('my-local-app')
    expect(metadata.client_name).toBe('my-local-app')
  })

  it('returns seeded metadata from cache', async () => {
    _seedClientMetadataCacheForTest('https://cool.app/client-metadata.json', {
      client_name: 'Cool App',
      client_uri: 'https://cool.app',
      logo_uri: 'https://cool.app/logo.png',
    })

    const metadata = await resolveClientMetadata(
      'https://cool.app/client-metadata.json',
    )
    expect(metadata.client_name).toBe('Cool App')
    expect(metadata.client_uri).toBe('https://cool.app')
    expect(metadata.logo_uri).toBe('https://cool.app/logo.png')
  })

  it('preserves ePDS extension fields', async () => {
    _seedClientMetadataCacheForTest(
      'https://extended.app/client-metadata.json',
      {
        client_name: 'Extended App',
        brand_color: '#ff0000',
        background_color: '#ffffff',
        epds_handle_mode: 'random',
        epds_skip_consent_on_signup: true,
      },
    )

    const metadata = await resolveClientMetadata(
      'https://extended.app/client-metadata.json',
    )
    expect(metadata.brand_color).toBe('#ff0000')
    expect(metadata.background_color).toBe('#ffffff')
    expect(metadata.epds_handle_mode).toBe('random')
    expect(metadata.epds_skip_consent_on_signup).toBe(true)
  })

  it('falls back to domain for http:// URLs (safeFetch rejects non-HTTPS)', async () => {
    const metadata = await resolveClientMetadata(
      'http://local.app/client-metadata.json', // NOSONAR — testing SSRF guard
    )
    expect(metadata.client_name).toBe('local.app')
  })

  it('returns cached metadata on second call', async () => {
    _seedClientMetadataCacheForTest('https://cached.app/client-metadata.json', {
      client_name: 'Cached App',
    })

    const first = await resolveClientMetadata(
      'https://cached.app/client-metadata.json',
    )
    const second = await resolveClientMetadata(
      'https://cached.app/client-metadata.json',
    )
    expect(first).toEqual(second)
    expect(first.client_name).toBe('Cached App')
  })

  it('noCache:true + fetch failure does not poison a valid cache entry', async () => {
    // Regression test for a bug where preview flows that failed to
    // fetch client metadata would overwrite a real flow's 10-minute
    // cache entry with a 60-second branding-less fallback, silently
    // dropping CSS on real OAuth flows for up to a minute.
    const url = 'https://127.0.0.1/client-metadata.json' // NOSONAR — testing SSRF guard
    _seedClientMetadataCacheForTest(url, {
      client_name: 'Seeded App',
      branding: { css: 'body { background: red; }' },
    })
    // safeFetch rejects 127.0.0.1 as a non-unicast host, so this fetch
    // fails deterministically. The preview-style call returns the
    // fallback metadata to its caller (so the preview page still
    // renders), but must NOT clobber the seeded cache entry.
    const previewResult = await resolveClientMetadata(url, { noCache: true })
    expect(previewResult.client_name).toBe('127.0.0.1')
    expect(previewResult.branding).toBeUndefined()
    // A subsequent real-flow call (noCache defaulted to false) must
    // still see the original seeded entry — not a poisoned fallback.
    const realFlowResult = await resolveClientMetadata(url)
    expect(realFlowResult.client_name).toBe('Seeded App')
    expect(realFlowResult.branding?.css).toBe('body { background: red; }')
  })
})

describe('resolveClientName', () => {
  it('returns client_name from metadata', async () => {
    _seedClientMetadataCacheForTest('https://named.app/client-metadata.json', {
      client_name: 'Named App',
    })

    const name = await resolveClientName(
      'https://named.app/client-metadata.json',
    )
    expect(name).toBe('Named App')
  })

  it('falls back to domain when client_name is missing', async () => {
    _seedClientMetadataCacheForTest(
      'https://no-name.app/client-metadata.json',
      {},
    )

    const name = await resolveClientName(
      'https://no-name.app/client-metadata.json',
    )
    expect(name).toBe('no-name.app')
  })

  it('returns client_id as-is for non-URL', async () => {
    const name = await resolveClientName('unnamed-client')
    expect(name).toBe('unnamed-client')
  })
})

describe('getClientCss', () => {
  const TRUSTED = ['https://trusted.app/client-metadata.json']
  const CLIENT_ID = 'https://trusted.app/client-metadata.json'

  it('returns null for untrusted clients', () => {
    const result = getClientCss(
      'https://untrusted.app/client-metadata.json',
      { branding: { css: 'body { color: red; }' } },
      TRUSTED,
    )
    expect(result).toBeNull()
  })

  it('returns null when branding.css is absent', () => {
    expect(getClientCss(CLIENT_ID, {}, TRUSTED)).toBeNull()
    expect(getClientCss(CLIENT_ID, { branding: {} }, TRUSTED)).toBeNull()
  })

  it('returns escaped CSS for trusted client within size limit', () => {
    const result = getClientCss(
      CLIENT_ID,
      { branding: { css: 'body { color: red; }' } },
      TRUSTED,
    )
    expect(result).toBe('body { color: red; }')
  })

  it('escapes </style> sequences to prevent tag closure', () => {
    const result = getClientCss(
      CLIENT_ID,
      {
        branding: { css: 'body { content: "</style><script>bad</script>"; }' },
      },
      TRUSTED,
    )
    expect(result).not.toContain('</style>')
    expect(result).toContain('\\u003c/style>')
  })

  it('escapes </style > with whitespace (HTML5 RAWTEXT variant)', () => {
    const result = getClientCss(
      CLIENT_ID,
      {
        branding: {
          css: 'body { content: "</style ><script>bad</script>"; }',
        },
      },
      TRUSTED,
    )
    expect(result).not.toContain('</style')
    expect(result).toContain('\\u003c/style>')
  })

  it('escapes </style/> self-closing variant', () => {
    const result = getClientCss(
      CLIENT_ID,
      {
        branding: {
          css: 'body { content: "</style/><script>bad</script>"; }',
        },
      },
      TRUSTED,
    )
    expect(result).not.toContain('</style')
    expect(result).toContain('\\u003c/style>')
  })

  it('returns null when CSS exceeds 32 KB', () => {
    const oversized = 'a'.repeat(32_769)
    const result = getClientCss(
      CLIENT_ID,
      { branding: { css: oversized } },
      TRUSTED,
    )
    expect(result).toBeNull()
  })

  it('returns CSS exactly at the 32 KB limit', () => {
    const atLimit = 'a'.repeat(32_768)
    const result = getClientCss(
      CLIENT_ID,
      { branding: { css: atLimit } },
      TRUSTED,
    )
    expect(result).toBe(atLimit)
  })
})

describe('getClientFaviconUrl', () => {
  const TRUSTED = ['https://trusted.app/client-metadata.json']
  const CLIENT_ID = 'https://trusted.app/client-metadata.json'

  it('returns null for untrusted clients', () => {
    expect(
      getClientFaviconUrl(
        'https://untrusted.app/client-metadata.json',
        { branding: { favicon_url: 'https://untrusted.app/icon.svg' } },
        TRUSTED,
      ),
    ).toBeNull()
  })

  it('returns null when branding.favicon_url is absent', () => {
    expect(getClientFaviconUrl(CLIENT_ID, {}, TRUSTED)).toBeNull()
    expect(getClientFaviconUrl(CLIENT_ID, { branding: {} }, TRUSTED)).toBeNull()
  })

  it('returns the URL for trusted client with same-origin HTTPS favicon', () => {
    expect(
      getClientFaviconUrl(
        CLIENT_ID,
        { branding: { favicon_url: 'https://trusted.app/icon.svg' } },
        TRUSTED,
      ),
    ).toBe('https://trusted.app/icon.svg')
  })

  // Rejection cases share the same {input → null} shape, so a table-driven
  // suite is both more readable and avoids duplicated boilerplate (Sonar
  // flagged the per-case repetition above the 3% threshold).
  const longPath = 'a'.repeat(2100)
  it.each<[string, string, string[], unknown]>([
    [
      'cross-origin favicon (CSP img-src only allows client_id origin)',
      CLIENT_ID,
      TRUSTED,
      'https://cdn.app/icon.svg',
    ],
    [
      'favicon on a sibling subdomain of client_id',
      CLIENT_ID,
      TRUSTED,
      'https://assets.trusted.app/icon.svg',
    ],
    [
      'favicon on the same host but a different port',
      CLIENT_ID,
      TRUSTED,
      'https://trusted.app:8443/icon.svg',
    ],
    [
      'when client_id is not a parseable URL',
      'not-a-url',
      ['not-a-url'],
      'https://trusted.app/icon.svg',
    ],
    [
      'http:// (mixed content)', // NOSONAR — testing the mixed-content gate
      CLIENT_ID,
      TRUSTED,
      'http://trusted.app/icon.svg', // NOSONAR — testing the mixed-content gate
    ],
    [
      'data: URIs (could smuggle SVG with script)',
      CLIENT_ID,
      TRUSTED,
      'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg"/>', // NOSONAR — fixed SVG xmlns identifier (the URL is W3C's namespace, not a fetched resource)
    ],
    ['javascript: URIs', CLIENT_ID, TRUSTED, 'javascript:alert(1)'],
    [
      'URLs carrying userinfo credentials',
      CLIENT_ID,
      TRUSTED,
      'https://user:pass@trusted.app/icon.svg',
    ],
    ['malformed URLs', CLIENT_ID, TRUSTED, 'not a url'],
    [
      'URLs over 2048 chars',
      CLIENT_ID,
      TRUSTED,
      `https://trusted.app/${longPath}.svg`,
    ],
    [
      // Raw input is exactly 2048 chars but url.href percent-encodes the
      // trailing kanji (1 byte → 9 chars), pushing the normalised form
      // past the cap. Caught by the post-parse url.href.length check.
      'URLs whose normalised form exceeds 2048 chars',
      CLIENT_ID,
      TRUSTED,
      `https://trusted.app/${'a'.repeat(2027)}日`,
    ],
    ['non-string favicon_url values', CLIENT_ID, TRUSTED, 42],
  ])('rejects %s', (_name, clientId, trusted, faviconUrl) => {
    expect(
      getClientFaviconUrl(
        clientId,
        // eslint-disable-next-line @typescript-eslint/no-explicit-any -- table covers both string and non-string inputs
        { branding: { favicon_url: faviconUrl as any } },
        trusted,
      ),
    ).toBeNull()
  })
})

describe('getClientFaviconUrlDark', () => {
  const TRUSTED = ['https://trusted.app/client-metadata.json']
  const CLIENT_ID = 'https://trusted.app/client-metadata.json'

  it('returns null for untrusted clients', () => {
    expect(
      getClientFaviconUrlDark(
        'https://untrusted.app/client-metadata.json',
        {
          branding: { favicon_url_dark: 'https://untrusted.app/icon-dark.svg' },
        },
        TRUSTED,
      ),
    ).toBeNull()
  })

  it('returns null when branding.favicon_url_dark is absent', () => {
    expect(getClientFaviconUrlDark(CLIENT_ID, {}, TRUSTED)).toBeNull()
    expect(
      getClientFaviconUrlDark(CLIENT_ID, { branding: {} }, TRUSTED),
    ).toBeNull()
  })

  it('returns null when only favicon_url is set (no fallback to light)', () => {
    expect(
      getClientFaviconUrlDark(
        CLIENT_ID,
        { branding: { favicon_url: 'https://trusted.app/icon.svg' } },
        TRUSTED,
      ),
    ).toBeNull()
  })

  it('returns the URL for trusted client with same-origin HTTPS dark favicon', () => {
    expect(
      getClientFaviconUrlDark(
        CLIENT_ID,
        { branding: { favicon_url_dark: 'https://trusted.app/icon-dark.svg' } },
        TRUSTED,
      ),
    ).toBe('https://trusted.app/icon-dark.svg')
  })

  it('resolves light and dark independently from the same metadata', () => {
    const metadata = {
      branding: {
        favicon_url: 'https://trusted.app/icon.svg',
        favicon_url_dark: 'https://trusted.app/icon-dark.svg',
      },
    }
    expect(getClientFaviconUrl(CLIENT_ID, metadata, TRUSTED)).toBe(
      'https://trusted.app/icon.svg',
    )
    expect(getClientFaviconUrlDark(CLIENT_ID, metadata, TRUSTED)).toBe(
      'https://trusted.app/icon-dark.svg',
    )
  })

  // Same rejection rules as the light variant — exercise a representative
  // subset to prove the shared validateFaviconUrl helper covers both fields.
  const longPath = 'a'.repeat(2100)
  it.each<[string, string, string[], unknown]>([
    [
      'cross-origin dark favicon',
      CLIENT_ID,
      TRUSTED,
      'https://cdn.app/icon-dark.svg',
    ],
    [
      'http:// dark favicon (mixed content)', // NOSONAR — testing the mixed-content gate
      CLIENT_ID,
      TRUSTED,
      'http://trusted.app/icon-dark.svg', // NOSONAR — testing the mixed-content gate
    ],
    [
      'dark favicon URLs over 2048 chars',
      CLIENT_ID,
      TRUSTED,
      `https://trusted.app/${longPath}.svg`,
    ],
    [
      'dark favicon with userinfo credentials',
      CLIENT_ID,
      TRUSTED,
      'https://user:pass@trusted.app/icon-dark.svg',
    ],
    ['non-string dark favicon values', CLIENT_ID, TRUSTED, 42],
  ])('rejects %s', (_name, clientId, trusted, faviconUrl) => {
    expect(
      getClientFaviconUrlDark(
        clientId,
        // eslint-disable-next-line @typescript-eslint/no-explicit-any -- table covers both string and non-string inputs
        { branding: { favicon_url_dark: faviconUrl as any } },
        trusted,
      ),
    ).toBeNull()
  })
})
