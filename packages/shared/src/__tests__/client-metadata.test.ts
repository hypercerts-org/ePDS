/**
 * Tests for client metadata resolution (resolveClientName, resolveClientMetadata)
 * and CSS extraction (getClientCss).
 *
 * Uses global fetch mocking to simulate HTTP responses without real network calls.
 * Since resolveClientMetadata uses safeFetch (which delegates to globalThis.fetch
 * at call time), mocking globalThis.fetch is sufficient — but mocks must return
 * Response-shaped objects with a `.headers` property because safeFetch checks
 * Content-Length.
 */
import {
  describe,
  it,
  expect,
  vi,
  beforeEach,
  afterEach,
  type Mock,
} from 'vitest'
import {
  resolveClientName,
  resolveClientMetadata,
  clearClientMetadataCache,
  getClientCss,
} from '../client-metadata.js'

// ── fetch mock helpers ─────────────────────────────────────────────────────
//
// safeFetch checks res.headers.get('content-length'), so mocks must include
// a headers object. Using real Response objects avoids shape mismatches.

function installFetchMock(impl: Mock): Mock {
  globalThis.fetch = impl as unknown as typeof fetch
  return impl
}

function mockFetchOk(body: Record<string, unknown>): Mock {
  const json = JSON.stringify(body)
  return installFetchMock(
    vi.fn().mockResolvedValue(
      new Response(json, {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    ),
  )
}

function mockFetchNotOk(status: number): Mock {
  return installFetchMock(
    vi.fn().mockResolvedValue(new Response('', { status })),
  )
}

function mockFetchReject(message: string): Mock {
  return installFetchMock(vi.fn().mockRejectedValue(new Error(message)))
}

// ── setup / teardown ───────────────────────────────────────────────────────

const originalFetch = globalThis.fetch

beforeEach(() => {
  globalThis.fetch = originalFetch
  clearClientMetadataCache()
})

afterEach(() => {
  globalThis.fetch = originalFetch
})

// ── tests ──────────────────────────────────────────────────────────────────

describe('resolveClientMetadata', () => {
  it('returns client_name for non-URL client_id', async () => {
    const metadata = await resolveClientMetadata('my-local-app')
    expect(metadata.client_name).toBe('my-local-app')
  })

  it('fetches metadata from URL client_id', async () => {
    mockFetchOk({
      client_name: 'Cool App',
      client_uri: 'https://cool.app',
      logo_uri: 'https://cool.app/logo.png',
    })

    const metadata = await resolveClientMetadata(
      'https://shared-cool.app/client-metadata.json',
    )
    expect(metadata.client_name).toBe('Cool App')
    expect(metadata.client_uri).toBe('https://cool.app')
    expect(metadata.logo_uri).toBe('https://cool.app/logo.png')
  })

  it('preserves ePDS extension fields', async () => {
    mockFetchOk({
      client_name: 'Extended App',
      brand_color: '#ff0000',
      background_color: '#ffffff',
      epds_handle_mode: 'random',
      epds_skip_consent_on_signup: true,
    })

    const metadata = await resolveClientMetadata(
      'https://shared-extended.app/client-metadata.json',
    )
    expect(metadata.brand_color).toBe('#ff0000')
    expect(metadata.background_color).toBe('#ffffff')
    expect(metadata.epds_handle_mode).toBe('random')
    expect(metadata.epds_skip_consent_on_signup).toBe(true)
  })

  it('falls back to domain on fetch failure', async () => {
    mockFetchReject('Network error')

    const metadata = await resolveClientMetadata(
      'https://shared-broken.app/client-metadata.json',
    )
    expect(metadata.client_name).toBe('shared-broken.app')
  })

  it('falls back to domain on non-ok response', async () => {
    mockFetchNotOk(404)

    const metadata = await resolveClientMetadata(
      'https://shared-missing.app/client-metadata.json',
    )
    expect(metadata.client_name).toBe('shared-missing.app')
  })

  it('caches successful fetches', async () => {
    const mockFetch = mockFetchOk({ client_name: 'Cached App' })

    await resolveClientMetadata(
      'https://shared-cached.app/client-metadata.json',
    )
    await resolveClientMetadata(
      'https://shared-cached.app/client-metadata.json',
    )

    // Only one fetch call — second hit the cache
    expect(mockFetch).toHaveBeenCalledTimes(1)
  })

  it('caches failures briefly', async () => {
    const mockFetch = mockFetchReject('Down')

    await resolveClientMetadata('https://shared-down.app/client-metadata.json')
    await resolveClientMetadata('https://shared-down.app/client-metadata.json')

    // Only one fetch call — failure was cached
    expect(mockFetch).toHaveBeenCalledTimes(1)
  })

  it('falls back to domain for http:// URLs (safeFetch rejects non-HTTPS)', async () => {
    const metadata = await resolveClientMetadata(
      'http://shared-local.app/client-metadata.json',
    )
    // safeFetch blocks http:// → catch branch returns fallback with domain name
    expect(metadata.client_name).toBe('shared-local.app')
  })
})

describe('resolveClientName', () => {
  it('returns client_name from metadata', async () => {
    mockFetchOk({ client_name: 'Named App' })

    const name = await resolveClientName(
      'https://shared-named.app/client-metadata.json',
    )
    expect(name).toBe('Named App')
  })

  it('falls back to domain when client_name is missing', async () => {
    mockFetchOk({})

    const name = await resolveClientName(
      'https://shared-no-name.app/client-metadata.json',
    )
    expect(name).toBe('shared-no-name.app')
  })

  it('returns "an application" for non-URL without name', async () => {
    const name = await resolveClientName('unnamed-client')
    expect(name).toBe('unnamed-client')
  })

  it('returns "an application" when domain extraction fails', async () => {
    mockFetchOk({})

    const name = await resolveClientName('not-a-url')
    expect(name).toBe('not-a-url')
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

  it('returns null when CSS exceeds 8 KB', () => {
    const oversized = 'a'.repeat(8_193)
    const result = getClientCss(
      CLIENT_ID,
      { branding: { css: oversized } },
      TRUSTED,
    )
    expect(result).toBeNull()
  })

  it('returns CSS exactly at the 8 KB limit', () => {
    const atLimit = 'a'.repeat(8_192)
    const result = getClientCss(
      CLIENT_ID,
      { branding: { css: atLimit } },
      TRUSTED,
    )
    expect(result).toBe(atLimit)
  })
})
