import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// Intercept the SSRF-hardened fetch used by preview-validation.ts —
// safeFetchWrap speaks via an undici dispatcher, not globalThis.fetch,
// so spying on globalThis.fetch doesn't help. Replace the factory
// instead and return a plain async fn we control per-test. vi.hoisted
// lets the spy exist by the time vi.mock's factory runs (mocks are
// hoisted above imports).
const { mockSafeFetch } = vi.hoisted(() => ({ mockSafeFetch: vi.fn() }))
vi.mock('../safe-fetch.js', () => ({
  makeSafeFetch: () => mockSafeFetch,
}))

// Import after the mock so preview-validation picks up the stub.
import { validateClientMetadataForPreview } from '../preview-validation.js'

beforeEach(() => {
  mockSafeFetch.mockReset()
})

afterEach(() => {
  vi.restoreAllMocks()
})

function mockFetchOnce(body: unknown, status = 200): void {
  mockSafeFetch.mockResolvedValueOnce({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
  } as unknown as Response)
}

describe('validateClientMetadataForPreview', () => {
  it('returns a single error-severity check for a non-URL string', async () => {
    const result = await validateClientMetadataForPreview('not a url', null)
    expect(result.fetched).toBe(false)
    expect(result.checks).toHaveLength(1)
    expect(result.checks[0]).toMatchObject({
      id: 'url-parseable',
      severity: 'error',
    })
  })

  it('errors on http:// URLs and short-circuits before fetching', async () => {
    const result = await validateClientMetadataForPreview(
      'http://insecure.example/client-metadata.json',
      null,
    )
    // The https check fires first; we deliberately return early so
    // safeFetch isn't invoked and the operator isn't shown a second
    // overlapping `fetch` error for the same root cause.
    expect(result.fetched).toBe(false)
    expect(result.checks).toHaveLength(1)
    expect(result.checks[0]).toMatchObject({
      id: 'url-https',
      severity: 'error',
    })
    expect(mockSafeFetch).not.toHaveBeenCalled()
  })

  it('flags ok for all ok fields on a well-formed metadata', async () => {
    const url = 'https://good.example/client-metadata.json'
    mockFetchOnce({
      client_id: url,
      redirect_uris: [`${url.replace('/client-metadata.json', '')}/cb`],
      brand_color: '#f59e0b',
      background_color: '#1a1208',
      branding: { css: 'body { color: red; }' },
      tos_uri: 'https://good.example/terms',
      policy_uri: 'https://good.example/privacy',
    })
    const result = await validateClientMetadataForPreview(url, [url])
    expect(result.fetched).toBe(true)
    const byId = Object.fromEntries(result.checks.map((c) => [c.id, c]))
    expect(byId.fetch.severity).toBe('ok')
    expect(byId['client-id-match'].severity).toBe('ok')
    expect(byId['redirect-uris'].severity).toBe('ok')
    expect(byId['brand-color'].severity).toBe('ok')
    expect(byId['background-color'].severity).toBe('ok')
    expect(byId['branding-css'].severity).toBe('ok')
    expect(byId['tos-uri'].severity).toBe('ok')
    expect(byId['policy-uri'].severity).toBe('ok')
    expect(byId['trusted-client'].severity).toBe('ok')
  })

  it('flags branding.css as error when escaped size exceeds the 32 KB limit', async () => {
    // getClientCss measures *escaped* bytes against MAX_CSS_BYTES and
    // silently returns null above it. The validator must mirror that
    // check, not a raw-byte check — otherwise a developer whose CSS is
    // just under the raw limit but over it after escapeCss() still sees
    // "ok" here and gets their CSS silently dropped on real flows.
    //
    // Fixture construction: exactly MAX_CSS_BYTES (32 768) raw bytes,
    // composed entirely of `</style>` occurrences that escapeCss()
    // rewrites to `\u003c/style>` (+5 bytes each). Raw = 4096 × 8 =
    // 32 768 (at the limit, passes a naive raw check); escaped =
    // 4096 × 13 = 53 248 (over).
    const url = 'https://heavy.example/client-metadata.json'
    const bigCss = '</style>'.repeat(4096)
    expect(bigCss.length).toBe(32_768)
    mockFetchOnce({
      client_id: url,
      redirect_uris: ['https://heavy.example/cb'],
      branding: { css: bigCss },
    })
    const result = await validateClientMetadataForPreview(url, [url])
    const byId = Object.fromEntries(result.checks.map((c) => [c.id, c]))
    expect(byId['branding-css'].severity).toBe('error')
    expect(byId['branding-css'].detail).toContain('exceeds')
  })

  it('warns (not errors) when optional branding fields are missing', async () => {
    const url = 'https://plain.example/client-metadata.json'
    mockFetchOnce({
      client_id: url,
      redirect_uris: ['https://plain.example/cb'],
      // no brand_color, background_color, or branding.css
    })
    const result = await validateClientMetadataForPreview(url, [])
    const byId = Object.fromEntries(result.checks.map((c) => [c.id, c]))
    expect(byId['brand-color'].severity).toBe('warn')
    expect(byId['background-color'].severity).toBe('warn')
    expect(byId['branding-css'].severity).toBe('warn')
    expect(byId['tos-uri'].severity).toBe('warn')
    expect(byId['policy-uri'].severity).toBe('warn')
    // trust check also warn, not error
    expect(byId['trusted-client'].severity).toBe('warn')
    // No error-level checks on an otherwise-valid metadata:
    expect(result.checks.every((c) => c.severity !== 'error')).toBe(true)
  })

  it('errors when tos_uri / policy_uri are not valid https URLs', async () => {
    const url = 'https://d.example/client-metadata.json'
    mockFetchOnce({
      client_id: url,
      redirect_uris: ['https://d.example/cb'],
      tos_uri: 'not a url',
      policy_uri: 'http://insecure.example/privacy',
    })
    const result = await validateClientMetadataForPreview(url, null)
    const byId = Object.fromEntries(result.checks.map((c) => [c.id, c]))
    expect(byId['tos-uri'].severity).toBe('error')
    expect(byId['policy-uri'].severity).toBe('error')
  })

  it('errors when client_id field does not match the URL', async () => {
    const url = 'https://a.example/client-metadata.json'
    mockFetchOnce({
      client_id: 'https://different.example/client-metadata.json',
      redirect_uris: ['https://a.example/cb'],
    })
    const result = await validateClientMetadataForPreview(url, null)
    const check = result.checks.find((c) => c.id === 'client-id-match')
    expect(check?.severity).toBe('error')
  })

  it('errors on missing redirect_uris', async () => {
    const url = 'https://b.example/client-metadata.json'
    mockFetchOnce({
      client_id: url,
      // no redirect_uris
    })
    const result = await validateClientMetadataForPreview(url, null)
    const check = result.checks.find((c) => c.id === 'redirect-uris')
    expect(check?.severity).toBe('error')
  })

  it('errors when the upstream returns 404', async () => {
    const url = 'https://missing.example/client-metadata.json'
    mockFetchOnce({}, 404)
    const result = await validateClientMetadataForPreview(url, null)
    expect(result.fetched).toBe(false)
    expect(result.checks.find((c) => c.id === 'fetch')?.severity).toBe('error')
  })

  it('skips the trust check when trustedClients is null', async () => {
    const url = 'https://c.example/client-metadata.json'
    mockFetchOnce({
      client_id: url,
      redirect_uris: ['https://c.example/cb'],
    })
    const result = await validateClientMetadataForPreview(url, null)
    expect(result.checks.find((c) => c.id === 'trusted-client')).toBeUndefined()
  })
})
