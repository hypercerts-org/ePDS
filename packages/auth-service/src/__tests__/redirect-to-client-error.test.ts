/**
 * Tests for buildClientErrorRedirect — the auth-service helper that
 * resolves an OAuth client's published metadata and constructs an
 * RFC 6749 §4.1.2.1 error redirect URL pointing at redirect_uris[0].
 *
 * Drives every branch (happy redirect, missing metadata, no
 * redirect_uris, unparseable URL, non-http(s) scheme) by mocking
 * resolveClientMetadata at the module boundary.
 */
import {
  describe,
  it,
  expect,
  vi,
  beforeEach,
  beforeAll,
  afterAll,
} from 'vitest'

const PDS_URL = 'https://pds.example'
const CLIENT_ID = 'https://demo.example/client-metadata.json'
const REDIRECT_URI = 'https://demo.example/api/oauth/callback'

const ORIGINAL_PDS_URL = process.env.PDS_INTERNAL_URL
const ORIGINAL_SECRET = process.env.EPDS_INTERNAL_SECRET

beforeAll(() => {
  // The lib doesn't read these directly, but importing transitively
  // pulls in modules that do, and an unset `EPDS_INTERNAL_SECRET`
  // would crash a sibling import.
  process.env.PDS_INTERNAL_URL = 'https://core:3000'
  process.env.EPDS_INTERNAL_SECRET = 'test-secret'
})

afterAll(() => {
  if (ORIGINAL_PDS_URL === undefined) delete process.env.PDS_INTERNAL_URL
  else process.env.PDS_INTERNAL_URL = ORIGINAL_PDS_URL
  if (ORIGINAL_SECRET === undefined) delete process.env.EPDS_INTERNAL_SECRET
  else process.env.EPDS_INTERNAL_SECRET = ORIGINAL_SECRET
})

const resolveClientMetadataMock = vi.hoisted(() => vi.fn())
vi.mock('@certified-app/shared', async (importActual) => {
  const actual = await importActual<Record<string, unknown>>()
  return {
    ...actual,
    resolveClientMetadata: resolveClientMetadataMock,
  }
})

import { buildClientErrorRedirect } from '../lib/redirect-to-client-error.js'

beforeEach(() => {
  resolveClientMetadataMock.mockReset()
})

describe('buildClientErrorRedirect', () => {
  it('builds a redirect URL with all RFC 6749 §4.1.2.1 query params on the happy path', async () => {
    resolveClientMetadataMock.mockResolvedValueOnce({
      redirect_uris: [REDIRECT_URI],
    })
    const target = await buildClientErrorRedirect({
      clientId: CLIENT_ID,
      pdsUrl: PDS_URL,
      code: 'access_denied',
      description: 'Sign-in took too long.',
    })
    expect(target).not.toBeNull()
    const url = new URL(target!)
    expect(url.origin + url.pathname).toBe(REDIRECT_URI)
    expect(url.searchParams.get('error')).toBe('access_denied')
    expect(url.searchParams.get('error_description')).toBe(
      'Sign-in took too long.',
    )
    expect(url.searchParams.get('iss')).toBe(PDS_URL)
    expect(url.searchParams.has('state')).toBe(false)
  })

  it('preserves state when supplied', async () => {
    resolveClientMetadataMock.mockResolvedValueOnce({
      redirect_uris: [REDIRECT_URI],
    })
    const target = await buildClientErrorRedirect({
      clientId: CLIENT_ID,
      pdsUrl: PDS_URL,
      code: 'server_error',
      description: 'Internal error.',
      state: 'XNMi-ebr4JAUAEWa-52HEA',
    })
    const url = new URL(target!)
    expect(url.searchParams.get('state')).toBe('XNMi-ebr4JAUAEWa-52HEA')
    expect(url.searchParams.get('error')).toBe('server_error')
  })

  it('returns null when resolveClientMetadata throws', async () => {
    resolveClientMetadataMock.mockRejectedValueOnce(
      new Error('network unreachable'),
    )
    const target = await buildClientErrorRedirect({
      clientId: CLIENT_ID,
      pdsUrl: PDS_URL,
      code: 'access_denied',
      description: 'd',
    })
    expect(target).toBeNull()
  })

  it('returns null when metadata has no redirect_uris', async () => {
    resolveClientMetadataMock.mockResolvedValueOnce({})
    const target = await buildClientErrorRedirect({
      clientId: CLIENT_ID,
      pdsUrl: PDS_URL,
      code: 'access_denied',
      description: 'd',
    })
    expect(target).toBeNull()
  })

  it('returns null when redirect_uris is empty', async () => {
    resolveClientMetadataMock.mockResolvedValueOnce({ redirect_uris: [] })
    const target = await buildClientErrorRedirect({
      clientId: CLIENT_ID,
      pdsUrl: PDS_URL,
      code: 'access_denied',
      description: 'd',
    })
    expect(target).toBeNull()
  })

  it('returns null when redirect_uris[0] is not a valid URL', async () => {
    resolveClientMetadataMock.mockResolvedValueOnce({
      redirect_uris: ['not a url at all'],
    })
    const target = await buildClientErrorRedirect({
      clientId: CLIENT_ID,
      pdsUrl: PDS_URL,
      code: 'access_denied',
      description: 'd',
    })
    expect(target).toBeNull()
  })

  it('rejects a redirect_uris[0] with a non-http(s) scheme', async () => {
    // Defence in depth — atproto upstream validates redirect_uris at
    // PAR creation, but the catch path that calls this helper exists
    // precisely to spare the user a 500. An unhandled `javascript:`
    // redirect would defeat that purpose.
    resolveClientMetadataMock.mockResolvedValueOnce({
      redirect_uris: ['javascript:alert(1)'],
    })
    const target = await buildClientErrorRedirect({
      clientId: CLIENT_ID,
      pdsUrl: PDS_URL,
      code: 'access_denied',
      description: 'd',
    })
    expect(target).toBeNull()
  })

  it('accepts http:// (for localhost dev loops)', async () => {
    resolveClientMetadataMock.mockResolvedValueOnce({
      redirect_uris: ['http://localhost:3002/api/oauth/callback'],
    })
    const target = await buildClientErrorRedirect({
      clientId: CLIENT_ID,
      pdsUrl: PDS_URL,
      code: 'access_denied',
      description: 'd',
    })
    expect(target).not.toBeNull()
    expect(target!.startsWith('http://localhost:3002/')).toBe(true)
  })

  it('uses redirect_uris[0] when multiple are registered', async () => {
    // Documented limitation: the dead-PAR path lost the in-flight choice
    // of which URI the client used. Pinning [0] is RFC-compliant ("any
    // registered URI") but loses correlation. See the deferred Copilot
    // threads on PR #154 for the full rationale.
    resolveClientMetadataMock.mockResolvedValueOnce({
      redirect_uris: ['https://demo.example/cb-1', 'https://demo.example/cb-2'],
    })
    const target = await buildClientErrorRedirect({
      clientId: CLIENT_ID,
      pdsUrl: PDS_URL,
      code: 'access_denied',
      description: 'd',
    })
    const url = new URL(target!)
    expect(url.pathname).toBe('/cb-1')
  })
})
