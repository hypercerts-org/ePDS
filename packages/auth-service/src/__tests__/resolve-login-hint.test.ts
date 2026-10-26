/**
 * Tests for resolveLoginHint() and fetchParLoginHint().
 *
 * resolveLoginHint() determines whether a login_hint is an email, handle,
 * or DID and resolves it to an email address via pds-core's internal API.
 *
 * fetchParLoginHint() retrieves a login_hint from a stored PAR request
 * on pds-core when the hint isn't on the redirect URL query string.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  resolveLoginHint,
  fetchParLoginHint,
} from '../lib/resolve-login-hint.js'

const PDS_URL = 'http://core:3000'
const SECRET = 'test-internal-secret'

// Spy on global fetch — restored after each test
let fetchSpy: ReturnType<typeof vi.spyOn>

beforeEach(() => {
  fetchSpy = vi.spyOn(globalThis, 'fetch')
})

afterEach(() => {
  fetchSpy.mockRestore()
})

describe('resolveLoginHint', () => {
  it('returns null for empty string', async () => {
    expect(await resolveLoginHint('', PDS_URL, SECRET)).toBeNull()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it.each([
    ['plain', 'user@example.com'],
    ['mixed case', 'User@Example.COM'],
    [
      'plus-addressed on a multi-label domain',
      'first.last+tag@mail.example.co.uk',
    ],
    ['hyphen inside a domain label', 'user@my-example.com'],
  ])(
    'returns a well-formed email hint (%s) directly',
    async (_label, email) => {
      expect(await resolveLoginHint(email, PDS_URL, SECRET)).toBe(email)
      expect(fetchSpy).not.toHaveBeenCalled()
    },
  )

  it.each([
    ['object (?login_hint[a]=b)', { a: 'b' }],
    ['array (?login_hint=a&login_hint=b)', ['a@example.com', 'b']],
    ['number', 42],
  ])(
    'returns null without throwing for a non-string hint (%s)',
    async (_label, hint) => {
      expect(
        await resolveLoginHint(hint as unknown as string, PDS_URL, SECRET),
      ).toBeNull()
      expect(fetchSpy).not.toHaveBeenCalled()
    },
  )

  it.each([
    ['script-closing payload', 'a@</script><script>alert(1)</script>'],
    ['attribute breakout', 'a@example.com"><img src=x onerror=alert(1)>'],
    ['whitespace in domain', 'user@exa mple.com'],
    ['trailing newline', 'user@example.com\n'],
    ['empty local part', '@example.com'],
    ['single-label domain', 'user@example'],
    ['double @', 'user@@example.com'],
    ['empty domain label', 'user@example..com'],
    ['label starting with a hyphen', 'user@-example.com'],
    ['label ending with a hyphen', 'user@example-.com'],
    ['over-long address', `${'a'.repeat(250)}@example.com`],
  ])(
    'returns null for malformed email-shaped hint (%s) without calling the internal API',
    async (_label, hint) => {
      expect(await resolveLoginHint(hint, PDS_URL, SECRET)).toBeNull()
      expect(fetchSpy).not.toHaveBeenCalled()
    },
  )

  it('resolves handle to email via internal API', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ email: 'alice@example.com' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    const result = await resolveLoginHint('alice.pds.example', PDS_URL, SECRET)
    expect(result).toBe('alice@example.com')

    expect(fetchSpy).toHaveBeenCalledOnce()
    const [url, opts] = fetchSpy.mock.calls[0]
    expect(url).toBe(
      `${PDS_URL}/_internal/account-by-handle?handle=alice.pds.example`,
    )
    expect((opts as RequestInit).headers).toEqual({
      'x-internal-secret': SECRET,
    })
  })

  it('resolves DID to email via internal API', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ email: 'bob@example.com' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    const result = await resolveLoginHint('did:plc:abc123', PDS_URL, SECRET)
    expect(result).toBe('bob@example.com')

    const [url] = fetchSpy.mock.calls[0]
    expect(url).toBe(
      `${PDS_URL}/_internal/account-by-handle?handle=did%3Aplc%3Aabc123`,
    )
  })

  it('returns null when internal API returns 404', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'Not found' }), { status: 404 }),
    )

    const result = await resolveLoginHint(
      'unknown.pds.example',
      PDS_URL,
      SECRET,
    )
    expect(result).toBeNull()
  })

  it('returns null when internal API returns 401', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 }),
    )

    const result = await resolveLoginHint('alice.pds.example', PDS_URL, SECRET)
    expect(result).toBeNull()
  })

  it('returns null when internal API returns email: null', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ email: null }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    const result = await resolveLoginHint('alice.pds.example', PDS_URL, SECRET)
    expect(result).toBeNull()
  })

  it('returns null when fetch throws (network error)', async () => {
    fetchSpy.mockRejectedValueOnce(new Error('Connection refused'))

    const result = await resolveLoginHint('alice.pds.example', PDS_URL, SECRET)
    expect(result).toBeNull()
  })

  it('returns null when fetch times out', async () => {
    fetchSpy.mockRejectedValueOnce(new DOMException('Timeout', 'TimeoutError'))

    const result = await resolveLoginHint('alice.pds.example', PDS_URL, SECRET)
    expect(result).toBeNull()
  })

  it('URL-encodes special characters in handle', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ email: null }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    await resolveLoginHint('handle with spaces', PDS_URL, SECRET)

    const [url] = fetchSpy.mock.calls[0]
    expect(url).toBe(
      `${PDS_URL}/_internal/account-by-handle?handle=handle%20with%20spaces`,
    )
  })
})

describe('fetchParLoginHint', () => {
  it('returns login_hint from PAR when present', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ login_hint: 'alice.pds.example' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    const result = await fetchParLoginHint(
      PDS_URL,
      'urn:ietf:params:oauth:request_uri:req-abc123',
      SECRET,
    )
    expect(result).toBe('alice.pds.example')

    const [url, opts] = fetchSpy.mock.calls[0]
    expect(url).toBe(
      `${PDS_URL}/_internal/par-login-hint?request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Areq-abc123`,
    )
    expect((opts as RequestInit).headers).toEqual({
      'x-internal-secret': SECRET,
    })
  })

  it('returns null when PAR has no login_hint', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ login_hint: null }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    const result = await fetchParLoginHint(
      PDS_URL,
      'urn:ietf:params:oauth:request_uri:req-nohint',
      SECRET,
    )
    expect(result).toBeNull()
  })

  it('returns null when request_uri is expired/not found', async () => {
    // pds-core returns { login_hint: null } for missing/expired PAR requests
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ login_hint: null }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    const result = await fetchParLoginHint(
      PDS_URL,
      'urn:ietf:params:oauth:request_uri:req-expired',
      SECRET,
    )
    expect(result).toBeNull()
  })

  it('returns null when internal API returns 401', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 }),
    )

    const result = await fetchParLoginHint(
      PDS_URL,
      'urn:ietf:params:oauth:request_uri:req-abc123',
      SECRET,
    )
    expect(result).toBeNull()
  })

  it('returns null when fetch fails (network error)', async () => {
    fetchSpy.mockRejectedValueOnce(new Error('Connection refused'))

    const result = await fetchParLoginHint(
      PDS_URL,
      'urn:ietf:params:oauth:request_uri:req-abc123',
      SECRET,
    )
    expect(result).toBeNull()
  })

  it('returns null when fetch times out (hairpin NAT / missing PDS_INTERNAL_URL)', async () => {
    fetchSpy.mockRejectedValueOnce(
      new DOMException(
        'The operation was aborted due to timeout',
        'TimeoutError',
      ),
    )

    const result = await fetchParLoginHint(
      PDS_URL,
      'urn:ietf:params:oauth:request_uri:req-abc123',
      SECRET,
    )
    expect(result).toBeNull()
  })
})
