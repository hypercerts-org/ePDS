/**
 * Tests for pingParRequest().
 *
 * This function calls pds-core's /_internal/ping-request endpoint to
 * reset the inactivity timer on a pending PAR request_uri, preventing
 * "This request has expired" errors in users who take >5 min on
 * intermediate pages (handle picker, OTP, etc.).
 *
 * The function never throws or logs — it returns a plain result object
 * so each call site decides on severity and message.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { pingParRequest } from '../lib/ping-par-request.js'

const PDS_URL = 'http://core:3000'
const SECRET = 'test-internal-secret'
const REQUEST_URI = 'urn:ietf:params:oauth:request_uri:req-abc123'

let fetchSpy: ReturnType<typeof vi.spyOn>

beforeEach(() => {
  fetchSpy = vi.spyOn(globalThis, 'fetch')
})

afterEach(() => {
  fetchSpy.mockRestore()
})

describe('pingParRequest', () => {
  it('returns { ok: true } when endpoint responds with 200', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ ok: true }), { status: 200 }),
    )

    const result = await pingParRequest(REQUEST_URI, PDS_URL, SECRET)

    expect(result).toEqual({ ok: true })
  })

  it('returns { ok: false, status: 404 } when request_uri is expired', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'request_expired' }), {
        status: 404,
      }),
    )

    const result = await pingParRequest(REQUEST_URI, PDS_URL, SECRET)

    expect(result).toEqual({ ok: false, status: 404 })
  })

  it('returns { ok: false, status } for other non-OK responses', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response('Internal Server Error', { status: 503 }),
    )

    const result = await pingParRequest(REQUEST_URI, PDS_URL, SECRET)

    expect(result).toEqual({ ok: false, status: 503 })
  })

  it('returns { ok: false, err } on network error', async () => {
    const networkError = new Error('ECONNREFUSED')
    fetchSpy.mockRejectedValueOnce(networkError)

    const result = await pingParRequest(REQUEST_URI, PDS_URL, SECRET)

    expect(result.ok).toBe(false)
    expect((result as { ok: false; err?: unknown }).err).toBe(networkError)
  })

  it('returns { ok: false, err } on timeout (AbortError)', async () => {
    const abortError = new DOMException('Aborted', 'AbortError')
    fetchSpy.mockRejectedValueOnce(abortError)

    const result = await pingParRequest(REQUEST_URI, PDS_URL, SECRET)

    expect(result.ok).toBe(false)
    expect((result as { ok: false; err?: unknown }).err).toBe(abortError)
  })

  it('URL-encodes request_uri in the query string', async () => {
    fetchSpy.mockResolvedValueOnce(new Response('{}', { status: 200 }))

    await pingParRequest(REQUEST_URI, PDS_URL, SECRET)

    expect(fetchSpy).toHaveBeenCalledWith(
      `${PDS_URL}/_internal/ping-request?request_uri=${encodeURIComponent(REQUEST_URI)}`,
      expect.anything(),
    )
  })

  it('passes the x-internal-secret header', async () => {
    fetchSpy.mockResolvedValueOnce(new Response('{}', { status: 200 }))

    await pingParRequest(REQUEST_URI, PDS_URL, 'my-secret-token')

    expect(fetchSpy).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        headers: { 'x-internal-secret': 'my-secret-token' },
      }),
    )
  })

  it('includes an AbortSignal on the request', async () => {
    fetchSpy.mockResolvedValueOnce(new Response('{}', { status: 200 }))

    await pingParRequest(REQUEST_URI, PDS_URL, SECRET)

    const options = fetchSpy.mock.calls[0][1] as RequestInit
    expect(options.signal).toBeInstanceOf(AbortSignal)
  })

  it('works with different pdsUrl values', async () => {
    fetchSpy.mockResolvedValueOnce(new Response('{}', { status: 200 }))

    await pingParRequest(REQUEST_URI, 'https://pds.example.com', SECRET)

    expect(fetchSpy).toHaveBeenCalledWith(
      `https://pds.example.com/_internal/ping-request?request_uri=${encodeURIComponent(REQUEST_URI)}`,
      expect.anything(),
    )
  })
})
