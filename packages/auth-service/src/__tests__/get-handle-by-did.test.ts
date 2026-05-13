/**
 * Tests for getHandleByDid().
 *
 * This helper calls the PDS's public describeRepo XRPC endpoint to look
 * up the current handle for a DID. Used by the account-settings page to
 * show the user their authoritative handle before offering the update
 * form. Must degrade to null on any error — the settings page falls back
 * to `(unknown)` rather than breaking the whole page.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { getHandleByDid } from '../lib/get-handle-by-did.js'

const PDS_URL = 'https://core:3000'
const DID = 'did:plc:abc123'

let fetchSpy: ReturnType<typeof vi.spyOn>

beforeEach(() => {
  fetchSpy = vi.spyOn(globalThis, 'fetch')
})

afterEach(() => {
  fetchSpy.mockRestore()
})

describe('getHandleByDid', () => {
  it('returns the handle when describeRepo succeeds', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ did: DID, handle: 'alice.pds.test' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    const result = await getHandleByDid(DID, PDS_URL)

    expect(result).toBe('alice.pds.test')
    expect(fetchSpy).toHaveBeenCalledOnce()
    expect(fetchSpy).toHaveBeenCalledWith(
      `${PDS_URL}/xrpc/com.atproto.repo.describeRepo?repo=did%3Aplc%3Aabc123`,
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    )
  })

  it('returns null when describeRepo returns no handle field', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ did: DID }), { status: 200 }),
    )

    const result = await getHandleByDid(DID, PDS_URL)

    expect(result).toBeNull()
  })

  it('returns null when handle field is not a string', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ did: DID, handle: 42 }), { status: 200 }),
    )

    const result = await getHandleByDid(DID, PDS_URL)

    expect(result).toBeNull()
  })

  it('returns null on non-OK HTTP response', async () => {
    fetchSpy.mockResolvedValueOnce(new Response('Bad Request', { status: 400 }))

    const result = await getHandleByDid(DID, PDS_URL)

    expect(result).toBeNull()
  })

  it('returns null when the repo is not found (404)', async () => {
    fetchSpy.mockResolvedValueOnce(new Response('Not Found', { status: 404 }))

    const result = await getHandleByDid(DID, PDS_URL)

    expect(result).toBeNull()
  })

  it('returns null on 500 server error', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response('Internal Server Error', { status: 500 }),
    )

    const result = await getHandleByDid(DID, PDS_URL)

    expect(result).toBeNull()
  })

  it('returns null on network error (fetch throws)', async () => {
    fetchSpy.mockRejectedValueOnce(new Error('ECONNREFUSED'))

    const result = await getHandleByDid(DID, PDS_URL)

    expect(result).toBeNull()
  })

  it('returns null on timeout', async () => {
    fetchSpy.mockRejectedValueOnce(new DOMException('Aborted', 'AbortError'))

    const result = await getHandleByDid(DID, PDS_URL)

    expect(result).toBeNull()
  })

  it('URL-encodes the DID in the query string', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ handle: 'x.pds.test' }), { status: 200 }),
    )

    await getHandleByDid('did:web:example.com:user', PDS_URL)

    expect(fetchSpy).toHaveBeenCalledWith(
      `${PDS_URL}/xrpc/com.atproto.repo.describeRepo?repo=did%3Aweb%3Aexample.com%3Auser`,
      expect.anything(),
    )
  })

  it('works with different PDS URLs', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ handle: 'bob.example.com' }), {
        status: 200,
      }),
    )

    const result = await getHandleByDid(DID, 'https://pds.example.com')

    expect(result).toBe('bob.example.com')
    expect(fetchSpy).toHaveBeenCalledWith(
      'https://pds.example.com/xrpc/com.atproto.repo.describeRepo?repo=did%3Aplc%3Aabc123',
      expect.anything(),
    )
  })

  it('includes AbortSignal with timeout in request', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ handle: 'x.pds.test' }), { status: 200 }),
    )

    await getHandleByDid(DID, PDS_URL)

    const callArgs = fetchSpy.mock.calls[0]
    const options = callArgs[1] as RequestInit
    expect(options.signal).toBeInstanceOf(AbortSignal)
  })

  it('returns null when response body is not JSON', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response('<html>not json</html>', {
        status: 200,
        headers: { 'Content-Type': 'text/html' },
      }),
    )

    const result = await getHandleByDid(DID, PDS_URL)

    expect(result).toBeNull()
  })
})
