/**
 * Tests for fetchDeviceAccountEmails().
 *
 * Calls pds-core's /_internal/device-accounts endpoint to enumerate
 * the emails bound to a given (dev-id, ses-id) cookie pair, returning
 * null on any failure so callers can fall back to the email/OTP form.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchDeviceAccountEmails } from '../lib/fetch-device-accounts.js'

const PDS_URL = 'http://core:3000' // NOSONAR — intentional: docker-compose internal hostname for the unit test
const SECRET = 'test-internal-secret'
const DEV = 'dev-0123456789abcdef0123456789abcdef'
const SES = 'ses-fedcba9876543210fedcba9876543210'

let fetchSpy: ReturnType<typeof vi.spyOn>

beforeEach(() => {
  fetchSpy = vi.spyOn(globalThis, 'fetch')
})

afterEach(() => {
  fetchSpy.mockRestore()
})

describe('fetchDeviceAccountEmails', () => {
  it('returns the emails array on a 200 with a non-null payload', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ emails: ['alice@example.com', 'bob@example.com'] }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    expect(await fetchDeviceAccountEmails(PDS_URL, DEV, SES, SECRET)).toEqual([
      'alice@example.com',
      'bob@example.com',
    ])

    const [url, opts] = fetchSpy.mock.calls[0]
    expect(url).toBe(
      `${PDS_URL}/_internal/device-accounts?dev_id=${DEV}&ses_id=${SES}`,
    )
    expect((opts as RequestInit).headers).toEqual({
      'x-internal-secret': SECRET,
    })
  })

  it('returns null when the payload reports null emails (stale cookie pair)', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ emails: null }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    expect(await fetchDeviceAccountEmails(PDS_URL, DEV, SES, SECRET)).toBeNull()
  })

  it('returns an empty array when the device has no bindings', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ emails: [] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    expect(await fetchDeviceAccountEmails(PDS_URL, DEV, SES, SECRET)).toEqual(
      [],
    )
  })

  it('returns null when the endpoint responds non-2xx', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response('Unauthorized', { status: 401 }),
    )
    expect(await fetchDeviceAccountEmails(PDS_URL, DEV, SES, SECRET)).toBeNull()
  })

  it('returns null when fetch rejects', async () => {
    fetchSpy.mockRejectedValueOnce(new Error('network down'))
    expect(await fetchDeviceAccountEmails(PDS_URL, DEV, SES, SECRET)).toBeNull()
  })

  it('returns null without calling fetch when devId is empty', async () => {
    expect(await fetchDeviceAccountEmails(PDS_URL, '', SES, SECRET)).toBeNull()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('returns null without calling fetch when sesId is empty', async () => {
    expect(await fetchDeviceAccountEmails(PDS_URL, DEV, '', SECRET)).toBeNull()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('URL-encodes dev_id and ses_id', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ emails: [] }), { status: 200 }),
    )
    await fetchDeviceAccountEmails(
      PDS_URL,
      'dev with space',
      'ses+plus',
      SECRET,
    )
    const [url] = fetchSpy.mock.calls[0]
    expect(url).toBe(
      `${PDS_URL}/_internal/device-accounts?dev_id=dev%20with%20space&ses_id=ses%2Bplus`,
    )
  })
})
