/**
 * Tests for resolveRecoveryEmail().
 *
 * This helper is called from /auth/complete when the better-auth session's
 * verified email does not map to a PDS primary account. It looks up the
 * DID in the auth-service backup_email table and then resolves DID →
 * primary email via pds-core's /_internal/account-by-handle endpoint.
 * Returns null on any failure so the caller can fall through to the
 * "new account" branch.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import type { AuthServiceContext } from '../context.js'
import { resolveRecoveryEmail } from '../lib/resolve-recovery-email.js'

const PDS_URL = 'https://core:3000'
const SECRET = 'test-internal-secret'
const BACKUP_EMAIL = 'backup@example.com'
const DID = 'did:plc:abc123'
const PRIMARY_EMAIL = 'alice@example.com'

type MockCtx = Pick<AuthServiceContext, 'db'>

function makeCtx(did: string | undefined): MockCtx {
  return {
    db: {
      getDidByBackupEmail: vi.fn().mockReturnValue(did),
    } as unknown as AuthServiceContext['db'],
  }
}

let fetchSpy: ReturnType<typeof vi.spyOn>

beforeEach(() => {
  fetchSpy = vi.spyOn(globalThis, 'fetch')
})

afterEach(() => {
  fetchSpy.mockRestore()
})

describe('resolveRecoveryEmail', () => {
  it('translates a registered backup email to {email, did}', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ email: PRIMARY_EMAIL }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    const ctx = makeCtx(DID) as AuthServiceContext
    const result = await resolveRecoveryEmail(
      BACKUP_EMAIL,
      ctx,
      PDS_URL,
      SECRET,
    )

    expect(result).toEqual({ email: PRIMARY_EMAIL, did: DID })
    // eslint-disable-next-line @typescript-eslint/unbound-method -- vi.fn() method access for assertion, not a call
    expect(ctx.db.getDidByBackupEmail).toHaveBeenCalledWith(BACKUP_EMAIL)
    expect(fetchSpy).toHaveBeenCalledOnce()
    const [url, opts] = fetchSpy.mock.calls[0]
    expect(url).toBe(
      `${PDS_URL}/_internal/account-by-handle?handle=${encodeURIComponent(DID)}`,
    )
    expect((opts as RequestInit).headers).toEqual({
      'x-internal-secret': SECRET,
    })
  })

  it('lowercases the resolved primary email', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ email: 'Alice@Example.COM' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    const ctx = makeCtx(DID) as AuthServiceContext
    const result = await resolveRecoveryEmail(
      BACKUP_EMAIL,
      ctx,
      PDS_URL,
      SECRET,
    )

    expect(result).toEqual({ email: 'alice@example.com', did: DID })
  })

  it('returns null when the backup email is not registered', async () => {
    const ctx = makeCtx(undefined) as AuthServiceContext
    const result = await resolveRecoveryEmail(
      'unknown@example.com',
      ctx,
      PDS_URL,
      SECRET,
    )

    expect(result).toBeNull()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('returns null when the DID has no primary email on the PDS', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ email: null }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    const ctx = makeCtx(DID) as AuthServiceContext
    const result = await resolveRecoveryEmail(
      BACKUP_EMAIL,
      ctx,
      PDS_URL,
      SECRET,
    )

    expect(result).toBeNull()
  })

  it('returns null when the PDS internal API returns a non-OK status', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response('Internal server error', { status: 500 }),
    )

    const ctx = makeCtx(DID) as AuthServiceContext
    const result = await resolveRecoveryEmail(
      BACKUP_EMAIL,
      ctx,
      PDS_URL,
      SECRET,
    )

    expect(result).toBeNull()
  })

  it('returns null when fetch throws (network error)', async () => {
    fetchSpy.mockRejectedValueOnce(new Error('network down'))

    const ctx = makeCtx(DID) as AuthServiceContext
    const result = await resolveRecoveryEmail(
      BACKUP_EMAIL,
      ctx,
      PDS_URL,
      SECRET,
    )

    expect(result).toBeNull()
  })
})
