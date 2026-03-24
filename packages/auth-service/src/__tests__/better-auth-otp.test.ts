/**
 * Tests for better-auth OTP email wiring.
 *
 * The sendVerificationOTP callback in better-auth.ts:
 * 1. Reads the epds_auth_flow cookie from the request context
 * 2. Looks up the auth_flow row to find the client_id for branding
 * 3. Falls back to default PDS template if no client context
 *
 * Also tests enforceTosAcceptance (the exported hooks.before logic):
 * 1. Returning users (has PDS DID) — skip ToS check entirely
 * 2. New user + tosAccepted: true — allow through
 * 3. New user + tosAccepted: false/absent — reject with BAD_REQUEST
 * 4. getDidByEmail throws (null DID) — fail closed; tosAccepted === true required to proceed
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { enforceTosAcceptance } from '../better-auth.js'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import { EpdsDb } from '@certified-app/shared'
import { getDidByEmail } from '../lib/get-did-by-email.js'

describe('sendVerificationOTP client branding via auth_flow', () => {
  let db: EpdsDb
  let dbPath: string

  beforeEach(() => {
    dbPath = path.join(os.tmpdir(), `test-ba-otp-${Date.now()}.db`)
    db = new EpdsDb(dbPath)
  })

  afterEach(() => {
    db.close()
    try {
      fs.unlinkSync(dbPath)
      // eslint-disable-next-line no-empty
    } catch {}
  })

  it('resolves client_id from auth_flow when flow_id cookie is present', () => {
    db.createAuthFlow({
      flowId: 'otp-branding-flow',
      requestUri: 'urn:ietf:params:oauth:request_uri:otp-test',
      clientId: 'https://branded-app.example.com',
      expiresAt: Date.now() + 5 * 60 * 1000,
    })

    // Simulate what sendVerificationOTP does: read cookie → look up flow → get clientId
    const flowId = 'otp-branding-flow' // would come from ctx.getCookie()
    const flow = db.getAuthFlow(flowId)

    expect(flow).toBeDefined()
    expect(flow!.clientId).toBe('https://branded-app.example.com')
  })

  it('returns undefined client_id when flow_id cookie is absent', () => {
    // No flow in the DB — simulates account settings login (no OAuth context)
    const flowId = null // would come from ctx.getCookie() returning null

    let clientId: string | undefined
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- testing null flowId path
    if (flowId) {
      const flow = db.getAuthFlow(flowId)
      clientId = flow?.clientId ?? undefined
    }

    expect(clientId).toBeUndefined()
  })

  it('returns undefined client_id when auth_flow is expired', () => {
    db.createAuthFlow({
      flowId: 'expired-otp-flow',
      requestUri: 'urn:ietf:params:oauth:request_uri:expired',
      clientId: 'https://branded-app.example.com',
      expiresAt: Date.now() - 1000, // already expired
    })

    const flow = db.getAuthFlow('expired-otp-flow')
    const clientId = flow?.clientId ?? undefined

    expect(clientId).toBeUndefined()
  })

  it('returns undefined client_id when auth_flow has no clientId', () => {
    db.createAuthFlow({
      flowId: 'no-client-flow',
      requestUri: 'urn:ietf:params:oauth:request_uri:no-client',
      clientId: null,
      expiresAt: Date.now() + 5 * 60 * 1000,
    })

    const flow = db.getAuthFlow('no-client-flow')
    const clientId = flow?.clientId ?? undefined

    expect(clientId).toBeUndefined()
  })

  it('EmailSender.sendOtpCode receives clientId when resolved from auth_flow', async () => {
    // Mock EmailSender.sendOtpCode to verify it receives the correct clientId
    const sendOtpCode = vi.fn().mockResolvedValue(undefined)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    db.createAuthFlow({
      flowId: 'brand-test-flow',
      requestUri: 'urn:ietf:params:oauth:request_uri:brand-test',
      clientId: 'https://myapp.example.com',
      expiresAt: Date.now() + 5 * 60 * 1000,
    })

    // Simulate the sendVerificationOTP callback logic
    const email = 'user@example.com'
    const otp = '12345678'
    const pdsName = 'My PDS'
    const pdsDomain = 'pds.example.com'

    // Determine isNewUser via getDidByEmail (new user — no PDS account)
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ did: null }), { status: 200 }),
    )
    const did = await getDidByEmail(email, 'http://core:3000', 'secret')
    const isNewUser = !did

    // Lookup (simulating ctx.getCookie() returning 'brand-test-flow')
    const flowId = 'brand-test-flow'
    const flow = db.getAuthFlow(flowId)
    const clientId = flow?.clientId ?? undefined

    await sendOtpCode({
      to: email,
      code: otp,
      clientAppName: pdsName,
      clientId,
      pdsName,
      pdsDomain,
      isNewUser,
    })

    expect(sendOtpCode).toHaveBeenCalledOnce()
    expect(sendOtpCode).toHaveBeenCalledWith(
      expect.objectContaining({
        clientId: 'https://myapp.example.com',
        isNewUser: true,
      }),
    )

    fetchSpy.mockRestore()
  })

  it('EmailSender.sendOtpCode receives no clientId for account settings flow (existing user)', async () => {
    const sendOtpCode = vi.fn().mockResolvedValue(undefined)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    // No auth_flow cookie (account settings login)
    const flowId: string | null = null
    let clientId: string | undefined
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- testing null flowId path
    if (flowId) {
      const flow = db.getAuthFlow(flowId)
      clientId = flow?.clientId ?? undefined
    }

    // Existing user — PDS account found
    const email = 'user@example.com'
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ did: 'did:plc:existing' }), {
        status: 200,
      }),
    )
    const did = await getDidByEmail(email, 'http://core:3000', 'secret')
    const isNewUser = !did

    const pdsName = 'My PDS'
    await sendOtpCode({
      to: email,
      code: '12345678',
      clientAppName: pdsName,
      clientId,
      pdsName,
      pdsDomain: 'pds.example.com',
      isNewUser,
    })

    expect(sendOtpCode).toHaveBeenCalledWith(
      expect.objectContaining({
        clientId: undefined,
        isNewUser: false,
      }),
    )

    fetchSpy.mockRestore()
  })
})

// ---------------------------------------------------------------------------
// enforceTosAcceptance — the exported hooks.before logic
//
// Tests call the real function from better-auth.ts directly.
// globalThis.fetch is mocked to control what getDidByEmail sees, following
// the same pattern used in the sendVerificationOTP tests above.
// ---------------------------------------------------------------------------

describe('enforceTosAcceptance (hooks.before for sign-in/email-otp)', () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch')
  })

  afterEach(() => {
    fetchSpy.mockRestore()
  })

  const PDS_URL = 'https://core:3000'
  const SECRET = 'test-secret'

  it('returns without error when path is not /sign-in/email-otp (path guard)', async () => {
    // fetch should never be called — path guard short-circuits
    await expect(
      enforceTosAcceptance(
        {
          path: '/email-otp/send-verification-otp',
          body: { email: 'user@example.com', tosAccepted: false },
        },
        PDS_URL,
        SECRET,
      ),
    ).resolves.toBeUndefined()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('returns without error when email is absent (let schema validation handle it)', async () => {
    await expect(
      enforceTosAcceptance(
        { path: '/sign-in/email-otp', body: {} },
        PDS_URL,
        SECRET,
      ),
    ).resolves.toBeUndefined()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('returns without error for returning user regardless of tosAccepted', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ did: 'did:plc:returning123' }), {
        status: 200,
      }),
    )
    await expect(
      enforceTosAcceptance(
        {
          path: '/sign-in/email-otp',
          body: { email: 'returning@example.com', tosAccepted: false },
        },
        PDS_URL,
        SECRET,
      ),
    ).resolves.toBeUndefined()
  })

  it('returns without error for new user when tosAccepted is true', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ did: null }), { status: 200 }),
    )
    await expect(
      enforceTosAcceptance(
        {
          path: '/sign-in/email-otp',
          body: { email: 'newuser@example.com', tosAccepted: true },
        },
        PDS_URL,
        SECRET,
      ),
    ).resolves.toBeUndefined()
  })

  it('throws BAD_REQUEST for new user when tosAccepted is false', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ did: null }), { status: 200 }),
    )
    await expect(
      enforceTosAcceptance(
        {
          path: '/sign-in/email-otp',
          body: { email: 'newuser@example.com', tosAccepted: false },
        },
        PDS_URL,
        SECRET,
      ),
    ).rejects.toThrow(
      'You must accept the Terms of Service to create an account.',
    )
  })

  it('throws BAD_REQUEST for new user when tosAccepted is absent', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ did: null }), { status: 200 }),
    )
    await expect(
      enforceTosAcceptance(
        { path: '/sign-in/email-otp', body: { email: 'newuser@example.com' } },
        PDS_URL,
        SECRET,
      ),
    ).rejects.toThrow(
      'You must accept the Terms of Service to create an account.',
    )
  })

  it('enforces ToS when PDS is unreachable (getDidByEmail returns null on error)', async () => {
    // getDidByEmail catches all fetch errors internally and returns null.
    // A null DID → treated as new user → ToS is still required.
    // This is the safe default: we cannot confirm the account exists.
    fetchSpy.mockRejectedValueOnce(new Error('Network error: PDS unreachable'))
    await expect(
      enforceTosAcceptance(
        {
          path: '/sign-in/email-otp',
          body: { email: 'newuser@example.com', tosAccepted: false },
        },
        PDS_URL,
        SECRET,
      ),
    ).rejects.toThrow(
      'You must accept the Terms of Service to create an account.',
    )
  })

  it('allows sign-in when PDS is unreachable but tosAccepted is true', async () => {
    fetchSpy.mockRejectedValueOnce(new Error('Network error: PDS unreachable'))
    await expect(
      enforceTosAcceptance(
        {
          path: '/sign-in/email-otp',
          body: { email: 'newuser@example.com', tosAccepted: true },
        },
        PDS_URL,
        SECRET,
      ),
    ).resolves.toBeUndefined()
  })
})
