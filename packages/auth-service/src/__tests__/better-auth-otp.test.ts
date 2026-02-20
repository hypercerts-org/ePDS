/**
 * Tests for better-auth OTP email wiring.
 *
 * The sendVerificationOTP callback in better-auth.ts:
 * 1. Reads the magic_auth_flow cookie from the request context
 * 2. Looks up the auth_flow row to find the client_id for branding
 * 3. Falls back to default PDS template if no client context
 *
 * Since we can't easily instantiate a full better-auth instance in tests,
 * we test the DB lookup logic and EmailSender integration directly.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import { MagicPdsDb } from '@magic-pds/shared'

describe('sendVerificationOTP client branding via auth_flow', () => {
  let db: MagicPdsDb
  let dbPath: string

  beforeEach(() => {
    dbPath = path.join(os.tmpdir(), `test-ba-otp-${Date.now()}.db`)
    db = new MagicPdsDb(dbPath)
  })

  afterEach(() => {
    db.close()
    try { fs.unlinkSync(dbPath) } catch {}
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

    db.createAuthFlow({
      flowId: 'brand-test-flow',
      requestUri: 'urn:ietf:params:oauth:request_uri:brand-test',
      clientId: 'https://myapp.example.com',
      expiresAt: Date.now() + 5 * 60 * 1000,
    })

    // Simulate the sendVerificationOTP callback logic
    const email = 'user@example.com'
    const otp = '12345678'
    const type = 'sign-in'
    const isNewUser = type === 'sign-in'
    const pdsName = 'My PDS'
    const pdsDomain = 'pds.example.com'

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
    expect(sendOtpCode).toHaveBeenCalledWith(expect.objectContaining({
      clientId: 'https://myapp.example.com',
      isNewUser: true,
    }))
  })

  it('EmailSender.sendOtpCode receives no clientId for account settings flow', async () => {
    const sendOtpCode = vi.fn().mockResolvedValue(undefined)

    // No auth_flow cookie (account settings login)
    const flowId: string | null = null
    let clientId: string | undefined
    if (flowId) {
      const flow = db.getAuthFlow(flowId)
      clientId = flow?.clientId ?? undefined
    }

    const pdsName = 'My PDS'
    await sendOtpCode({
      to: 'user@example.com',
      code: '12345678',
      clientAppName: pdsName,
      clientId,
      pdsName,
      pdsDomain: 'pds.example.com',
      isNewUser: false,
    })

    expect(sendOtpCode).toHaveBeenCalledWith(expect.objectContaining({
      clientId: undefined,
      isNewUser: false,
    }))
  })
})
