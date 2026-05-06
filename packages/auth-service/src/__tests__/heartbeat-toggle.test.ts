/**
 * Tests for the server-side and rendered-page sides of the PAR-heartbeat
 * test toggle.
 *
 * Two surfaces:
 *   1. heartbeatEnabledFor(req) — the function login-page.ts and
 *      recovery.ts call to decide whether to inline the heartbeat
 *      fetch into the page.
 *   2. The rendered HTML — a smoke test that proves the OTP form and
 *      recovery OTP form actually contain (or omit) the /auth/ping
 *      fetch wired up by the toggle.
 */
import { describe, it, expect, afterEach } from 'vitest'
import type { Request } from 'express'
import { heartbeatEnabledFor, renderLoginPage } from '../routes/login-page.js'
import { renderRecoveryOtpForm } from '../routes/recovery.js'

const ORIGINAL_TEST_HOOKS = process.env.EPDS_TEST_HOOKS

afterEach(() => {
  if (ORIGINAL_TEST_HOOKS === undefined) delete process.env.EPDS_TEST_HOOKS
  else process.env.EPDS_TEST_HOOKS = ORIGINAL_TEST_HOOKS
})

function reqWith(query: Record<string, string>): Request {
  return { query, body: undefined } as unknown as Request
}

function reqWithBody(body: Record<string, string>): Request {
  return { query: {}, body } as unknown as Request
}

describe('heartbeatEnabledFor', () => {
  it('is enabled by default in production (no test hooks)', () => {
    delete process.env.EPDS_TEST_HOOKS
    expect(heartbeatEnabledFor(reqWith({}))).toBe(true)
  })

  it('ignores no_heartbeat=1 when EPDS_TEST_HOOKS is unset', () => {
    delete process.env.EPDS_TEST_HOOKS
    expect(heartbeatEnabledFor(reqWith({ no_heartbeat: '1' }))).toBe(true)
  })

  it('is enabled when EPDS_TEST_HOOKS=1 but no_heartbeat is unset', () => {
    process.env.EPDS_TEST_HOOKS = '1'
    expect(heartbeatEnabledFor(reqWith({}))).toBe(true)
  })

  it('is disabled when both EPDS_TEST_HOOKS=1 AND no_heartbeat=1', () => {
    process.env.EPDS_TEST_HOOKS = '1'
    expect(heartbeatEnabledFor(reqWith({ no_heartbeat: '1' }))).toBe(false)
  })

  it('does not match arbitrary truthy no_heartbeat values', () => {
    // Tighten the toggle: only '1' disables. Anything else (incl. 'true')
    // is treated as a no-op rather than a footgun.
    process.env.EPDS_TEST_HOOKS = '1'
    expect(heartbeatEnabledFor(reqWith({ no_heartbeat: 'true' }))).toBe(true)
  })

  it('honours no_heartbeat=1 in form-encoded request bodies', () => {
    // The recovery flow's POST handlers re-render the form from
    // body fields, not query params, so the toggle must work
    // through req.body for symmetry with req.query.
    process.env.EPDS_TEST_HOOKS = '1'
    expect(heartbeatEnabledFor(reqWithBody({ no_heartbeat: '1' }))).toBe(false)
  })

  it('treats body.no_heartbeat as disabled only on the literal string "1"', () => {
    process.env.EPDS_TEST_HOOKS = '1'
    expect(heartbeatEnabledFor(reqWithBody({ no_heartbeat: 'true' }))).toBe(
      true,
    )
    expect(heartbeatEnabledFor(reqWithBody({}))).toBe(true)
  })

  it('ignores body.no_heartbeat when EPDS_TEST_HOOKS is unset', () => {
    delete process.env.EPDS_TEST_HOOKS
    expect(heartbeatEnabledFor(reqWithBody({ no_heartbeat: '1' }))).toBe(true)
  })
})

function renderLoginPageWithHeartbeat(heartbeatEnabled: boolean): string {
  return renderLoginPage({
    flowId: 'flow-1',
    clientId: 'https://example.com/client-metadata.json',
    clientName: 'Example',
    branding: {},
    customCss: null,
    customFaviconUrl: null,
    customFaviconUrlDark: null,
    loginHint: '',
    initialStep: 'email',
    otpAlreadySent: false,
    csrfToken: 'csrf',
    authBasePath: '/api/auth',
    pdsPublicUrl: 'https://pds.example.com',
    otpLength: 6,
    otpCharset: 'numeric',
    heartbeatEnabled,
  })
}

function renderRecoveryOtpFormWithHeartbeat(heartbeatEnabled: boolean): string {
  return renderRecoveryOtpForm({
    email: 'user@example.com',
    csrfToken: 'csrf',
    requestUri: 'urn:ietf:params:oauth:request_uri:req-abc',
    otpLength: 6,
    otpCharset: 'numeric',
    heartbeatEnabled,
  })
}

describe('renderLoginPage heartbeat wiring', () => {
  it('inlines /auth/ping when heartbeat is enabled', () => {
    const html = renderLoginPageWithHeartbeat(true)
    expect(html).toContain("'/auth/ping'")
    expect(html).toContain('var heartbeatEnabled = true;')
  })

  it('emits a disabled flag when heartbeat is off', () => {
    const html = renderLoginPageWithHeartbeat(false)
    expect(html).toContain('var heartbeatEnabled = false;')
    // The fetch literal is still in the bundle, gated at runtime by
    // the flag — that's fine and matches how the IIFE composes.
    // What matters: the flag is false.
  })
})

describe('renderRecoveryOtpForm heartbeat wiring', () => {
  it('inlines /auth/ping when heartbeat is enabled', () => {
    const html = renderRecoveryOtpFormWithHeartbeat(true)
    expect(html).toContain("'/auth/ping'")
    // The if-guard at the top of the recovery script reads the flag
    // and bails when false, so check the flag's compile-time value.
    expect(html).toContain('if (!true) return;')
  })

  it('emits an early-return guard when heartbeat is off', () => {
    const html = renderRecoveryOtpFormWithHeartbeat(false)
    expect(html).toContain('if (!false) return;')
  })
})
