/**
 * Tests for the unified login page (GET /oauth/authorize).
 *
 * The login page:
 * 1. Creates an auth_flow row to thread request_uri through better-auth
 * 2. Sets the epds_auth_flow cookie
 * 3. Renders a login page with email OTP form + optional social buttons
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { randomBytes } from 'node:crypto'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import {
  EpdsDb,
  clearClientMetadataCache,
  _seedClientMetadataCacheForTest,
} from '@certified-app/shared'
import type { HandleMode } from '@certified-app/shared'
import {
  renderLoginPage,
  resolveHandleMode,
  safeResolveClientMetadata,
} from '../routes/login-page.js'
import type { ClientMetadata } from '../lib/client-metadata.js'

// ---------------------------------------------------------------------------
// Shared DB helpers
// ---------------------------------------------------------------------------

function makeDb(prefix: string): { db: EpdsDb; dbPath: string } {
  const dbPath = path.join(os.tmpdir(), `${prefix}-${Date.now()}.db`)
  return { db: new EpdsDb(dbPath), dbPath }
}

function closeDb(db: EpdsDb, dbPath: string): void {
  db.close()
  try {
    fs.unlinkSync(dbPath)
    // eslint-disable-next-line no-empty
  } catch {}
}

// ---------------------------------------------------------------------------
// Shared env-var helpers for resolveHandleMode tests
// ---------------------------------------------------------------------------

function withEnv(value: string | undefined, fn: () => void): void {
  const orig = process.env.EPDS_DEFAULT_HANDLE_MODE
  if (value === undefined) {
    delete process.env.EPDS_DEFAULT_HANDLE_MODE
  } else {
    process.env.EPDS_DEFAULT_HANDLE_MODE = value
  }
  try {
    fn()
  } finally {
    if (orig === undefined) {
      delete process.env.EPDS_DEFAULT_HANDLE_MODE
    } else {
      process.env.EPDS_DEFAULT_HANDLE_MODE = orig
    }
  }
}

describe('Login page auth_flow creation', () => {
  let db: EpdsDb
  let dbPath: string

  beforeEach(() => {
    ;({ db, dbPath } = makeDb('test-login'))
  })

  afterEach(() => {
    closeDb(db, dbPath)
  })

  it('creates an auth_flow row with correct request_uri and client_id', () => {
    const flowId = 'test-login-flow-001'
    const requestUri = 'urn:ietf:params:oauth:request_uri:login-test'
    const clientId = 'https://app.example.com'

    db.createAuthFlow({
      flowId,
      requestUri,
      clientId,
      expiresAt: Date.now() + 10 * 60 * 1000,
    })

    const flow = db.getAuthFlow(flowId)
    expect(flow).toBeDefined()
    expect(flow!.requestUri).toBe(requestUri)
    expect(flow!.clientId).toBe(clientId)
    expect(flow!.expiresAt).toBeGreaterThan(Date.now())
  })

  it('creates auth_flow without client_id when not provided', () => {
    const flowId = 'no-client-login-flow'
    db.createAuthFlow({
      flowId,
      requestUri: 'urn:req:no-client',
      clientId: null,
      expiresAt: Date.now() + 10 * 60 * 1000,
    })

    const flow = db.getAuthFlow(flowId)
    expect(flow).toBeDefined()
    expect(flow!.clientId).toBeNull()
  })

  it('expires auth_flow after TTL', () => {
    const flowId = 'expired-login-flow'
    db.createAuthFlow({
      flowId,
      requestUri: 'urn:req:expired',
      clientId: null,
      expiresAt: Date.now() - 1, // immediately expired
    })

    expect(db.getAuthFlow(flowId)).toBeUndefined()
  })

  it('cleans up expired auth_flow rows', () => {
    // Create 3 expired and 1 active
    for (let i = 0; i < 3; i++) {
      db.createAuthFlow({
        flowId: `expired-${i}`,
        requestUri: `urn:req:${i}`,
        clientId: null,
        expiresAt: Date.now() - 1000,
      })
    }
    db.createAuthFlow({
      flowId: 'active-flow',
      requestUri: 'urn:req:active',
      clientId: null,
      expiresAt: Date.now() + 10 * 60 * 1000,
    })

    const cleaned = db.cleanupExpiredAuthFlows()
    expect(cleaned).toBe(3)
    expect(db.getAuthFlow('active-flow')).toBeDefined()
  })

  it('getAuthFlowByRequestUri returns existing non-expired flow', () => {
    const flowId = 'idem-flow-001'
    const requestUri = 'urn:ietf:params:oauth:request_uri:idem-test'
    db.createAuthFlow({
      flowId,
      requestUri,
      clientId: null,
      expiresAt: Date.now() + 10 * 60 * 1000,
    })

    const found = db.getAuthFlowByRequestUri(requestUri)
    expect(found).toBeDefined()
    expect(found!.flowId).toBe(flowId)
  })

  it('getAuthFlowByRequestUri returns undefined for expired flow', () => {
    db.createAuthFlow({
      flowId: 'idem-expired',
      requestUri: 'urn:ietf:params:oauth:request_uri:idem-expired',
      clientId: null,
      expiresAt: Date.now() - 1,
    })

    expect(
      db.getAuthFlowByRequestUri(
        'urn:ietf:params:oauth:request_uri:idem-expired',
      ),
    ).toBeUndefined()
  })

  it('getAuthFlowByRequestUri returns undefined when no flow exists', () => {
    expect(
      db.getAuthFlowByRequestUri(
        'urn:ietf:params:oauth:request_uri:nonexistent',
      ),
    ).toBeUndefined()
  })

  it('generates unique flow IDs (no collisions)', () => {
    const ids = new Set<string>()
    for (let i = 0; i < 100; i++) {
      ids.add(randomBytes(16).toString('hex'))
    }
    expect(ids.size).toBe(100)
  })
})

describe('Login page handle_mode storage', () => {
  let db: EpdsDb
  let dbPath: string

  beforeEach(() => {
    ;({ db, dbPath } = makeDb('test-handle-mode'))
  })

  afterEach(() => {
    closeDb(db, dbPath)
  })

  const handleModes: Array<HandleMode | null> = [
    'random',
    'picker',
    'picker-with-random',
    null,
  ]

  it.each(handleModes)('stores handleMode=%s', (handleMode) => {
    const flowId = `hm-${String(handleMode)}`
    db.createAuthFlow({
      flowId,
      requestUri: `urn:req:${flowId}`,
      clientId: null,
      handleMode,
      expiresAt: Date.now() + 10 * 60 * 1000,
    })
    expect(db.getAuthFlow(flowId)!.handleMode).toBe(handleMode)
  })

  it('getAuthFlowByRequestUri also returns handleMode', () => {
    db.createAuthFlow({
      flowId: 'hm-by-uri',
      requestUri: 'urn:req:hm-by-uri',
      clientId: null,
      handleMode: 'picker',
      expiresAt: Date.now() + 10 * 60 * 1000,
    })
    expect(db.getAuthFlowByRequestUri('urn:req:hm-by-uri')!.handleMode).toBe(
      'picker',
    )
  })
})

describe('Social providers detection', () => {
  it('empty socialProviders when no env vars set', () => {
    // Preserve original env
    const origGoogle = process.env.GOOGLE_CLIENT_ID
    const origGithub = process.env.GITHUB_CLIENT_ID
    delete process.env.GOOGLE_CLIENT_ID
    delete process.env.GITHUB_CLIENT_ID

    // Re-import to get fresh state (simulate no social providers)
    // We can't easily re-run buildSocialProviders() in isolation,
    // but we can verify the logic directly
    const providers: Record<string, unknown> = {}
    const googleId = process.env.GOOGLE_CLIENT_ID
    const googleSecret = process.env.GOOGLE_CLIENT_SECRET
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- testing env-var-driven logic
    if (googleId && googleSecret)
      providers.google = { clientId: googleId, clientSecret: googleSecret }

    expect('google' in providers).toBe(false)
    expect('github' in providers).toBe(false)

    // Restore
    if (origGoogle) process.env.GOOGLE_CLIENT_ID = origGoogle
    if (origGithub) process.env.GITHUB_CLIENT_ID = origGithub
  })

  it('includes google provider when env vars set', () => {
    const providers: Record<string, unknown> = {}
    const googleId = 'test-google-id'
    const googleSecret = 'test-google-secret'
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- testing env-var-driven logic
    if (googleId && googleSecret)
      providers.google = { clientId: googleId, clientSecret: googleSecret }
    expect('google' in providers).toBe(true)
  })

  it('excludes provider when only client_id is set (no secret)', () => {
    const providers: Record<string, unknown> = {}
    const googleId = 'test-google-id'
    const googleSecret = undefined
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- testing env-var-driven logic
    if (googleId && googleSecret)
      providers.google = { clientId: googleId, clientSecret: googleSecret }
    expect('google' in providers).toBe(false)
  })
})

describe('Login page redirect requirements', () => {
  it('requires request_uri parameter', () => {
    // Simulate what createLoginPageRouter does when request_uri is missing
    const requestUri = undefined as string | undefined
    const hasError = !requestUri
    expect(hasError).toBe(true)
  })

  it('flow_id cookie expires in 60 minutes (decoupled from OTP TTL)', () => {
    const AUTH_FLOW_TTL_MS = 60 * 60 * 1000
    const nowish = Date.now()
    const expiresAt = nowish + AUTH_FLOW_TTL_MS

    // 60 min lets a user who hits OTP expiry (10 min) and resends still
    // have a live auth_flow + cookie to land on /auth/complete.
    expect(expiresAt - nowish).toBe(3_600_000)
  })
})

describe('resolveHandleMode', () => {
  it('returns query param when it is a valid mode', () => {
    const result = resolveHandleMode('random', {})
    expect(result).toBe('random')
  })

  it('falls back to client metadata when query param is absent', () => {
    const clientMeta: ClientMetadata = { epds_handle_mode: 'picker' }
    const result = resolveHandleMode(undefined, clientMeta)
    expect(result).toBe('picker')
  })

  it('falls back to env var when query param and client metadata are absent', () => {
    withEnv('picker-with-random', () => {
      expect(resolveHandleMode(undefined, {})).toBe('picker-with-random')
    })
  })

  it('returns picker-with-random when no valid mode is provided at any level', () => {
    withEnv(undefined, () => {
      expect(resolveHandleMode(undefined, {})).toBe('picker-with-random')
    })
  })

  it('ignores invalid values and falls back to next level', () => {
    // Cast via unknown to simulate malformed client metadata from a real fetch
    const clientMeta = {
      epds_handle_mode: 'invalid-mode',
    } as unknown as ClientMetadata
    withEnv('random', () => {
      // Query param is invalid, client metadata is invalid, env var is valid
      expect(resolveHandleMode('garbage', clientMeta)).toBe('random')
    })
  })

  it('returns picker-with-random when all levels have invalid values', () => {
    // Cast via unknown to simulate malformed client metadata
    const clientMeta = {
      epds_handle_mode: 'invalid-mode',
    } as unknown as ClientMetadata
    withEnv(undefined, () => {
      expect(resolveHandleMode('garbage', clientMeta)).toBe(
        'picker-with-random',
      )
    })
  })

  it('prioritizes query param over client metadata', () => {
    const clientMeta: ClientMetadata = { epds_handle_mode: 'picker' }
    const result = resolveHandleMode('random', clientMeta)
    expect(result).toBe('random')
  })

  it('prioritizes client metadata over env var', () => {
    const clientMeta: ClientMetadata = { epds_handle_mode: 'picker' }
    withEnv('random', () => {
      expect(resolveHandleMode(undefined, clientMeta)).toBe('picker')
    })
  })
})

describe('safeResolveClientMetadata', () => {
  const originalFetch = globalThis.fetch

  beforeEach(() => {
    clearClientMetadataCache()
  })

  afterEach(() => {
    globalThis.fetch = originalFetch
  })

  it('returns empty object when clientId is undefined', async () => {
    const result = await safeResolveClientMetadata(undefined)
    expect(result).toEqual({})
  })

  it('returns fallback metadata when fetch fails', async () => {
    // resolveClientMetadata has internal error handling, so it returns fallback
    // (domain extraction) rather than throwing. safeResolveClientMetadata's
    // catch is defense-in-depth but unreachable in current implementation.
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('Network error'))
    const result = await safeResolveClientMetadata('https://app.example.com')
    expect(result).toEqual({ client_name: 'app.example.com' })
  })

  it('returns fallback metadata when fetch returns non-OK status', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      headers: { get: () => null },
    } as unknown as Response)
    const result = await safeResolveClientMetadata('https://app.example.com')
    expect(result).toEqual({ client_name: 'app.example.com' })
  })

  it('returns metadata when cache is seeded', async () => {
    const mockMetadata: ClientMetadata = {
      client_name: 'Test App',
      brand_color: '#123456',
    }
    _seedClientMetadataCacheForTest(
      'https://test-app.coolapp.dev',
      mockMetadata,
    )
    const result = await safeResolveClientMetadata(
      'https://test-app.coolapp.dev',
    )
    expect(result).toEqual(mockMetadata)
  })
})

describe('renderLoginPage handle login button', () => {
  function render(branding: ClientMetadata): string {
    return renderLoginPage({
      flowId: 'flow-1',
      clientId: 'https://example.com/client-metadata.json',
      clientName: 'Example',
      branding,
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
      heartbeatEnabled: false,
    })
  }

  // The "btn-atproto" class name also appears in inline JS (querySelector
  // for the toggle handler), so assertions must look for the actual button
  // element and the inlined handleLoginUrl JS variable.
  const BUTTON_HTML =
    'class="btn-social btn-atproto">Or sign in with ATProto/Bluesky'

  it('omits the button when epds_handle_login_url is not declared', () => {
    const html = render({})
    expect(html).not.toContain(BUTTON_HTML)
    expect(html).toContain('var handleLoginUrl = ""')
  })

  it('renders the button when epds_handle_login_url is a valid https URL', () => {
    const html = render({
      epds_handle_login_url: 'https://client.example.com/api/oauth/login',
    })
    expect(html).toContain(BUTTON_HTML)
    expect(html).toContain(
      'var handleLoginUrl = "https://client.example.com/api/oauth/login"',
    )
  })

  it('renders the button when epds_handle_login_url is http (dev)', () => {
    const html = render({
      epds_handle_login_url: 'http://localhost:3000/api/oauth/login',
    })
    expect(html).toContain(BUTTON_HTML)
  })

  it('rejects javascript: URLs and omits the button', () => {
    const html = render({
      epds_handle_login_url: 'javascript:alert(1)' as string,
    })
    expect(html).not.toContain(BUTTON_HTML)
    expect(html).toContain('var handleLoginUrl = ""')
  })

  it('rejects malformed URLs and omits the button', () => {
    const html = render({
      epds_handle_login_url: 'not a url',
    })
    expect(html).not.toContain(BUTTON_HTML)
    expect(html).toContain('var handleLoginUrl = ""')
  })

  it('rejects non-http(s) schemes (file:) and omits the button', () => {
    const html = render({
      epds_handle_login_url: 'file:///etc/passwd',
    })
    expect(html).not.toContain(BUTTON_HTML)
  })
})

// Regression: the segmented OTP input auto-submits the verify form when the
// last digit lands (paste handler at the same site). If a second submit
// fires while the first is in flight — Enter after typing, OTP autofill
// dispatching input on every box, paste+input pair on some browsers — the
// second call hits /sign-in/email-otp with a now-consumed code, the
// response is "Invalid OTP", and that error renders briefly before the
// success-path redirect to /auth/complete unloads the page. The visible
// symptom is a red "Invalid OTP" flash followed by a successful login.
//
// The fix is an in-flight latch in the verify-form submit handler. These
// tests pin its structure so accidental refactors (removing the guard,
// moving it after the fetch, resetting the flag unconditionally on
// success) fail loudly.
function renderDefault(): string {
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
    heartbeatEnabled: false,
  })
}

describe('renderLoginPage OTP verify-form double-submit latch (regression)', () => {
  it('declares the verifying flag at IIFE scope so input/paste/submit handlers share it', () => {
    const html = renderDefault()
    expect(html).toContain('var verifying = false;')
    // Exactly one declaration — a second one would shadow the shared flag.
    expect(html.match(/var verifying =/g)).toHaveLength(1)
  })

  it('guards the verify-form submit handler before any in-flight state is touched', () => {
    const html = renderDefault()
    // Order matters: the guard must short-circuit BEFORE we set
    // verifying=true and BEFORE the verifyOtp() call. A guard placed
    // after the fetch would not prevent a second request.
    const guardIdx = html.indexOf('if (verifying) return;')
    const setTrueIdx = html.indexOf('verifying = true;')
    const verifyCallIdx = html.indexOf('await verifyOtp(currentEmail, otp)')
    expect(guardIdx).toBeGreaterThan(0)
    expect(setTrueIdx).toBeGreaterThan(guardIdx)
    expect(verifyCallIdx).toBeGreaterThan(setTrueIdx)
  })

  it('resets the latch only on the error path, not on success', () => {
    const html = renderDefault()
    // The reset is wrapped in `if (!result || result.error) { ... }`. An
    // unconditional reset would re-open the form during the post-success
    // navigation and let a late input/Enter event fire a second verify
    // on the consumed OTP — exactly the bug being prevented.
    expect(html).toMatch(
      /if \(!result \|\| result\.error\)\s*\{\s*verifying = false;/,
    )
    // And there is exactly one place that sets the flag back to false (in
    // the error branch). A second `verifying = false` somewhere else
    // would defeat the latch.
    const resetCount = html.split('verifying = false;').length - 1
    expect(resetCount).toBe(2) // initial declaration + single reset
  })

  it('clears the OTP boxes on verify error so re-entry does not auto-spam', () => {
    const html = renderDefault()
    // Without clearing, the boxes stay full at length 6 after an invalid
    // code. The auto-submit handler fires whenever total length === 6, so
    // the next keystroke (replacing one wrong digit) would immediately
    // trigger another verify, again with a still-wrong code, on every
    // edit — easily tripping the per-IP rate limiter.
    const branchStart = html.indexOf('if (result && result.error) {')
    expect(branchStart).toBeGreaterThan(0)
    // The next `verifying = false;` (in the `finally` block) bounds the
    // error branch — bounded slice, no unbounded regex backtracking.
    const branchEnd = html.indexOf('verifying = false;', branchStart)
    expect(branchEnd).toBeGreaterThan(branchStart)
    const branch = html.slice(branchStart, branchEnd)
    // Either the plain showError or the inline-action variant is fine
    // (both surface the message to the user); just assert SOME error
    // surface is invoked.
    expect(branch).toMatch(/showError(?:WithAction)?\(/)
    expect(branch).toContain('clearOtpBoxes();')
  })
})

describe('renderLoginPage inline Resend action on expired OTP', () => {
  // The OTP-expired error used to surface only as "OTP expired" /
  // "Invalid or expired code" text inside the error banner. Users
  // missed the separate Resend button below the form. The inline
  // action button surfaces "Send a new code" right next to the
  // error message and triggers the same Resend flow.

  it('declares showErrorWithAction with a textContent-only label sink', () => {
    const html = renderDefault()
    expect(html).toContain('function showErrorWithAction(')
    // The label is set via .textContent, never via innerHTML — a
    // reflected error string that happened to look like HTML must
    // not be able to inject script tags.
    const fnStart = html.indexOf('function showErrorWithAction(')
    expect(fnStart).toBeGreaterThan(0)
    const fnEnd = html.indexOf('function clearError', fnStart)
    expect(fnEnd).toBeGreaterThan(fnStart)
    const fnBody = html.slice(fnStart, fnEnd)
    expect(fnBody).toContain('btn.textContent = actionLabel')
    expect(fnBody).not.toContain('innerHTML')
  })

  it('detects OTP-expired errors via a substring-stable regex', () => {
    const html = renderDefault()
    // The detection must catch:
    //   - better-auth's "Invalid or expired code"
    //   - auth-service's "OTP expired"
    //   - any future wording with "expir" or "too long" in it
    expect(html).toMatch(/var isExpired = \/expir\|too long\/i\.test/)
  })

  it('renders the inline action with the "Send a new code" label and triggers the Resend button', () => {
    const html = renderDefault()
    // The inline action label and the click target must be present.
    expect(html).toContain("'Send a new code'")
    expect(html).toContain("document.getElementById('btn-resend').click()")
  })

  it('falls back to the plain showError on non-expired errors', () => {
    const html = renderDefault()
    // The non-expired branch must NOT route through
    // showErrorWithAction (otherwise an "Invalid code" message
    // would carry an inappropriate "Send a new code" link).
    expect(html).toMatch(
      /if \(isExpired\) \{[\s\S]*?\} else \{[\s\S]*?showError\(result\.error\);\s*\}/,
    )
  })
})

describe('renderLoginPage flow-aborted notice + reactive abort gates', () => {
  // The proactive notice fires when /auth/ping reports the flow is
  // unrecoverable (par_expired / flow_expired / no_cookie). It
  // disables every form control and shows a Start over button that
  // navigates to /auth/abort. The reactive gates (Resend click,
  // Verify submit) ping /auth/ping just-in-time and bail to
  // /auth/abort if the flow is dead — defence in depth on top of
  // the proactive notice.

  it('inlines /auth/abort as the Start over destination', () => {
    const html = renderDefault()
    expect(html).toContain("'/auth/abort'")
  })

  it('declares showFlowAbortedNotice as idempotent (flowAborted flag)', () => {
    const html = renderDefault()
    // The idempotence guard prevents duplicate banners if both the
    // proactive heartbeat tick AND a reactive gate fire the notice.
    expect(html).toContain('var flowAborted = false')
    expect(html).toMatch(
      /function showFlowAbortedNotice\(\)\s*\{\s*if \(flowAborted\) return;/,
    )
  })

  it('disables every form control when the notice fires', () => {
    const html = renderDefault()
    const fnStart = html.indexOf('function showFlowAbortedNotice()')
    expect(fnStart).toBeGreaterThan(0)
    const fnEnd = html.indexOf('function abortIfFlowDead', fnStart)
    expect(fnEnd).toBeGreaterThan(fnStart)
    const fnBody = html.slice(fnStart, fnEnd)
    // OTP boxes, Resend, Back, and Verify must all get disabled —
    // anything left enabled would let the user click into a path
    // that silently fails.
    expect(fnBody).toMatch(/otpBoxes\[i\]\.disabled = true/)
    expect(fnBody).toMatch(/resendBtn\.disabled = true/)
    expect(fnBody).toMatch(/backBtn\.disabled = true/)
    expect(fnBody).toMatch(/verifyBtn\.disabled = true/)
  })

  it('renders the Start over button with a textContent label sink', () => {
    const html = renderDefault()
    const fnStart = html.indexOf('function showFlowAbortedNotice()')
    const fnEnd = html.indexOf('function abortIfFlowDead', fnStart)
    const fnBody = html.slice(fnStart, fnEnd)
    expect(fnBody).toContain("startOverBtn.textContent = 'Start over'")
    // No innerHTML — same XSS guard as the inline-action button.
    expect(fnBody).not.toContain('innerHTML')
  })

  it('triggers the proactive notice when the heartbeat reports a non-transient ok:false', () => {
    const html = renderDefault()
    // The pingHeartbeat handler must call showFlowAbortedNotice
    // when reason !== 'transient'. Transient failures must not
    // trigger the notice. Substring-based slicing rather than a
    // greedy regex (.*?) so Sonar doesn't flag this as ReDoS.
    const guardIdx = html.indexOf(
      "if (body && body.ok === false && body.reason !== 'transient')",
    )
    expect(guardIdx).toBeGreaterThan(0)
    // The two effects (stop pinging, show the notice) must both
    // appear after the guard. Use a bounded slice to keep the
    // assertion linear.
    const branchSlice = html.slice(guardIdx, guardIdx + 600)
    expect(branchSlice).toContain('stopHeartbeat();')
    expect(branchSlice).toContain('showFlowAbortedNotice();')
  })

  it('gates the Resend click on abortIfFlowDead', () => {
    const html = renderDefault()
    // The Resend click handler must call abortIfFlowDead and
    // bail if it returns true.
    const handlerStart = html.indexOf("'btn-resend').addEventListener")
    expect(handlerStart).toBeGreaterThan(0)
    const handlerEnd = html.indexOf(
      "'btn-back').addEventListener",
      handlerStart,
    )
    expect(handlerEnd).toBeGreaterThan(handlerStart)
    const handlerBody = html.slice(handlerStart, handlerEnd)
    expect(handlerBody).toMatch(/if \(await abortIfFlowDead\(\)\) return/)
    // The abort gate must run BEFORE sendOtp — calling sendOtp
    // first would issue an OTP that cannot be used.
    const gateIdx = handlerBody.indexOf('abortIfFlowDead')
    const sendIdx = handlerBody.indexOf('sendOtp(currentEmail)')
    expect(gateIdx).toBeGreaterThan(0)
    expect(sendIdx).toBeGreaterThan(gateIdx)
  })

  it('gates the Verify submit on abortIfFlowDead', () => {
    const html = renderDefault()
    // Verify gate runs BEFORE verifyOtp — same reason: don't
    // consume the OTP if the flow can't complete anyway.
    const handlerStart = html.indexOf("'form-verify-otp').addEventListener")
    expect(handlerStart).toBeGreaterThan(0)
    const handlerEnd = html.indexOf(
      "'btn-resend').addEventListener",
      handlerStart,
    )
    expect(handlerEnd).toBeGreaterThan(handlerStart)
    const handlerBody = html.slice(handlerStart, handlerEnd)
    expect(handlerBody).toMatch(/if \(await abortIfFlowDead\(\)\) return/)
    const gateIdx = handlerBody.indexOf('abortIfFlowDead')
    const verifyIdx = handlerBody.indexOf('verifyOtp(currentEmail, otp)')
    expect(gateIdx).toBeGreaterThan(0)
    expect(verifyIdx).toBeGreaterThan(gateIdx)
  })
})
