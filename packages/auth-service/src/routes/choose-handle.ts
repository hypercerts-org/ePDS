/**
 * GET  /auth/choose-handle — Render handle picker page for new users
 * POST /auth/choose-handle — Validate chosen handle, sign callback, redirect
 * GET  /api/check-handle   — JSON availability endpoint (session-gated)
 *
 * Flow:
 *   1. New user arrives here after OTP verification (redirected from /auth/complete)
 *   2. User picks a local-part handle; client-side JS checks availability in real-time
 *   3. On POST, server validates format + availability, then:
 *      a. Signs the epds-callback URL with the chosen handle included in HMAC
 *      b. Deletes auth_flow row + clears cookie (deferred cleanup from complete.ts)
 *      c. Redirects to pds-core /oauth/epds-callback
 *
 * The auth_flow cookie and row are intentionally kept alive through the GET
 * (complete.ts deferred cleanup) and only cleaned up on successful POST.
 */
import { Router, type Request, type Response } from 'express'
import type { AuthServiceContext } from '../context.js'
import { createLogger, escapeHtml, signCallback } from '@certified-app/shared'
import { fromNodeHeaders } from 'better-auth/node'
import { getDidByEmail } from '../lib/get-did-by-email.js'

const logger = createLogger('auth:choose-handle')

const AUTH_FLOW_COOKIE = 'epds_auth_flow'

/** Regex for valid handle local parts: 3-20 chars, lowercase alphanumeric + hyphens, no leading/trailing hyphen */
export const HANDLE_REGEX = /^[a-z0-9][a-z0-9-]{1,18}[a-z0-9]$/

/** Reserved handles that cannot be registered */
export const RESERVED_HANDLES = new Set([
  'admin',
  'support',
  'help',
  'abuse',
  'postmaster',
  'root',
  'system',
  'moderator',
  'www',
  'mail',
  'ftp',
  'api',
  'auth',
  'oauth',
  'account',
  'settings',
  'security',
  'info',
  'contact',
  'noreply',
  'no-reply',
])

export function createChooseHandleRouter(
  ctx: AuthServiceContext,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- better-auth instance has no exported type
  auth: any,
): Router {
  const router = Router()

  const pdsUrl = process.env.PDS_INTERNAL_URL || ctx.config.pdsPublicUrl
  const internalSecret = process.env.EPDS_INTERNAL_SECRET ?? ''
  const handleDomain = ctx.config.pdsHostname

  /**
   * Shared guard: validates the auth_flow cookie + session.
   * Returns { flowId, flow, email } on success, or sends an error response and returns null.
   */
  async function getFlowAndSession(
    req: Request,
    res: Response,
  ): Promise<{
    flowId: string
    flow: { requestUri: string }
    email: string
  } | null> {
    // Guard 1: auth_flow cookie
    const flowId = req.cookies[AUTH_FLOW_COOKIE] as string | undefined
    if (!flowId) {
      logger.warn('No epds_auth_flow cookie on choose-handle')
      res
        .status(400)
        .type('html')
        .send(renderError('Session expired, please start over'))
      return null
    }

    // Guard 2: auth_flow row in DB
    const flow = ctx.db.getAuthFlow(flowId)
    if (!flow) {
      logger.warn({ flowId }, 'auth_flow not found or expired on choose-handle')
      res.clearCookie(AUTH_FLOW_COOKIE)
      res
        .status(400)
        .type('html')
        .send(renderError('Session expired, please start over'))
      return null
    }

    // Guard 3: better-auth session
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- better-auth session type not exported
    let session: any
    try {
      session = await auth.api.getSession({
        headers: fromNodeHeaders(req.headers),
      })
    } catch (err) {
      logger.error(
        { err },
        'Failed to get better-auth session on choose-handle',
      )
      res
        .status(500)
        .type('html')
        .send(renderError('Authentication failed. Please try again.'))
      return null
    }

    if (!session?.user?.email) {
      logger.warn({ flowId }, 'No authenticated session on choose-handle')
      res
        .status(401)
        .type('html')
        .send(renderError('Session expired, please start over'))
      return null
    }

    return { flowId, flow, email: session.user.email.toLowerCase() }
  }

  // ---------------------------------------------------------------------------
  // Handler 1: GET /auth/choose-handle — Render handle picker page
  // ---------------------------------------------------------------------------
  router.get('/auth/choose-handle', async (req: Request, res: Response) => {
    const result = await getFlowAndSession(req, res)
    if (!result) return

    const { email } = result

    // Guard: if PDS account already exists for this email, redirect to /auth/complete
    const did = await getDidByEmail(email, pdsUrl, internalSecret)
    if (did) {
      logger.info(
        { email },
        'Existing user reached choose-handle — redirecting to /auth/complete',
      )
      res.redirect(303, '/auth/complete')
      return
    }

    const error = req.query.error as string | undefined
    res
      .type('html')
      .send(renderChooseHandlePage(handleDomain, error, res.locals.csrfToken))
  })

  // ---------------------------------------------------------------------------
  // Handler 2: POST /auth/choose-handle — Validate, sign callback, redirect
  // ---------------------------------------------------------------------------
  router.post('/auth/choose-handle', async (req: Request, res: Response) => {
    const result = await getFlowAndSession(req, res)
    if (!result) return

    const { flowId, flow, email } = result

    // Step 1: Read and normalise the local part
    const rawHandle = ((req.body.handle as string) || '').trim().toLowerCase()

    // Step 2: Validate format
    if (!HANDLE_REGEX.test(rawHandle)) {
      logger.debug({ rawHandle }, 'Invalid handle format on POST choose-handle')
      res
        .type('html')
        .send(
          renderChooseHandlePage(
            handleDomain,
            'Invalid handle format. Use 3-20 lowercase letters, numbers, or hyphens.',
            res.locals.csrfToken,
          ),
        )
      return
    }

    // Step 3: Check reserved blocklist
    if (RESERVED_HANDLES.has(rawHandle)) {
      logger.debug(
        { rawHandle },
        'Reserved handle rejected on POST choose-handle',
      )
      res
        .type('html')
        .send(
          renderChooseHandlePage(
            handleDomain,
            'That handle is reserved.',
            res.locals.csrfToken,
          ),
        )
      return
    }

    // Step 4: Construct full handle and check availability via PDS internal API
    const fullHandle = `${rawHandle}.${handleDomain}`
    let handleAvailable = false
    try {
      const checkRes = await fetch(
        `${pdsUrl}/_internal/check-handle?handle=${encodeURIComponent(fullHandle)}`,
        {
          headers: { 'x-internal-secret': internalSecret },
          signal: AbortSignal.timeout(5000),
        },
      )
      if (checkRes.ok) {
        const data = (await checkRes.json()) as { exists: boolean }
        handleAvailable = !data.exists
      } else {
        logger.warn(
          { status: checkRes.status, fullHandle },
          'PDS check-handle returned non-OK status',
        )
        res
          .type('html')
          .send(
            renderChooseHandlePage(
              handleDomain,
              'Could not verify handle availability. Please try again.',
              res.locals.csrfToken,
            ),
          )
        return
      }
    } catch (err) {
      logger.error({ err, fullHandle }, 'Failed to check handle availability')
      res
        .type('html')
        .send(
          renderChooseHandlePage(
            handleDomain,
            'Could not verify handle availability. Please try again.',
            res.locals.csrfToken,
          ),
        )
      return
    }

    if (!handleAvailable) {
      res
        .type('html')
        .send(
          renderChooseHandlePage(
            handleDomain,
            'That handle is already taken.',
            res.locals.csrfToken,
          ),
        )
      return
    }

    // Step 5: Sign callback with handle local part included in HMAC payload.
    // Only the local part (e.g. 'alice') is sent — pds-core appends its own
    // trusted handleDomain, eliminating any possibility of domain mismatch.
    const callbackParams = {
      request_uri: flow.requestUri,
      email,
      approved: '1',
      new_account: '1',
      handle: rawHandle,
    }
    const { sig, ts } = signCallback(
      callbackParams,
      ctx.config.epdsCallbackSecret,
    )
    const params = new URLSearchParams({ ...callbackParams, ts, sig })

    // Step 6: Cleanup — delete auth_flow row and clear cookie
    ctx.db.deleteAuthFlow(flowId)
    res.clearCookie(AUTH_FLOW_COOKIE)

    logger.info(
      { email, flowId, fullHandle },
      'Handle chosen: redirecting to epds-callback',
    )
    res.redirect(
      303,
      `${ctx.config.pdsPublicUrl}/oauth/epds-callback?${params.toString()}`,
    )
  })

  // ---------------------------------------------------------------------------
  // Handler 3: GET /api/check-handle — JSON availability endpoint
  // ---------------------------------------------------------------------------
  router.get('/api/check-handle', async (req: Request, res: Response) => {
    // Guard: require active better-auth session
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- better-auth session type not exported
    let session: any
    try {
      session = await auth.api.getSession({
        headers: fromNodeHeaders(req.headers),
      })
    } catch {
      res.status(401).json({ error: 'unauthenticated' })
      return
    }

    if (!session?.user?.email) {
      res.status(401).json({ error: 'unauthenticated' })
      return
    }

    // Read and validate the local part
    const localPart = ((req.query.handle as string) || '').trim().toLowerCase()

    if (!HANDLE_REGEX.test(localPart)) {
      res.json({ error: 'invalid_format' })
      return
    }

    if (RESERVED_HANDLES.has(localPart)) {
      res.json({ error: 'reserved', available: false })
      return
    }

    const fullHandle = `${localPart}.${handleDomain}`

    try {
      const checkRes = await fetch(
        `${pdsUrl}/_internal/check-handle?handle=${encodeURIComponent(fullHandle)}`,
        {
          headers: { 'x-internal-secret': internalSecret },
          signal: AbortSignal.timeout(5000),
        },
      )
      if (!checkRes.ok) {
        logger.warn(
          { status: checkRes.status, fullHandle },
          'PDS check-handle returned non-OK on /api/check-handle',
        )
        res.json({ error: 'service_unavailable' })
        return
      }
      const data = (await checkRes.json()) as { exists: boolean }
      const available = !data.exists
      res.json({ available, handle: fullHandle })
    } catch (err) {
      logger.error(
        { err, fullHandle },
        'Failed to check handle availability via PDS',
      )
      res.json({ error: 'service_unavailable' })
    }
  })

  return router
}

// ---------------------------------------------------------------------------
// Template
// ---------------------------------------------------------------------------

function renderChooseHandlePage(
  handleDomain: string,
  error?: string,
  csrfToken?: string,
): string {
  const errorAdmonition = error
    ? `<div id="error-msg" class="admonition error">
        <span class="admonition-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor">
            <path fill-rule="evenodd" clip-rule="evenodd" d="M11.14 4.494a.995.995 0 0 1 1.72 0l7.001 12.008a.996.996 0 0 1-.86 1.498H4.999a.996.996 0 0 1-.86-1.498L11.14 4.494Zm3.447-1.007c-1.155-1.983-4.019-1.983-5.174 0L2.41 15.494C1.247 17.491 2.686 20 4.998 20h14.004c2.312 0 3.751-2.509 2.587-4.506L14.587 3.487ZM13 9.019a1 1 0 1 0-2 0v2.994a1 1 0 1 0 2 0V9.02Zm-1 4.731a1.25 1.25 0 1 0 0 2.5 1.25 1.25 0 0 0 0-2.5Z"/>
          </svg>
        </span>
        <span id="error-text">${escapeHtml(error)}</span>
      </div>`
    : `<div id="error-msg" class="admonition error" style="display:none;">
        <span class="admonition-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor">
            <path fill-rule="evenodd" clip-rule="evenodd" d="M11.14 4.494a.995.995 0 0 1 1.72 0l7.001 12.008a.996.996 0 0 1-.86 1.498H4.999a.996.996 0 0 1-.86-1.498L11.14 4.494Zm3.447-1.007c-1.155-1.983-4.019-1.983-5.174 0L2.41 15.494C1.247 17.491 2.686 20 4.998 20h14.004c2.312 0 3.751-2.509 2.587-4.506L14.587 3.487ZM13 9.019a1 1 0 1 0-2 0v2.994a1 1 0 1 0 2 0V9.02Zm-1 4.731a1.25 1.25 0 1 0 0 2.5 1.25 1.25 0 0 0 0-2.5Z"/>
          </svg>
        </span>
        <span id="error-text"></span>
      </div>`

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Choose your handle</title>
  <style>
    /* ── CSS custom property color token system (mirrors atproto oauth-provider-ui) ── */
    :root {
      --hue-primary: 265;

      --color-primary: #8338ec;
      --color-primary-contrast: #fff;
      --color-error: rgb(255 0 110);
      --color-success: rgb(23 204 136);

      --color-contrast-0:    hsl(var(--hue-primary) 20% 100%);
      --color-contrast-25:   hsl(var(--hue-primary) 20% 95.3%);
      --color-contrast-50:   hsl(var(--hue-primary) 20% 90.6%);
      --color-contrast-100:  hsl(var(--hue-primary) 20% 85.9%);
      --color-contrast-200:  hsl(var(--hue-primary) 20% 81.2%);
      --color-contrast-300:  hsl(var(--hue-primary) 20% 71.8%);
      --color-contrast-400:  hsl(var(--hue-primary) 20% 62.4%);
      --color-contrast-500:  hsl(var(--hue-primary) 20% 53%);
      --color-contrast-600:  hsl(var(--hue-primary) 20% 43.6%);
      --color-contrast-700:  hsl(var(--hue-primary) 20% 34.2%);
      --color-contrast-800:  hsl(var(--hue-primary) 20% 24.8%);
      --color-contrast-900:  hsl(var(--hue-primary) 20% 20.1%);
      --color-contrast-950:  hsl(var(--hue-primary) 20% 15.4%);
      --color-contrast-975:  hsl(var(--hue-primary) 20% 10.7%);
      --color-contrast-1000: hsl(var(--hue-primary) 20% 6%);

      --color-text-default: var(--color-contrast-900);
      --color-text-light:   var(--color-contrast-700);
      --color-border-default: var(--color-contrast-200);

      --color-panel: var(--color-contrast-25);
      --color-panel-text: var(--color-primary);
      --color-panel-subtitle: var(--color-text-light);
    }

    @media (prefers-color-scheme: dark) {
      :root {
        --color-contrast-1000: hsl(var(--hue-primary) 20% 100%);
        --color-contrast-975:  hsl(var(--hue-primary) 20% 95.3%);
        --color-contrast-950:  hsl(var(--hue-primary) 20% 90.6%);
        --color-contrast-900:  hsl(var(--hue-primary) 20% 85.9%);
        --color-contrast-800:  hsl(var(--hue-primary) 20% 81.2%);
        --color-contrast-700:  hsl(var(--hue-primary) 20% 71.8%);
        --color-contrast-600:  hsl(var(--hue-primary) 20% 62.4%);
        --color-contrast-500:  hsl(var(--hue-primary) 20% 53%);
        --color-contrast-400:  hsl(var(--hue-primary) 20% 43.6%);
        --color-contrast-300:  hsl(var(--hue-primary) 20% 34.2%);
        --color-contrast-200:  hsl(var(--hue-primary) 20% 24.8%);
        --color-contrast-100:  hsl(var(--hue-primary) 20% 20.1%);
        --color-contrast-50:   hsl(var(--hue-primary) 20% 15.4%);
        --color-contrast-25:   hsl(var(--hue-primary) 20% 10.7%);
        --color-contrast-0:    hsl(var(--hue-primary) 20% 6%);
      }
    }

    /* ── Reset ── */
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    /* ── Body / layout ── */
    body {
      font-family: ui-sans-serif, system-ui, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol", "Noto Color Emoji";
      min-height: 100vh;
      background: var(--color-contrast-0);
      color: var(--color-text-default);
      display: flex;
      flex-direction: column;
      align-items: center;
    }

    @media (prefers-color-scheme: light) {
      body { background: white; }
    }

    /* ── Split-panel wrapper ── */
    .layout {
      display: flex;
      flex-direction: column;
      align-items: center;
      min-width: 100vw;
      min-height: 100vh;
    }

    @media (min-width: 768px) {
      .layout {
        flex-direction: row;
        align-items: stretch;
      }
    }

    /* ── Left / title panel ── */
    .title-panel {
      width: 100%;
      padding: 16px 24px;
      display: flex;
      flex-direction: row;
      align-items: center;
      gap: 12px;
    }

    .title-panel-inner {
      display: flex;
      flex-direction: row;
      align-items: center;
      gap: 12px;
    }

    @media (min-width: 768px) {
      .title-panel {
        width: 50%;
        max-width: 512px;
        padding: 16px;
        text-align: right;
        background: var(--color-panel);
        align-self: stretch;
        display: grid;
        align-content: center;
        justify-items: end;
      }

      .title-panel-inner {
        display: grid;
        align-content: center;
        justify-items: start;
        text-align: left;
      }
    }

    @media (min-width: 768px) and (prefers-color-scheme: dark) {
      .title-panel {
        border-right: 1px solid var(--color-contrast-200);
      }
    }

    @media (min-width: 768px) and (prefers-color-scheme: light) {
      .title-panel {
        background: var(--color-panel, hsl(var(--hue-primary) 20% 95.3%));
      }
    }

    .client-logo {
      height: 48px;
      width: 48px;
      object-fit: contain;
    }

    @media (min-width: 768px) {
      .client-logo {
        height: 64px;
        width: 64px;
        margin-bottom: 16px;
      }
    }

    .title-svg {
      width: 200px;
      height: auto;
      margin: 8px 0;
    }

    @media (min-width: 768px) {
      .title-svg {
        width: 280px;
        margin: 16px 0;
      }
    }

    @media (min-width: 1024px) {
      .title-svg {
        width: 334px;
      }
    }

    .title-panel .subtitle {
      display: none;
      font-size: 15px;
      color: var(--color-panel-subtitle, var(--color-text-light));
      max-width: 320px;
      line-height: 1.5;
    }

    @media (min-width: 768px) {
      .title-panel .subtitle { display: block; }
    }

    /* ── Right / form panel ── */
    .form-panel {
      width: 100%;
      padding: 24px;
      display: flex;
      flex-direction: column;
      justify-content: center;
    }

    @media (min-width: 768px) {
      .form-panel {
        max-width: 600px;
        padding: 24px 48px;
      }
    }

    /* ── Form panel heading ── */
    .form-panel h1 {
      font-size: 22px;
      font-weight: 600;
      color: var(--color-text-default);
      margin-bottom: 8px;
      line-height: 1.2;
    }

    .form-panel .form-subtitle {
      font-size: 15px;
      color: var(--color-text-light);
      margin-bottom: 24px;
      line-height: 1.5;
    }

    /* ── Field label ── */
    .field-label {
      display: block;
      font-size: 14px;
      font-weight: 500;
      color: var(--color-text-light);
      margin-bottom: 4px;
    }

    /* ── Pill input container (atproto InputContainer pattern) ── */
    .input-container {
      min-height: 48px;
      border-radius: 8px;
      background: var(--color-contrast-25);
      overflow: hidden;
      transition: all 0.3s ease-in-out;
      outline: none;
      cursor: text;
    }

    @media (prefers-color-scheme: dark) {
      .input-container { background: var(--color-contrast-50); }
    }

    .input-container:focus-within {
      box-shadow: 0 0 0 2px var(--color-primary), 0 0 0 3px var(--color-contrast-0);
    }

    .input-inner {
      display: flex;
      align-items: center;
      min-height: 48px;
      padding: 0 4px;
      border-radius: 8px;
      color: var(--color-text-default);
    }

    /* Square off bottom corners when preview strip is visible below */
    .input-inner.has-preview {
      border-bottom-left-radius: 0;
      border-bottom-right-radius: 0;
    }

    .input-icon {
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      margin: 0 8px;
      color: var(--color-text-light);
      transition: color 0.3s ease-in-out;
    }

    .input-container:focus-within .input-icon {
      color: var(--color-primary);
    }

    .input-field {
      flex: 1;
      background: transparent;
      border: none;
      outline: none;
      font-size: 16px;
      color: var(--color-text-default);
      padding: 8px 8px 8px 0;
      width: 100%;
      min-width: 0;
      text-overflow: ellipsis;
      background-clip: padding-box;
    }

    .input-field::placeholder { color: var(--color-text-light); }

    @media (prefers-color-scheme: dark) {
      .input-field::placeholder { color: rgb(107 114 128); }
    }

    /* Domain suffix sitting inside the input row */
    .handle-suffix {
      flex-shrink: 0;
      margin-left: 4px;
      padding-right: 12px;
      font-size: 16px;
      color: var(--color-text-light);
      white-space: nowrap;
    }

    /* Full-handle preview strip — attaches below .input-inner */
    .handle-preview {
      display: none;
      background: var(--color-contrast-50);
      padding: 8px 12px;
      font-size: 14px;
      font-style: italic;
      color: var(--color-text-light);
      border-radius: 0 0 8px 8px;
    }

    @media (prefers-color-scheme: dark) {
      .handle-preview { background: var(--color-contrast-100); }
    }

    .handle-preview strong {
      font-style: normal;
      color: var(--color-text-default);
    }

    /* ── Validation rules ── */
    .validation-rules {
      display: flex;
      flex-direction: column;
      gap: 4px;
      margin-bottom: 12px;
    }

    .validation-rule {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 13px;
      color: var(--color-text-light);
    }

    .rule-icon {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 16px;
      height: 16px;
      flex-shrink: 0;
      font-size: 14px;
    }

    .validation-rule.pass { color: var(--color-success); }
    .validation-rule.fail { color: var(--color-error); }

    /* ── Availability status ── */
    .status {
      min-height: 20px;
      font-size: 14px;
      margin-top: 6px;
    }

    .status.available { color: var(--color-success); }
    .status.taken     { color: var(--color-error); }
    .status.format-error { color: var(--color-error); }
    .status.checking  { color: var(--color-text-light); }

    /* ── Form layout ── */
    .form-group { display: flex; flex-direction: column; gap: 16px; }
    .field { display: flex; flex-direction: column; gap: 4px; }

    .form-actions {
      display: flex;
      flex-direction: column;
      margin-top: 8px;
    }

    /* ── Primary button ── */
    .btn-primary {
      width: 100%;
      background: var(--color-primary);
      color: var(--color-primary-contrast);
      border: none;
      border-radius: 6px;
      padding: 12px 24px;
      min-height: 48px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-size: 16px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.3s ease-in-out;
      outline: none;
      letter-spacing: 0.025em;
      touch-action: manipulation;
    }

    .btn-primary:hover:not(:disabled) { opacity: 0.85; }

    .btn-primary:focus-visible {
      outline: 2px solid var(--color-contrast-1000);
      outline-offset: 2px;
    }

    .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }

    /* ── Error / admonition ── */
    .admonition {
      border-radius: 8px;
      padding: 12px;
      border: 1px solid var(--color-border-default);
      display: flex;
      gap: 8px;
      align-items: flex-start;
      font-size: 14px;
      margin-bottom: 16px;
    }

    .admonition.error {
      border-color: var(--color-error);
      color: var(--color-error);
      background: rgba(255, 0, 110, 0.08);
    }

    .admonition-icon { flex-shrink: 0; margin-top: 1px; }
  </style>
</head>
<body>
  <div class="layout">

    <!-- Left panel: branding -->
    <div class="title-panel">
      <div class="title-panel-inner">
        <img src="/static/gainforest-logo.png" alt="GainForest" class="client-logo">
        <div>
          <img src="/static/sign-in-with-certified-title.svg" alt="Create account with Certified" class="title-svg">
          <p class="subtitle">Create your account</p>
        </div>
      </div>
    </div>

    <!-- Right panel: form -->
    <main class="form-panel">
      ${errorAdmonition}

      <h1>Choose your handle</h1>
      <p class="form-subtitle">Your handle is your public username on the AT Protocol network.</p>

      <form method="POST" action="/auth/choose-handle" id="handle-form" class="form-group">
        <input type="hidden" name="csrf" value="${escapeHtml(csrfToken || '')}">

        <!-- Validation rules — neutral dots until user types, then checkmarks/X -->
        <div class="validation-rules" id="validation-rules">
          <div class="validation-rule" id="rule-length">
            <span class="rule-icon" id="rule-length-icon">·</span>
            <span>Between 3 and 20 characters</span>
          </div>
          <div class="validation-rule" id="rule-charset">
            <span class="rule-icon" id="rule-charset-icon">·</span>
            <span>Only letters, numbers, and hyphens. Cannot start or end with a hyphen.</span>
          </div>
        </div>

        <div class="field">
          <label class="field-label" for="handle-input">Handle</label>
          <div class="input-container">
            <div class="input-inner" id="input-inner">
              <span class="input-icon" aria-hidden="true">
                <svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor">
                  <path d="M12 2C6.477 2 2 6.477 2 12s4.477 10 10 10a1 1 0 1 0 0-2 8 8 0 1 1 5.263-1.977l-.39.39a2.104 2.104 0 0 1-2.976-2.976l2.658-2.658a1 1 0 0 0-1.414-1.414l-.22.22A3.98 3.98 0 0 0 12 8a4 4 0 1 0 2.745 6.904 4.1 4.1 0 0 0 5.703-.457A9.956 9.956 0 0 0 22 12C22 6.477 17.523 2 12 2Zm0 11a2 2 0 1 1 0-4 2 2 0 0 1 0 4Z"/>
                </svg>
              </span>
              <input
                type="text"
                id="handle-input"
                name="handle"
                class="input-field"
                placeholder="yourname"
                autocomplete="off"
                autocapitalize="none"
                autocorrect="off"
                spellcheck="false"
                maxlength="20"
                autofocus
              >
              <span class="handle-suffix" id="handle-suffix">.${escapeHtml(handleDomain)}</span>
            </div>
            <!-- Full handle preview — shown once user starts typing -->
            <div class="handle-preview" id="handle-preview">
              Your full handle will be: <strong id="preview-text"></strong>
            </div>
          </div>
          <div class="status" id="handle-status"></div>
        </div>

        <div class="form-actions">
          <button type="submit" id="submit-btn" class="btn-primary" disabled>Continue</button>
        </div>
      </form>
    </main>

  </div>

  <script>
    (function() {
      var HANDLE_DOMAIN = '${escapeHtml(handleDomain)}';
      var HANDLE_REGEX = /^[a-z0-9][a-z0-9-]{1,18}[a-z0-9]$/;
      var RESERVED = new Set([
        'admin','support','help','abuse','postmaster','root','system',
        'moderator','www','mail','ftp','api','auth','oauth','account',
        'settings','security','info','contact','noreply','no-reply'
      ]);

      var input = document.getElementById('handle-input');
      var inputInner = document.getElementById('input-inner');
      var statusEl = document.getElementById('handle-status');
      var submitBtn = document.getElementById('submit-btn');
      var errorMsg = document.getElementById('error-msg');
      var handlePreview = document.getElementById('handle-preview');
      var previewText = document.getElementById('preview-text');
      var ruleLengthEl = document.getElementById('rule-length');
      var ruleCharsetEl = document.getElementById('rule-charset');
      var ruleLengthIcon = document.getElementById('rule-length-icon');
      var ruleCharsetIcon = document.getElementById('rule-charset-icon');
      var debounceTimer = null;
      var lastChecked = '';
      var isAvailable = false;

      function setStatus(text, cls) {
        statusEl.textContent = text;
        statusEl.className = 'status' + (cls ? ' ' + cls : '');
      }

      function updateSubmit() {
        submitBtn.disabled = !isAvailable;
      }

      function setRule(el, iconEl, state) {
        // state: 'neutral' | 'pass' | 'fail'
        el.className = 'validation-rule' + (state === 'pass' ? ' pass' : state === 'fail' ? ' fail' : '');
        iconEl.textContent = state === 'pass' ? '\u2713' : state === 'fail' ? '\u2717' : '\u00b7';
      }

      function updateRules(raw) {
        if (!raw) {
          setRule(ruleLengthEl, ruleLengthIcon, 'neutral');
          setRule(ruleCharsetEl, ruleCharsetIcon, 'neutral');
          return;
        }
        var validLength = raw.length >= 3 && raw.length <= 20;
        var validCharset = /^[a-z0-9][a-z0-9-]*[a-z0-9]$/.test(raw) || (raw.length >= 1 && /^[a-z0-9]+$/.test(raw));
        var noLeadTrailHyphen = !/^-|-$/.test(raw);
        setRule(ruleLengthEl, ruleLengthIcon, validLength ? 'pass' : 'fail');
        setRule(ruleCharsetEl, ruleCharsetIcon, (validCharset && noLeadTrailHyphen) ? 'pass' : 'fail');
      }

      function updatePreview(raw) {
        if (raw) {
          previewText.textContent = '@' + raw + '.' + HANDLE_DOMAIN;
          handlePreview.style.display = 'block';
          inputInner.classList.add('has-preview');
        } else {
          handlePreview.style.display = 'none';
          inputInner.classList.remove('has-preview');
        }
      }

      function checkAvailability(value) {
        if (value === lastChecked) return;
        lastChecked = value;
        isAvailable = false;
        updateSubmit();

        setStatus('Checking\u2026', 'checking');

        fetch('/api/check-handle?handle=' + encodeURIComponent(value))
          .then(function(r) { return r.json(); })
          .then(function(data) {
            if (data.error === 'invalid_format') {
              setStatus('Invalid format.', 'format-error');
            } else if (data.error === 'reserved') {
              setStatus('\u2717 That handle is reserved.', 'taken');
            } else if (data.error) {
              setStatus('Could not check availability.', 'format-error');
            } else if (data.available) {
              setStatus('\u2713 Available!', 'available');
              isAvailable = true;
            } else {
              setStatus('\u2717 Already taken.', 'taken');
            }
            updateSubmit();
          })
          .catch(function() {
            setStatus('Could not check availability.', 'format-error');
            updateSubmit();
          });
      }

      input.addEventListener('input', function() {
        // Normalise: lowercase, strip invalid chars
        var raw = this.value.toLowerCase().replace(/[^a-z0-9-]/g, '');
        if (this.value !== raw) {
          var pos = this.selectionStart;
          this.value = raw;
          this.setSelectionRange(pos, pos);
        }

        isAvailable = false;
        updateSubmit();
        clearTimeout(debounceTimer);
        updateRules(raw);
        updatePreview(raw);

        if (!raw) {
          setStatus('', '');
          return;
        }

        if (RESERVED.has(raw)) {
          setStatus('\u2717 That handle is reserved.', 'taken');
          return;
        }

        if (!HANDLE_REGEX.test(raw)) {
          setStatus('3\u201320 characters, letters, numbers, or hyphens. Cannot start or end with a hyphen.', 'format-error');
          return;
        }

        // Valid format — debounce the availability check
        debounceTimer = setTimeout(function() {
          checkAvailability(raw);
        }, 500);
      });

      // Hide server-rendered error once user starts typing
      input.addEventListener('input', function() {
        if (errorMsg && errorMsg.style.display !== 'none') {
          errorMsg.style.display = 'none';
        }
      }, { once: true });
    })();
  </script>
</body>
</html>`
}

function renderError(message: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Error</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: ui-sans-serif, system-ui, sans-serif;
      min-height: 100vh;
      background: white;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .admonition {
      max-width: 480px;
      width: 100%;
      border-radius: 8px;
      padding: 16px;
      border: 1px solid rgb(255 0 110);
      display: flex;
      gap: 10px;
      align-items: flex-start;
      font-size: 15px;
      color: rgb(255 0 110);
      background: rgba(255, 0, 110, 0.08);
    }
    .admonition-icon { flex-shrink: 0; margin-top: 2px; }
  </style>
</head>
<body>
  <div class="admonition">
    <span class="admonition-icon" aria-hidden="true">
      <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
        <path fill-rule="evenodd" clip-rule="evenodd" d="M11.14 4.494a.995.995 0 0 1 1.72 0l7.001 12.008a.996.996 0 0 1-.86 1.498H4.999a.996.996 0 0 1-.86-1.498L11.14 4.494Zm3.447-1.007c-1.155-1.983-4.019-1.983-5.174 0L2.41 15.494C1.247 17.491 2.686 20 4.998 20h14.004c2.312 0 3.751-2.509 2.587-4.506L14.587 3.487ZM13 9.019a1 1 0 1 0-2 0v2.994a1 1 0 1 0 2 0V9.02Zm-1 4.731a1.25 1.25 0 1 0 0 2.5 1.25 1.25 0 0 0 0-2.5Z"/>
      </svg>
    </span>
    <span>${escapeHtml(message)}</span>
  </div>
</body>
</html>`
}
