/**
 * Account recovery via backup email.
 *
 * Flow:
 *   1. User enters their backup email address
 *   2. We look up the DID via backup_email table (auth-service-owned data)
 *   3. If found, send OTP to backup email via better-auth emailOTP plugin
 *   4. User enters OTP; we verify via better-auth
 *   5. Redirect to /auth/complete to complete the AT Protocol flow
 *
 * This follows the same bridge pattern as the main login flow:
 *   better-auth session → /auth/complete → HMAC-signed epds-callback
 *
 * Note: recovery uses the backup email as the verified identity. The auth_flow
 * table threads request_uri through the flow via epds_auth_flow cookie.
 */
import { Router, type Request, type Response } from 'express'
import type { AuthServiceContext } from '../context.js'
import { createLogger, escapeHtml, maskEmail } from '@certified-app/shared'
import { buildOtpInputProps } from '../otp-input.js'
import { resolveClientBranding } from '../lib/client-metadata.js'
import {
  renderOptionalStyleTag,
  renderFaviconTag,
  POWERED_BY_CSS,
  POWERED_BY_HTML,
} from '../lib/page-helpers.js'
import { renderError } from '../lib/render-error.js'
import { AUTH_FLOW_COOKIE, AUTH_FLOW_TTL_MS } from '../lib/auth-flow.js'
import { heartbeatEnabledFor } from './login-page.js'

const logger = createLogger('auth:recovery')

export function createRecoveryRouter(
  ctx: AuthServiceContext,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- better-auth instance has no exported type
  auth: any,
): Router {
  const router = Router()
  const otpLength = ctx.config.otpLength
  const otpCharset = ctx.config.otpCharset

  /** Look up clientId, requestUri, and branding from the epds_auth_flow cookie. */
  async function getFlowBranding(req: Request): Promise<{
    clientId: string | null
    backUri: string | null
    customCss: string | null
    customFaviconUrl: string | null
    customFaviconUrlDark: string | null
  }> {
    const flowId = req.cookies[AUTH_FLOW_COOKIE] as string | undefined
    const flow = flowId ? ctx.db.getAuthFlow(flowId) : undefined
    const clientId = flow?.clientId ?? null
    const backUri = flow?.requestUri ?? null
    if (!clientId) {
      return {
        clientId: null,
        backUri,
        customCss: null,
        customFaviconUrl: null,
        customFaviconUrlDark: null,
      }
    }
    const { customCss, customFaviconUrl, customFaviconUrlDark } =
      await resolveClientBranding(clientId, ctx.config.trustedClients)
    return {
      clientId,
      backUri,
      customCss,
      customFaviconUrl,
      customFaviconUrlDark,
    }
  }

  router.get('/auth/recover', async (req: Request, res: Response) => {
    const requestUri = req.query.request_uri as string | undefined

    if (!requestUri) {
      res
        .status(400)
        .type('html')
        .send(renderError('Missing request_uri parameter'))
      return
    }

    const { customCss, customFaviconUrl, customFaviconUrlDark, backUri } =
      await getFlowBranding(req)

    res.type('html').send(
      renderRecoveryForm({
        requestUri,
        csrfToken: res.locals.csrfToken,
        customCss,
        customFaviconUrl,
        customFaviconUrlDark,
        backUri,
        heartbeatEnabled: heartbeatEnabledFor(req),
      }),
    )
  })

  router.post('/auth/recover', async (req: Request, res: Response) => {
    const email = ((req.body.email as string) || '').trim().toLowerCase()
    const requestUri = req.body.request_uri as string

    const { customCss, customFaviconUrl, customFaviconUrlDark, backUri } =
      await getFlowBranding(req)

    if (!email || !requestUri) {
      res.status(400).send(
        renderRecoveryForm({
          requestUri: requestUri || '',
          csrfToken: res.locals.csrfToken,
          error: 'Email and request URI are required.',
          customCss,
          customFaviconUrl,
          customFaviconUrlDark,
          backUri,
          heartbeatEnabled: heartbeatEnabledFor(req),
        }),
      )
      return
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      res.status(400).send(
        renderRecoveryForm({
          requestUri,
          csrfToken: res.locals.csrfToken,
          error: 'Please enter a valid email address.',
          customCss,
          customFaviconUrl,
          customFaviconUrlDark,
          backUri,
          heartbeatEnabled: heartbeatEnabledFor(req),
        }),
      )
      return
    }

    // Look up backup email - ALWAYS show OTP form (anti-enumeration)
    const did = ctx.db.getDidByBackupEmail(email)

    if (did) {
      try {
        // Ensure the auth_flow cookie is set so /auth/complete can thread the request_uri.
        // If one already exists from a previous step, we keep it; otherwise create a new one.
        let flowId = req.cookies[AUTH_FLOW_COOKIE] as string | undefined
        const existingFlow = flowId ? ctx.db.getAuthFlow(flowId) : undefined
        if (!flowId || !existingFlow) {
          const { randomBytes } = await import('node:crypto')
          flowId = randomBytes(16).toString('hex')
          // Recover the original OAuth client_id by looking up the live
          // auth_flow row keyed by this request_uri (the login page
          // populated it on the parent flow). Falls back to null when
          // the parent flow has expired or never existed — the rest of
          // the clean-exit pipeline already handles a null clientId
          // gracefully (text-only fallback page), so missing clientId
          // is graceful degradation rather than a breakage.
          const parentFlow = ctx.db.getAuthFlowByRequestUri(requestUri)
          ctx.db.createAuthFlow({
            flowId,
            requestUri,
            clientId: parentFlow?.clientId ?? null,
            // handleMode omitted — recovery flows don't go through handle assignment
            expiresAt: Date.now() + AUTH_FLOW_TTL_MS,
          })
          res.cookie(AUTH_FLOW_COOKIE, flowId, {
            httpOnly: true,
            secure: process.env.NODE_ENV !== 'development',
            sameSite: 'lax',
            maxAge: AUTH_FLOW_TTL_MS,
          })
        }

        // Send OTP via better-auth emailOTP plugin
        await auth.api.sendVerificationOTP({
          body: { email, type: 'sign-in' },
        })

        logger.info({ email }, 'Recovery OTP sent via better-auth')
        res.send(
          renderRecoveryOtpForm({
            email,
            csrfToken: res.locals.csrfToken,
            requestUri,
            otpLength,
            otpCharset,
            customCss,
            customFaviconUrl,
            customFaviconUrlDark,
            backUri,
            heartbeatEnabled: heartbeatEnabledFor(req),
          }),
        )
      } catch (err) {
        logger.error({ err }, 'Failed to send recovery OTP')
        res.status(500).send(
          renderRecoveryOtpForm({
            email,
            csrfToken: res.locals.csrfToken,
            requestUri,
            error: 'Failed to send code. Please try again.',
            otpLength,
            otpCharset,
            customCss,
            customFaviconUrl,
            customFaviconUrlDark,
            backUri,
            heartbeatEnabled: heartbeatEnabledFor(req),
          }),
        )
      }
    } else {
      // No backup email found, but show OTP form anyway (anti-enumeration)
      res.send(
        renderRecoveryOtpForm({
          email,
          csrfToken: res.locals.csrfToken,
          requestUri,
          otpLength,
          otpCharset,
          customCss,
          customFaviconUrl,
          customFaviconUrlDark,
          backUri,
          heartbeatEnabled: heartbeatEnabledFor(req),
        }),
      )
    }
  })

  // POST /auth/recover/verify - verify recovery OTP via better-auth
  router.post('/auth/recover/verify', async (req: Request, res: Response) => {
    const code = ((req.body.code as string) || '').trim()
    const email = ((req.body.email as string) || '').trim().toLowerCase()
    const requestUri = req.body.request_uri as string

    if (!code || !email || !requestUri) {
      res.status(400).type('html').send(renderError('Missing required fields.'))
      return
    }

    try {
      // Verify OTP via better-auth — this creates/updates a session
      const response = await auth.api.signInEmailOTP({
        body: { email, otp: code.toUpperCase() },
        asResponse: true,
      })

      // Forward better-auth's session cookie
      if (
        response instanceof Response ||
        (response && typeof response.headers?.get === 'function')
      ) {
        const setCookie = response.headers.get('set-cookie')
        if (setCookie) {
          res.setHeader('Set-Cookie', setCookie)
        }
      }

      // Redirect to /auth/complete which will read the better-auth session
      // and issue the HMAC-signed callback to pds-core
      logger.info(
        { email },
        'Recovery OTP verified, redirecting to /auth/complete',
      )
      res.redirect(303, '/auth/complete')
    } catch (err: unknown) {
      logger.warn({ err, email }, 'Recovery OTP verification failed')
      const errMsg =
        err instanceof Error &&
        (err.message.includes('invalid') || err.message.includes('expired'))
          ? 'Invalid or expired code. Please try again.'
          : 'Verification failed. Please try again.'
      const { customCss, customFaviconUrl, customFaviconUrlDark, backUri } =
        await getFlowBranding(req)
      res.send(
        renderRecoveryOtpForm({
          email,
          csrfToken: res.locals.csrfToken,
          requestUri,
          error: errMsg,
          otpLength,
          otpCharset,
          customCss,
          customFaviconUrl,
          customFaviconUrlDark,
          backUri,
          heartbeatEnabled: heartbeatEnabledFor(req),
        }),
      )
    }
  })

  return router
}

export function renderRecoveryForm(opts: {
  requestUri: string
  csrfToken: string
  error?: string
  customCss?: string | null
  customFaviconUrl?: string | null
  customFaviconUrlDark?: string | null
  backUri?: string | null
  /**
   * Forwarded test-only flag: when the request's heartbeat was
   * disabled via `?no_heartbeat=1` (gated by `EPDS_TEST_HOOKS=1`),
   * propagate it as a hidden field so the OTP-form re-render after
   * the email submit still sees it. Production callers leave this
   * undefined; the field is only emitted when the flag was actually
   * set, so this stays a no-op outside tests.
   */
  heartbeatEnabled?: boolean
}): string {
  const requestUriForBack = opts.backUri ?? opts.requestUri
  const backHref = requestUriForBack
    ? `/oauth/authorize?request_uri=${encodeURIComponent(requestUriForBack)}`
    : '/oauth/authorize'
  // Only emit the hidden field when heartbeat is explicitly OFF — the
  // field is functionless in production and would just clutter the
  // form. heartbeatEnabledFor() reads body.no_heartbeat === '1' so
  // the field carries the literal '1' to disable.
  const noHeartbeatField =
    opts.heartbeatEnabled === false
      ? '<input type="hidden" name="no_heartbeat" value="1">'
      : ''
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  ${renderFaviconTag(opts.customFaviconUrl, opts.customFaviconUrlDark)}
  <title>Account Recovery</title>
  <style>${CSS}</style>${renderOptionalStyleTag(opts.customCss)}
</head>
<body>
  <div class="page-wrap">
    <div class="container">
      <h1>Account Recovery</h1>
      <p class="subtitle">Enter the backup email address associated with your account.</p>
      ${opts.error ? '<p class="error">' + escapeHtml(opts.error) + '</p>' : ''}
      <form method="POST" action="/auth/recover">
        <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
        <input type="hidden" name="request_uri" value="${escapeHtml(opts.requestUri)}">
        ${noHeartbeatField}
        <div class="field">
          <label for="email">Backup email address</label>
          <input type="email" id="email" name="email" required autofocus
                 placeholder="backup@example.com">
        </div>
        <button type="submit" class="btn-primary">Send recovery code</button>
      </form>
      <a href="${backHref}" class="btn-secondary">Back to sign in</a>
    </div>
    ${POWERED_BY_HTML}
  </div>
  <script>
    (function() {
      // PAR heartbeat for the email-input recovery page — same shape
      // as the OTP form and recovery OTP form. A user who lands on
      // /auth/recover and then pauses (rummaging for a backup email
      // address, switching tabs, fishing through a different inbox)
      // would otherwise let the parent OAuth flow's PAR die before
      // they even submit the email. Stops on form submit / unload /
      // when the server reports the auth_flow or PAR is gone.
      if (!${JSON.stringify(opts.heartbeatEnabled !== false)}) return;
      var handle = null;
      function ping() {
        fetch('/auth/ping', { credentials: 'include', cache: 'no-store' })
          .then(function(r) { return r.json(); })
          .then(function(body) {
            if (body && body.ok === false && body.reason !== 'transient') stop();
          })
          .catch(function() {});
      }
      function stop() { if (handle !== null) { clearInterval(handle); handle = null; } }
      handle = setInterval(ping, 3 * 60 * 1000);
      window.addEventListener('beforeunload', stop);
      Array.prototype.forEach.call(document.querySelectorAll('form'), function(form) {
        form.addEventListener('submit', stop);
      });
    })();
  </script>
</body>
</html>`
}

export function renderRecoveryOtpForm(opts: {
  email: string
  csrfToken: string
  requestUri: string
  otpLength: number
  otpCharset: 'numeric' | 'alphanumeric'
  error?: string
  customCss?: string | null
  customFaviconUrl?: string | null
  customFaviconUrlDark?: string | null
  backUri?: string | null
  /**
   * When true, the page polls /auth/ping every 3 min to slide the
   * upstream PAR's inactivity timer while the user reads their
   * recovery email. Mirror of the OTP-form heartbeat in login-page.
   */
  heartbeatEnabled: boolean
}): string {
  const maskedEmail = maskEmail(opts.email)
  const requestUriForBack = opts.backUri ?? opts.requestUri
  const backHref = requestUriForBack
    ? `/oauth/authorize?request_uri=${encodeURIComponent(requestUriForBack)}`
    : '/oauth/authorize'
  const inputProps = buildOtpInputProps(opts.otpLength, opts.otpCharset)
  // Forward the heartbeat-disabled flag through Resend (POST
  // /auth/recover) so the re-rendered OTP form keeps it disabled.
  // Verify (POST /auth/recover/verify) doesn't re-render this form,
  // so the flag is irrelevant there. Field is only emitted when
  // heartbeat is explicitly off — production calls leave it absent.
  const noHeartbeatField = opts.heartbeatEnabled
    ? ''
    : '<input type="hidden" name="no_heartbeat" value="1">'

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  ${renderFaviconTag(opts.customFaviconUrl, opts.customFaviconUrlDark)}
  <title>Enter recovery code</title>
  <style>${CSS}</style>${renderOptionalStyleTag(opts.customCss)}
</head>
<body>
  <div class="page-wrap">
    <div class="container">
      <h1>Enter recovery code</h1>
      <p id="code-help" class="subtitle">If a backup email matches, we sent a ${opts.otpLength}-${opts.otpCharset === 'alphanumeric' ? 'character' : 'digit'} code to <strong>${escapeHtml(maskedEmail)}</strong></p>
      ${opts.error ? '<p class="error">' + escapeHtml(opts.error) + '</p>' : ''}
      <form method="POST" action="/auth/recover/verify">
        <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
        <input type="hidden" name="request_uri" value="${escapeHtml(opts.requestUri)}">
        <input type="hidden" name="email" value="${escapeHtml(opts.email)}">
        ${noHeartbeatField}
        <div class="field">
          <input type="text" id="code" name="code" required autofocus
                 aria-label="One-time code"
                 aria-describedby="code-help"
                 maxlength="${opts.otpLength}"
                 pattern="${inputProps.pattern}"
                 inputmode="${inputProps.inputmode}"
                 autocomplete="one-time-code"
                 autocapitalize="${inputProps.autocapitalize}"
                 placeholder="${inputProps.placeholder}"
                 class="otp-input"
                  oninput="this.value=this.value.replace(/[\\s-]/g,'')"
                 style="letter-spacing: ${Math.max(2, Math.round(32 / opts.otpLength))}px">
        </div>
        <button type="submit" class="btn-primary">Verify</button>
      </form>
      <form method="POST" action="/auth/recover" style="margin-top: 12px;">
        <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
        <input type="hidden" name="request_uri" value="${escapeHtml(opts.requestUri)}">
        <input type="hidden" name="email" value="${escapeHtml(opts.email)}">
        ${noHeartbeatField}
        <button type="submit" class="btn-secondary">Resend code</button>
      </form>
      <a href="${backHref}" class="btn-secondary">Back to sign in</a>
    </div>
    ${POWERED_BY_HTML}
  </div>
  <script>
    (function() {
      // PAR heartbeat — see packages/auth-service/src/routes/heartbeat.ts.
      // Mirrors the login-page OTP heartbeat. Stops on form submit /
      // unload / when the server reports the auth_flow or PAR is gone.
      if (!${JSON.stringify(opts.heartbeatEnabled)}) return;
      var handle = null;
      function ping() {
        fetch('/auth/ping', { credentials: 'include', cache: 'no-store' })
          .then(function(r) { return r.json(); })
          .then(function(body) {
            // Only terminal reasons stop the loop; 'transient' (5xx /
            // network blip) keeps polling so the next tick recovers.
            if (body && body.ok === false && body.reason !== 'transient') stop();
          })
          .catch(function() {});
      }
      function stop() { if (handle !== null) { clearInterval(handle); handle = null; } }
      handle = setInterval(ping, 3 * 60 * 1000);
      window.addEventListener('beforeunload', stop);
      Array.prototype.forEach.call(document.querySelectorAll('form'), function(form) {
        form.addEventListener('submit', stop);
      });
    })();
  </script>
</body>
</html>`
}

const CSS = `
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; }
  .page-wrap { display: flex; flex-direction: column; align-items: stretch; max-width: 420px; width: 100%; }
  ${POWERED_BY_CSS}
  .container { background: white; border-radius: 12px; padding: 40px; width: 100%; box-shadow: 0 2px 8px rgba(0,0,0,0.08); text-align: center; }
  h1 { font-size: 24px; margin-bottom: 8px; color: #111; }
  .subtitle { color: #666; margin-bottom: 20px; font-size: 15px; line-height: 1.5; }
  .field { margin-bottom: 20px; text-align: left; }
  .field label { display: block; font-size: 14px; font-weight: 500; color: #333; margin-bottom: 6px; }
  .field input { width: 100%; padding: 10px 12px; border: 1px solid #ddd; border-radius: 8px; font-size: 16px; outline: none; }
  .field input:focus { border-color: #0f1828; }
  .otp-input { font-size: 28px !important; text-align: center; font-family: 'SF Mono', Menlo, Consolas, monospace !important; padding: 14px !important; }
  .btn-primary { width: 100%; padding: 12px; background: #0f1828; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 500; cursor: pointer; }
  .btn-primary:hover { background: #1a2a40; }
  .btn-secondary { display: inline-block; margin-top: 12px; color: #0f1828; background: none; border: none; font-size: 14px; cursor: pointer; text-decoration: underline; }
  .error { color: #dc3545; background: #fdf0f0; padding: 12px; border-radius: 8px; margin: 12px 0; }
`
