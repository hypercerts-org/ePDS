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
import { createLogger } from '@certified-app/shared'
import { escapeHtml, maskEmail } from '@certified-app/shared'
import { buildOtpInputProps } from '../otp-input.js'

const logger = createLogger('auth:recovery')

const AUTH_FLOW_COOKIE = 'epds_auth_flow'

export function createRecoveryRouter(
  ctx: AuthServiceContext,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- better-auth instance has no exported type
  auth: any,
): Router {
  const router = Router()
  const otpLength = ctx.config.otpLength
  const otpCharset = ctx.config.otpCharset

  router.get('/auth/recover', (req: Request, res: Response) => {
    const requestUri = req.query.request_uri as string | undefined

    if (!requestUri) {
      res.status(400).send(renderError('Missing request_uri parameter'))
      return
    }

    res.type('html').send(
      renderRecoveryForm({
        requestUri,
        csrfToken: res.locals.csrfToken,
      }),
    )
  })

  router.post('/auth/recover', async (req: Request, res: Response) => {
    const email = ((req.body.email as string) || '').trim().toLowerCase()
    const requestUri = req.body.request_uri as string

    if (!email || !requestUri) {
      res.status(400).send(
        renderRecoveryForm({
          requestUri: requestUri || '',
          csrfToken: res.locals.csrfToken,
          error: 'Email and request URI are required.',
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
        if (!flowId || !ctx.db.getAuthFlow(flowId)) {
          const { randomBytes } = await import('node:crypto')
          flowId = randomBytes(16).toString('hex')
          ctx.db.createAuthFlow({
            flowId,
            requestUri,
            clientId: null,
            expiresAt: Date.now() + 10 * 60 * 1000,
          })
          res.cookie(AUTH_FLOW_COOKIE, flowId, {
            httpOnly: true,
            secure: process.env.NODE_ENV !== 'development',
            sameSite: 'lax',
            maxAge: 10 * 60 * 1000,
          })
        }

        // Send OTP via better-auth emailOTP plugin
        await auth.api.sendVerificationOTP({
          body: { email, type: 'sign-in' },
        })

        logger.info({ email }, 'Recovery OTP sent via better-auth')
        res.send(
          renderOtpForm({
            email,
            csrfToken: res.locals.csrfToken,
            requestUri,
            otpLength,
            otpCharset,
          }),
        )
      } catch (err) {
        logger.error({ err }, 'Failed to send recovery OTP')
        res.status(500).send(
          renderOtpForm({
            email,
            csrfToken: res.locals.csrfToken,
            requestUri,
            error: 'Failed to send code. Please try again.',
            otpLength,
            otpCharset,
          }),
        )
      }
    } else {
      // No backup email found, but show OTP form anyway (anti-enumeration)
      res.send(
        renderOtpForm({
          email,
          csrfToken: res.locals.csrfToken,
          requestUri,
          otpLength,
          otpCharset,
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
      res.status(400).send('<p>Missing required fields.</p>')
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
      res.send(
        renderOtpForm({
          email,
          csrfToken: res.locals.csrfToken,
          requestUri,
          error: errMsg,
          otpLength,
          otpCharset,
        }),
      )
    }
  })

  return router
}

function renderRecoveryForm(opts: {
  requestUri: string
  csrfToken: string
  error?: string
}): string {
  const encodedUri = encodeURIComponent(opts.requestUri)
  const errorHtml = opts.error
    ? `<div class="admonition error" role="alert">
        <span class="admonition-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor">
            <path fill-rule="evenodd" clip-rule="evenodd" d="M11.14 4.494a.995.995 0 0 1 1.72 0l7.001 12.008a.996.996 0 0 1-.86 1.498H4.999a.996.996 0 0 1-.86-1.498L11.14 4.494Zm3.447-1.007c-1.155-1.983-4.019-1.983-5.174 0L2.41 15.494C1.247 17.491 2.686 20 4.998 20h14.004c2.312 0 3.751-2.509 2.587-4.506L14.587 3.487ZM13 9.019a1 1 0 1 0-2 0v2.994a1 1 0 1 0 2 0V9.02Zm-1 4.731a1.25 1.25 0 1 0 0 2.5 1.25 1.25 0 0 0 0-2.5Z"/>
          </svg>
        </span>
        <span>${escapeHtml(opts.error)}</span>
      </div>`
    : ''

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Account Recovery</title>
  <style>${getBaseCSS()}</style>
</head>
<body>
  <div class="layout">
    <div class="title-panel">
      <div class="title-panel-content">
        <h1 class="title">Account Recovery</h1>
        <p class="subtitle">Enter the backup email address associated with your account.</p>
      </div>
    </div>
    <main class="form-panel">
      ${errorHtml}
      <form method="POST" action="/auth/recover">
        <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
        <input type="hidden" name="request_uri" value="${escapeHtml(opts.requestUri)}">
        <div class="field">
          <label class="field-label" for="email">Backup email address</label>
          <div class="input-container">
            <div class="input-inner">
              <span class="input-icon" aria-hidden="true">
                <svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor">
                  <path fill-rule="evenodd" clip-rule="evenodd" d="M12 4a8 8 0 1 0 4.21 14.804 1 1 0 0 1 1.054 1.7A9.958 9.958 0 0 1 12 22C6.477 22 2 17.523 2 12S6.477 2 12 2s10 4.477 10 10c0 1.104-.27 2.31-.949 3.243-.716.984-1.849 1.6-3.331 1.465a4.207 4.207 0 0 1-2.93-1.585c-.94 1.21-2.388 1.94-3.985 1.715-2.53-.356-4.04-2.91-3.682-5.458.358-2.547 2.514-4.586 5.044-4.23.905.127 1.68.536 2.286 1.126a1 1 0 0 1 1.964.368l-.515 3.545v.002a2.222 2.222 0 0 0 1.999 2.526c.75.068 1.212-.21 1.533-.65.358-.493.566-1.245.566-2.067a8 8 0 0 0-8-8Zm-.112 5.13c-1.195-.168-2.544.819-2.784 2.529-.24 1.71.784 3.03 1.98 3.198 1.195.168 2.543-.819 2.784-2.529.24-1.71-.784-3.03-1.98-3.198Z"/>
                </svg>
              </span>
              <input type="email" id="email" name="email" class="input-field" required autofocus
                     autocomplete="email" placeholder="backup@example.com">
            </div>
          </div>
        </div>
        <div class="form-actions">
          <a href="/oauth/authorize?request_uri=${encodedUri}" class="link-btn">Back to sign in</a>
          <button type="submit" class="btn-primary">Send Recovery Code</button>
        </div>
      </form>
    </main>
  </div>
</body>
</html>`
}

function renderOtpForm(opts: {
  email: string
  csrfToken: string
  requestUri: string
  otpLength: number
  otpCharset: 'numeric' | 'alphanumeric'
  error?: string
}): string {
  const maskedEmail = maskEmail(opts.email)
  const encodedUri = encodeURIComponent(opts.requestUri)
  const inputProps = buildOtpInputProps(opts.otpLength, opts.otpCharset)
  const errorHtml = opts.error
    ? `<div class="admonition error" role="alert">
        <span class="admonition-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor">
            <path fill-rule="evenodd" clip-rule="evenodd" d="M11.14 4.494a.995.995 0 0 1 1.72 0l7.001 12.008a.996.996 0 0 1-.86 1.498H4.999a.996.996 0 0 1-.86-1.498L11.14 4.494Zm3.447-1.007c-1.155-1.983-4.019-1.983-5.174 0L2.41 15.494C1.247 17.491 2.686 20 4.998 20h14.004c2.312 0 3.751-2.509 2.587-4.506L14.587 3.487ZM13 9.019a1 1 0 1 0-2 0v2.994a1 1 0 1 0 2 0V9.02Zm-1 4.731a1.25 1.25 0 1 0 0 2.5 1.25 1.25 0 0 0 0-2.5Z"/>
          </svg>
        </span>
        <span>${escapeHtml(opts.error)}</span>
      </div>`
    : ''

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Enter recovery code</title>
  <style>${getBaseCSS()}</style>
</head>
<body>
  <div class="layout">
    <div class="title-panel">
      <div class="title-panel-content">
        <h1 class="title">Account Recovery</h1>
        <p class="subtitle">Enter the recovery code</p>
      </div>
    </div>
    <main class="form-panel">
      ${errorHtml}
      <p class="otp-subtitle">If a backup email matches, we sent a ${opts.otpLength}-${opts.otpCharset === 'alphanumeric' ? 'character' : 'digit'} code to <strong>${escapeHtml(maskedEmail)}</strong></p>
      <form method="POST" action="/auth/recover/verify">
        <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
        <input type="hidden" name="request_uri" value="${escapeHtml(opts.requestUri)}">
        <input type="hidden" name="email" value="${escapeHtml(opts.email)}">
        <div class="field">
          <label class="field-label" for="code">One-time code</label>
          <div class="input-container">
            <div class="input-inner">
              <span class="input-icon" aria-hidden="true">
                <svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor">
                  <path fill-rule="evenodd" clip-rule="evenodd" d="M4 5.5a.5.5 0 0 0-.5.5v2.535a.5.5 0 0 0 .25.433A3.498 3.498 0 0 1 5.5 12a3.498 3.498 0 0 1-1.75 3.032.5.5 0 0 0-.25.433V18a.5.5 0 0 0 .5.5h16a.5.5 0 0 0 .5-.5v-2.535a.5.5 0 0 0-.25-.433A3.498 3.498 0 0 1 18.5 12a3.5 3.5 0 0 1 1.75-3.032.5.5 0 0 0 .25-.433V6a.5.5 0 0 0-.5-.5H4ZM2.5 6A1.5 1.5 0 0 1 4 4.5h16A1.5 1.5 0 0 1 21.5 6v3.17a.5.5 0 0 1-.333.472 2.501 2.501 0 0 0 0 4.716.5.5 0 0 1 .333.471V18a1.5 1.5 0 0 1-1.5 1.5H4A1.5 1.5 0 0 1 2.5 18v-3.17a.5.5 0 0 1 .333-.472 2.501 2.501 0 0 0 0-4.716.5.5 0 0 1-.333-.471V6Zm12 2a.5.5 0 1 1 1 0 .5.5 0 0 1-1 0Zm0 4a.5.5 0 1 1 1 0 .5.5 0 0 1-1 0Zm0 4a.5.5 0 1 1 1 0 .5.5 0 0 1-1 0Z"/>
                </svg>
              </span>
              <input type="text" id="code" name="code" class="input-field otp-input" required autofocus
                     maxlength="${opts.otpLength}"
                     pattern="${inputProps.pattern}"
                     inputmode="${inputProps.inputmode}"
                     autocomplete="one-time-code"
                     autocapitalize="${inputProps.autocapitalize}"
                     placeholder="${inputProps.placeholder}">
            </div>
          </div>
        </div>
        <div class="form-actions">
          <div class="otp-links">
            <a href="/oauth/authorize?request_uri=${encodedUri}" class="link-btn">Back to sign in</a>
            <span class="otp-links-dot">·</span>
            <form method="POST" action="/auth/recover" class="inline-form">
              <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
              <input type="hidden" name="request_uri" value="${escapeHtml(opts.requestUri)}">
              <input type="hidden" name="email" value="${escapeHtml(opts.email)}">
              <button type="submit" class="link-btn">Resend Code</button>
            </form>
          </div>
          <button type="submit" class="btn-primary">Verify</button>
        </div>
      </form>
    </main>
  </div>
</body>
</html>`
}

function renderError(message: string): string {
  const errorHtml = `<div class="admonition error" role="alert">
    <span class="admonition-icon" aria-hidden="true">
      <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor">
        <path fill-rule="evenodd" clip-rule="evenodd" d="M11.14 4.494a.995.995 0 0 1 1.72 0l7.001 12.008a.996.996 0 0 1-.86 1.498H4.999a.996.996 0 0 1-.86-1.498L11.14 4.494Zm3.447-1.007c-1.155-1.983-4.019-1.983-5.174 0L2.41 15.494C1.247 17.491 2.686 20 4.998 20h14.004c2.312 0 3.751-2.509 2.587-4.506L14.587 3.487ZM13 9.019a1 1 0 1 0-2 0v2.994a1 1 0 1 0 2 0V9.02Zm-1 4.731a1.25 1.25 0 1 0 0 2.5 1.25 1.25 0 0 0 0-2.5Z"/>
      </svg>
    </span>
    <span>${escapeHtml(message)}</span>
  </div>`

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Error</title>
  <style>${getBaseCSS()}</style>
</head>
<body>
  <div class="layout">
    <div class="title-panel">
      <div class="title-panel-content">
        <h1 class="title">Account Recovery</h1>
      </div>
    </div>
    <main class="form-panel">
      ${errorHtml}
    </main>
  </div>
</body>
</html>`
}

/** Returns the shared CSS token system and layout styles for all recovery pages. */
function getBaseCSS(): string {
  return `
    /* ── CSS custom property color token system (mirrors atproto oauth-provider-ui) ── */
    :root {
      --hue-primary: 265;

      --color-primary: #8338ec;
      --color-primary-contrast: #fff;
      --color-error: rgb(255 0 110);
      --color-success: rgb(16 153 102);

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
      min-width: 100%;
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
    }

    .title-panel-content {
      display: grid;
      flex-grow: 1;
      align-content: center;
      justify-items: end;
    }

    @media (min-width: 768px) {
      .title-panel {
        width: 50%;
        max-width: 512px;
        padding: 16px;
        background: var(--color-panel);
        align-self: stretch;
        flex-direction: column;
        align-items: end;
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

    .title-panel h1 {
      font-size: 20px;
      font-weight: 600;
      color: var(--color-panel-text, var(--color-primary));
      line-height: 1.2;
    }

    @media (min-width: 768px) {
      .title-panel h1 {
        font-size: 24px;
        margin: 16px 0;
        text-align: right;
      }
    }

    @media (min-width: 1024px) {
      .title-panel h1 {
        font-size: 48px;
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
      .title-panel .subtitle { display: block; text-align: right; }
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
      text-overflow: ellipsis;
      background-clip: padding-box;
    }

    .input-field::placeholder { color: var(--color-text-light); }

    /* OTP-specific input styling */
    .otp-input {
      font-family: 'SF Mono', Menlo, Consolas, monospace;
      font-size: 28px;
      letter-spacing: 8px;
      text-align: center;
      padding: 8px 0;
    }

    /* ── Form layout ── */
    .field { display: flex; flex-direction: column; gap: 4px; margin-bottom: 16px; }

    /* ── OTP links layout ── */
    .otp-links {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      font-size: 14px;
      flex-wrap: wrap;
      width: 100%;
      margin-top: 12px;
    }

    /* ── Text link button ── */
    .link-btn {
      background: none;
      border: none;
      padding: 0;
      font-size: 14px;
      font-weight: 500;
      color: var(--color-primary);
      cursor: pointer;
      text-decoration: none;
      transition: opacity 0.2s ease;
    }

    .link-btn:hover {
      text-decoration: underline;
    }

    .link-btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    /* ── Primary button ── */
    .btn-primary {
      background: var(--color-primary);
      color: var(--color-primary-contrast);
      border: none;
      border-radius: 6px;
      padding: 12px 24px;
      min-height: 48px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      font-size: 16px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.3s ease-in-out;
      outline: none;
      white-space: nowrap;
      overflow: hidden;
      letter-spacing: 0.025em;
      touch-action: manipulation;
      width: auto;
    }

    .btn-primary:hover:not(:disabled) {
      opacity: 0.85;
    }

    .btn-primary:focus-visible {
      outline: 2px solid var(--color-contrast-1000);
      outline-offset: 2px;
    }

    .form-actions {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 8px;
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

    .admonition.success {
      border-color: var(--color-success);
      color: var(--color-success);
      background: rgba(16, 153, 102, 0.08);
    }

    .admonition-icon { flex-shrink: 0; margin-top: 1px; }

    /* ── OTP subtitle ── */
    .otp-subtitle {
      font-size: 14px;
      color: var(--color-text-light);
      margin-bottom: 16px;
      line-height: 1.5;
    }

    .inline-form { display: inline; }
  `
}
