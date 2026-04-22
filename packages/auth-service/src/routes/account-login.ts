/**
 * Account Settings Login via better-auth email OTP
 *
 * The login page collects the user's email and then delegates to better-auth's
 * email OTP endpoints:
 *   - POST /api/auth/email-otp/send-verification-otp  (sends OTP)
 *   - POST /api/auth/sign-in/email-otp               (verifies OTP, creates session)
 *
 * After successful sign-in, better-auth sets its session cookie and better-auth
 * returns a redirect to /account (the callbackURL we specify in the form).
 *
 * Note: The actual OTP send/verify calls are made from the browser (via fetch or form
 * submit) directly to the better-auth API endpoints. This file provides the HTML
 * forms that orchestrate those calls.
 */
import { Router, type Request, type Response } from 'express'
import { escapeHtml, maskEmail, createLogger } from '@certified-app/shared'
import { fromNodeHeaders } from 'better-auth/node'
import type { AuthServiceContext } from '../context.js'
import { buildOtpInputProps } from '../otp-input.js'
import type { BetterAuthInstance } from '../better-auth.js'

const logger = createLogger('auth:account-login')

export function createAccountLoginRouter(
  auth: BetterAuthInstance,
  ctx: AuthServiceContext,
): Router {
  const router = Router()

  // GET /account/login - show email form (or redirect if already logged in)
  router.get('/account/login', async (req: Request, res: Response) => {
    try {
      const session = await auth.api.getSession({
        headers: fromNodeHeaders(req.headers),
      })
      if (session?.user.email) {
        res.redirect(303, '/account')
        return
      }
    } catch {
      /* not logged in, continue */
    }

    res.type('html').send(renderLoginForm({ csrfToken: res.locals.csrfToken }))
  })

  // POST /account/send-otp - send OTP via better-auth, show OTP form
  router.post('/account/send-otp', async (req: Request, res: Response) => {
    const email = ((req.body.email as string) || '').trim().toLowerCase()

    if (!email) {
      res.status(400).send(
        renderLoginForm({
          csrfToken: res.locals.csrfToken,
          error: 'Email is required.',
        }),
      )
      return
    }

    try {
      // Call better-auth's email OTP send endpoint
      await auth.api.sendVerificationOTP({
        body: { email, type: 'sign-in' },
      })
    } catch (err) {
      logger.error({ err, email }, 'Failed to send OTP via better-auth')
      // Anti-enumeration: show OTP form even on failure
    }

    res.type('html').send(
      renderOtpForm({
        email,
        csrfToken: res.locals.csrfToken,
        otpLength: ctx.config.otpLength,
        otpCharset: ctx.config.otpCharset,
      }),
    )
  })

  // POST /account/verify-otp - verify OTP via better-auth, redirect to /account
  router.post('/account/verify-otp', async (req: Request, res: Response) => {
    const email = ((req.body.email as string) || '').trim().toLowerCase()
    const otp = ((req.body.otp as string) || '').trim()

    if (!email || !otp) {
      res.status(400).send(
        renderOtpForm({
          email,
          csrfToken: res.locals.csrfToken,
          otpLength: ctx.config.otpLength,
          otpCharset: ctx.config.otpCharset,
          error: 'Email and code are required.',
        }),
      )
      return
    }

    try {
      // Call better-auth's sign-in endpoint — it sets the session cookie and returns JSON
      const response = await auth.api.signInEmailOTP({
        body: { email, otp: otp.toUpperCase() },
        // We don't pass headers here since we want better-auth to create a new session
        // The session cookie will be set on the response
        asResponse: true,
      })

      // Forward the Set-Cookie header from better-auth's response
      const setCookie = response.headers.get('set-cookie')
      if (setCookie) {
        res.setHeader('Set-Cookie', setCookie)
      }
      res.redirect(303, '/account')
      return
    } catch (err: unknown) {
      logger.warn({ err, email }, 'OTP verification failed')
      const errMsg =
        err instanceof Error && err.message.includes('invalid')
          ? 'Invalid or expired code. Please try again.'
          : 'Verification failed. Please try again.'
      res.type('html').send(
        renderOtpForm({
          email,
          csrfToken: res.locals.csrfToken,
          otpLength: ctx.config.otpLength,
          otpCharset: ctx.config.otpCharset,
          error: errMsg,
        }),
      )
    }
  })

  return router
}

function renderLoginForm(opts: { csrfToken: string; error?: string }): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Account Settings - Sign In</title>
  <style>${CSS}</style>
</head>
<body>
  <div class="container">
    <h1>Account Settings</h1>
    <p class="subtitle">Sign in to manage your account</p>
    ${opts.error ? '<p class="error">' + escapeHtml(opts.error) + '</p>' : ''}
    <form method="POST" action="/account/send-otp">
      <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
      <div class="field">
        <label for="email">Email address</label>
        <input type="email" id="email" name="email" required autofocus
               placeholder="you@example.com">
      </div>
      <button type="submit" class="btn-primary">Continue with email</button>
    </form>
  </div>
</body>
</html>`
}

function renderOtpForm(opts: {
  email: string
  csrfToken: string
  otpLength: number
  otpCharset: 'numeric' | 'alphanumeric'
  error?: string
}): string {
  const maskedEmail = maskEmail(opts.email)
  const inputProps = buildOtpInputProps(opts.otpLength, opts.otpCharset)

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Enter your code</title>
  <style>${CSS}</style>
</head>
<body>
  <div class="container">
    <h1>Enter your code</h1>
    <p id="otp-help" class="subtitle">We sent a ${opts.otpLength}-${opts.otpCharset === 'alphanumeric' ? 'character' : 'digit'} code to <strong>${escapeHtml(maskedEmail)}</strong></p>
    ${opts.error ? '<p class="error">' + escapeHtml(opts.error) + '</p>' : ''}
    <form method="POST" action="/account/verify-otp">
      <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
      <input type="hidden" name="email" value="${escapeHtml(opts.email)}">
      <div class="field">
        <input type="text" id="otp" name="otp" required autofocus
               aria-label="One-time code"
               aria-describedby="otp-help"
               maxlength="${opts.otpLength}"
               pattern="${inputProps.pattern}"
               inputmode="${inputProps.inputmode}"
               autocomplete="one-time-code"
               autocapitalize="${inputProps.autocapitalize}"
               placeholder="${inputProps.placeholder}"
               class="otp-input"
               style="letter-spacing: ${Math.max(2, Math.round(32 / opts.otpLength))}px">
      </div>
      <button type="submit" class="btn-primary">Verify</button>
    </form>
    <form method="POST" action="/account/send-otp" style="margin-top: 12px;">
      <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
      <input type="hidden" name="email" value="${escapeHtml(opts.email)}">
      <button type="submit" class="btn-secondary">Resend code</button>
    </form>
  </div>
</body>
</html>`
}

const CSS = `
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
  .container { background: white; border-radius: 12px; padding: 40px; max-width: 420px; width: 100%; box-shadow: 0 2px 8px rgba(0,0,0,0.08); text-align: center; }
  h1 { font-size: 24px; margin-bottom: 8px; color: #111; }
  .subtitle { color: #666; margin-bottom: 20px; font-size: 15px; line-height: 1.5; }
  .field { margin-bottom: 20px; text-align: left; }
  .field label { display: block; font-size: 14px; font-weight: 500; color: #333; margin-bottom: 6px; }
  .field input { width: 100%; padding: 10px 12px; border: 1px solid #ddd; border-radius: 8px; font-size: 16px; outline: none; }
  .field input:focus { border-color: #0f1828; }
  .otp-input { font-size: 28px !important; text-align: center; font-family: 'SF Mono', Menlo, Consolas, monospace !important; padding: 14px !important; }
  .btn-primary { width: 100%; padding: 12px; background: #0f1828; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 500; cursor: pointer; }
  .btn-primary:hover { background: #1a2a40; }
  .btn-secondary { display: inline-block; color: #0f1828; background: none; border: none; font-size: 14px; cursor: pointer; text-decoration: underline; }
  .error { color: #dc3545; background: #fdf0f0; padding: 12px; border-radius: 8px; margin: 12px 0; }
`
