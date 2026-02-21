/**
 * GET /oauth/authorize — unified login page
 *
 * Replaces the old authorize.ts → send-code.ts → verify-code.ts chain.
 *
 * Flow:
 *   1. Receive request from pds-core AS metadata redirect
 *      (?request_uri=...&client_id=...&prompt=...&login_hint=...)
 *   2. Create an auth_flow row (flow_id, request_uri, client_id)
 *   3. Set magic_auth_flow cookie (10 min, httpOnly)
 *   4. Render login page with:
 *      - Email OTP form (submits to better-auth /api/auth/* endpoints)
 *      - Social login buttons (only for configured providers)
 *      - "Recover with backup email" link
 *      - Client branding from OAuth metadata
 *
 * The better-auth flow after login:
 *   - Email OTP: user submits code to /api/auth/sign-in/email-otp/verify
 *   - Social: user clicks button → /api/auth/sign-in/{provider} → OAuth exchange
 *   - On success, better-auth redirects to /auth/complete (the bridge route)
 *   - Bridge reads magic_auth_flow cookie → auth_flow → HMAC-signed redirect
 */
import { Router, type Request, type Response } from 'express'
import { randomBytes } from 'node:crypto'
import type { AuthServiceContext } from '../context.js'
import {
  resolveClientMetadata,
  resolveClientName,
  type ClientMetadata,
} from '../lib/client-metadata.js'
import { escapeHtml, createLogger } from '@certified-app/shared'
import { socialProviders } from '../better-auth.js'

const logger = createLogger('auth:login-page')

const AUTH_FLOW_COOKIE = 'magic_auth_flow'
const AUTH_FLOW_TTL_MS = 10 * 60 * 1000 // 10 minutes

export function createLoginPageRouter(ctx: AuthServiceContext): Router {
  const router = Router()

  router.get('/oauth/authorize', async (req: Request, res: Response) => {
    const requestUri = req.query.request_uri as string | undefined
    const clientId = req.query.client_id as string | undefined
    const loginHint = req.query.login_hint as string | undefined

    if (!requestUri) {
      res
        .status(400)
        .type('html')
        .send(renderError('Missing request_uri parameter'))
      return
    }

    logger.debug(
      {
        requestUri: requestUri.slice(0, 60),
        loginHint: loginHint
          ? loginHint.replace(/(.{2})[^@]*(@.*)/, '$1***$2')
          : undefined,
        userAgent: req.headers['user-agent'],
        referer: req.headers['referer'],
        ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
      },
      'GET /oauth/authorize',
    )

    // Idempotency: if a flow already exists for this request_uri, reuse it rather
    // than creating a second row (and triggering a second OTP send). This protects
    // against duplicate GETs from browser extensions, prefetch, or StayFocusd.
    let flowId: string
    const existingFlow = ctx.db.getAuthFlowByRequestUri(requestUri)
    if (existingFlow) {
      flowId = existingFlow.flowId
      logger.warn(
        {
          flowId,
          requestUri: requestUri.slice(0, 60),
          userAgent: req.headers['user-agent'],
          ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
        },
        'Duplicate GET /oauth/authorize for existing request_uri — reusing flow, dropping duplicate',
      )
    } else {
      flowId = randomBytes(16).toString('hex')
      try {
        ctx.db.createAuthFlow({
          flowId,
          requestUri,
          clientId: clientId ?? null,
          expiresAt: Date.now() + AUTH_FLOW_TTL_MS,
        })
      } catch (err) {
        logger.error({ err }, 'Failed to create auth_flow')
        res
          .status(500)
          .type('html')
          .send(renderError('Internal server error. Please try again.'))
        return
      }
    }

    // Set httpOnly cookie so /auth/complete can retrieve the flow_id
    res.cookie(AUTH_FLOW_COOKIE, flowId, {
      httpOnly: true,
      secure: process.env.NODE_ENV !== 'development',
      sameSite: 'lax',
      maxAge: AUTH_FLOW_TTL_MS,
    })

    // Resolve client branding
    const clientMeta: ClientMetadata = clientId
      ? await resolveClientMetadata(clientId)
      : {}
    const clientName =
      clientMeta.client_name ??
      (clientId ? await resolveClientName(clientId) : 'an application')

    // Pillar 1 — State Determination: decide which step to render based on
    // login_hint presence. No method-assuming side effects in the GET handler.
    const hasLoginHint = !!(loginHint && loginHint.includes('@'))
    const initialStep = hasLoginHint ? 'otp' : 'email'

    // Pillar 3 — Idempotency (Option A): when this is a duplicate GET for an
    // existing flow (e.g. browser extension, StayFocusd), tell the client-side
    // script that OTP was already sent so it skips the auto-send.
    const otpAlreadySent = hasLoginHint && !!existingFlow

    logger.info(
      {
        flowId,
        clientId,
        requestUri: requestUri.slice(0, 50),
        reused: !!existingFlow,
        initialStep,
        otpAlreadySent,
      },
      'Serving login page for auth_flow',
    )

    res.type('html').send(
      renderLoginPage({
        flowId,
        clientId: clientId ?? '',
        clientName,
        branding: clientMeta,
        loginHint: loginHint ?? '',
        initialStep,
        otpAlreadySent,
        csrfToken: res.locals.csrfToken,
        authBasePath: '/api/auth',
        pdsPublicUrl: ctx.config.pdsPublicUrl,
      }),
    )
  })

  return router
}

function renderLoginPage(opts: {
  flowId: string
  clientId: string
  clientName: string
  branding: ClientMetadata
  loginHint: string
  initialStep: 'email' | 'otp'
  otpAlreadySent: boolean
  csrfToken: string
  authBasePath: string
  pdsPublicUrl: string
}): string {
  const b = opts.branding
  const appName = b.client_name || opts.clientName || 'Certified'
  const brandColor = b.brand_color || '#1A130F'
  const bgColor = b.background_color || '#F2EBE4'
  const logoHtml = b.logo_uri
    ? `<img src="${escapeHtml(b.logo_uri)}" alt="${escapeHtml(appName)}" class="client-logo">`
    : ''

  const hasGoogle = 'google' in socialProviders
  const hasGithub = 'github' in socialProviders
  const hasSocialProviders = hasGoogle || hasGithub

  // Social login buttons — redirect to better-auth provider endpoints
  const socialButtonsHtml = hasSocialProviders
    ? `
    <div class="divider"><span>or continue with</span></div>
    <div class="social-buttons">
      ${
        hasGoogle
          ? `
      <a href="${opts.authBasePath}/sign-in/social?provider=google&callbackURL=/auth/complete" class="btn-social btn-google">
        <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
          <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
          <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
          <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/>
          <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
        </svg>
        Sign in with Google
      </a>`
          : ''
      }
      ${
        hasGithub
          ? `
      <a href="${opts.authBasePath}/sign-in/social?provider=github&callbackURL=/auth/complete" class="btn-social btn-github">
        <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
          <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/>
        </svg>
        Sign in with GitHub
      </a>`
          : ''
      }
    </div>
    <div class="divider"><span>or use email</span></div>
  `
    : ''

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in to ${escapeHtml(appName)}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: ${escapeHtml(bgColor)}; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .container { background: transparent; padding: 40px; max-width: 420px; width: 100%; text-align: center; }
    .client-logo { height: 80px; margin-bottom: 24px; display: block; margin-left: auto; margin-right: auto; }
    h1 { font-size: 24px; margin-bottom: 8px; color: #1A130F; }
    .subtitle { color: #555; margin-bottom: 24px; font-size: 15px; line-height: 1.5; }
    .field { margin-bottom: 16px; text-align: left; }
    .field label { display: block; font-size: 14px; font-weight: 500; color: #333; margin-bottom: 6px; }
    .field input { width: 100%; padding: 10px 12px; border: 1px solid #ddd; border-radius: 8px; font-size: 16px; outline: none; background: white; }
    .field input:focus { border-color: ${escapeHtml(brandColor)}; }
    .otp-input { font-size: 28px !important; text-align: center; letter-spacing: 8px; font-family: 'SF Mono', Menlo, Consolas, monospace !important; padding: 14px !important; }
    .otp-input:focus { border-color: ${escapeHtml(brandColor)} !important; }
    .btn-primary { width: 100%; padding: 12px; background: ${escapeHtml(brandColor)}; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 500; cursor: pointer; }
    .btn-primary:hover { opacity: 0.9; }
    .btn-primary:disabled { opacity: 0.7; cursor: not-allowed; }
    .btn-secondary { display: inline-block; margin-top: 12px; color: #555; background: none; border: none; font-size: 14px; cursor: pointer; text-decoration: underline; }
    .btn-social { display: flex; align-items: center; justify-content: center; gap: 8px; width: 100%; padding: 10px 16px; border: 1px solid #ddd; border-radius: 8px; font-size: 15px; font-weight: 500; cursor: pointer; text-decoration: none; background: white; color: #333; margin-bottom: 8px; }
    .btn-social:hover { background: #f5f5f5; }
    .divider { display: flex; align-items: center; gap: 12px; margin: 16px 0; color: #888; font-size: 13px; }
    .divider::before, .divider::after { content: ''; flex: 1; height: 1px; background: #ddd; }
    .error { color: #dc3545; background: #fdf0f0; padding: 12px; border-radius: 8px; margin: 12px 0; font-size: 14px; }
    .step-otp { display: none; }
    .step-otp.active { display: block; }
    .step-email.hidden { display: none; }
    .recovery-link { display: block; margin-top: 16px; color: #888; font-size: 13px; text-decoration: none; }
    .recovery-link:hover { color: #555; }
  </style>
</head>
<body>
  <div class="container">
    ${logoHtml}
    <h1>Sign in</h1>
    <p class="subtitle">to use <strong>${escapeHtml(appName)}</strong></p>

    <div id="error-msg" class="error" style="display:none;"></div>

    ${socialButtonsHtml}

    <!-- Step 1: Email entry (calls better-auth sendOtp) -->
    <div id="step-email" class="step-email${opts.initialStep === 'otp' ? ' hidden' : ''}">
      <form id="form-send-otp">
        <div class="field">
          <label for="email">Email address</label>
          <input type="email" id="email" name="email" required autofocus
                 placeholder="you@example.com"
                 value="${escapeHtml(opts.loginHint)}">
        </div>
        <button type="submit" class="btn-primary">Continue with email</button>
      </form>
    </div>

    <!-- Step 2: OTP entry (calls better-auth verifyOtp) -->
    <div id="step-otp" class="step-otp${opts.initialStep === 'otp' ? ' active' : ''}">
      <p class="subtitle" id="otp-subtitle">${
        opts.initialStep === 'otp'
          ? opts.otpAlreadySent
            ? `Code already sent to ${escapeHtml(opts.loginHint.replace(/(.{2})[^@]*(@.*)/, '$1***$2'))}`
            : `Sending code to ${escapeHtml(opts.loginHint.replace(/(.{2})[^@]*(@.*)/, '$1***$2'))}…`
          : 'We sent a code to your email'
      }</p>
      <form id="form-verify-otp">
        <input type="hidden" id="otp-email" name="email" value="${escapeHtml(opts.loginHint)}">
        <div class="field">
          <input type="text" id="code" name="code" required
                 maxlength="8" pattern="[0-9]{8}" inputmode="numeric"
                 autocomplete="one-time-code" placeholder="00000000" class="otp-input">
        </div>
        <button type="submit" class="btn-primary">Verify</button>
      </form>
      <button type="button" class="btn-secondary" id="btn-resend">Resend code</button>
      <button type="button" class="btn-secondary" id="btn-back" style="margin-left: 8px;">Use different email</button>
    </div>

    <a href="/auth/recover?request_uri=${encodeURIComponent(opts.pdsPublicUrl + '/placeholder')}"
       class="recovery-link" id="recovery-link" style="display:${opts.initialStep === 'otp' ? 'block' : 'none'};">
      Recover with backup email
    </a>
  </div>

  <script>
    (function() {
      var authBasePath = ${JSON.stringify(opts.authBasePath)};
      var requestUri = ${JSON.stringify('')};  // not needed client-side; flow_id is in cookie
      var currentEmail = '';
      var errorEl = document.getElementById('error-msg');
      var stepEmail = document.getElementById('step-email');
      var stepOtp = document.getElementById('step-otp');
      var otpSubtitle = document.getElementById('otp-subtitle');
      var otpEmailInput = document.getElementById('otp-email');
      var recoveryLink = document.getElementById('recovery-link');

      function showError(msg) {
        errorEl.textContent = msg;
        errorEl.style.display = 'block';
      }

      function clearError() {
        errorEl.style.display = 'none';
        errorEl.textContent = '';
      }

      function showOtpStep(email) {
        currentEmail = email;
        otpEmailInput.value = email;
        var masked = email.replace(/(.{2})[^@]*(@.*)/, '$1***$2');
        otpSubtitle.textContent = 'We sent an 8-digit code to ' + masked;
        stepEmail.classList.add('hidden');
        stepOtp.classList.add('active');
        recoveryLink.style.display = 'block';
        document.getElementById('code').focus();
        clearError();
      }

      function showEmailStep() {
        stepOtp.classList.remove('active');
        stepEmail.classList.remove('hidden');
        recoveryLink.style.display = 'none';
        clearError();
      }

      // Send OTP via better-auth
      async function sendOtp(email) {
        try {
          var res = await fetch(authBasePath + '/email-otp/send-verification-otp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: email, type: 'sign-in' }),
          });
          if (!res.ok) {
            var data = await res.json().catch(function() { return {}; });
            return { error: data.message || data.error || 'Failed to send code' };
          }
          return { ok: true };
        } catch (err) {
          return { error: 'Network error. Please try again.' };
        }
      }

      // Verify OTP via better-auth and redirect
      async function verifyOtp(email, otp) {
        try {
          var res = await fetch(authBasePath + '/sign-in/email-otp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: email, otp: otp }),
          });
          if (!res.ok) {
            var data = await res.json().catch(function() { return {}; });
            return { error: data.message || data.error || 'Invalid code' };
          }
          // Success: redirect to /auth/complete to complete the AT Protocol flow
          window.location.href = '/auth/complete';
          return { ok: true };
        } catch (err) {
          return { error: 'Network error. Please try again.' };
        }
      }

      // Form: send OTP
      document.getElementById('form-send-otp').addEventListener('submit', async function(e) {
        e.preventDefault();
        clearError();
        var email = document.getElementById('email').value.trim().toLowerCase();
        if (!email) return;
        var btn = this.querySelector('button[type=submit]');
        btn.disabled = true;
        btn.textContent = 'Sending...';

        var result = await sendOtp(email);
        btn.disabled = false;
        btn.textContent = 'Continue with email';

        if (result.error) {
          showError(result.error);
        } else {
          showOtpStep(email);
        }
      });

      // Form: verify OTP
      document.getElementById('form-verify-otp').addEventListener('submit', async function(e) {
        e.preventDefault();
        clearError();
        var otp = document.getElementById('code').value.trim();
        var btn = this.querySelector('button[type=submit]');
        btn.disabled = true;
        btn.textContent = 'Verifying...';

        var result = await verifyOtp(currentEmail, otp);
        btn.disabled = false;
        btn.textContent = 'Verify';

        if (result && result.error) {
          showError(result.error);
        }
      });

      // Resend code
      document.getElementById('btn-resend').addEventListener('click', async function() {
        clearError();
        this.disabled = true;
        this.textContent = 'Sending...';
        var result = await sendOtp(currentEmail);
        this.disabled = false;
        this.textContent = 'Resend code';
        if (result.error) {
          showError(result.error);
        } else {
          showError('Code resent!');
          errorEl.style.color = '#28a745';
          errorEl.style.background = '#f0fff4';
        }
      });

      // Back to email step
      document.getElementById('btn-back').addEventListener('click', function() {
        showEmailStep();
        document.getElementById('code').value = '';
      });

      // Pillar 1: If login_hint was provided, the OTP step is already visible
      // server-side — no DOM transition needed.
      // Pillar 2: Auto-fire the OTP send as a client-side POST.
      // Pillar 3: Skip auto-send if this is a duplicate GET (otpAlreadySent).
      var loginHint = ${JSON.stringify(opts.loginHint)};
      var initialStep = ${JSON.stringify(opts.initialStep)};
      var otpAlreadySent = ${JSON.stringify(opts.otpAlreadySent)};

      if (initialStep === 'otp' && loginHint) {
        currentEmail = loginHint;
        var masked = loginHint.replace(/(.{2})[^@]*(@.*)/, '$1***$2');
        if (!otpAlreadySent) {
          // First load — fire the OTP send in the background.
          sendOtp(loginHint).then(function(result) {
            if (result.error) {
              showError(result.error);
            } else {
              otpSubtitle.textContent = 'We sent an 8-digit code to ' + masked;
            }
          });
        }
      }
    })();
  </script>
</body>
</html>`
}

function renderError(message: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Error</title></head>
<body><p style="color:red;padding:20px">${escapeHtml(message)}</p></body>
</html>`
}
