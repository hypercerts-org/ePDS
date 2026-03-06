/**
 * GET /oauth/authorize — unified login page
 *
 * Replaces the old authorize.ts → send-code.ts → verify-code.ts chain.
 *
 * Flow:
 *   1. Receive request from pds-core AS metadata redirect
 *      (?request_uri=...&client_id=...&prompt=...&login_hint=...)
 *   2. Create an auth_flow row (flow_id, request_uri, client_id)
 *   3. Set epds_auth_flow cookie (10 min, httpOnly)
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
 *   - Bridge reads epds_auth_flow cookie → auth_flow → HMAC-signed redirect
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
import {
  resolveLoginHint,
  fetchParLoginHint,
} from '../lib/resolve-login-hint.js'

const logger = createLogger('auth:login-page')

const AUTH_FLOW_COOKIE = 'epds_auth_flow'
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

    // Pillar 1 — State Determination: decide which step to render.
    // login_hint on the query string means our app explicitly passed an email
    // → show the OTP flow. If absent (standard ATProto clients pass handle/DID
    // in the PAR body, not on the redirect URL), show the email form with a
    // "Sign in with password" link pointing to the PDS built-in OAuth page.
    const pdsInternalUrl =
      process.env.PDS_INTERNAL_URL || ctx.config.pdsPublicUrl
    const internalSecret = process.env.EPDS_INTERNAL_SECRET ?? ''

    // Three cases:
    //   1. login_hint on query string → our app passed an email → OTP flow
    //   2. No query hint, PAR has a hint (handle/DID) → standard ATProto client
    //      → redirect immediately to the PDS built-in OAuth page
    //   3. No hint anywhere → show email form with "Sign in with password" link

    // Case 1: email OTP path
    const resolvedEmail = loginHint
      ? await resolveLoginHint(loginHint, pdsInternalUrl, internalSecret)
      : null

    // Build the PDS authorize URL (used for case 2 redirect and case 3 link).
    const pdsAuthorizeUrl = (() => {
      const u = new URL('/oauth/authorize', ctx.config.pdsPublicUrl)
      u.searchParams.set('request_uri', requestUri)
      if (clientId) u.searchParams.set('client_id', clientId)
      return u.toString()
    })()

    // Case 2: no query hint — check PAR for a handle/DID hint
    if (!loginHint && requestUri) {
      const parLoginHint = await fetchParLoginHint(
        pdsInternalUrl,
        requestUri,
        internalSecret,
      )
      if (parLoginHint) {
        logger.info(
          { loginHint: parLoginHint, redirectTo: pdsAuthorizeUrl },
          'PAR login_hint detected — redirecting to PDS built-in OAuth page',
        )
        res.redirect(302, pdsAuthorizeUrl)
        return
      }
    }

    // Case 3: no hint anywhere — show email form (falls through to render)
    const hasLoginHint = !!resolvedEmail
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

    // Use the resolved email (not the raw loginHint) for pre-filling forms.
    // This ensures handle-based hints get resolved to the correct email.
    const emailHint = resolvedEmail ?? ''

    res.type('html').send(
      renderLoginPage({
        flowId,
        clientId: clientId ?? '',
        clientName,
        branding: clientMeta,
        loginHint: emailHint,
        initialStep,
        otpAlreadySent,
        csrfToken: res.locals.csrfToken,
        authBasePath: '/api/auth',
        pdsPublicUrl: ctx.config.pdsPublicUrl,
        requestUri,
        pdsAuthorizeUrl,
        defaultBrandColor: ctx.config.brandColor,
        defaultBgColor: ctx.config.backgroundColor,
        defaultPanelColor: ctx.config.panelColor,
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
  requestUri: string
  /** PDS-level branding defaults (overridden by OAuth client metadata if present) */
  defaultBrandColor?: string
  defaultBgColor?: string
  defaultPanelColor?: string
  pdsAuthorizeUrl: string
}): string {
  const b = opts.branding
  const appName = b.client_name || opts.clientName || 'Certified'
  // Priority: client metadata > env var defaults > hardcoded fallbacks
  const brandColor = b.brand_color || opts.defaultBrandColor || '#8338ec'
  const bgColor = b.background_color || opts.defaultBgColor || null
  const panelColor = opts.defaultPanelColor || null
  const logoUrl = '/static/gainforest-logo.png'
  const logoHtml = `<img src="${escapeHtml(logoUrl)}" alt="${escapeHtml(appName)}" class="client-logo">`

  // Inline style on :root to override CSS custom properties from client branding.
  // We parse the brand_color hex to extract an approximate hue for the contrast scale.
  // For simplicity we set --color-primary directly; the hue-based scale uses the
  // default 265 (atproto purple) unless overridden.
  //
  // NOTE: background_color is NOT applied on <html> because the light-mode
  // media query `body { background: white }` (body > html specificity) would
  // override it. Instead, bgColor is injected into a <style> block targeting
  // `body` directly (see bgColorStyle below), which wins over the media query
  // rule because it appears later in the stylesheet.
  //
  // When panelColor is set, also override --color-panel and panel text colors
  // so the left panel uses the solid brand color with white text.
  let rootStyleProps = ''
  if (brandColor !== '#8338ec') {
    rootStyleProps += `--color-primary:${escapeHtml(brandColor)};--color-primary-contrast:#fff;`
  }
  if (panelColor) {
    rootStyleProps += `--color-panel:${escapeHtml(panelColor)};--color-panel-text:#fff;--color-panel-subtitle:rgba(255,255,255,0.8);`
  }
  const rootStyle = rootStyleProps ? ` style="${rootStyleProps}"` : ''

  // Inject background_color override as a <style> block targeting body so it
  // takes precedence over the `@media (prefers-color-scheme: light) { body { background: white } }`
  // rule (later declaration wins at equal specificity).
  const bgColorStyle = bgColor
    ? `\n  <style>body { background: ${escapeHtml(bgColor)} !important; }</style>`
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
        <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" aria-hidden="true">
          <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
          <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
          <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/>
          <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
        </svg>
        Sign In with Google
      </a>`
          : ''
      }
      ${
        hasGithub
          ? `
      <a href="${opts.authBasePath}/sign-in/social?provider=github&callbackURL=/auth/complete" class="btn-social btn-github">
        <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" aria-hidden="true">
          <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/>
        </svg>
        Sign In with GitHub
      </a>`
          : ''
      }
    </div>
    <div class="divider"><span>or use email</span></div>
  `
    : ''

  return `<!DOCTYPE html>
<html lang="en"${rootStyle}>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in to ${escapeHtml(appName)}</title>
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

      /* Panel color — overridden via inline style when AUTH_PANEL_COLOR is set */
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

    /* Inner wrapper for title panel content — grid centering on desktop */
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
        /* Only apply the hsl fallback when --color-panel hasn't been overridden */
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
      }
    }

    @media (min-width: 1024px) {
      .title-panel h1 {
        font-size: 48px;
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

    @media (prefers-color-scheme: dark) {
      .input-field::placeholder { color: rgb(107 114 128); }
    }

    /* OTP-specific input styling */
    .otp-input {
      font-family: 'SF Mono', Menlo, Consolas, monospace;
      font-size: 28px;
      letter-spacing: 8px;
      text-align: center;
      padding: 8px 0;
    }

    /* ── Form layout ── */
    .form-group { display: flex; flex-direction: column; gap: 16px; }
    .field { display: flex; flex-direction: column; gap: 4px; }

    /* ── OTP actions layout ── */
    .otp-actions {
      display: flex;
      flex-direction: column;
      align-items: flex-end;
      gap: 16px;
      margin-top: 8px;
    }

    .otp-links {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      font-size: 14px;
      flex-wrap: wrap;
      width: 100%;
    }

    .otp-links-right {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .otp-links-dot {
      color: var(--color-text-light);
    }

    /* ── Text link button (looks like a link, behaves like a button) ── */
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
    }

    .btn-icon {
      width: 20px;
      height: 20px;
      flex-shrink: 0;
    }

    .btn-primary:hover:not(:disabled) {
      opacity: 0.85;
    }

    .btn-primary:focus-visible {
      outline: 2px solid var(--color-contrast-1000);
      outline-offset: 2px;
    }

    .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }

    /* ── Social login buttons ── */
    .social-buttons { display: flex; flex-direction: column; gap: 8px; }

    .btn-social {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      width: 100%;
      padding: 12px 16px;
      min-height: 48px;
      border: none;
      border-radius: 8px;
      font-size: 15px;
      font-weight: 500;
      cursor: pointer;
      text-decoration: none;
      background: var(--color-contrast-25);
      color: var(--color-text-default);
      transition: all 0.3s ease-in-out;
    }

    @media (prefers-color-scheme: dark) {
      .btn-social { background: var(--color-contrast-50); }
    }

    .btn-social:hover { background: var(--color-contrast-50); }

    @media (prefers-color-scheme: dark) {
      .btn-social:hover { background: var(--color-contrast-100); }
    }

    /* ── Divider ── */
    .divider {
      display: flex;
      align-items: center;
      gap: 12px;
      margin: 16px 0;
      color: var(--color-text-light);
      font-size: 13px;
    }

    .divider::before, .divider::after {
      content: '';
      flex: 1;
      height: 1px;
      background: var(--color-border-default);
    }

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
      background: rgba(255, 0, 110, 0.08); /* fallback for color-mix() — matches --color-error at 8% */
    }

    .admonition.success {
      border-color: var(--color-success);
      color: var(--color-success);
      background: rgba(23, 204, 136, 0.08); /* fallback for color-mix() — matches --color-success at 8% */
    }

    .admonition-icon { flex-shrink: 0; margin-top: 1px; }

    /* ── OTP subtitle ── */
    .otp-subtitle {
      font-size: 14px;
      color: var(--color-text-light);
      margin-bottom: 16px;
      line-height: 1.5;
    }

    /* ── Step visibility ── */
    .step-otp { display: none; }
    .step-otp.active { display: block; }
    .step-email.hidden { display: none; }


  </style>${bgColorStyle}
</head>
<body>
  <div class="layout">
    <!-- Left panel: branding -->
    <div class="title-panel">
      <div class="title-panel-inner">
        ${logoHtml}
        <div>
           <img src="/static/sign-in-with-certified-title.svg" alt="Sign in with Certified" class="title-svg">
           <p class="subtitle">Sign in for the interop using Certified</p>
        </div>
      </div>
    </div>

    <!-- Right panel: form -->
    <main class="form-panel">
      <!-- Error / success message -->
      <div id="error-msg" class="admonition error" style="display:none;">
        <span class="admonition-icon admonition-icon-error" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor">
            <path fill-rule="evenodd" clip-rule="evenodd" d="M11.14 4.494a.995.995 0 0 1 1.72 0l7.001 12.008a.996.996 0 0 1-.86 1.498H4.999a.996.996 0 0 1-.86-1.498L11.14 4.494Zm3.447-1.007c-1.155-1.983-4.019-1.983-5.174 0L2.41 15.494C1.247 17.491 2.686 20 4.998 20h14.004c2.312 0 3.751-2.509 2.587-4.506L14.587 3.487ZM13 9.019a1 1 0 1 0-2 0v2.994a1 1 0 1 0 2 0V9.02Zm-1 4.731a1.25 1.25 0 1 0 0 2.5 1.25 1.25 0 0 0 0-2.5Z"/>
          </svg>
        </span>
        <span class="admonition-icon admonition-icon-success" style="display:none;" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor">
            <path d="M21.59 3.193a1 1 0 0 1 .217 1.397l-11.706 16a1 1 0 0 1-1.429.193l-6.294-5a1 1 0 1 1 1.244-1.566l5.48 4.353 11.09-15.16a1 1 0 0 1 1.398-.217Z"/>
          </svg>
        </span>
        <span id="error-text"></span>
      </div>

      <div id="social-section"${opts.initialStep === 'otp' ? ' style="display:none;"' : ''}>
        ${socialButtonsHtml}
      </div>

      <!-- Step 1: Email entry (calls better-auth sendOtp) -->
      <div id="step-email" class="step-email${opts.initialStep === 'otp' ? ' hidden' : ''}">
        <form id="form-send-otp" class="form-group">
          <div class="field">
            <label class="field-label" for="email">Email address</label>
            <div class="input-container">
              <div class="input-inner">
                <span class="input-icon" aria-hidden="true">
                  <svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor">
                    <path fill-rule="evenodd" clip-rule="evenodd" d="M12 4a8 8 0 1 0 4.21 14.804 1 1 0 0 1 1.054 1.7A9.958 9.958 0 0 1 12 22C6.477 22 2 17.523 2 12S6.477 2 12 2s10 4.477 10 10c0 1.104-.27 2.31-.949 3.243-.716.984-1.849 1.6-3.331 1.465a4.207 4.207 0 0 1-2.93-1.585c-.94 1.21-2.388 1.94-3.985 1.715-2.53-.356-4.04-2.91-3.682-5.458.358-2.547 2.514-4.586 5.044-4.23.905.127 1.68.536 2.286 1.126a1 1 0 0 1 1.964.368l-.515 3.545v.002a2.222 2.222 0 0 0 1.999 2.526c.75.068 1.212-.21 1.533-.65.358-.493.566-1.245.566-2.067a8 8 0 0 0-8-8Zm-.112 5.13c-1.195-.168-2.544.819-2.784 2.529-.24 1.71.784 3.03 1.98 3.198 1.195.168 2.543-.819 2.784-2.529.24-1.71-.784-3.03-1.98-3.198Z"/>
                  </svg>
                </span>
                <input type="email" id="email" name="email" class="input-field" required autofocus
                       autocomplete="email" placeholder="you@example.com"
                       value="${escapeHtml(opts.loginHint)}">
              </div>
            </div>
          </div>
          <div class="otp-actions">
            <button type="submit" class="btn-primary">Continue with Email</button>
          </div>
        </form>
        <div style="margin-top: 16px; text-align: center; font-size: 14px;">
        <a href="${escapeHtml(opts.pdsAuthorizeUrl)}" class="link-btn">Sign in with password instead</a>
      </div>
    </div>

      <!-- Step 2: OTP entry (calls better-auth verifyOtp) -->
      <div id="step-otp" class="step-otp${opts.initialStep === 'otp' ? ' active' : ''}">
        <p class="otp-subtitle" id="otp-subtitle">${
          opts.initialStep === 'otp'
            ? opts.otpAlreadySent
              ? `Code already sent to ${escapeHtml(opts.loginHint.replace(/(.{2})[^@]*(@.*)/, '$1***$2'))}`
              : `Sending code to ${escapeHtml(opts.loginHint.replace(/(.{2})[^@]*(@.*)/, '$1***$2'))}...`
            : ''
        }</p>
        <form id="form-verify-otp" class="form-group">
          <input type="hidden" id="otp-email" name="email" value="${escapeHtml(opts.loginHint)}">
          <div class="field">
            <label class="field-label" for="code">One-time code</label>
            <div class="input-container">
              <div class="input-inner">
                <span class="input-icon" aria-hidden="true">
                  <svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor">
                    <path fill-rule="evenodd" clip-rule="evenodd" d="M4 5.5a.5.5 0 0 0-.5.5v2.535a.5.5 0 0 0 .25.433A3.498 3.498 0 0 1 5.5 12a3.498 3.498 0 0 1-1.75 3.032.5.5 0 0 0-.25.433V18a.5.5 0 0 0 .5.5h16a.5.5 0 0 0 .5-.5v-2.535a.5.5 0 0 0-.25-.433A3.498 3.498 0 0 1 18.5 12a3.5 3.5 0 0 1 1.75-3.032.5.5 0 0 0 .25-.433V6a.5.5 0 0 0-.5-.5H4ZM2.5 6A1.5 1.5 0 0 1 4 4.5h16A1.5 1.5 0 0 1 21.5 6v3.17a.5.5 0 0 1-.333.472 2.501 2.501 0 0 0 0 4.716.5.5 0 0 1 .333.471V18a1.5 1.5 0 0 1-1.5 1.5H4A1.5 1.5 0 0 1 2.5 18v-3.17a.5.5 0 0 1 .333-.472 2.501 2.501 0 0 0 0-4.716.5.5 0 0 1-.333-.471V6Zm12 2a.5.5 0 1 1 1 0 .5.5 0 0 1-1 0Zm0 4a.5.5 0 1 1 1 0 .5.5 0 0 1-1 0Zm0 4a.5.5 0 1 1 1 0 .5.5 0 0 1-1 0Z"/>
                  </svg>
                </span>
                <input type="text" id="code" name="code" class="input-field otp-input" required
                       maxlength="8" pattern="[0-9]{8}" inputmode="numeric"
                       autocomplete="one-time-code" placeholder="00000000">
              </div>
            </div>
          </div>
          <div class="otp-actions">
            <button type="submit" class="btn-primary"><img src="/static/certified-green-signin.svg" alt="" class="btn-icon" aria-hidden="true"> Sign In with Certified</button>
            <div class="otp-links">
              <a href="/auth/recover?request_uri=${encodeURIComponent(opts.requestUri)}"
                 class="link-btn" id="recovery-link">Recover with Backup Email</a>
              <div class="otp-links-right">
                <button type="button" class="link-btn" id="btn-back">Use Different Email</button>
                <span class="otp-links-dot">·</span>
                <button type="button" class="link-btn" id="btn-resend">Resend Code</button>
              </div>
            </div>
          </div>
        </form>
      </div>
    </main>
  </div>

  <script>
    (function() {
      var authBasePath = ${JSON.stringify(opts.authBasePath)};
      var requestUri = ${JSON.stringify('')};  // not needed client-side; flow_id is in cookie
      var currentEmail = '';
      var errorEl = document.getElementById('error-msg');
      var errorText = document.getElementById('error-text');
      var iconError = errorEl.querySelector('.admonition-icon-error');
      var iconSuccess = errorEl.querySelector('.admonition-icon-success');
      var stepEmail = document.getElementById('step-email');
      var stepOtp = document.getElementById('step-otp');
      var otpSubtitle = document.getElementById('otp-subtitle');
      var otpEmailInput = document.getElementById('otp-email');
      var recoveryLink = document.getElementById('recovery-link');

      function showError(msg) {
        errorText.textContent = msg;
        errorEl.classList.remove('success');
        errorEl.classList.add('error');
        iconError.style.display = '';
        iconSuccess.style.display = 'none';
        errorEl.setAttribute('role', 'alert');
        errorEl.style.display = 'flex';
      }

      function showSuccess(msg) {
        errorText.textContent = msg;
        errorEl.classList.remove('error');
        errorEl.classList.add('success');
        iconError.style.display = 'none';
        iconSuccess.style.display = '';
        errorEl.setAttribute('role', 'status');
        errorEl.style.display = 'flex';
      }

      function clearError() {
        errorEl.style.display = 'none';
        errorText.textContent = '';
        errorEl.removeAttribute('role');
      }

      function showOtpStep(email) {
        currentEmail = email;
        otpEmailInput.value = email;
        var masked = email.replace(/(.{2})[^@]*(@.*)/, '$1***$2');
        otpSubtitle.textContent = 'We sent an 8-digit code to ' + masked;
        stepEmail.classList.add('hidden');
        stepOtp.classList.add('active');
        var socialSection = document.getElementById('social-section');
        if (socialSection) socialSection.style.display = 'none';
        document.getElementById('code').focus();
        clearError();
      }

      function showEmailStep() {
        stepOtp.classList.remove('active');
        stepEmail.classList.remove('hidden');
        var socialSection = document.getElementById('social-section');
        if (socialSection) socialSection.style.display = '';
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
        btn.textContent = 'Continue with Email';

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
        btn.innerHTML = '<img src="/static/certified-green-signin.svg" alt="" class="btn-icon" aria-hidden="true"> Verifying...';

        var email = currentEmail || otpEmailInput.value;
        var result = await verifyOtp(email, otp);
        btn.disabled = false;
        btn.innerHTML = '<img src="/static/certified-green-signin.svg" alt="" class="btn-icon" aria-hidden="true"> Sign In with Certified';

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
        this.textContent = 'Resend Code';
        if (result.error) {
          showError(result.error);
        } else {
          showSuccess('Code resent!');
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
