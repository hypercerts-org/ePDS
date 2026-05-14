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
 *      - "Recover with backup email" link (shown by default; clients
 *        hide via --recovery-link-display: none in branding.css)
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
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import type { AuthServiceContext } from '../context.js'
import {
  resolveClientMetadata,
  resolveClientName,
  getClientCss,
  getClientFaviconUrl,
  getClientFaviconUrlDark,
  type ClientMetadata,
} from '../lib/client-metadata.js'
import {
  escapeHtml,
  createLogger,
  resolveHandleMode as sharedResolveHandleMode,
  type HandleMode,
} from '@certified-app/shared'
import { socialProviders } from '../better-auth.js'
import { buildOtpInputProps } from '../otp-input.js'
import {
  resolveLoginHint,
  fetchParLoginHint,
} from '../lib/resolve-login-hint.js'
import { ensurePdsUrl } from '../lib/pds-url.js'
import {
  renderOptionalStyleTag,
  renderFaviconTag,
} from '../lib/page-helpers.js'
import { renderError } from '../lib/render-error.js'
import {
  appendOrphanDeviceCookieClearHeaders,
  buildPdsAuthorizeRedirect,
  deriveSharedCookieDomain,
  hasOrphanDeviceCookie,
  readDeviceSessionCookies,
  shouldReuseSession,
} from '../lib/session-reuse.js'
import { fetchDeviceAccountEmails } from '../lib/fetch-device-accounts.js'
import { AUTH_FLOW_COOKIE, AUTH_FLOW_TTL_MS } from '../lib/auth-flow.js'

const logger = createLogger('auth:login-page')

// Inline the Certified wordmark so CSS `color` can tint it via `currentColor`.
const __dirname = path.dirname(fileURLToPath(import.meta.url))
const CERTIFIED_MARK_SVG = readFileSync(
  path.resolve(
    __dirname,
    '..',
    '..',
    'public',
    'certified-text-monochrome.svg',
  ),
  'utf8',
)
  .replace(/fill="#726A60"/g, 'fill="currentColor"')
  .replace(
    '<svg ',
    '<svg class="certified-mark" aria-label="Certified" role="img" ',
  )

/**
 * Reject URLs that aren't http(s) — keeps `javascript:` and other
 * exotic schemes out of the page when client metadata is read raw.
 */
function isSafeHttpUrl(value: string | undefined): boolean {
  if (!value) return false
  try {
    const u = new URL(value)
    return u.protocol === 'https:' || u.protocol === 'http:'
  } catch {
    return false
  }
}

export async function safeResolveClientMetadata(
  clientId: string | undefined,
): Promise<ClientMetadata> {
  if (!clientId) return {}
  try {
    return await resolveClientMetadata(clientId)
  } catch (err) {
    // Degrade gracefully: no branding, handleMode falls back to null. user can still continue
    logger.error({ err, clientId }, 'Failed to resolve client metadata')
    return {}
  }
}

/**
 * Thin wrapper around the shared resolver that accepts a full `ClientMetadata`
 * object for ergonomics. The shared resolver takes the narrower
 * `epds_handle_mode` field because it is also called by pds-core, which only
 * has the same three-level precedence to apply.
 */
export function resolveHandleMode(
  queryParam: string | undefined,
  clientMeta: ClientMetadata,
): HandleMode {
  return sharedResolveHandleMode(queryParam, clientMeta.epds_handle_mode)
}

/**
 * Decide whether to enable the OTP-form / recovery-form heartbeat for
 * this request. Heartbeat is on by default; the only way to disable it
 * is to combine `EPDS_TEST_HOOKS=1` (a server-side opt-in already
 * required for the e2e test-only routes) with `no_heartbeat=1` on the
 * URL OR in the form body. This lets e2e scenarios prove the
 * heartbeat is what saves a slow user without removing the heartbeat
 * in production.
 *
 * The body branch matters for the recovery flow: the email-submit
 * POST to `/auth/recover` strips query params from the subsequent
 * OTP form re-render, so a recovery scenario that wants to disable
 * the heartbeat needs to forward the flag as a hidden field on the
 * email form. The toggle's only consumer today is the
 * @par-heartbeat e2e scenario which goes through the login page,
 * not recovery, so the recovery propagation is a future concern —
 * documented here so that path doesn't surprise a future reader.
 */
export function heartbeatEnabledFor(req: Request): boolean {
  if (process.env.EPDS_TEST_HOOKS !== '1') return true
  if (req.query.no_heartbeat === '1') return false
  // Express's body parser populates req.body for
  // application/x-www-form-urlencoded POSTs. Reading both surfaces
  // covers the GET-with-query and POST-with-hidden-field cases
  // symmetrically; the field is treated as a literal '1' switch so
  // garbage values don't accidentally disable production heartbeat.
  const body = req.body as { no_heartbeat?: string } | undefined
  if (body?.no_heartbeat === '1') return false
  return true
}

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

    // HYPER-268: Cross-client OAuth session reuse.
    //
    // If a device session already exists in this browser (dev-id cookie
    // set on the shared parent domain by a previous sign-in via any
    // client), hand the flow straight to pds-core's upstream
    // /oauth/authorize. Upstream will then either auto-select the single
    // matching session (flow 1, login_hint matches) or render the
    // account chooser (flow 2, no hint).
    //
    // Flow 1 hint-vs-bindings gate: when login_hint resolves to an
    // email that is NOT bound to the current device, we skip the chooser
    // redirect and fall through to the email/OTP form. Otherwise the
    // chooser would either auto-select the wrong account (single
    // binding) or surface the hinted user's mailbox to a stranger
    // (multi-binding). Cookies are left intact so other accounts on the
    // device remain reusable on subsequent un-hinted visits.
    //
    // The prompt=login escape hatch (OIDC "force reauthentication") is
    // honoured inside shouldReuseSession — so the "Use a different
    // account" link on the chooser can redirect back here and force
    // the email form to render for a fresh sign-in.
    //
    // Requires pds-core and auth-service to share a parent domain
    // (AUTH_HOSTNAME ends with .<PDS_HOSTNAME>) so pds-core broadens
    // the dev-id cookie to that parent. On deployments with unrelated
    // hostnames (e.g. Railway preview envs) the cookie stays host-only
    // and this branch is a no-op.
    const sessionReuseReq = {
      cookies: (req as unknown as { cookies?: Record<string, string> }).cookies,
      headers: { cookie: req.headers.cookie },
      query: req.query as Record<string, unknown>,
    }

    // Resolve the login_hint up-front so we can decide whether the
    // device session is a match before redirecting to pds-core. The
    // resolution result is also reused below for the email/OTP form.
    //
    // pds-core's "Another account" rebind sets epds_skip_par_hint=1
    // (issue #138) — the user clicked an opt-out, so any login_hint
    // stored in the PAR by the RP at OAuth init must be ignored. The
    // rebind also strips URL login_hint, so on that path effectiveLoginHint
    // ends up null and the spec-correct decision below renders the email
    // form. This skip flag does NOT affect prompt=login alone: pds-core's
    // sign-in-view bounce also sets prompt=login (without the skip flag)
    // and expects the hint to resolve normally so the OTP step renders.
    const skipParHint = req.query.epds_skip_par_hint === '1'
    const pdsInternalUrl = ensurePdsUrl(
      process.env.PDS_INTERNAL_URL,
      ctx.config.pdsPublicUrl,
    )
    const internalSecret = process.env.EPDS_INTERNAL_SECRET ?? ''

    let effectiveLoginHint = loginHint ?? null
    if (!skipParHint && !effectiveLoginHint && requestUri) {
      effectiveLoginHint = await fetchParLoginHint(
        pdsInternalUrl,
        requestUri,
        internalSecret,
      )
    }
    const resolvedEmail = effectiveLoginHint
      ? await resolveLoginHint(
          effectiveLoginHint,
          pdsInternalUrl,
          internalSecret,
        )
      : null

    // Only fetch device-bound emails when we actually need them: the
    // cookie pair is present AND a hint resolved. Otherwise the existing
    // cookie-only reuse logic stands and the round trip to pds-core is
    // pure overhead.
    let deviceBoundEmails: string[] | null | undefined
    const cookiePair = readDeviceSessionCookies(sessionReuseReq)
    if (resolvedEmail && cookiePair) {
      deviceBoundEmails = await fetchDeviceAccountEmails(
        pdsInternalUrl,
        cookiePair.devId,
        cookiePair.sesId,
        internalSecret,
      )
    }

    if (
      shouldReuseSession(sessionReuseReq, {
        resolvedEmail,
        deviceBoundEmails,
      })
    ) {
      const target = buildPdsAuthorizeRedirect(
        ctx.config.pdsPublicUrl,
        req.query as Record<string, unknown>,
      )
      logger.info(
        { requestUri, clientId, target },
        'HYPER-268 session reuse: device session detected, redirecting to pds-core',
      )
      res.redirect(302, target)
      return
    }

    // Layer 1 cleanup: when exactly one of dev-id / ses-id is present,
    // the browser jar is in a divergent state that upstream's
    // DeviceManager cannot hydrate from. Emit Max-Age=0 clears for both
    // cookies in both host-only and shared-parent-domain scopes so the
    // next OAuth flow gets a clean slate — otherwise the orphan half
    // keeps bouncing through pds-core's auth-ui-guard every time.
    const orphan = hasOrphanDeviceCookie(sessionReuseReq)
    if (orphan.isOrphan) {
      const cookieDomain = deriveSharedCookieDomain(
        ctx.config.hostname,
        ctx.config.pdsHostname,
      )
      appendOrphanDeviceCookieClearHeaders(res, cookieDomain)
      logger.info(
        {
          requestUri,
          clientId,
          hasDevId: orphan.devId,
          hasSesId: orphan.sesId,
          cookieDomain,
        },
        'HYPER-268 orphan device cookie detected, clearing on email-form response',
      )
    }

    // Look up any existing flow for this request_uri early so we can fall back
    // to its stored clientId when the query string omits client_id (e.g. when
    // the user navigates back from the recovery page via a bare request_uri link).
    // The persisted flow's clientId takes precedence over the query-string
    // client_id — the flow was stored from a validated PAR request server-side,
    // whereas client_id on the query string is user-controlled.
    const existingFlow = ctx.db.getAuthFlowByRequestUri(requestUri)
    const effectiveClientId = existingFlow?.clientId ?? clientId ?? undefined

    const clientMeta = await safeResolveClientMetadata(effectiveClientId)
    const handleMode = resolveHandleMode(
      req.query.epds_handle_mode as string | undefined,
      clientMeta,
    )

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
          handleMode,
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

    const clientName =
      clientMeta.client_name ??
      (effectiveClientId
        ? await resolveClientName(effectiveClientId)
        : 'an application')

    // Branding injection for trusted clients
    const customCss = effectiveClientId
      ? getClientCss(effectiveClientId, clientMeta, ctx.config.trustedClients)
      : null
    const customFaviconUrl = effectiveClientId
      ? getClientFaviconUrl(
          effectiveClientId,
          clientMeta,
          ctx.config.trustedClients,
        )
      : null
    const customFaviconUrlDark = effectiveClientId
      ? getClientFaviconUrlDark(
          effectiveClientId,
          clientMeta,
          ctx.config.trustedClients,
        )
      : null
    logger.debug(
      {
        clientId: effectiveClientId,
        cssTrusted: customCss !== null,
        faviconTrusted: customFaviconUrl !== null,
        faviconDarkTrusted: customFaviconUrlDark !== null,
      },
      'client branding trust check',
    )

    // Pillar 1 — State Determination: decide which step to render based on
    // login_hint presence. No method-assuming side effects in the GET handler.
    // The login_hint may be:
    //   a) On the query string as an email (from our demo app)
    //   b) On the query string as a handle/DID (unlikely but possible)
    //   c) Only in the stored PAR request (third-party apps that put the
    //      handle in the PAR body but don't duplicate it on the redirect URL)
    // The hint was already resolved above for the session-reuse decision; we
    // reuse `resolvedEmail` here rather than re-fetching. On the "Another
    // account" rebind path (issue #138) `epds_skip_par_hint=1` upstream
    // suppresses both URL and PAR hint resolution, so resolvedEmail is null
    // and the email step falls out without a special case here.
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
        clientId: effectiveClientId ?? '',
        clientName,
        branding: clientMeta,
        customCss,
        customFaviconUrl,
        customFaviconUrlDark,
        loginHint: emailHint,
        initialStep,
        otpAlreadySent,
        csrfToken: res.locals.csrfToken,
        authBasePath: '/api/auth',
        pdsPublicUrl: ctx.config.pdsPublicUrl,
        termsOfServiceUrl: ctx.config.termsOfServiceUrl,
        privacyPolicyUrl: ctx.config.privacyPolicyUrl,
        legalEntityName: ctx.config.legalEntityName,
        otpLength: ctx.config.otpLength,
        otpCharset: ctx.config.otpCharset,
        heartbeatEnabled: heartbeatEnabledFor(req),
      }),
    )
  })

  return router
}

export function renderLoginPage(opts: {
  flowId: string
  clientId: string
  clientName: string
  branding: ClientMetadata
  customCss: string | null
  customFaviconUrl: string | null
  customFaviconUrlDark: string | null
  loginHint: string
  initialStep: 'email' | 'otp'
  otpAlreadySent: boolean
  csrfToken: string
  authBasePath: string
  pdsPublicUrl: string
  termsOfServiceUrl?: string
  privacyPolicyUrl?: string
  legalEntityName?: string
  otpLength: number
  otpCharset: 'numeric' | 'alphanumeric'
  /**
   * When true, the rendered page starts a 3-min `setInterval` that
   * GETs /auth/ping while the user is on the OTP step, sliding the
   * upstream PAR's inactivity timer so the user can read their email
   * without losing the OAuth flow. Disabled only by the
   * `?no_heartbeat=1` test toggle (see `heartbeatEnabledFor`).
   */
  heartbeatEnabled: boolean
}): string {
  const b = opts.branding
  const appName = b.client_name || opts.clientName || 'Certified'
  // brand_color is interpolated into <style> below. escapeHtml() doesn't
  // make a value safe in CSS context — a `;` or `}` would break out of the
  // declaration — so restrict to a hex literal before use.
  const rawBrandColor = b.brand_color || '#1A130F'
  const brandColor = /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/.test(
    rawBrandColor,
  )
    ? rawBrandColor
    : '#1A130F'
  const logoHtml = b.logo_uri
    ? `<img src="${escapeHtml(b.logo_uri)}" alt="${escapeHtml(appName)}" class="client-logo">`
    : `<img src="/static/certified-brandmark.svg" alt="Certified" class="client-logo">`

  const inputProps = buildOtpInputProps(opts.otpLength, opts.otpCharset)

  // ATProto/Bluesky handle login button.
  //
  // Only rendered when the OAuth client declares `epds_handle_login_url` in
  // its client metadata. The button toggles the email form into handle-entry
  // mode; submitting a handle navigates the browser to that URL with
  // `?handle=<value>` appended. The client owns handle-to-PDS resolution
  // and starts a fresh OAuth flow against whichever PDS the handle resolves
  // to — auth-service is bound to one PDS and cannot PAR on the client's
  // behalf, so off-PDS handles only work via this hand-off.
  //
  // The URL is validated to be http(s) to prevent a malformed metadata
  // value from injecting a `javascript:` redirect target into the page.
  const handleLoginUrl = isSafeHttpUrl(b.epds_handle_login_url)
    ? (b.epds_handle_login_url as string)
    : ''
  const handleLoginButtonHtml = handleLoginUrl
    ? `<button type="button" class="btn-social btn-atproto">Or sign in with ATProto/Bluesky</button>`
    : ''

  // Terms-of-use / privacy-policy line. Only rendered when both URLs are
  // configured (`PDS_TERMS_OF_SERVICE_URL` + `PDS_PRIVACY_POLICY_URL`);
  // a partial config would surface a broken link, so skip the line
  // entirely instead. The possessive ("Acme's Terms of Use…") falls back
  // to a generic "the Terms of Use…" when `PDS_LEGAL_ENTITY_NAME` is unset.
  const showTerms =
    isSafeHttpUrl(opts.termsOfServiceUrl) &&
    isSafeHttpUrl(opts.privacyPolicyUrl)
  const termsLead = opts.legalEntityName
    ? `${escapeHtml(opts.legalEntityName)}'s`
    : 'the'
  const termsHtml = showTerms
    ? `<div class="terms" id="terms" style="display:${
        opts.initialStep === 'otp' ? 'none' : 'block'
      };">By signing in, you agree to ${termsLead} <a href="${escapeHtml(
        opts.termsOfServiceUrl as string,
      )}" class="terms-link" target="_blank" rel="noopener noreferrer">Terms of Use</a> and <a href="${escapeHtml(
        opts.privacyPolicyUrl as string,
      )}" class="terms-link" target="_blank" rel="noopener noreferrer">Privacy Policy</a>.</div>`
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
  ${renderFaviconTag(opts.customFaviconUrl, opts.customFaviconUrlDark)}
  <title>Sign in to ${escapeHtml(appName)}</title>
  <style>
    :root { --muted-foreground: #999; --input-bg: #ffffff; --input-border: #e5e5e5; --page-bg: #E8E8E8; --card-bg: #F8F8F8; --card-border: #E5E5E5; --btn-secondary-border: #e5e5e5; --focus-border: ${brandColor}; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--page-bg); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; color: #1A130F; }
    .page-wrap { display: flex; flex-direction: column; align-items: stretch; max-width: 497px; width: 100%; }
    .container { background: var(--card-bg); padding: 64px 48px 40px; width: 100%; text-align: center; border-radius: 20px; border: 1px solid var(--card-border); box-shadow: 0 1px 2px rgba(0,0,0,0.03); }
    .client-logo { max-height: 48px; max-width: 48px; margin: 0 auto 56px; display: block; }
    h1 { font-size: 32px; line-height: 38px; font-weight: 500; margin-bottom: 40px; color: #1A130F; letter-spacing: -0.01em; }
    .subtitle { color: #6b6b6b; margin-bottom: 28px; font-size: 15px; line-height: 1.5; }
    .field { margin-bottom: 24px; text-align: left; }
    .field label { display: block; font-size: 16px; line-height: 24px; font-weight: 600; color: #1A130F; margin-bottom: 8px; }
    .field input { width: 100%; padding: 14px 20px; border: 1px solid var(--input-border); border-radius: 8px; font-size: 16px; outline: none; background: var(--input-bg); transition: border-color 0.15s; }
    .field input:focus { border-color: var(--focus-border); }
    .otp-boxes { display: flex; gap: 10px; justify-content: center; margin-bottom: 24px; }
    .otp-box { width: 48px; height: 56px; padding: 0; text-align: center; font-size: 24px; font-family: 'SF Mono', Menlo, Consolas, monospace; border: 1px solid var(--input-border); border-radius: 8px; background: var(--input-bg); color: #1A130F; outline: none; transition: border-color 0.15s; }
    .otp-box::placeholder { color: #d4d4d4; }
    .otp-box:focus { border-color: var(--focus-border); }
    .otp-actions { display: flex; gap: 32px; justify-content: center; margin-top: 12px; }
    .btn-primary { width: 100%; padding: 15px; background: ${brandColor}; color: white; border: none; border-radius: 9999px; font-size: 15px; font-weight: 500; cursor: pointer; transition: opacity 0.15s; }
    .btn-primary:hover { opacity: 0.9; }
    .btn-primary:disabled { opacity: 0.7; cursor: not-allowed; }
    .btn-secondary { display: inline-block; color: #6b6b6b; background: none; border: none; font-size: 14px; font-weight: 500; cursor: pointer; padding: 4px 0; }
    .btn-secondary:hover { color: #1A130F; }
    .btn-social { display: flex; align-items: center; justify-content: center; gap: 8px; width: 100%; padding: 13px 20px; border: 1px solid var(--btn-secondary-border); border-radius: 9999px; font-size: 15px; font-weight: 500; cursor: pointer; text-decoration: none; background: white; color: #333; margin-bottom: 8px; transition: background 0.15s; }
    .btn-social:hover { background: #fafafa; }
    .btn-atproto { margin-top: 12px; margin-bottom: 0; color: #1A130F !important; background: var(--input-bg) !important; border-color: var(--input-border) !important; }
    .divider { display: flex; align-items: center; gap: 12px; margin: 20px 0; color: #999; font-size: 13px; }
    .divider::before, .divider::after { content: ''; flex: 1; height: 1px; background: #ececec; }
    .flash-msg { padding: 12px; border-radius: 10px; margin: 12px 0; font-size: 14px; text-align: center; }
    .flash-msg.error { color: #dc3545; background: #fdf0f0; }
    .flash-msg.success { color: #28a745; background: #f0fff4; }
    /* Inline action button rendered next to an OTP-expired error so
       the user doesn't have to hunt for the separate Resend button.
       Styled as a link rather than a button to make it visually
       continuous with the message text. */
    .flash-action { background: none; border: none; padding: 0; font: inherit; color: inherit; text-decoration: underline; cursor: pointer; }
    .flash-action:hover { text-decoration: none; }
    .step-otp { display: none; }
    .step-otp.active { display: block; }
    .step-email.hidden { display: none; }
    .terms { margin-top: 24px; color: var(--muted-foreground); font-size: 13px; font-weight: 400; line-height: 1.5; text-align: center; }
    .terms-link { color: inherit; text-decoration: underline; cursor: pointer; }
    .powered-by { display: flex; align-items: center; justify-content: center; gap: 8px; margin-top: 16px; color: var(--muted-foreground); font-size: 13px; text-decoration: none; cursor: pointer; }
    .powered-by:hover, .powered-by:focus, .powered-by:visited { color: var(--muted-foreground); text-decoration: none; }
    .powered-by .certified-mark { height: 14px; width: auto; display: block; }
    /* Recovery-via-backup-email link. Shown by default; trusted clients
       hide it by setting --recovery-link-display: none in their injected
       branding.css. */
    .recovery-link { display: var(--recovery-link-display, block); margin-top: 16px; color: var(--muted-foreground); font-size: 13px; text-decoration: underline; text-align: center; }
    .recovery-link:hover { color: #1A130F; }
  </style>${renderOptionalStyleTag(opts.customCss)}
</head>
<body>
  <div class="page-wrap">
    <div class="container">
    ${logoHtml}
    <h1 id="heading">${opts.initialStep === 'otp' ? 'Enter your code' : 'Sign in'}</h1>

    <div id="error-msg" class="flash-msg" style="display:none;"></div>

    ${socialButtonsHtml}

    <!-- Step 1: Email entry (calls better-auth sendOtp) -->
    <div id="step-email" class="step-email${opts.initialStep === 'otp' ? ' hidden' : ''}">
      <form id="form-send-otp">
        <div class="field">
          <label for="email">Enter your email address</label>
          <input type="email" id="email" name="email" required autofocus
                 placeholder="you@example.com"
                 value="${escapeHtml(opts.loginHint)}">
        </div>
        <button type="submit" class="btn-primary">Continue</button>
      </form>
      ${handleLoginButtonHtml}
    </div>

    <!-- Step 2: OTP entry (calls better-auth verifyOtp) -->
    <div id="step-otp" class="step-otp${opts.initialStep === 'otp' ? ' active' : ''}">
      <p class="subtitle" id="otp-subtitle">${
        opts.initialStep === 'otp' && opts.otpAlreadySent
          ? `Code already sent to ${escapeHtml(opts.loginHint.replace(/(.{2})[^@]*(@.*)/, '$1***$2'))}`
          : ''
      }</p>
      <form id="form-verify-otp">
        <input type="hidden" id="otp-email" name="email" value="${escapeHtml(opts.loginHint)}">
        <input type="hidden" id="code" name="code">
        <div class="otp-boxes" id="otp-boxes">
          ${Array.from({ length: opts.otpLength })
            .map(
              (_, i) =>
                `<input type="text" class="otp-box" data-slot="${i}" maxlength="1"
                   inputmode="${inputProps.inputmode}" autocapitalize="${inputProps.autocapitalize}"
                   ${i === 0 ? 'autocomplete="one-time-code"' : 'autocomplete="off"'}
                   placeholder="${opts.otpCharset === 'alphanumeric' ? 'A' : '0'}"
                   aria-label="${opts.otpCharset === 'alphanumeric' ? 'Character' : 'Digit'} ${i + 1}">`,
            )
            .join('\n          ')}
        </div>
        <button type="submit" class="btn-primary">Verify</button>
      </form>
      <div class="otp-actions">
        <button type="button" class="btn-secondary" id="btn-resend">Resend code</button>
        <button type="button" class="btn-secondary" id="btn-back">Use different email</button>
      </div>
      <a href="/auth/recover?request_uri=${encodeURIComponent(opts.pdsPublicUrl + '/placeholder')}"
         class="recovery-link" id="recovery-link">Recover with backup email</a>
    </div>
    </div>

    ${termsHtml}

    <a class="powered-by" href="https://certified.app/" target="_blank" rel="noopener noreferrer">
      <span>Powered by</span>
      ${CERTIFIED_MARK_SVG}
    </a>
  </div>

  <script>
    (function() {
      var authBasePath = ${JSON.stringify(opts.authBasePath)};
      var handleLoginUrl = ${JSON.stringify(handleLoginUrl)};
      var requestUri = ${JSON.stringify('')};  // not needed client-side; flow_id is in cookie
      var currentEmail = '';
      var loginMode = 'email'; // 'email' | 'handle'
      var verifying = false;
      var errorEl = document.getElementById('error-msg');
      var stepEmail = document.getElementById('step-email');
      var stepOtp = document.getElementById('step-otp');
      var otpSubtitle = document.getElementById('otp-subtitle');
      var otpEmailInput = document.getElementById('otp-email');
      var atprotoBtn = document.querySelector('.btn-atproto');
      var emailInput = document.getElementById('email');
      var emailLabel = document.querySelector('label[for="email"]');
      var sendOtpBtn = document.querySelector('#form-send-otp button[type=submit]');
      var headingEl = document.getElementById('heading');
      var termsEl = document.getElementById('terms');
      var otpBoxes = Array.prototype.slice.call(document.querySelectorAll('.otp-box'));
      var hiddenCode = document.getElementById('code');

      // PAR heartbeat — slides the upstream request_uri inactivity
      // timer (atproto's AUTHORIZATION_INACTIVITY_TIMEOUT, 5 min) so
      // a user who waits >5 min for the OTP email doesn't trip the
      // dead-PAR path on submit. Disabled when ?no_heartbeat=1 was
      // passed on the original /oauth/authorize URL with EPDS_TEST_HOOKS=1.
      var heartbeatEnabled = ${JSON.stringify(opts.heartbeatEnabled)};
      var heartbeatHandle = null;
      var heartbeatIntervalMs = 3 * 60 * 1000;
      // Set to true the moment we know the flow can no longer
      // complete (PAR or auth_flow gone). Resend / Verify gates
      // check this so a click that races the proactive notice
      // still bails to /auth/abort instead of issuing a fresh OTP
      // that would only fail.
      var flowAborted = false;
      function pingHeartbeat() {
        return fetch('/auth/ping', { credentials: 'include', cache: 'no-store' })
          .then(function(r) { return r.json(); })
          .then(function(body) {
            if (body && body.ok === false && body.reason !== 'transient') {
              // Auth flow / PAR genuinely dead — no point pinging again,
              // and no point letting the user keep typing. 'transient'
              // (5xx / network blip) does NOT stop the interval; the
              // next tick may recover.
              stopHeartbeat();
              showFlowAbortedNotice();
            }
            return body;
          })
          .catch(function() { return null; /* network blip — caller may retry */ });
      }
      function startHeartbeat() {
        if (!heartbeatEnabled) return;
        if (heartbeatHandle !== null) return;
        heartbeatHandle = setInterval(pingHeartbeat, heartbeatIntervalMs);
      }
      function stopHeartbeat() {
        if (heartbeatHandle !== null) {
          clearInterval(heartbeatHandle);
          heartbeatHandle = null;
        }
      }
      window.addEventListener('beforeunload', stopHeartbeat);

      // Show the proactive "this won't work — start over" notice when
      // the flow is unrecoverable. Disables the OTP boxes, the verify
      // button, and the resend button so nothing the user types or
      // clicks on the form can silently fail. Replaces the error
      // banner content with copy + a single Start over button that
      // navigates to /auth/abort (which performs the spec-compliant
      // RFC 6749 §4.1.2.1 redirect to the OAuth client). Idempotent —
      // safe to call from the heartbeat tick AND from the reactive
      // gates without duplicating the notice.
      function showFlowAbortedNotice() {
        if (flowAborted) return;
        flowAborted = true;
        // Disable every form control on the OTP step so nothing the
        // user does on the form has any effect from here on.
        for (var i = 0; i < otpBoxes.length; i++) otpBoxes[i].disabled = true;
        var resendBtn = document.getElementById('btn-resend');
        if (resendBtn) resendBtn.disabled = true;
        var backBtn = document.getElementById('btn-back');
        if (backBtn) backBtn.disabled = true;
        var verifyBtn = document.querySelector('#form-verify-otp button[type=submit]');
        if (verifyBtn) verifyBtn.disabled = true;
        // Render the notice in the existing error banner so the
        // styling / position is consistent with other errors. The
        // copy is set via textContent (no HTML), the Start over
        // button is built imperatively.
        clearError();
        showFlash(
          'Your sign-in has timed out. The code we sent will no longer work. Start sign-in again from the app you came from.',
          'error',
        );
        errorEl.appendChild(document.createElement('br'));
        var startOverBtn = document.createElement('button');
        startOverBtn.type = 'button';
        startOverBtn.className = 'flash-action';
        startOverBtn.textContent = 'Start over';
        startOverBtn.addEventListener('click', function() {
          window.location.href = '/auth/abort';
        });
        errorEl.appendChild(startOverBtn);
      }

      /**
       * Reactive gate used by the Resend and Verify click handlers.
       * Pings /auth/ping synchronously; if the result indicates the
       * flow is no longer recoverable, navigates to /auth/abort and
       * returns true. Caller should bail (return) when this returns
       * true, since navigation is already in flight. Returns false
       * for ok / transient / network errors — those should not block
       * the action since they may not be terminal.
       */
      async function abortIfFlowDead() {
        if (flowAborted) {
          window.location.href = '/auth/abort';
          return true;
        }
        try {
          var body = await pingHeartbeat();
          if (body && body.ok === false && body.reason !== 'transient') {
            window.location.href = '/auth/abort';
            return true;
          }
        } catch (e) { /* fall through; treat as transient */ }
        return false;
      }

      function updateHiddenCode() {
        var v = '';
        for (var i = 0; i < otpBoxes.length; i++) v += otpBoxes[i].value;
        hiddenCode.value = v;
      }

      function clearOtpBoxes() {
        for (var i = 0; i < otpBoxes.length; i++) otpBoxes[i].value = '';
        hiddenCode.value = '';
      }

      otpBoxes.forEach(function(box, idx) {
        box.addEventListener('input', function() {
          // keep only the last typed char (handles paste into a single box)
          var v = box.value.replace(/\\s/g, '');
          if (v.length > 1) v = v.slice(-1);
          box.value = v;
          updateHiddenCode();
          if (box.value && idx < otpBoxes.length - 1) otpBoxes[idx + 1].focus();
          if (hiddenCode.value.length === otpBoxes.length) {
            document.getElementById('form-verify-otp').requestSubmit();
          }
        });
        box.addEventListener('keydown', function(e) {
          if (e.key === 'Backspace' && !box.value && idx > 0) {
            otpBoxes[idx - 1].focus();
            otpBoxes[idx - 1].value = '';
            updateHiddenCode();
            e.preventDefault();
          } else if (e.key === 'ArrowLeft' && idx > 0) {
            otpBoxes[idx - 1].focus();
          } else if (e.key === 'ArrowRight' && idx < otpBoxes.length - 1) {
            otpBoxes[idx + 1].focus();
          }
        });
        box.addEventListener('paste', function(e) {
          e.preventDefault();
          var data = (e.clipboardData || window.clipboardData).getData('text') || '';
          var cleaned = data.replace(/\\s/g, '').slice(0, otpBoxes.length - idx);
          for (var i = 0; i < cleaned.length; i++) otpBoxes[idx + i].value = cleaned[i];
          updateHiddenCode();
          var nextIdx = Math.min(idx + cleaned.length, otpBoxes.length - 1);
          otpBoxes[nextIdx].focus();
          if (hiddenCode.value.length === otpBoxes.length) {
            document.getElementById('form-verify-otp').requestSubmit();
          }
        });
        box.addEventListener('focus', function() { box.select(); });
      });

      function showFlash(msg, kind) {
        // Build the message DOM imperatively so showErrorWithAction
        // can append an inline action (e.g. Resend) without ever
        // interpolating user-influenced strings as HTML. textContent
        // is the only sink for the msg argument, which neutralises
        // any HTML in the better-auth error string.
        errorEl.textContent = msg;
        errorEl.classList.remove('error', 'success');
        errorEl.classList.add(kind);
        errorEl.style.display = 'block';
      }

      function showError(msg) { showFlash(msg, 'error'); }
      function showSuccess(msg) { showFlash(msg, 'success'); }

      /**
       * Show an error message with an inline action button (e.g. a
       * "Send a new code" link rendered next to the OTP-expired
       * message). The action label is set via textContent so a
       * reflected error string can never inject HTML; the click
       * handler runs the supplied callback. When actionLabel is
       * absent, behaves like showError.
       */
      function showErrorWithAction(msg, actionLabel, onClick) {
        showFlash(msg, 'error');
        if (!actionLabel || typeof onClick !== 'function') return;
        errorEl.appendChild(document.createTextNode(' '));
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'flash-action';
        btn.textContent = actionLabel;
        btn.addEventListener('click', onClick);
        errorEl.appendChild(btn);
      }

      function clearError() {
        errorEl.style.display = 'none';
        errorEl.textContent = '';
        errorEl.classList.remove('error', 'success');
      }

      function setLoginMode(mode) {
        loginMode = mode;
        if (mode === 'handle') {
          emailLabel.textContent = 'Handle';
          emailInput.type = 'text';
          emailInput.placeholder = 'you.bsky.social';
          emailInput.name = 'handle';
          emailInput.value = '';
          // Browser's built-in type="email" validation would block valid
          // handles; remove it for handle mode.
          emailInput.removeAttribute('required');
          sendOtpBtn.textContent = 'Sign in';
          atprotoBtn.textContent = 'Or sign in with email';
        } else {
          emailLabel.textContent = 'Enter your email address';
          emailInput.type = 'email';
          emailInput.placeholder = 'you@example.com';
          emailInput.name = 'email';
          emailInput.value = '';
          emailInput.setAttribute('required', '');
          sendOtpBtn.textContent = 'Continue';
          atprotoBtn.textContent = 'Or sign in with ATProto/Bluesky';
        }
        emailInput.focus();
        clearError();
      }

      if (atprotoBtn) {
        atprotoBtn.addEventListener('click', function(e) {
          e.preventDefault();
          setLoginMode(loginMode === 'email' ? 'handle' : 'email');
        });
      }

      var otpLength = ${opts.otpLength};
      var otpCharset = ${JSON.stringify(opts.otpCharset)};
      function showOtpStep(email) {
        currentEmail = email;
        otpEmailInput.value = email;
        var masked = email.replace(/(.{2})[^@]*(@.*)/, '$1***$2');
        otpSubtitle.textContent = 'We sent a ' + otpLength + (otpCharset === 'alphanumeric' ? '-character' : '-digit') + ' code to ' + masked;
        stepEmail.classList.add('hidden');
        stepOtp.classList.add('active');
        headingEl.textContent = 'Enter your code';
        if (termsEl) termsEl.style.display = 'none';
        clearOtpBoxes();
        if (otpBoxes.length) otpBoxes[0].focus();
        clearError();
        startHeartbeat();
      }

      function showEmailStep() {
        stepOtp.classList.remove('active');
        stepEmail.classList.remove('hidden');
        headingEl.textContent = 'Sign in';
        if (termsEl) termsEl.style.display = 'block';
        clearError();
        stopHeartbeat();
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

      // Form: send OTP (email mode) or hand off to client (handle mode)
      document.getElementById('form-send-otp').addEventListener('submit', async function(e) {
        e.preventDefault();
        clearError();
        var raw = emailInput.value.trim();
        if (!raw) return;
        var btn = this.querySelector('button[type=submit]');
        var defaultLabel = loginMode === 'handle' ? 'Sign in' : 'Continue';
        btn.disabled = true;
        btn.textContent = loginMode === 'handle' ? 'Signing in...' : 'Sending...';

        if (loginMode === 'handle') {
          // Hand off to the client's handle-login URL with ?handle=<value>
          // appended (preserving any existing query string the client put on
          // the URL). The client resolves the handle to its PDS and starts a
          // fresh PAR against that PDS. handleLoginUrl is server-validated
          // as http(s) before being inlined here.
          var target = new URL(handleLoginUrl);
          target.searchParams.set('handle', raw);
          window.location.href = target.toString();
          return;
        }

        var email = raw.toLowerCase();
        var result = await sendOtp(email);
        btn.disabled = false;
        btn.textContent = defaultLabel;

        if (result.error) {
          showError(result.error);
        } else {
          showOtpStep(email);
        }
      });

      // Form: verify OTP
      document.getElementById('form-verify-otp').addEventListener('submit', async function(e) {
        e.preventDefault();
        // Collapse duplicate submits (auto-submit on 6th digit + Enter, OTP
        // autofill firing input on every box, paste+input pair, etc.). The
        // first call consumes the code; a second one races the redirect and
        // flashes "Invalid OTP" before the page unloads.
        if (verifying) return;
        verifying = true;
        // Stop pinging the moment a verify is in flight — the redirect
        // is imminent and any further heartbeat is wasted.
        stopHeartbeat();
        clearError();
        var otp = document.getElementById('code').value.trim();
        var btn = this.querySelector('button[type=submit]');
        btn.disabled = true;
        btn.textContent = 'Verifying...';

        // Reactive gate (defence in depth on top of the proactive
        // notice): if the PAR or auth_flow is already dead by the
        // time the user submits, don't even attempt the verify —
        // it would consume the OTP and then the dead-PAR path on
        // /oauth/epds-callback would bounce the user with
        // error=access_denied anyway. Cleaner to bail upfront.
        if (await abortIfFlowDead()) return;

        try {
          var result = await verifyOtp(currentEmail, otp);
          if (result && result.error) {
            // Inline a "Send a new code" action when the error
            // indicates the OTP has aged out — too easy to miss the
            // separate Resend button below the form. The substring
            // match catches the better-auth wording ("Invalid or
            // expired code") and the auth-service wording ("OTP
            // expired") plus generic "expir"/"too long" variants.
            var isExpired = /expir|too long/i.test(result.error);
            if (isExpired) {
              // The inline action triggers the same Resend handler,
              // which itself runs abortIfFlowDead() before issuing
              // a new code. So even if the PAR is dead the user
              // gets the spec-compliant bounce rather than a fresh
              // OTP that wouldn't work — no need to gate the
              // action's visibility separately here.
              showErrorWithAction(result.error, 'Send a new code', function() {
                document.getElementById('btn-resend').click();
              });
            } else {
              showError(result.error);
            }
            // Clear the boxes so the user re-enters all 6 digits. Editing
            // a still-full grid would auto-submit on the first keystroke
            // (length stays at 6) and spam the rate limiter.
            clearOtpBoxes();
            if (otpBoxes.length) otpBoxes[0].focus();
          }
        } finally {
          // Leave the latch set on success: verifyOtp triggers a redirect,
          // and we don't want late events to re-open the form mid-navigation.
          if (!result || result.error) {
            verifying = false;
            btn.disabled = false;
            btn.textContent = 'Verify';
            // Verify failed (typo, expired OTP, etc.) — the form is
            // still live, so resume keeping the PAR alive.
            startHeartbeat();
          }
        }
      });

      // Resend code
      document.getElementById('btn-resend').addEventListener('click', async function() {
        clearError();
        this.disabled = true;
        this.textContent = 'Sending...';
        // Reactive gate (defence in depth on top of the proactive
        // notice): if the PAR or auth_flow is already dead, don't
        // issue a fresh OTP — the user would never be able to
        // submit it. Bounce to /auth/abort instead.
        if (await abortIfFlowDead()) return;
        var result = await sendOtp(currentEmail);
        this.disabled = false;
        this.textContent = 'Resend code';
        if (result.error) {
          showError(result.error);
        } else {
          showSuccess('Code resent!');
        }
      });

      // Back to email step
      document.getElementById('btn-back').addEventListener('click', function() {
        showEmailStep();
        clearOtpBoxes();
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
        if (otpBoxes.length) otpBoxes[0].focus();
        if (!otpAlreadySent) {
          // First load — fire the OTP send in the background.
          sendOtp(loginHint).then(function(result) {
            if (result.error) {
              showError(result.error);
            } else {
              otpSubtitle.textContent = 'We sent a ' + otpLength + (otpCharset === 'alphanumeric' ? '-character' : '-digit') + ' code to ' + masked;
            }
          });
        }
        // OTP form is already visible server-side; showOtpStep() never
        // ran, so kick off the heartbeat ourselves.
        startHeartbeat();
      }
    })();
  </script>
</body>
</html>`
}
