/**
 * Preview routes for auth-service pages.
 *
 * Renders each auth-service page with fixture data and real CSS
 * injection, so client-app developers can iterate on their
 * `branding.css` without walking through the full OAuth flow each
 * time they want to see what a colour change looks like.
 *
 * Gated by `AUTH_PREVIEW_ROUTES=1`. Disabled by default; intended
 * for preview envs, dev instances, and `pr-base`. The trusted-clients
 * gate on CSS injection is preserved: a `client_id` passed via query
 * param gets its CSS injected only if it's on
 * `PDS_OAUTH_TRUSTED_CLIENTS`, exactly as in a real flow. Untrusted
 * clients still render the page but with no branding, which is what
 * real untrusted clients would see in production.
 *
 * Query params (all optional):
 *   ?client_id=<URL>   fetch branding CSS from this client_metadata,
 *                      subject to the trusted-clients check.
 *   ?error=<msg>       show error banner (exercises error-state CSS).
 */
import { Router, type Request, type Response } from 'express'
import { randomBytes } from 'node:crypto'
import type { AuthServiceContext } from '../context.js'
import { resolveClientMetadata, getClientCss } from '../lib/client-metadata.js'
import {
  createLogger,
  getClientMetadataCacheStatus,
  renderPreviewIndexPage,
  validateClientMetadataForPreview,
  type ClientMetadata,
} from '@certified-app/shared'
import { renderLoginPage } from './login-page.js'
import { renderChooseHandlePage } from './choose-handle.js'
import { renderRecoveryForm, renderRecoveryOtpForm } from './recovery.js'

const logger = createLogger('auth:preview')

const FAKE_FLOW_ID = 'preview-flow-000000000000000000000000'
const FAKE_REQUEST_URI =
  'urn:ietf:params:oauth:request_uri:req-preview-0000000000000000'
const FAKE_EMAIL = 'alice@example.com'
const FAKE_HANDLE_DOMAIN = 'preview.example'

function fakeCsrfToken(): string {
  return randomBytes(16).toString('hex')
}

/**
 * Turn a bare hostname (e.g. `auth.localhost`, `auth.pds.example`) into
 * an absolute origin. `localhost` (and `*.localhost`) uses http; anything
 * else uses https. This mirrors how the rest of the codebase treats the
 * `*_HOSTNAME` vars — see packages/pds-core/src/index.ts where `pdsUrl`
 * is built the same way from `PDS_HOSTNAME`.
 */
function hostnameToUrl(hostname: string): string {
  const scheme =
    hostname === 'localhost' || hostname.endsWith('.localhost')
      ? 'http'
      : 'https'
  return `${scheme}://${hostname}`
}

async function resolvePreviewBranding(
  clientId: string | undefined,
  trustedClients: string[],
): Promise<{ clientId: string; metadata: ClientMetadata; css: string | null }> {
  const defaultClientId = 'https://preview.example/client-metadata.json'
  if (!clientId) {
    return { clientId: defaultClientId, metadata: {}, css: null }
  }
  try {
    // Preview routes always bypass the 10-minute cache so devs see
    // branding.css edits on the next refresh.
    const metadata = await resolveClientMetadata(clientId, { noCache: true })
    // Preview respects the real trusted-clients gate: CSS is only
    // injected when clientId is on PDS_OAUTH_TRUSTED_CLIENTS, exactly
    // as it is during a real OAuth flow. This keeps preview useful as
    // a pre-production check ("does my CSS actually load once I'm
    // added to the trusted list?") without letting arbitrary clients
    // inject CSS onto a preview instance just by being typed into a
    // URL.
    const css = getClientCss(clientId, metadata, trustedClients)
    return { clientId, metadata, css }
  } catch (err) {
    logger.warn({ err, clientId }, 'Preview: failed to resolve client metadata')
    return { clientId, metadata: {}, css: null }
  }
}

function queryString(req: Request, name: string): string | undefined {
  const v = req.query[name]
  return typeof v === 'string' ? v : undefined
}

function sendHtml(res: Response, html: string): void {
  res.setHeader('Content-Type', 'text/html; charset=utf-8')
  // Preview flows server-side bypass the client-metadata cache, but that
  // only helps if the browser actually asks for the page. Without
  // no-store, heuristic caching (RFC 9111 §4.2.2) lets the browser serve
  // the previous HTML on refresh, so fresh branding.css never reaches
  // the client. The JSON endpoints already set this header; HTML was
  // the missing piece.
  res.setHeader('Cache-Control', 'no-store')
  res.send(html)
}

export function createPreviewRouter(ctx: AuthServiceContext): Router {
  const router = Router()

  // Single gate: every route 404s unless the env flag is on. Checked
  // at each request rather than at mount time so the flag can flip
  // without a restart.
  router.use('/preview', (req, res, next) => {
    if (process.env.AUTH_PREVIEW_ROUTES !== '1') {
      res.status(404).send('Not Found')
      return
    }
    next()
  })

  // Cross-links on the index go to the sibling pds-core service on the
  // base PDS domain. Derive absolute URLs from the hostnames: the
  // auth-service runs on auth.<PDS_HOSTNAME> and pds-core on the bare
  // <PDS_HOSTNAME>, matching the Caddyfile and setup.sh layout.
  const authPublicUrl = hostnameToUrl(ctx.config.hostname)
  const pdsPublicUrl = ctx.config.pdsPublicUrl

  const getBranding = (req: Request) =>
    resolvePreviewBranding(
      queryString(req, 'client_id'),
      ctx.config.trustedClients,
    )

  router.get('/preview', (_req: Request, res: Response) => {
    sendHtml(
      res,
      renderPreviewIndexPage({
        currentService: 'auth',
        authPublicUrl,
        pdsPublicUrl,
      }),
    )
  })

  router.get('/preview/cache-status', (_req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-store')
    res.json({
      now: Date.now(),
      entries: getClientMetadataCacheStatus(),
    })
  })

  router.get('/preview/validate', async (req: Request, res: Response) => {
    const url = queryString(req, 'client_id') ?? ''
    res.setHeader('Cache-Control', 'no-store')
    if (!url) {
      res.json({ url: '', fetched: false, checks: [] })
      return
    }
    const result = await validateClientMetadataForPreview(
      url,
      ctx.config.trustedClients,
    )
    res.json(result)
  })

  router.get('/preview/login', async (req: Request, res: Response) => {
    const { clientId, metadata, css } = await getBranding(req)
    sendHtml(
      res,
      renderLoginPage({
        flowId: FAKE_FLOW_ID,
        clientId,
        clientName: metadata.client_name || 'Preview Client',
        branding: metadata,
        customCss: css,
        loginHint: '',
        initialStep: 'email',
        otpAlreadySent: false,
        csrfToken: fakeCsrfToken(),
        authBasePath: '/api/auth',
        pdsPublicUrl: ctx.config.pdsPublicUrl,
        otpLength: ctx.config.otpLength,
        otpCharset: ctx.config.otpCharset,
      }),
    )
  })

  router.get('/preview/login-otp', async (req: Request, res: Response) => {
    const { clientId, metadata, css } = await getBranding(req)
    sendHtml(
      res,
      renderLoginPage({
        flowId: FAKE_FLOW_ID,
        clientId,
        clientName: metadata.client_name || 'Preview Client',
        branding: metadata,
        customCss: css,
        loginHint: FAKE_EMAIL,
        initialStep: 'otp',
        otpAlreadySent: true,
        csrfToken: fakeCsrfToken(),
        authBasePath: '/api/auth',
        pdsPublicUrl: ctx.config.pdsPublicUrl,
        otpLength: ctx.config.otpLength,
        otpCharset: ctx.config.otpCharset,
      }),
    )
  })

  router.get('/preview/choose-handle', async (req: Request, res: Response) => {
    const { css } = await getBranding(req)
    sendHtml(
      res,
      renderChooseHandlePage(
        FAKE_HANDLE_DOMAIN,
        queryString(req, 'error'),
        fakeCsrfToken(),
        true,
        css,
      ),
    )
  })

  router.get(
    '/preview/choose-handle-picker',
    async (req: Request, res: Response) => {
      const { css } = await getBranding(req)
      // EPDS_HANDLE_MODE=picker: no "generate random" button.
      sendHtml(
        res,
        renderChooseHandlePage(
          FAKE_HANDLE_DOMAIN,
          queryString(req, 'error'),
          fakeCsrfToken(),
          false,
          css,
        ),
      )
    },
  )

  router.get('/preview/recovery', async (req: Request, res: Response) => {
    const { css } = await getBranding(req)
    sendHtml(
      res,
      renderRecoveryForm({
        requestUri: FAKE_REQUEST_URI,
        csrfToken: fakeCsrfToken(),
        error: queryString(req, 'error'),
        customCss: css,
        backUri: FAKE_REQUEST_URI,
      }),
    )
  })

  router.get('/preview/recovery-otp', async (req: Request, res: Response) => {
    const { css } = await getBranding(req)
    sendHtml(
      res,
      renderRecoveryOtpForm({
        email: FAKE_EMAIL,
        csrfToken: fakeCsrfToken(),
        requestUri: FAKE_REQUEST_URI,
        otpLength: ctx.config.otpLength,
        otpCharset: ctx.config.otpCharset,
        error: queryString(req, 'error'),
        customCss: css,
        backUri: FAKE_REQUEST_URI,
      }),
    )
  })

  return router
}
