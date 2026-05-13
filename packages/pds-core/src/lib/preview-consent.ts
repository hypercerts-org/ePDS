/**
 * Preview route for the pds-core OAuth consent page.
 *
 * Reconstructs the same HTML shell that `@atproto/oauth-provider`'s
 * authorization-page middleware emits, but with fixture hydration data
 * instead of a real OAuth request — so client-app developers can iterate
 * on their `branding.css` without walking through the full OAuth flow.
 *
 * Gated by `PDS_PREVIEW_ROUTES=1`. Disabled by default; intended for
 * preview envs and dev instances. The trusted-clients gate on CSS
 * injection is preserved (see `installCssInjectionMiddleware` — the same
 * CSS injection middleware intercepts /preview/consent responses).
 *
 * Implementation notes:
 *
 * - The provider's `sendAuthorizePageFactory` is not publicly exported, so
 *   we can't call into it directly. We rebuild the shell ourselves by
 *   mimicking `sendWebAppFactory('authorization-page', ...)` in
 *   @atproto/oauth-provider/router/assets/assets.ts.
 *
 * - The UI bundle is already served by the real provider's asset
 *   middleware at `/@atproto/oauth-provider/~assets/*`. Our preview HTML
 *   references those URLs, so the SPA loads the exact same JS/CSS the
 *   real consent page does.
 *
 * - Hydration format matches `declareHydrationData` in
 *   @atproto/oauth-provider/lib/html/hydration-data.js: each value is
 *   serialised and assigned to `window[key]`. The script then removes
 *   itself so later scripts can't read the globals. We use
 *   `serialize-javascript` rather than hand-rolling the escape so that
 *   `</script>`, `U+2028`, `U+2029`, and other JS-string-literal hazards
 *   in attacker-controllable fields (e.g. `clientId`) cannot break out
 *   of the inline script.
 *
 * - CSP: we use `script-src 'self' 'unsafe-inline'` rather than sha256-
 *   pinning the hydration script, matching the auth-service preview
 *   routes' relaxed CSP. See {@link ./preview-shared.ts} for the shared
 *   header set.
 */
import { escapeHtml, renderPreviewIndexPage } from '@certified-app/shared'
import { DEFAULT_BRANDING_CSS } from './default-branding.js'
import {
  applyPreviewHeaders,
  assetUrl,
  buildAuthorizeData,
  loadAssetRefs,
  readClientIdQuery,
  renderHydration,
  resolveClientForPreview,
  type PreviewAuthorizeFixture,
  type PreviewMetadataDeps,
  type RequestLike,
  type ResponseLike,
} from './preview-shared.js'

function buildSessions(): unknown {
  // Fixture session that drives the SPA straight to the consent screen:
  // `selected && !loginRequired && consentRequired` is the exact gate in
  // authorize-view.tsx that mounts <ConsentView>.
  return [
    {
      account: {
        sub: 'did:web:preview.example',
        aud: 'https://preview.example',
        preferred_username: 'alice.preview.example',
        name: 'Alice Preview',
        email: 'alice@preview.example',
      },
      selected: true,
      loginRequired: false,
      consentRequired: true,
    },
  ]
}

/** Build the HTML page that the real oauth-provider SPA boots from. */
async function renderConsentHtml(opts: {
  fixture: PreviewAuthorizeFixture
  injectedCss: string | null
}): Promise<string> {
  const { scripts, styles } = await loadAssetRefs()

  const hydration = renderHydration({
    __authorizeData: buildAuthorizeData(opts.fixture),
    __sessions: buildSessions(),
    // No customization data: pds-core's provider isn't configured with
    // `branding.colors`, so the SPA falls back to its defaults.
    __customizationData: {},
  })

  const styleLinks = styles
    .map((f) => `<link rel="stylesheet" href="${assetUrl(f)}">`)
    .join('')
  const scriptTags = scripts
    .map((f) => `<script type="module" src="${assetUrl(f)}"></script>`)
    .join('')

  // Default CSS goes first so trusted-client `branding.css` overrides it
  // through normal cascade ordering.
  const defaultStyle = `<style>${DEFAULT_BRANDING_CSS}</style>`
  const clientStyle = opts.injectedCss
    ? `<style>${opts.injectedCss}</style>`
    : ''
  const injectedStyle = `${defaultStyle}${clientStyle}`

  return `<!doctype html>
<html>
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex">
    <link rel="icon" href="/static/favicon.svg" media="(prefers-color-scheme: light)" type="image/svg+xml">
    <link rel="icon" href="/static/favicon-dark.svg" media="(prefers-color-scheme: dark)" type="image/svg+xml">
    <title>Consent preview — ${escapeHtml(opts.fixture.clientId)}</title>
    ${styleLinks}
    ${injectedStyle}
  </head>
  <body class="bg-white text-slate-900 dark:bg-slate-900 dark:text-slate-100">
    <div id="root"></div>
    <script>${hydration}</script>
    ${scriptTags}
  </body>
</html>`
}

type PreviewConsentDeps = PreviewMetadataDeps

/**
 * Express handler factory: creates a GET /preview/consent handler if the
 * env var is on, returns null otherwise so the caller can skip wiring.
 */
export function createPreviewConsentHandler(
  deps: PreviewConsentDeps,
): ((req: RequestLike, res: ResponseLike) => Promise<void>) | null {
  if (process.env.PDS_PREVIEW_ROUTES !== '1') return null

  return async function previewConsent(req: RequestLike, res: ResponseLike) {
    const clientId = readClientIdQuery(req)
    const { metadata, injectedCss } = await resolveClientForPreview(
      deps,
      clientId,
      'Preview consent',
    )

    const fixture: PreviewAuthorizeFixture = {
      clientId,
      clientMetadata: metadata,
      isTrusted: deps.trustedClients.includes(clientId),
    }

    const html = await renderConsentHtml({ fixture, injectedCss })

    applyPreviewHeaders(res)
    res.send(html)
  }
}

/** Static index page listing preview routes from both services. */
export function renderPreviewIndex(opts: {
  authPublicUrl: string
  pdsPublicUrl: string
}): string {
  return renderPreviewIndexPage({
    currentService: 'pds',
    authPublicUrl: opts.authPublicUrl,
    pdsPublicUrl: opts.pdsPublicUrl,
  })
}
