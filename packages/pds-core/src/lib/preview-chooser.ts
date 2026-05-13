/**
 * Preview route for the pds-core OAuth account chooser.
 *
 * Mirrors {@link ./preview-consent.ts} but drives the SPA into chooser
 * mode (no `selected` session, no `consentRequired`) and exercises the
 * same `<head>` injection that the real `chooserEnrichmentMiddleware`
 * applies — `<meta name="epds-handle-mode">`, `<meta
 * name="epds-auth-origin">`, and the enrichment `<script>` — so what
 * branding developers see here matches what real users see.
 *
 * Gated by `PDS_PREVIEW_ROUTES=1`. Shared shell mechanics live in
 * {@link ./preview-shared.ts}.
 *
 * Query parameters drive the fixture without needing N separate routes:
 *   - `?numAccounts=N`        — 1..10 fixture sessions (default 1). Zero is
 *                               clamped up to 1 — the chooser is meaningless
 *                               with no accounts to choose from, and an empty
 *                               `__sessions` array makes the upstream SPA
 *                               fall through to its no-session welcome view,
 *                               which is exactly the surface this preview
 *                               route exists to demonstrate users won't see.
 *   - `?epds_handle_mode=<x>` — same per-request handle-mode override
 *                               that real OAuth flows accept. When
 *                               absent, the mode is resolved from the
 *                               `?client_id=` metadata via the same
 *                               `resolveHandleMode` chain the real
 *                               middleware uses (query > metadata >
 *                               env default).
 *   - `?client_id=<url>`      — same client-metadata-driven CSS
 *                               injection as /preview/consent.
 *
 * Emails are always present on the fixture sessions — the chooser's
 * value-add is showing email beside (or instead of) handle, so a
 * preview without emails would have nothing to demonstrate.
 */
import {
  escapeHtml,
  resolveHandleMode,
  VALID_HANDLE_MODES,
  type ClientMetadata,
  type HandleMode,
} from '@certified-app/shared'
import {
  buildChooserEnrichmentScript,
  escapeHtmlAttr,
} from '../chooser-enrichment.js'
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

interface PreviewChooserFixture extends PreviewAuthorizeFixture {
  numAccounts: number
  handleMode: HandleMode
}

const MAX_FIXTURE_ACCOUNTS = 10

// A small, recognisable cast of fixture identities so the chooser
// preview shows visibly different rows rather than alice-1/alice-2/…
const FIXTURE_ACCOUNTS: readonly { handle: string; name: string }[] = [
  { handle: 'alice.preview.example', name: 'Alice Preview' },
  { handle: 'bob.preview.example', name: 'Bob Preview' },
  { handle: 'carol.preview.example', name: 'Carol Preview' },
  { handle: 'dave.preview.example', name: 'Dave Preview' },
  { handle: 'erin.preview.example', name: 'Erin Preview' },
  { handle: 'frank.preview.example', name: 'Frank Preview' },
  { handle: 'gina.preview.example', name: 'Gina Preview' },
  { handle: 'henry.preview.example', name: 'Henry Preview' },
  { handle: 'iris.preview.example', name: 'Iris Preview' },
  { handle: 'jack.preview.example', name: 'Jack Preview' },
] as const

function buildSessions(opts: PreviewChooserFixture): unknown {
  // Drive the SPA's chooser view: every session has selected=false so
  // the gate that mounts <ConsentView> never fires. loginRequired=false
  // because the chooser shows fully-bound accounts; consentRequired is
  // irrelevant in the chooser view but we set it true so a user click
  // through would land on the consent step (matching real-flow shape).
  const n = Math.min(MAX_FIXTURE_ACCOUNTS, Math.max(0, opts.numAccounts))
  return FIXTURE_ACCOUNTS.slice(0, n).map((a, idx) => ({
    account: {
      sub: `did:web:preview-${idx}.example`,
      aud: 'https://preview.example',
      preferred_username: a.handle,
      name: a.name,
      email: `${a.handle.split('.')[0]}@preview.example`,
    },
    selected: false,
    loginRequired: false,
    consentRequired: true,
  }))
}

async function renderChooserHtml(opts: {
  fixture: PreviewChooserFixture
  authOrigin: string
  injectedCss: string | null
}): Promise<string> {
  const { scripts, styles } = await loadAssetRefs()

  const hydration = renderHydration({
    __authorizeData: buildAuthorizeData(opts.fixture),
    __sessions: buildSessions(opts.fixture),
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

  // Mirror the real chooserEnrichmentMiddleware's <head> injection
  // exactly: meta epds-handle-mode + meta epds-auth-origin + the
  // enrichment script. Order matters — the script reads both metas at
  // start, so they must appear first.
  const enrichmentJs = buildChooserEnrichmentScript()
  const handleModeMeta = `<meta name="epds-handle-mode" content="${opts.fixture.handleMode}">`
  const authOriginMeta = `<meta name="epds-auth-origin" content="${escapeHtmlAttr(opts.authOrigin)}">`
  const enrichmentScript = `<script>${enrichmentJs}</script>`

  return `<!doctype html>
<html>
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex">
    ${handleModeMeta}
    ${authOriginMeta}
    <link rel="icon" href="/static/favicon.svg" media="(prefers-color-scheme: light)" type="image/svg+xml">
    <link rel="icon" href="/static/favicon-dark.svg" media="(prefers-color-scheme: dark)" type="image/svg+xml">
    <title>Chooser preview — ${escapeHtml(opts.fixture.clientId)}</title>
    ${styleLinks}
    ${injectedStyle}
    ${enrichmentScript}
  </head>
  <body class="bg-white text-slate-900 dark:bg-slate-900 dark:text-slate-100">
    <div id="root"></div>
    <script>${hydration}</script>
    ${scriptTags}
  </body>
</html>`
}

interface PreviewChooserDeps extends PreviewMetadataDeps {
  /** Auth-service origin written into the epds-auth-origin meta tag. */
  authOrigin: string
}

function parseNumAccounts(raw: unknown): number {
  if (typeof raw !== 'string') return 1
  const n = Number.parseInt(raw, 10)
  if (!Number.isFinite(n)) return 1
  // Clamp to >=1: numAccounts=0 would render an empty __sessions array and
  // let the upstream SPA fall through to its no-session welcome view — a
  // surface ePDS exists to suppress, so it must never leak via the preview.
  return Math.min(MAX_FIXTURE_ACCOUNTS, Math.max(1, n))
}

function resolveQueryHandleMode(
  req: RequestLike,
  metadata: ClientMetadata,
): HandleMode {
  // Resolve handle-mode the same way the real chooserEnrichment
  // middleware does: query > client metadata > env default. Same
  // override name (epds_handle_mode) so the index dropdown exercises
  // the production resolver path verbatim.
  const queryMode =
    typeof req.query.epds_handle_mode === 'string'
      ? req.query.epds_handle_mode
      : undefined
  const rawMetaMode = metadata.epds_handle_mode
  const metaMode =
    typeof rawMetaMode === 'string' &&
    (VALID_HANDLE_MODES as readonly string[]).includes(rawMetaMode)
      ? rawMetaMode
      : undefined
  return resolveHandleMode(queryMode, metaMode)
}

/**
 * Express handler factory: creates a GET /preview/chooser handler if
 * the env var is on, returns null otherwise so the caller can skip
 * wiring.
 */
export function createPreviewChooserHandler(
  deps: PreviewChooserDeps,
): ((req: RequestLike, res: ResponseLike) => Promise<void>) | null {
  if (process.env.PDS_PREVIEW_ROUTES !== '1') return null

  return async function previewChooser(req: RequestLike, res: ResponseLike) {
    const clientId = readClientIdQuery(req)
    const { metadata, injectedCss } = await resolveClientForPreview(
      deps,
      clientId,
      'Preview chooser',
    )

    const handleMode = resolveQueryHandleMode(req, metadata)
    const numAccounts = parseNumAccounts(req.query.numAccounts)

    const html = await renderChooserHtml({
      fixture: {
        clientId,
        clientMetadata: metadata,
        isTrusted: deps.trustedClients.includes(clientId),
        numAccounts,
        handleMode,
      },
      authOrigin: deps.authOrigin,
      injectedCss,
    })

    applyPreviewHeaders(res)
    res.send(html)
  }
}
