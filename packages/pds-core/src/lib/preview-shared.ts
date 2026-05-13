/**
 * Shared helpers for the pds-core OAuth preview routes.
 *
 * Both `/preview/consent` and `/preview/chooser` reconstruct the same HTML
 * shell that `@atproto/oauth-provider`'s authorization-page middleware
 * emits. The mechanics are identical: load the bundle manifest, render
 * inline hydration, and serve under a relaxed CSP. This module owns those
 * mechanics; the per-route modules supply the route-specific fixture
 * shape and `<head>` extras.
 *
 * The CSP, hydration format, and asset-URL prefix are documented further
 * in {@link ./preview-consent.ts}.
 */
import type { ClientMetadata } from '@certified-app/shared'
import { readFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import serialize from 'serialize-javascript'

// pds-core compiles to CommonJS, so createRequire(__filename) gives us a
// require that can resolve the sibling package without tripping the
// no-require-imports lint rule (we never call the local `require` — only
// require.resolve, which is a function lookup not a syntactic require).
const nodeRequire = createRequire(__filename)

// Use structural request/response types rather than importing from
// express — pds-core doesn't depend on express's types directly and
// pulling them in would be a heavier change than the handlers warrant.
export type RequestLike = {
  query: Record<string, unknown>
}

export type ResponseLike = {
  setHeader: (name: string, value: string) => unknown
  send: (body: string) => unknown
}

export type LoggerLike = {
  info: (obj: object, msg: string) => void
  warn: (obj: object, msg: string) => void
  debug: (obj: object, msg: string) => void
}

// Deep read into the provider-ui package. Its exports map explicitly lists
// `./bundle-manifest.json`, so this is a supported entry point. If the
// package's layout changes, the preview routes will fail loudly — fine for
// a dev tool. Loaded lazily (not at import-time) to avoid paying the cost
// on instances that never enable the previews.
type BundleManifest = Record<
  string,
  { type: string; mime?: string; name?: string; isEntry?: boolean }
>

let cachedAssets: { scripts: string[]; styles: string[] } | null = null

export async function loadAssetRefs(): Promise<{
  scripts: string[]
  styles: string[]
}> {
  if (cachedAssets) return cachedAssets
  // Read the manifest as a plain file rather than via `import(..., { with:
  // { type: 'json' } })`. Import-attributes are only stable in Node 22+
  // and the repo allows Node >=20.0.0; require.resolve + fs.readFile
  // works on every Node 20.x without attributes.
  const manifestPath = nodeRequire.resolve(
    '@atproto/oauth-provider-ui/bundle-manifest.json',
  )
  const manifest = JSON.parse(
    await readFile(manifestPath, 'utf8'),
  ) as BundleManifest
  const scripts = Object.entries(manifest)
    .filter(
      ([, a]) =>
        a.type === 'chunk' && a.isEntry && a.name === 'authorization-page',
    )
    .map(([filename]) => filename)
  const styles = Object.entries(manifest)
    .filter(([, a]) => a.mime === 'text/css')
    .map(([filename]) => filename)
  cachedAssets = { scripts, styles }
  return cachedAssets
}

const ASSETS_URL_PREFIX = '/@atproto/oauth-provider/~assets/'

export function assetUrl(filename: string): string {
  return `${ASSETS_URL_PREFIX}${encodeURIComponent(filename)}`
}

export function renderHydration(values: Record<string, unknown>): string {
  // Mirrors @atproto/oauth-provider's declareHydrationData. We delegate the
  // actual escaping to serialize-javascript so `</script>`, U+2028/2029,
  // and other inline-script hazards in attacker-controllable values (e.g.
  // `clientId`) can't break out. `isJSON: true` tells serialize-javascript
  // the value is plain JSON-safe data (no Date/Function/RegExp round-trip
  // needed), which makes the output a drop-in for the SPA's JSON.parse.
  const lines: string[] = []
  for (const [key, val] of Object.entries(values)) {
    const keyLit = serialize(key, { isJSON: true })
    const valLit = serialize(JSON.stringify(val), { isJSON: true })
    lines.push(`window[${keyLit}]=JSON.parse(${valLit});`)
  }
  lines.push('document.currentScript.remove();')
  return lines.join('')
}

export interface PreviewAuthorizeFixture {
  clientId: string
  clientMetadata: ClientMetadata
  isTrusted: boolean
}

/** Minimal AuthorizeData fixture shared by /preview/consent + /preview/chooser. */
export function buildAuthorizeData(opts: PreviewAuthorizeFixture): unknown {
  // Fixture matching the AuthorizeData type in
  // @atproto/oauth-provider-ui/hydration-data.d.ts. The SPA tolerates
  // missing optional fields and empty permissionSets, so this is the
  // minimal viable shape.
  //
  // Intentionally no `loginHint`: setting it flips AuthorizeView into
  // `forceSignIn` mode, which neither preview route wants.
  return {
    requestUri:
      'urn:ietf:params:oauth:request_uri:req-preview-0000000000000000',
    clientId: opts.clientId,
    clientMetadata: opts.clientMetadata,
    clientTrusted: opts.isTrusted,
    clientFirstParty: false,
    scope: 'atproto transition:generic',
    uiLocales: undefined,
    promptMode: undefined,
    permissionSets: {},
  }
}

export const PREVIEW_FIXTURE_DEFAULT_CLIENT_ID =
  'https://preview.example/client-metadata.json'

export interface PreviewMetadataDeps {
  trustedClients: string[]
  resolveClientMetadata: (
    clientId: string,
    options?: { noCache?: boolean },
  ) => Promise<ClientMetadata>
  getClientCss: (
    clientId: string,
    metadata: ClientMetadata,
    trustedClients: string[],
  ) => string | null
  logger: LoggerLike
}

/**
 * Resolve the requesting client's metadata + CSS for a preview render.
 *
 * Always bypasses the 10-minute client-metadata cache — the whole point
 * of /preview is to iterate on branding.css and see the change on the
 * next refresh. Returns the default fixture (no metadata, no CSS) when
 * the caller didn't supply a real `client_id` or when the resolver
 * fails; the failure is logged with the supplied prefix.
 */
export async function resolveClientForPreview(
  deps: PreviewMetadataDeps,
  clientId: string,
  logPrefix: string,
): Promise<{ metadata: ClientMetadata; injectedCss: string | null }> {
  if (clientId === PREVIEW_FIXTURE_DEFAULT_CLIENT_ID) {
    return { metadata: {}, injectedCss: null }
  }
  try {
    const metadata = await deps.resolveClientMetadata(clientId, {
      noCache: true,
    })
    const injectedCss = deps.getClientCss(
      clientId,
      metadata,
      deps.trustedClients,
    )
    return { metadata, injectedCss }
  } catch (err) {
    deps.logger.warn(
      { err, clientId },
      `${logPrefix}: failed to resolve client metadata`,
    )
    return { metadata: {}, injectedCss: null }
  }
}

/** Read the optional ?client_id= query, falling back to the fixture. */
export function readClientIdQuery(req: RequestLike): string {
  const raw = req.query.client_id
  return typeof raw === 'string' && raw
    ? raw
    : PREVIEW_FIXTURE_DEFAULT_CLIENT_ID
}

/**
 * Preview-route CSP: relaxed `script-src` to allow the inline hydration
 * block. Pinning its sha256 would fight every time the fixture changes,
 * and these are dev-only surfaces.
 */
export const PREVIEW_CSP = [
  "default-src 'none'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "connect-src 'self'",
  "img-src 'self' data: https:",
  "font-src 'self' data:",
  "frame-ancestors 'none'",
  "base-uri 'self'",
].join('; ')

/** Apply the standard preview headers (content type, cache, CSP). */
export function applyPreviewHeaders(res: ResponseLike): void {
  res.setHeader('Content-Type', 'text/html; charset=utf-8')
  res.setHeader('Cache-Control', 'no-store')
  res.setHeader('Content-Security-Policy', PREVIEW_CSP)
}
