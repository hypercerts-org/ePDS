/**
 * Favicon injection for upstream-rendered HTML.
 *
 * Upstream `@atproto/oauth-provider` renders several HTML surfaces
 * (`/account*`, `/oauth/authorize`, `/oauth/authorize/redirect`, plus
 * its error pages) via a single `buildDocument()` template. None of
 * them emit `<link rel="icon">` tags, so those pages show the browser's
 * default placeholder in the tab.
 *
 * This middleware rewrites the `<head>` of matching responses to prepend
 * the same two `<link rel="icon">` tags (light + dark via
 * `prefers-color-scheme`) that our own rendered pages use. Same pattern
 * as `chooser-enrichment.ts` (inject-into-<head> on the response path)
 * but scoped to favicon concerns only — no CSP changes, no script
 * content.
 */
import type { Buffer } from 'node:buffer'

const FAVICON_TAGS =
  '<link rel="icon" href="/static/favicon.svg" media="(prefers-color-scheme: light)" type="image/svg+xml">' +
  '<link rel="icon" href="/static/favicon-dark.svg" media="(prefers-color-scheme: dark)" type="image/svg+xml">'

/**
 * True when the request should have favicon tags injected.
 *
 * Covers all upstream HTML surfaces served from pds-core:
 *   - `/account*` — standalone account management SPA.
 *   - `/oauth/*` — authorize flow, redirect intermediate, error pages
 *     (error renders happen inside `/oauth/authorize*` handlers).
 *
 * Non-HTML endpoints under these prefixes (e.g. JSON POST bodies at
 * `/oauth/authorize/accept`) pass the path match but are filtered out
 * downstream: the body rewriter is a no-op when no `<head>` is present.
 */
export function isUpstreamHtmlRequest(req: {
  method: string
  path: string
}): boolean {
  if (req.method !== 'GET') return false
  if (/^\/account(?:\/.*)?$/.test(req.path)) return true
  if (/^\/oauth(?:\/.*)?$/.test(req.path)) return true
  return false
}

/**
 * Inject favicon `<link>` tags at the very start of the `<head>` element.
 * Returns the rewritten body and a flag indicating whether the head was
 * found — callers use the flag to decide whether to strip stale
 * Content-Length / ETag headers.
 *
 * Idempotent: if the body already contains our light-variant favicon
 * link, it is returned unchanged so chaining with another head-rewriter
 * or a re-entrant call cannot double-inject.
 */
export function injectFaviconIntoHead(body: string): {
  body: string
  injected: boolean
} {
  if (!body.includes('<head>')) {
    return { body, injected: false }
  }
  if (body.includes('href="/static/favicon.svg"')) {
    return { body, injected: false }
  }
  return {
    body: body.replace('<head>', `<head>${FAVICON_TAGS}`),
    injected: true,
  }
}

export interface UpstreamFaviconResponse {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- http.ServerResponse.end has complex overloads
  end: (chunk?: any, ...args: any[]) => unknown
  removeHeader: (name: string) => void
  readonly headersSent: boolean
}

export interface UpstreamFaviconRequest {
  method: string
  path: string
}

export type UpstreamFaviconNext = () => void

/**
 * Build the Express middleware that intercepts HTML responses for the
 * upstream `/account*` and `/oauth/*` routes and prepends favicon
 * `<link>` tags to the `<head>`. Pure factory: no side-effects at module
 * load, safe to construct in unit tests with a synthetic req/res pair.
 *
 * Must be mounted AFTER compression — same constraint as the chooser-
 * enrichment middleware — so our wrapped `end` sees the raw HTML string
 * rather than gzipped bytes.
 */
export function createUpstreamFaviconMiddleware() {
  return function upstreamFaviconMiddleware(
    req: UpstreamFaviconRequest,
    res: UpstreamFaviconResponse,
    next: UpstreamFaviconNext,
  ): void {
    if (!isUpstreamHtmlRequest(req)) {
      next()
      return
    }

    const origEnd = res.end.bind(res)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- http.ServerResponse.end overloads
    res.end = (chunk: any, ...args: any[]) => {
      // removeHeader throws ERR_HTTP_HEADERS_SENT once upstream has
      // flushed. Upstream's SPA routes flush synchronously before
      // calling res.end(), so guard the same way chooser-enrichment
      // does — see the ERR_HTTP_HEADERS_SENT regression comment there.
      const stripLengthHeaders = () => {
        if (res.headersSent) return
        res.removeHeader('Content-Length')
        res.removeHeader('ETag')
      }
      if (typeof chunk === 'string') {
        const { body, injected } = injectFaviconIntoHead(chunk)
        if (injected) {
          chunk = body
          stripLengthHeaders()
        }
      } else if (chunk instanceof Uint8Array) {
        const asString = (chunk as Buffer).toString('utf-8')
        const { body, injected } = injectFaviconIntoHead(asString)
        if (injected) {
          chunk = body
          stripLengthHeaders()
        }
      }
      return origEnd(chunk, ...args)
    }

    next()
  }
}
