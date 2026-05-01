import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { escapeHtml } from '@certified-app/shared'

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
 * "Powered by Certified" footer rendered below the auth pages' card. Place
 * inside a flex-column wrapper alongside `.container`; the wrapper sets the
 * shared max-width so the footer lines up with the card edges.
 */
export const POWERED_BY_HTML = `<a class="powered-by" href="https://certified.app/" target="_blank" rel="noopener noreferrer">
      <span>Powered by</span>
      ${CERTIFIED_MARK_SVG}
    </a>`

/**
 * CSS rules for the `.powered-by` link + Certified wordmark. Each page is
 * still responsible for its own `.page-wrap` width since card widths differ.
 */
export const POWERED_BY_CSS = `
  .powered-by { display: flex; align-items: center; justify-content: center; gap: 8px; margin-top: 16px; color: #999; font-size: 13px; text-decoration: none; }
  .powered-by:hover, .powered-by:focus, .powered-by:visited { color: #999; text-decoration: none; }
  .powered-by .certified-mark { height: 14px; width: auto; display: block; }
`

export function renderOptionalStyleTag(css?: string | null): string {
  if (!css) return ''
  return `\n  <style>${css}</style>`
}

const DEFAULT_FAVICON_TAGS =
  '<link rel="icon" href="/static/favicon.svg" media="(prefers-color-scheme: light)" type="image/svg+xml">\n  <link rel="icon" href="/static/favicon-dark.svg" media="(prefers-color-scheme: dark)" type="image/svg+xml">'

/**
 * Render the favicon `<link>` tag(s) for the rendered page's `<head>`.
 *
 * Three modes:
 *   - Neither URL set: emit the two default ePDS variants gated by
 *     `prefers-color-scheme` so modern browsers pick light or dark to
 *     match the user's OS theme.
 *   - Only `lightUrl`: emit a single bare `<link>` (no media query).
 *     The browser uses it for both schemes.
 *   - Both `lightUrl` and `darkUrl`: emit two `<link>`s, each with the
 *     matching `prefers-color-scheme` media query.
 *
 * Both URLs must already have been validated by `getClientFaviconUrl()` /
 * `getClientFaviconUrlDark()` upstream (HTTPS only, no credentials,
 * length-capped, same-origin as `client_id`). `escapeHtml` is
 * belt-and-suspenders against attribute-context injection; omitting a
 * type hint lets the browser sniff.
 */
export function renderFaviconTag(
  lightUrl?: string | null,
  darkUrl?: string | null,
): string {
  if (!lightUrl) return DEFAULT_FAVICON_TAGS
  if (!darkUrl) {
    return `<link rel="icon" href="${escapeHtml(lightUrl)}">`
  }
  return (
    `<link rel="icon" href="${escapeHtml(lightUrl)}" media="(prefers-color-scheme: light)">\n  ` +
    `<link rel="icon" href="${escapeHtml(darkUrl)}" media="(prefers-color-scheme: dark)">`
  )
}
