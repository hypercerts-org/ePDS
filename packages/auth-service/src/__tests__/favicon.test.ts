/**
 * Ensures every rendered `<head>` in the auth-service routes wires both
 * the light- and dark-mode Certified favicons. Routes that render a
 * branded page go through `renderFaviconTag()` so a custom client-supplied
 * favicon can override the default — those are covered by the separate
 * `renderFaviconTag` unit test in `page-helpers.test.ts`. Everything else
 * still embeds the two `<link>` tags literally; this scanner catches
 * future routes / render helpers that forget them.
 */
import * as fs from 'node:fs'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'

import { describe, it, expect } from 'vitest'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const SCAN_DIRS = [
  path.join(__dirname, '..', 'routes'),
  path.join(__dirname, '..', 'lib'),
]

const FAVICON_LIGHT =
  '<link rel="icon" href="/static/favicon.svg" media="(prefers-color-scheme: light)" type="image/svg+xml">'
const FAVICON_DARK =
  '<link rel="icon" href="/static/favicon-dark.svg" media="(prefers-color-scheme: dark)" type="image/svg+xml">'

/**
 * Match every `<head>...</head>` block. `[\s\S]` lets the body span
 * newlines; the `?` makes the quantifier lazy so adjacent heads don't
 * merge.
 */
const HEAD_BLOCK = /<head\b[^>]*>[\s\S]*?<\/head>/g

/**
 * Routes that render via `renderFaviconTag()` instead of literal
 * `<link>` tags — the helper is exercised in `page-helpers.test.ts`, so
 * scanning their source for the literal strings would false-fail.
 */
const HELPER_BACKED_ROUTES = new Set([
  'choose-handle.ts',
  'login-page.ts',
  'recovery.ts',
])

/**
 * Auto-discover every source file that renders at least one `<head>` block.
 * A hardcoded list silently misses new rendered pages; raw `readdirSync`
 * false-fails on files that never render HTML (e.g. `complete.ts`).
 * Filtering by "contains a `<head>`" catches future renderers automatically
 * while excluding non-HTML sources. `lib/` is scanned as well as `routes/`
 * because shared render helpers (e.g. `render-error.ts`) live there.
 */
const routeFiles = SCAN_DIRS.flatMap((dir) =>
  fs
    .readdirSync(dir)
    .filter((file) => file.endsWith('.ts'))
    .filter((file) => !HELPER_BACKED_ROUTES.has(file))
    .map((file) => ({
      file: `${path.basename(dir)}/${file}`,
      heads:
        fs.readFileSync(path.join(dir, file), 'utf8').match(HEAD_BLOCK) ?? [],
    }))
    .filter(({ heads }) => heads.length > 0),
)

describe('favicon wiring across auth-service route templates', () => {
  it('discovers at least one route that renders HTML', () => {
    expect(routeFiles.length).toBeGreaterThan(0)
  })

  for (const { file, heads } of routeFiles) {
    it(`${file}: every <head> block includes both favicon links`, () => {
      for (const head of heads) {
        expect(head).toContain(FAVICON_LIGHT)
        expect(head).toContain(FAVICON_DARK)
      }
    })
  }
})
