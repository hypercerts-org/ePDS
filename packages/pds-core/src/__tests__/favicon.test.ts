/**
 * Ensures every rendered `<head>` in the pds-core sources wires both
 * the light- and dark-mode Certified favicons. Mirrors the auth-service
 * favicon test, but scans the full pds-core `src/` tree because head
 * blocks here live across both route-level code (`index.ts`) and
 * standalone renderers (`lib/preview-consent.ts`) rather than a single
 * `routes/` dir.
 *
 * Test fixtures under `__tests__/` are excluded — they contain synthetic
 * `<head></head>` strings that have nothing to do with rendered output.
 */
import * as fs from 'node:fs'
import * as path from 'node:path'

import { describe, it, expect } from 'vitest'

const SRC_DIR = path.join(__dirname, '..')

const FAVICON_LIGHT =
  '<link rel="icon" href="/static/favicon.svg" media="(prefers-color-scheme: light)" type="image/svg+xml">'
const FAVICON_DARK =
  '<link rel="icon" href="/static/favicon-dark.svg" media="(prefers-color-scheme: dark)" type="image/svg+xml">'

const HEAD_BLOCK = /<head\b[^>]*>[\s\S]*?<\/head>/g

/**
 * Recursively collect every non-test `.ts` file under `src/`.
 */
function walk(dir: string): string[] {
  const out: string[] = []
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === '__tests__') continue
      out.push(...walk(full))
    } else if (entry.isFile() && entry.name.endsWith('.ts')) {
      out.push(full)
    }
  }
  return out
}

/**
 * Scan only the contents of backtick-delimited template literals that
 * contain a full HTML document (recognizable by `<!doctype` or `<html`).
 * A plain whole-file match pulls `<head>`/`</head>` tokens out of code
 * comments and regex fragments (e.g. `chooser-enrichment.ts`, or the
 * hydration docblock in `index.ts`) and gives false matches.
 *
 * The template-literal parser is intentionally naive — no `${}`
 * interpolation support needed since we only look for the static
 * `<head>...</head>` substring. It does handle escaped backticks so a
 * stray `` \` `` in an HTML string doesn't end the literal early.
 */
function extractTemplateLiterals(source: string): string[] {
  const literals: string[] = []
  let i = 0
  while (i < source.length) {
    if (source[i] === '`') {
      let j = i + 1
      while (j < source.length) {
        if (source[j] === '\\') {
          j += 2
          continue
        }
        if (source[j] === '`') break
        j++
      }
      literals.push(source.slice(i + 1, j))
      i = j + 1
    } else {
      i++
    }
  }
  return literals
}

const DOC_HINT = /<!doctype\b|<html\b/i

const sourceFiles = walk(SRC_DIR)
  .map((file) => {
    const contents = fs.readFileSync(file, 'utf8')
    const heads: string[] = []
    for (const literal of extractTemplateLiterals(contents)) {
      if (!DOC_HINT.test(literal)) continue
      heads.push(...(literal.match(HEAD_BLOCK) ?? []))
    }
    return { file: path.relative(SRC_DIR, file), heads }
  })
  .filter(({ heads }) => heads.length > 0)

describe('favicon wiring across pds-core rendered templates', () => {
  it('discovers at least one source file that renders HTML', () => {
    expect(sourceFiles.length).toBeGreaterThan(0)
  })

  for (const { file, heads } of sourceFiles) {
    it(`${file}: every <head> block includes both favicon links`, () => {
      for (const head of heads) {
        expect(head).toContain(FAVICON_LIGHT)
        expect(head).toContain(FAVICON_DARK)
      }
    })
  }
})
