#!/usr/bin/env node
// Insert a "Who should read this release" block at the top of the
// most recent release section in CHANGELOG.md, with each summary
// bullet linking to its corresponding detailed entry below.
//
// Runs after `changeset version` has consumed the pending changesets
// and rewritten CHANGELOG.md. For each changeset bullet in the
// topmost release section, pulls the summary line and the
// `**Affects:** ...` line, then:
//
//   1. Prepends an HTML anchor (`<a id="..."></a>`) to each main
//      changeset bullet so it can be linked to.
//   2. Groups summaries by audience and prepends a
//      "Who should read this release" block before the first
//      `### Minor Changes` / `### Patch Changes` subheading. Each
//      summary bullet in the block is a markdown link pointing at
//      the anchor for the corresponding main bullet.
//
// Strict mode: fails if any bullet lacks an `**Affects:**` line.
// This makes "forgot to tag your changeset" a loud release-blocking
// error.
//
// Idempotent: re-running strips the old "Who should read" block and
// strips any previously-inserted anchors, then regenerates both. No
// duplication on second run.
//
// Audience canonical order (outermost to innermost — user first,
// operator last):
//   1. End users
//   2. Client app developers
//   3. Operators
// Any audience name not in this list is sorted alphabetically AFTER
// these three.

import { readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(here, '..')
const changelogPath = resolve(repoRoot, 'CHANGELOG.md')

const CANONICAL_ORDER = ['End users', 'Client app developers', 'Operators']
const BLOCK_HEADING = '### Who should read this release'
// Anchors are prefixed with `v<version>-` so that (a) re-runs of
// this script only strip anchors belonging to the release they are
// regenerating, and (b) two different releases can have changesets
// with the same summary without colliding in the per-file anchor
// namespace. Computed at parse time from the release heading.

const changelog = readFileSync(changelogPath, 'utf8')

// -----------------------------------------------------------------
// Locate the topmost release section.
// -----------------------------------------------------------------

const headingRegex = /^## [^\n]*$/m
const firstMatch = headingRegex.exec(changelog)
if (!firstMatch) {
  console.error(
    'changelog-audience-summary: no `## <version>` heading found in CHANGELOG.md; nothing to do.',
  )
  process.exit(0)
}

const sectionStart = firstMatch.index
const afterHeading = sectionStart + firstMatch[0].length
const rest = changelog.slice(afterHeading)
const nextHeadingRelative = rest.search(/\n## /)
const sectionEnd =
  nextHeadingRelative === -1
    ? changelog.length
    : afterHeading + nextHeadingRelative + 1
const releaseHeading = firstMatch[0]
let sectionBody = changelog.slice(afterHeading, sectionEnd)

// Extract the version from the heading and build the anchor prefix.
// Heading shape: "## 0.2.0" or "## 1.0.0-beta.1". We take everything
// after the "## " and trim — the resulting string can contain dots,
// letters, and hyphens, all of which are valid in HTML id attributes.
// An explicit `v` is prepended so the anchor starts with a letter
// (some older CSS selectors dislike IDs that start with a digit).
const versionRaw = releaseHeading.replace(/^## /, '').trim()
const ANCHOR_PREFIX = `v${versionRaw}-`

// -----------------------------------------------------------------
// Idempotency cleanup: strip any previous "Who should read" block
// and strip any anchors we previously inserted inside bullets. Both
// are done in the working copy of sectionBody before we extract
// bullets, so the parser sees clean text.
// -----------------------------------------------------------------

const existingBlockRegex = new RegExp(
  `\\n${BLOCK_HEADING.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\n[\\s\\S]*?(?=\\n### |\\n## |$)`,
)
sectionBody = sectionBody.replace(existingBlockRegex, '')

// Strip our previously-inserted anchors for THIS release only.
// The prefix includes the version, so anchors from other releases
// (and any hand-written anchors) are left untouched.
const escapedPrefix = ANCHOR_PREFIX.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
const previousAnchorRegex = new RegExp(
  `<a id="${escapedPrefix}[^"]*"></a>\\s*`,
  'g',
)
sectionBody = sectionBody.replace(previousAnchorRegex, '')

// -----------------------------------------------------------------
// Walk bullets in the cleaned section body.
// -----------------------------------------------------------------

const bulletStartRegex = /\n- /g
const starts = []
let m
while ((m = bulletStartRegex.exec(sectionBody)) !== null) {
  starts.push(m.index + 1) // +1 to skip the leading newline
}
const bullets = []
for (let i = 0; i < starts.length; i++) {
  const from = starts[i]
  const to = i + 1 < starts.length ? starts[i + 1] : sectionBody.length
  bullets.push({ from, to, text: sectionBody.slice(from, to) })
}

if (bullets.length === 0) {
  console.log(
    'changelog-audience-summary: no changeset bullets in the topmost release section; nothing to do.',
  )
  process.exit(0)
}

// -----------------------------------------------------------------
// Parse each bullet: summary, audiences, and generate a slug.
// -----------------------------------------------------------------

// Slugify: lowercase, strip backticks and other markdown punctuation,
// replace runs of non-alphanumerics with a single hyphen, trim
// hyphens. Truncate at a word boundary at or before the MAX_LEN
// so anchors stay scannable in source without cutting words mid-way.
const SLUG_MAX_LEN = 60
function slugify(text) {
  // All regexes below use explicitly bounded quantifiers so they
  // cannot backtrack catastrophically on pathological input.
  const BOUND = 1000
  const raw = text
    .toLowerCase()
    // drop inline code spans: `...`
    .replace(new RegExp('`[^`]{0,' + BOUND + '}`', 'g'), ' ')
    // drop markdown links: [text](url)
    .replace(
      new RegExp(
        '\\[[^\\]]{0,' + BOUND + '}\\]\\([^)]{0,' + BOUND + '}\\)',
        'g',
      ),
      ' ',
    )
    // collapse runs of non-alphanumerics into a single hyphen
    .replace(new RegExp('[^a-z0-9]{1,' + BOUND + '}', 'g'), '-')
  // Trim leading and trailing hyphens without a regex alternation.
  let trimmed = raw
  while (trimmed.startsWith('-')) trimmed = trimmed.slice(1)
  while (trimmed.endsWith('-')) trimmed = trimmed.slice(0, -1)

  if (trimmed.length <= SLUG_MAX_LEN) return trimmed

  // Truncate at the last hyphen (word boundary) at or before
  // SLUG_MAX_LEN. If the first word alone is longer than the limit,
  // fall back to a hard cut.
  const slice = trimmed.slice(0, SLUG_MAX_LEN)
  const lastBoundary = slice.lastIndexOf('-')
  return lastBoundary > 0 ? slice.slice(0, lastBoundary) : slice
}

const entries = []
const missing = []
const usedSlugs = new Set()

for (const bullet of bullets) {
  const withoutMarker = bullet.text.replace(/^- /, '')
  const lines = withoutMarker.split('\n')

  // Collect summary lines until the first blank line.
  const summaryLines = [lines[0]]
  let cursor = 1
  while (cursor < lines.length) {
    const line = lines[cursor]
    if (line.trim() === '') break
    summaryLines.push(line.replace(/^ {2}/, ''))
    cursor++
  }

  // Join wrapped summary lines and strip generator-added prefixes.
  let summary = summaryLines.join(' ').replace(/\s+/g, ' ').trim()
  let previous
  do {
    previous = summary
    summary = summary
      .replace(/^[0-9a-f]{7,40}:\s*/, '')
      .replace(/^\[#?\d+\]\([^)]*\)\s*/, '')
      .replace(/^\[[0-9a-f]{7,40}\]\([^)]*\)\s*/, '')
      .replace(/^\[?`[0-9a-f]{7,40}`\]?(?:\([^)]*\))?\s*/, '')
      .replace(/^Thanks\s+(?:\[@[^\]]+\]\([^)]*\)|@\S+)!?\s*/, '')
      .replace(/^-\s*/, '')
      .trim()
  } while (summary !== previous)

  // Look for the `**Affects:**` line. Parsed via plain string ops
  // rather than a regex — the line shape is a fixed prefix plus a
  // comma-separated tail, which `startsWith()` + `slice()` handles
  // correctly without any regex quantifiers at all.
  const AFFECTS_PREFIX = '**Affects:**'
  let affects = null
  for (const line of lines.slice(cursor)) {
    const stripped = line.startsWith('  ') ? line.slice(2) : line
    if (!stripped.startsWith(AFFECTS_PREFIX)) continue
    const rest = stripped.slice(AFFECTS_PREFIX.length).trim()
    if (rest === '') continue
    affects = rest
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
    break
  }

  if (affects === null) {
    missing.push(summary || '(unparseable summary)')
    continue
  }

  // Generate a unique anchor slug for this bullet.
  let slug = slugify(summary) || 'entry'
  if (usedSlugs.has(slug)) {
    // Disambiguate by appending -2, -3, ...
    let n = 2
    while (usedSlugs.has(`${slug}-${n}`)) n++
    slug = `${slug}-${n}`
  }
  usedSlugs.add(slug)

  entries.push({
    summary,
    audiences: affects,
    slug: `${ANCHOR_PREFIX}${slug}`,
    from: bullet.from,
    to: bullet.to,
  })
}

if (missing.length > 0) {
  console.error(
    `changelog-audience-summary: ${missing.length} changeset bullet(s) in the topmost release section have no \`**Affects:**\` line. Every changeset must declare its audiences. Missing on:`,
  )
  for (const s of missing) {
    console.error(`  - ${s}`)
  }
  process.exit(1)
}

// -----------------------------------------------------------------
// Inject anchor tags into each main bullet. We walk entries in
// reverse order of position so that mutating the section text
// doesn't invalidate earlier offsets.
// -----------------------------------------------------------------

const sorted = entries.slice().sort((a, b) => b.from - a.from)
for (const entry of sorted) {
  // Insert the anchor right after the `- ` marker at the start of
  // the bullet. The anchor and a space come before the bullet's
  // existing content so the marker, the anchor, and the content
  // stay on the same source line and thus inside the list item.
  const before = sectionBody.slice(0, entry.from + 2) // include the `- `
  const after = sectionBody.slice(entry.from + 2)
  sectionBody = before + `<a id="${entry.slug}"></a> ` + after
}

// -----------------------------------------------------------------
// Build the "Who should read this release" block with links.
// -----------------------------------------------------------------

const byAudience = new Map()
for (const { summary, audiences, slug } of entries) {
  for (const audience of audiences) {
    if (!byAudience.has(audience)) byAudience.set(audience, [])
    byAudience.get(audience).push({ summary, slug })
  }
}

const sortedAudiences = Array.from(byAudience.keys()).sort((a, b) => {
  const ai = CANONICAL_ORDER.indexOf(a)
  const bi = CANONICAL_ORDER.indexOf(b)
  if (ai !== -1 && bi !== -1) return ai - bi
  if (ai !== -1) return -1
  if (bi !== -1) return 1
  return a.localeCompare(b)
})

const blockLines = [BLOCK_HEADING, '']
for (const audience of sortedAudiences) {
  blockLines.push(`- **${audience}:**`)
  for (const { summary, slug } of byAudience.get(audience)) {
    // Escape ] in summaries so markdown link text stays valid.
    const safeSummary = summary.replace(/\]/g, '\\]')
    blockLines.push(`  - [${safeSummary}](#${slug})`)
  }
}
blockLines.push('')
const block = blockLines.join('\n')

// -----------------------------------------------------------------
// Insert the block right after the release heading, before the
// first `### ` subheading in the now-anchored section body.
// -----------------------------------------------------------------

const firstSubheadingMatch = sectionBody.match(/\n### /)
let newSectionBody
if (firstSubheadingMatch) {
  const insertPoint = firstSubheadingMatch.index + 1
  newSectionBody = '\n\n' + block + '\n' + sectionBody.slice(insertPoint)
} else {
  newSectionBody = '\n\n' + block + sectionBody.trimStart()
}

const newChangelog =
  changelog.slice(0, sectionStart) +
  releaseHeading +
  newSectionBody +
  changelog.slice(sectionEnd)

writeFileSync(changelogPath, newChangelog)

console.log(
  `changelog-audience-summary: added "Who should read this release" block with ${sortedAudiences.length} audience(s) and ${entries.length} anchored entries to ${releaseHeading.trim()}`,
)
