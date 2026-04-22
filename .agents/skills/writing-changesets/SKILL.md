---
name: writing-changesets
description: Create changeset files for user-facing or operator-facing changes to ePDS. Use when adding features, changing configuration, altering OAuth flows, or any change a downstream consumer needs to adapt to.
---

# Writing Changesets

Create a changeset file to document user-facing or operator-facing
changes for release.

## When to Use

Add a changeset when making changes that affect anyone consuming or
running ePDS:

- Adding, removing, or renaming environment variables
- Changing default behaviour that operators would notice
- Changing or extending the OAuth authorization flow (new query
  params, new client metadata fields, new response fields)
- Changing email templates or OTP format in a way downstream
  consumers can observe
- Fail-fast validation that could cause previously-working
  configurations to error out on startup
- Changing default ports, URL schemes, or healthcheck behaviour
- New end-user-visible signup/login UI steps

Skip changesets for:

- Internal refactors with no observable behaviour change
- Tests-only changes
- CI / infra / tooling changes that do not affect anyone running or
  consuming ePDS
- Docs-only changes (unless they document a new operator-facing
  workflow)
- Changes to the internal trust boundary between `auth-service` and
  `pds-core` (e.g. the HMAC callback signature, internal-only
  routes under `/_internal/`). These are contributor-facing, not
  consumer-facing.

If in doubt, add one. An "empty" changeset (intentionally no
release) can be created with `pnpm changeset add --empty` to
document the decision.

## Audiences

ePDS changesets should call out which of the following audiences a
change affects, **listed in this order** — from the person closest
to the running software outward to the person maintaining it:

- **End users** — people signing up or logging in via an
  ePDS-powered app. Most changes are transparent to them, but
  changes to the signup/login UI flow, to what handles they can
  pick, or to OTP format are worth mentioning so that operators
  can write their own release announcements.
- **Client app developers** — people building apps that
  authenticate against an ePDS instance via OAuth. They care about
  OAuth client metadata fields, query parameters on
  `/oauth/authorize`, callback handling, and anything visible at
  the HTTP boundary.
- **Operators** — people deploying and running an ePDS instance.
  They care about environment variables, config files, reverse
  proxy / Caddyfile setup, healthchecks, migrations, and breaking
  validation.

List only the audiences that actually need to adapt or will notice
the change. Omit audiences that are not affected.

Do **not** list "library consumers" as an audience. The
`pds-core`, `auth-service`, and `shared` packages are all private
and never published to any registry; the only "consumer" of the
shared exports is ePDS itself, and that's contributor territory.

## Format

ePDS treats itself as a single release unit even though the source
is organised into `packages/*`. Changesets is configured to track
**only the root `ePDS` package**, so every changeset has a single
frontmatter entry and the resulting CHANGELOG is a single file at
the repo root.

Create a file in `.changeset/` with a descriptive kebab-case name
(e.g. `configurable-otp-length.md`, `handle-selection-flow.md`). Do
not use the random name Changesets generates — give it a name that
reflects the change.

```markdown
---
'ePDS': minor
---

One-sentence summary in the voice of the final changelog entry.

**Affects:** End users, Client app developers, Operators

Longer explanation with enough concrete detail that each listed audience can adapt their environment or code without reading the PR or source. Use concrete names, values, file paths, and example snippets where applicable. Write the per-audience sections in the same order as the `**Affects:**` line: end users first, then client app developers, then operators.
```

### Frontmatter

The frontmatter is always just `"ePDS": <bump>`. Do not list
`@certified-app/pds-core`, `@certified-app/auth-service`, or any
other package name — those packages are deliberately not tracked
by Changesets.

Bump types:

- `patch` — bug fixes, non-breaking internal-behaviour changes
  that downstream consumers can observe.
- `minor` — new features, new config options, additive API
  changes. Also used for breaking changes while `ePDS` is still at
  a `0.x.y` version, following the semver-for-0.x convention.
- `major` — breaking changes, only after `ePDS` reaches `1.0.0`.
  Avoid for now.

If a single changeset mixes a feature and a bug fix, pick `minor`
(the larger bump wins anyway when aggregated).

### Body structure

Every non-trivial changeset **must** contain, in this order:

1. **Summary sentence** — one physical line, in the voice of the final changelog entry (not a commit message).

   **The summary line is read by everyone listed in `**Affects:**`,
   not just the most technical audience.** It is the text that
   appears in the "Who should read this release" block at the top
   of the release section, and the "Who should read" block groups
   bullets by audience — so End users, Client app developers, and
   Operators all see the same summary line under their own
   heading. Write the summary in language the **least technical
   listed audience** can understand.

   Concretely: if the changeset affects End users (even just as
   one of several audiences), the summary must be written in
   end-user language. Avoid:
   - Acronyms and protocol terms (`OTP`, `DID`, `PAR`, `OAuth`,
     `HMAC`, `DPoP`) — spell them out or rephrase.
   - Parameter and field names (`login_hint`, `client_metadata`,
     `epds_handle_mode`) — the user doesn't know these exist.
   - Implementation concepts (`resolver chain`, `precedence`,
     `schema validation`) — describe the observable effect
     instead.
   - Monorepo / infra language (`auth service`, `pds-core`,
     `internal endpoint`) — say what the user sees happening.

   Technical naming belongs in the per-audience sections further
   down, where a client-app developer or operator reading _their_
   section expects to see exact field names and env vars. The
   summary line is not the place for it.

   Examples of the same change written badly and then well:
   - ❌ "Configurable OTP code length and charset."
   - ✅ "Longer sign-in codes, optionally mixing letters and numbers."

   - ❌ "Handle selection step in the new-user signup flow."
   - ✅ "Choose your own handle when signing up, instead of being given a random one."

   - ❌ "Accept AT Protocol handles and DIDs as OAuth `login_hint` values."
   - ✅ "Sign in faster from third-party apps that already know who you are."

   If the change is purely operator-facing (no End users in the
   `**Affects:**` line), operator language is fine in the summary
   — the only audience reading it is operators.

2. **`**Affects:**` line** — required, comma-separated list of
   audiences from the list above, in that order: End users, Client
   app developers, Operators. Omit audiences that are not affected,
   but never omit the `**Affects:**` line itself — the release
   workflow fails hard if a changeset has no `**Affects:**` line,
   because the "Who should read this release" block generation (see
   below) has nothing to aggregate. If a change genuinely affects
   nobody listed, it probably doesn't need a changeset at all.
3. **Per-audience adaptation detail** — one short section per
   affected audience, in the same order as the `**Affects:**`
   line, with concrete names and examples. Use **bold inline
   audience labels** rather than headings to keep generated
   changelogs readable. Inside each per-audience section you can
   and should use exact technical terms that the listed audience
   will recognise (env var names, field names, function names) —
   the plain-language rule only applies to the summary line above.

   Each paragraph in the changeset body must be **unwrapped**: one
   paragraph per physical line. Do not manually hard-wrap prose at
   72 or 80 columns inside the changeset file. Wrapped source lines
   are preserved by GitHub and some other Markdown renderers when
   the release notes are rendered from generated changelog bullets,
   which makes the published release notes look awkwardly
   line-broken. Keep prose unwrapped so the rendered release notes
   can wrap naturally.

   **Do not restate the summary in the per-audience sections.**
   The reader has already seen the summary once at the top of the
   bullet and once in the "Who should read this release" block.
   Per-audience sections should **extend** the summary with the
   information that audience specifically needs — not translate
   it into their vocabulary and repeat it. A useful test: if you
   delete the summary line and the per-audience section still
   makes sense as a standalone paragraph, the section was
   restating the summary. Rewrite it to start from what's new to
   _that audience_ instead.

   **Do not put a "shared preamble" paragraph between the
   `**Affects:**` line and the first per-audience section.** Such
   preambles are almost always either restating the summary, or
   containing information that actually belongs inside one of the
   per-audience sections (usually the most technical one — the
   fact that you were tempted to promote it out of the section
   means you were treating it as common knowledge when it isn't).
   Put it inside the right section instead.

Do **not** use `##` or `###` markdown headings anywhere in the
changeset body. `@changesets/changelog-github` renders each
changeset as a single bullet in the release section: the first
line becomes the bullet, every subsequent line is indented by two
spaces to stay inside the list item. An indented `##` will either
break out of the list (GitHub) or render as literal text (other
renderers), in both cases mangling the changelog. Use bold inline
labels (`**End users:**`, `**Operators:**`) instead. Fenced code
blocks and nested bullet lists are fine because they survive the
2-space indent cleanly.

The goal: a reader in one of the listed audiences should be able
to adapt their environment or code **without reading the PR or
the source**. Changesets are not release-note marketing copy —
they are migration instructions.

### What "concrete detail" means

Good adaptation detail includes:

- **Exact env var names** and their accepted values, defaults,
  ranges, and validation errors.
- **Exact field names** in OAuth client metadata, query params,
  HTTP request/response bodies.
- **Exact function/export names** being deprecated or renamed
  (only when the change actually crosses a public boundary).
- **Copy-pasteable examples** for client app developers — e.g. an
  example client metadata JSON with the new field highlighted.
- **The error message** that operators will see if they hit a new
  fail-fast path, quoted verbatim so they can grep for it.
- **The old behaviour vs the new behaviour**, explicitly, whenever
  defaults change.

Bad (avoid):

- "Various improvements to the OTP flow." — tells the reader
  nothing actionable.
- "Now configurable via env var." — which env var? What values?
- Paraphrased field names like "the handle mode setting" when the
  actual field is `epds_handle_mode`.

It is fine to reference documentation (e.g. `.env.example`) for
long details, but the changeset itself must still name the thing
and describe the change. Do not offload the entire explanation.

## Example

```markdown
---
'ePDS': minor
---

Longer sign-in codes, optionally mixing letters and numbers.

**Affects:** End users, Operators

**End users:** OTP codes may now be longer than 6 digits and may include uppercase letters if the operator has opted into the `alphanumeric` charset. Codes of length 8 or more are displayed with a space in the middle (e.g. `1234 5678`) for readability; copy-paste still yields the flat code.

**Operators:** two new environment variables on the auth service — `OTP_LENGTH` (integer, range 4–12, default 8) and `OTP_CHARSET` (`numeric` (default) or `alphanumeric`). Values outside the range cause the service to fail on startup. The OTP input form fields adapt automatically; no template changes required.
```

## What the `**Affects:**` line feeds

After `changeset version` runs, `scripts/changelog-audience-summary.mjs`
post-processes the newly-written release section of `CHANGELOG.md`.
For every changeset bullet it reads the `**Affects:**` line, groups
summaries by audience, and prepends a "Who should read this release"
block at the top of the release section. Each summary bullet in the
block is a markdown link to an HTML anchor on the corresponding
detailed entry below, so a reader can click through from their
audience to the specific adaptation instructions.

You do not need to do anything special to feed this — as long as
each changeset has a valid `**Affects:**` line, the block is
generated automatically on release. If a changeset omits the line,
the script fails and the release workflow stops, which is
intentional: it means "forgot to tag your changeset" is a loud,
fixable error, not silently-missing release notes.

## Publishing

See `docs/PUBLISHING.md` for how changesets are consumed at
release time and how the manual-dispatch release workflow produces
the git tag and GitHub Release.

## Key files

- `.changeset/config.json` — Changesets configuration.
- Root `package.json` — the `"workspaces": ["."]` field is what
  puts Changesets into single-package mode. See `docs/PUBLISHING.md`
  for why this coexists with `pnpm-workspace.yaml`.
- `.changeset/*.md` — existing changesets are the best reference
  for naming and format.
- `scripts/changelog-audience-summary.mjs` — post-processor that
  reads `**Affects:**` lines and builds the "Who should read this
  release" block.
- `docs/PUBLISHING.md` — full publishing / release workflow guide.
- `.github/workflows/release.yml` — the workflow that consumes
  changesets.
