# Publishing Guide for Maintainers

This document describes how ePDS versions itself and produces
release notes using [Changesets](https://github.com/changesets/changesets)
and a GitHub Actions workflow.

Unlike the `hypercerts-lexicon` and `hypercerts-sdk` repositories,
**ePDS does not publish to any registry** (not npm, not GitHub
Packages). The release workflow is purely version-only: it bumps
the root `ePDS` version, generates a changelog, creates a git tag,
and publishes a GitHub Release. Registry publishing could be added
later without changing the authoring workflow.

## Versioning model

ePDS is organised as a pnpm monorepo with packages under
`packages/`, but it is versioned and released as a **single
product**. Changesets is configured to track only the root `ePDS`
package (via `packages: ["."]` in `.changeset/config.json`); the
`packages/*/package.json` files are deliberately **not** tracked
and do not carry a `version` field at all.

Concretely:

- There is one version number, stored in the root `package.json`.
- There is one `CHANGELOG.md`, at the repo root.
- There is one git tag per release, of the form `v<major>.<minor>.<patch>`.
- There is one GitHub Release per tag.
- Every changeset has a single frontmatter entry: `"ePDS": minor`
  (or `patch` / `major`).

If the three in-scope packages ever need to be released
independently (e.g. if `@certified-app/shared` gets published to
npm for reuse outside ePDS), the setup can be migrated to a
per-package versioning model at that point. It is not locked in.

## Branch strategy

- **`main` branch**: the only release branch. Releases are tagged
  and GitHub Releases are published from this branch.
- **`feature/*` / `fix/*` branches**: short-lived branches for
  development work, merged into `main` via PR.

There is no beta / prerelease channel yet. If one is needed later,
it can be added following the `prerelease/*` pattern used by
`hypercerts-lexicon`.

## Authoring changesets

When you make a change that affects operators running ePDS, client
apps building on top of it, or end users of those apps, add a
changeset in the same PR:

```bash
pnpm changeset
```

The CLI will:

1. Detect that there is only one tracked package (`ePDS`) and bump
   it automatically without asking which packages changed.
2. Ask for the bump type (`major` / `minor` / `patch`). When
   multiple changesets accumulate, the largest bump wins (one
   `minor` + three `patch` changesets → one `minor` release).
3. Prompt for a short markdown description. Write it in the voice
   of the final changelog entry, not as a commit message — assume
   the reader has never heard of the internal refactor and just
   wants to know what changed for them.
4. Create a randomly-named markdown file in `.changeset/`. Rename
   it to something descriptive (e.g. `configurable-otp-length.md`)
   and commit it as part of your PR.

See the `writing-changesets` skill in
`.agents/skills/writing-changesets/SKILL.md` (also reachable as
`.claude/skills/writing-changesets/SKILL.md` via symlink) for the
required body structure (audience header, per-audience adaptation
detail) and what level of concrete detail is expected.

### What deserves a changeset

- New features, behaviour changes, configuration changes, env var
  additions, migration requirements, CLI/API changes, user-visible
  UI changes, developer-workflow changes (e.g. a new required
  build step).
- Bug fixes that a user or operator would notice.

### What does not

- Pure internal refactors with no behaviour change.
- Tests-only changes.
- CI / infrastructure / tooling changes that do not affect anyone
  consuming or running ePDS.
- Docs-only changes, unless they document a new developer
  workflow.
- Changes to the internal trust boundary between `auth-service`
  and `pds-core` (the HMAC callback signature, internal-only
  routes under `/_internal/`, the internal secret). These are
  contributor-facing, not consumer-facing.

If in doubt, add one. An "empty" changeset (intentionally no
release) can be created with `pnpm changeset add --empty` to
document the decision.

### Bump type guide

- **patch** (`0.2.0` → `0.2.1`): bug fixes, internal-behaviour
  changes that users should not notice.
- **minor** (`0.2.0` → `0.3.0`): new features, new configuration
  options, additive API changes.
- **major** (`0.2.0` → `1.0.0`): breaking changes — removed or
  renamed env vars, changed defaults that require operator
  action, removed HTTP endpoints or query params, migration-
  required database changes. Use deliberately; ePDS is pre-1.0 so
  most breaking changes can still land as minor, but call them
  out in the changeset body.

## Cutting a release

Releases are manually triggered to give maintainers full control
over timing.

1. **Prerequisites (one-time setup):**
   - The `hypercerts-release-bot` GitHub App must be installed on
     this repository with Contents and Pull requests read/write
     permissions. Its App ID and private key must be stored in
     the `RELEASE_BOT_APP_ID` and `RELEASE_BOT_APP_PRIVATE_KEY`
     repository secrets. This bot is used by the release workflow
     so that its automated "Version Packages" PR can bypass
     branch protection on `main`.
2. **Run the workflow:**
   - Navigate to the
     [Release workflow](https://github.com/hypercerts-org/ePDS/actions/workflows/release.yml).
   - Click "Run workflow" and select the `main` branch.
3. **What happens:**
   - The workflow checks out the repo using the release-bot app
     token, runs `pnpm build / format:check / lint / typecheck /
test` as a fail-fast gate, and then invokes
     `changesets/action`.
   - If there are pending changesets in `.changeset/`, the action
     opens (or updates) a **"Release" PR** against `main`. This
     PR applies the pending changesets: it bumps the root
     `ePDS` version, consumes the changeset files, and updates
     the root `CHANGELOG.md`. After `changeset version` has
     written the new release section, `scripts/changelog-audience-summary.mjs`
     runs as part of `pnpm version-packages` to post-process the
     section — it reads the `**Affects:**` line from each changeset
     bullet, groups summaries by audience (End users → Client app
     developers → Operators), prepends a "Who should read this
     release" block at the top of the section, and injects
     per-bullet HTML anchors so the summary links click through to
     the detailed entries. **If any changeset in the release lacks
     an `**Affects:**` line the script fails and the release
     workflow stops** — this is intentional so that a missed
     audience tag is surfaced immediately rather than becoming
     silently-missing release notes.
   - Review and merge the Release PR. This is the checkpoint
     where you verify the generated changelog and version number
     before they become permanent.
   - Re-run the Release workflow after the PR has been merged.
     This time there are no pending changesets but the tag is
     behind the `package.json` version, so the action runs
     `pnpm release` (`changeset tag`), creates a `v<version>`
     git tag, and publishes a single GitHub Release whose body
     is the matching section of `CHANGELOG.md`.
   - If there are no pending changesets and the tag is up to
     date, the workflow is a no-op.

## Validating PRs

The release workflow includes the fail-fast test/lint/build gate,
but `changeset status` is not currently run as a required PR
check. Day-to-day we rely on reviewers noticing when a PR touches
`packages/{pds-core,auth-service,shared}/**` without adding a
changeset. A GitHub App / bot-based changeset-check on PRs may be
added later to automate this.

If you discover a merged PR that should have had a changeset but
did not, add the missing changeset as a follow-up PR — the next
release will pick it up.

## Retroactive changesets at bootstrap

When Changesets was introduced to this repo there were already
several weeks of user-facing and developer-facing changes on
`main` without changesets. These were captured retroactively in
the same PR that introduced Changesets, grouped by logical change
rather than one-per-commit, so that the first generated release
notes would be meaningful rather than a wall of "configurable via
env var" one-liners.

## Troubleshooting

- **`changeset status` complains that packages have been changed
  without a changeset:** add a changeset (or an empty one) for
  the change you made. Note: this can fire for any commit since
  the last release, not just yours.
- **The Release PR does not appear after running the workflow:**
  check that there are committed changeset files in `.changeset/`
  on `main`, and that the workflow run succeeded past the
  fail-fast gate.
- **The Release PR appears but cannot be merged due to branch
  protection:** verify that the release bot GitHub App is
  installed and that its required-reviewer / required-status-check
  exemptions are configured correctly. The bot's app token is what
  the workflow uses to push the PR branch; merging still requires
  a human reviewer.
- **Changesets writes `version` fields back into
  `packages/*/package.json`:** this means a subpackage was
  accidentally picked up by the scanner. Check that the root
  `package.json` still has `"workspaces": ["."]` — that field is
  what puts Changesets into single-package mode via
  `@manypkg/get-packages`. Delete any `version` fields Changesets
  added to subpackages.
- **The workflow fails at `pnpm version-packages` with
  "changeset bullet(s) in the topmost release section have no
  `**Affects:**` line":** one or more changesets in this release
  are missing the required audience header. Find the offending
  changeset(s) named in the error output, add an `**Affects:**`
  line under the summary sentence listing the affected audiences
  (End users, Client app developers, Operators — in that order),
  commit, and re-run the workflow. The
  `scripts/changelog-audience-summary.mjs` post-processor refuses
  to generate the "Who should read this release" block if any
  entry is untagged.
