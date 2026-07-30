# PR #165 split assessment

## Executive summary

PR [#165](https://github.com/hypercerts-org/ePDS/pull/165) contains 37 commits spanning 44 files. It is not suitable to merge as one change, but most of the underlying work is worth retaining after rebasing and review.

I reconstructed the useful work as **16 local topic branches** from current `origin/main` (`7bce175fdd31bb4846fe3aca6c376a03387e298f`) in a fresh worktree at `/home/adam/.GIT/3rd-party/ePDS-pr165-split`. No branch was pushed and no pull request was created.

Disposition of the 37 source commits:

- **3 already landed or were superseded by the merged PR #187:** commits 1, 2, and 26.
- **3 are superseded by the stronger active PR #204:** segmented-input filtering/autofill commits 12, 13, and 27.
- **2 should be dropped:** commits 6 and 16 infer session expiry from ambiguous OAuth error text and can misclassify unrelated failures.
- **29 were retained, redistributed, rebased, and where necessary corrected** across the local branches below.

All 16 branches pass `git diff --check`, formatting of supported changed files, ESLint, a forced TypeScript build, and the full Vitest suite (73 test files and at least 1,076 tests, with branch-specific additions increasing that count). The root `pnpm typecheck` command could not find a root-level `tsc` binary after a clean install, so validation invoked the workspace-installed compiler directly: `packages/shared/node_modules/.bin/tsc --build tsconfig.json --force`.

### Recommended order

1. **Review first / strongest value:** recovery request URI, incomplete-code guard, clear-on-resend, accessible error announcements, account action banners, safe client-name fallback.
2. **Then focused UX correctness:** clear-email-on-back, lockout recovery, autocomplete, keyboard focus, handle-unavailable copy.
3. **Stack handle reservation after copy:** `split-pr165/reserved-handle-check` intentionally includes and depends on `split-pr165/handle-unavailable-copy`.
4. **Optional polish:** stale-link wording, spam hint, server-rendered charset filtering, demo error wording.

PR #204 does **not** logically block any reconstructed branch. It substantially rewrites the segmented OTP control, so whichever side lands second must reconcile the interactive portions of `ignore-incomplete-otp-submit`, `otp-lockout-recovery`, and `clear-code-on-resend`. The remaining branches can proceed independently; sharing `login-page.ts` alone is not a dependency.

## Baseline and method

- Source PR head: `473f6a066ab99941048c45479df5927e0ce6ab2e`
- Source merge base: `e060e2fd961e4361bbd63674ec0d339c4c8b8acd`
- Reconstruction base: `origin/main` at `7bce175fdd31bb4846fe3aca6c376a03387e298f`
- Fresh worktree: `/home/adam/.GIT/3rd-party/ePDS-pr165-split`
- Related merged work: [PR #187](https://github.com/hypercerts-org/ePDS/pull/187)
- Related active replacement: [PR #204](https://github.com/hypercerts-org/ePDS/pull/204)

The assessment included commit-by-commit diffs, current-main comparison, patch-equivalence checks, the PR description, 68 inline review comments, later merged work, active overlapping PRs, and current upstream `@atproto/pds` behavior. Review findings were applied rather than blindly preserving the old branch.

## Branch overview

All branch names in this table are under `split-pr165/`; linked PRs are drafts. Priorities are: **P0** = publish first, **P1** = publish next, **P2** = worthwhile follow-up, and **P3** = optional polish. “Reconcile with #204” identifies overlapping OTP-control code, not a blocker or prerequisite.

| Branch                           | PR                                                      |              Commits | Benefit                                                       | Complexity                                                  | Recommendation                                    | Priority |
| -------------------------------- | ------------------------------------------------------- | -------------------: | ------------------------------------------------------------- | ----------------------------------------------------------- | ------------------------------------------------- | :------: |
| `clear-email-on-back`            | [#215](https://github.com/hypercerts-org/ePDS/pull/215) |                    2 | Medium — makes account switching start cleanly                | Low — local state reset plus tests                          | Keep                                              |    P1    |
| `ignore-incomplete-otp-submit`   | [#216](https://github.com/hypercerts-org/ePDS/pull/216) |                    2 | High — avoids false errors and wasted attempts                | Low — client-side completeness guard                        | Keep; reconcile submit guard with #204            |    P0    |
| `otp-lockout-recovery`           | [#217](https://github.com/hypercerts-org/ePDS/pull/217) |                    8 | High — gives locked-out users a recovery path                 | High — three surfaces and string-based error classification | Keep; scrutinize coupling; reconcile UI with #204 |    P1    |
| `recovery-link-request-uri`      | [#218](https://github.com/hypercerts-org/ePDS/pull/218) |                    2 | High — repairs the return to the active auth flow             | Medium — render plumbing plus E2E coverage                  | Keep                                              |    P0    |
| `friendly-stale-link-errors`     | [#219](https://github.com/hypercerts-org/ePDS/pull/219) |                    3 | Medium — turns dead links into actionable guidance            | Medium — two flows and E2E coverage                         | Keep                                              |    P2    |
| `clear-code-on-resend`           | [#220](https://github.com/hypercerts-org/ePDS/pull/220) |                    1 | Medium — prevents stale-code confusion after resend           | Low — local input reset                                     | Keep; reconcile reset helper with #204            |    P1    |
| `spam-folder-hint`               | [#221](https://github.com/hypercerts-org/ePDS/pull/221) |                    1 | Low — may reduce email-delivery support friction              | Low — copy and styling only                                 | Optional                                          |    P3    |
| `email-autocomplete`             | [#222](https://github.com/hypercerts-org/ePDS/pull/222) |                    3 | Medium — improves autofill and password-manager behavior      | Low — input attributes and mode toggle                      | Keep                                              |    P1    |
| `server-otp-charset-filter`      | [#223](https://github.com/hypercerts-org/ePDS/pull/223) |                    2 | Medium — blocks impossible OTP characters early               | Low — two inline input filters                              | Keep after manual browser checks                  |    P2    |
| `accessible-error-announcements` | [#224](https://github.com/hypercerts-org/ePDS/pull/224) |                    4 | High — makes errors available to screen-reader users          | Low — standard alert/live-region semantics                  | Keep                                              |    P0    |
| `keyboard-focus-rings`           | [#225](https://github.com/hypercerts-org/ePDS/pull/225) |                    3 | High — restores visible keyboard navigation                   | Low — CSS-only behavior                                     | Keep                                              |    P1    |
| `friendly-demo-errors`           | [#226](https://github.com/hypercerts-org/ePDS/pull/226) |                    1 | Medium — replaces developer wording with user guidance        | Low — known-error copy mapping                              | Optional                                          |    P3    |
| `handle-unavailable-copy`        | [#227](https://github.com/hypercerts-org/ePDS/pull/227) |                    2 | Medium — avoids falsely claiming a handle is taken            | Low — copy normalization plus tests                         | Keep before reserved-handle check                 |    P1    |
| `reserved-handle-check`          | [#228](https://github.com/hypercerts-org/ePDS/pull/228) | 1 unique (3 stacked) | High — prevents false “Available” results                     | Medium — depends on a version-pinned upstream deep import   | Keep, stacked after handle-unavailable copy       |    P1    |
| `safe-client-name-fallback`      | [#229](https://github.com/hypercerts-org/ePDS/pull/229) |                    1 | High — avoids presenting attacker-controlled IDs as app names | Low — fallback logic plus tests                             | Keep                                              |    P0    |
| `account-settings-flash`         | [#230](https://github.com/hypercerts-org/ePDS/pull/230) |                    4 | High — gives truthful results for account actions             | Medium — multiple route actions and message states          | Keep                                              |    P0    |

The report itself is committed on `split-pr165/assessment-report`.

## Detailed branch assessments

### `split-pr165/clear-email-on-back`

**Scope:** Clears the previous address and focuses the email field when the user chooses **Use different email**. Includes Cucumber coverage and a focused unit assertion.

**Assessment:** Keep. The control promises a fresh account choice; retaining the old address undermines that intent. The change is small, local, and independent of PR #204.

**Validation:** All checks and the full unit suite pass.

### `split-pr165/ignore-incomplete-otp-submit`

**Scope:** Stops empty or partial Verify submissions before they call better-auth, focuses the first unfilled slot, and adds E2E plus unit coverage.

**Assessment:** Keep with high priority. It prevents a misleading “Invalid OTP” response and avoids spending a verification attempt when no complete code was submitted. The current segmented fields are not individually `required`, so the JavaScript guard is meaningful.

**Validation:** All checks and the full unit suite pass.

### `split-pr165/otp-lockout-recovery`

**Scope:** Treats the exact better-auth “Too many attempts” response as a dead code, offers **Send a new code**, remembers lockout in the interactive login page until Resend succeeds, and shares honest server-rendered error guidance between Account Settings login and account recovery.

**Corrections made during reconstruction:**

- Narrowed matching from any message containing `attempt` to the full `Too many attempts` phrase.
- Corrected documentation that had claimed stateless server routes could distinguish a post-lockout `Invalid OTP`; only the interactive page can do that because it keeps an in-page latch.
- Preserved the current-main PAR-liveness gates so Resend is offered only while the authorization flow can still complete.

**Assessment:** Keep, but it is the largest reconstructed branch and remains coupled to better-auth’s English error strings because no stable structured code is exposed at these call sites. Review that coupling carefully. If PR #204 lands first, port the interactive login portion onto its single-input controller; the Account Settings and recovery portions are independent.

**Validation:** All checks and the full unit suite pass.

### `split-pr165/recovery-link-request-uri`

**Scope:** Replaces the hard-coded recovery `/placeholder` value with the active PAR `request_uri`, threads it through render and preview call sites, and tests the round trip.

**Assessment:** Keep with high priority. The placeholder is a concrete functional bug: recovery may succeed, but **Back to sign in** cannot return to the originating authorization request.

**Validation:** All checks and the full unit suite pass.

### `split-pr165/friendly-stale-link-errors`

**Scope:** Replaces raw “Missing request_uri parameter” pages on direct/stale authorize and recovery visits with actionable explanations. E2E assertions inspect visible text only, avoiding the original review finding where hidden fields or scripts could cause false positives.

**Assessment:** Keep. It is user-facing error hygiene with no protocol behavior change. Lower priority than the functional fixes.

**Validation:** All checks and the full unit suite pass.

### `split-pr165/clear-code-on-resend`

**Scope:** Clears stale OTP slots and focuses the first slot after a successful resend, with unit coverage.

**Assessment:** Keep. A newly-issued code should not inherit the previous code’s UI state. It is low risk and not blocked by PR #204; whichever lands second should use PR #204’s `clearOtpBoxes()` helper.

**Validation:** All checks and the full unit suite pass.

### `split-pr165/spam-folder-hint`

**Scope:** Adds a small “check your spam folder” hint below the email-code form.

**Assessment:** Optional but reasonable. It can reduce support friction, though it is copy/UI polish rather than correctness and could be combined with a broader content review.

**Validation:** All checks and the full unit suite pass.

### `split-pr165/email-autocomplete`

**Scope:** Adds explicit email autocomplete tokens to all email entry forms. The reconstruction also changes the shared email/handle field to `username` autocomplete in handle mode and back to `email` when toggled, with unit coverage.

**Assessment:** Keep. The original commit’s static email token would have remained active after switching the shared field to handle mode; the follow-up fixes that oversight.

**Validation:** All checks and the full unit suite pass.

### `split-pr165/server-otp-charset-filter`

**Scope:** Filters and uppercases the full-length OTP inputs used by Account Settings login and account recovery. It deliberately excludes the segmented login control because PR #204 replaces that control with a more accessible single-input architecture.

**Assessment:** Keep as a separate follow-up, but manually test numeric and alphanumeric configurations before publishing. The implementation is small, yet it relies on inline input handlers and has less direct test coverage than the stronger branches.

**Validation:** Formatting, lint, typecheck, and the full unit suite pass.

### `split-pr165/accessible-error-announcements`

**Scope:** Adds appropriate live-region/alert semantics to interactive auth errors, server-rendered auth errors, demo errors, and the shared error renderer.

**Assessment:** Keep with high confidence. The changes are standards-based, minimal, and spread only because the repository has several independent renderers.

**Validation:** All checks and the full unit suite pass.

### `split-pr165/keyboard-focus-rings`

**Scope:** Adds visible `:focus-visible` outlines to primary and secondary controls across login, recovery, and handle selection.

**Assessment:** Keep with high confidence. This restores essential keyboard affordance without changing pointer styling or behavior.

**Validation:** All checks and the full unit suite pass.

### `split-pr165/friendly-demo-errors`

**Scope:** Rewrites known demo-client error banners in plain language and removes instructions such as “check server logs” from end-user UI.

**Assessment:** Optional but worthwhile. This branch intentionally excludes commits 6 and 16: improving known error copy is safe, whereas guessing timeout causes from OAuth text is not.

**Validation:** All checks and the full unit suite pass.

### `split-pr165/handle-unavailable-copy`

**Scope:** Uses “not available” consistently for submit-time errors and the live handle check rather than claiming every rejection means another user already took the handle. Adds focused render coverage.

**Assessment:** Keep. Reserved names and policy rejections are not ownership collisions. This branch is also the base for the reserved-handle check.

**Validation:** All checks and the full unit suite pass.

### `split-pr165/reserved-handle-check`

**Scope:** Extends the live availability result to include names rejected by upstream’s reserved-handle policy. It is stacked on `split-pr165/handle-unavailable-copy`.

**Corrections made during reconstruction:**

- Did not copy or directly query upstream’s internal reserved-name object.
- Calls upstream `baseNormalizeAndValidate()` and `ensureHandleServiceConstraints()` instead.
- Distinguishes `HandleNotAvailable` from unrelated validation failures and rethrows the latter.
- Avoids the original `in`-operator bug that treated inherited object properties as reserved.

**Assessment:** Keep. It fixes a real “Available” then rejected workflow. Risk is moderate because `@atproto/pds` does not export the helper from its package root, so the branch uses the version-pinned `dist/handle/index.js` path. That is still preferable to duplicating security/policy logic, but an upstream public export would be better.

**Validation:** All checks and the full unit suite pass, including focused reserved-handle tests.

### `split-pr165/safe-client-name-fallback`

**Scope:** Prevents malformed or non-HTTP client IDs from becoming visible application names; callers fall back to neutral copy instead. Includes shared-library tests.

**Assessment:** Keep. Existing escaping prevented markup injection, but reflecting an attacker-controlled malformed identifier as the application’s identity is still poor trust UX.

**Validation:** All checks and the full unit suite pass.

### `split-pr165/account-settings-flash`

**Scope:** Resolves whitelisted success/error query codes into accessible Account Settings banners and acknowledges backup-email, handle, and session actions.

**Corrections made during reconstruction:**

- A backup-email removal now reports success only when the account and email exist and the DB operation completes.
- Session revocation no longer reports success after an exception or missing token.
- Added dedicated `backup_remove_failed` and `revoke_failed` messages.
- Preserved whitelist-based rendering so arbitrary query text is never displayed.

**Assessment:** Keep with high priority after these review fixes. Silent redirects made settings actions appear broken; truthful feedback is a material usability improvement.

**Validation:** All checks and the full unit suite pass, including flash-resolution tests.

## Complete source-commit disposition

| #   | Source commit                                      | Disposition                                                                            |
| --- | -------------------------------------------------- | -------------------------------------------------------------------------------------- |
| 1   | `ccf4ece` hide Resend when sign-in cannot recover  | Already landed, refined in PR #187                                                     |
| 2   | `a5cb519` demo cookie/error handling               | Already landed, substantially reworked in PR #187                                      |
| 3   | `988be35` clear/focus different email              | `split-pr165/clear-email-on-back`                                                      |
| 4   | `073da54` ignore empty Verify                      | `split-pr165/ignore-incomplete-otp-submit`                                             |
| 5   | `4e23ee1` lockout inline resend                    | `split-pr165/otp-lockout-recovery`                                                     |
| 6   | `f6a243c` classify PDS timeout text                | Drop; ambiguous string inference and unsafe original logging                           |
| 7   | `4a899b6` stale recovery wording                   | `split-pr165/friendly-stale-link-errors`                                               |
| 8   | `f01f703` post-lockout latch                       | `split-pr165/otp-lockout-recovery`                                                     |
| 9   | `7a177e5` stale authorize wording                  | `split-pr165/friendly-stale-link-errors`                                               |
| 10  | `7dbd5d7` real recovery request URI                | `split-pr165/recovery-link-request-uri`                                                |
| 11  | `11ea1cc` login UX guard tests                     | Distributed to the clear-email, incomplete-submit, lockout, and recovery-link branches |
| 12  | `5eddf75` segmented paste filtering                | Superseded by PR #204                                                                  |
| 13  | `a3f594a` segmented keystroke filtering            | Superseded by PR #204                                                                  |
| 14  | `4aab907` Account Settings lockout copy            | `split-pr165/otp-lockout-recovery`                                                     |
| 15  | `3b82b31` Account Settings error tests             | `split-pr165/otp-lockout-recovery`                                                     |
| 16  | `010f0c0` classify token `invalid_grant` as expiry | Drop; `invalid_grant` has causes other than timeout                                    |
| 17  | `f900a9a` shared server OTP error picker           | `split-pr165/otp-lockout-recovery`                                                     |
| 18  | `e0c367b` clear code after resend                  | `split-pr165/clear-code-on-resend`                                                     |
| 19  | `74459b8` spam-folder hint                         | `split-pr165/spam-folder-hint`                                                         |
| 20  | `452eec3` deduplicate error-picker tests           | `split-pr165/otp-lockout-recovery`                                                     |
| 21  | `453d9a5` email autocomplete                       | `split-pr165/email-autocomplete`, corrected for handle mode                            |
| 22  | `35e76d2` announce auth errors                     | `split-pr165/accessible-error-announcements`                                           |
| 23  | `c1cd111` friendly demo errors                     | `split-pr165/friendly-demo-errors`                                                     |
| 24  | `619eedf` server-rendered charset filtering        | `split-pr165/server-otp-charset-filter`                                                |
| 25  | `d3e75a2` handle unavailable wording               | `split-pr165/handle-unavailable-copy`, broadened to all picker surfaces                |
| 26  | `97e5acb` demo-cookie E2E de-flake                 | Superseded by PR #187’s rewritten coverage                                             |
| 27  | `fe13498` segmented autofill distribution          | Superseded by PR #204                                                                  |
| 28  | `83de694` reserved handle live check               | `split-pr165/reserved-handle-check`, reimplemented                                     |
| 29  | `50077c0` login focus rings                        | `split-pr165/keyboard-focus-rings`                                                     |
| 30  | `645a2fb` remaining auth focus rings               | `split-pr165/keyboard-focus-rings`                                                     |
| 31  | `1493801` focus-ring changeset                     | `split-pr165/keyboard-focus-rings`                                                     |
| 32  | `116f833` demo alert semantics                     | `split-pr165/accessible-error-announcements`                                           |
| 33  | `fea121e` reserved-handle helper refactor          | `split-pr165/reserved-handle-check`, reimplemented                                     |
| 34  | `5fc9837` shared error alert semantics             | `split-pr165/accessible-error-announcements`                                           |
| 35  | `3ed32b9` safe malformed-client fallback           | `split-pr165/safe-client-name-fallback`                                                |
| 36  | `40ad0e0` Account Settings banners                 | `split-pr165/account-settings-flash`, corrected                                        |
| 37  | `473f6a0` flash resolver refactor                  | `split-pr165/account-settings-flash`                                                   |

## Why the dropped changes should stay dropped

### OAuth error-text timeout classification (`f6a243c`)

The commit parsed `error_description` with broad text such as `session` and treated matching `access_denied` errors as expiry. Review correctly noted that unrelated session errors would be misclassified, and the original code also logged query-controlled text unsafely. PR #187 now handles the concrete missing-state-cookie case from local state, which is a stronger signal. Keep the friendly known error copy, but do not revive this heuristic.

### Token `invalid_grant` means expiry (`010f0c0`)

`invalid_grant` can mean expired, invalid, reused, mismatched, or otherwise unacceptable authorization material. Presenting every instance as “your session expired” is not reliably honest. A future change should classify from a structured local condition or a narrower upstream contract, not the token error body.

### Segmented input filtering and autofill (`5eddf75`, `a3f594a`, `fe13498`)

These ideas are valid, but active PR #204 addresses them with a better architecture: one real full-length input behind visual slots, improved selection behavior, mobile paste/autofill support, and substantially broader tests. Maintaining a second implementation on the old per-character DOM would create conflict and regression risk.

## Validation record

For every code branch:

- `git diff --check origin/main...HEAD`
- Prettier check on changed supported files
- ESLint on changed JavaScript/TypeScript files
- `packages/shared/node_modules/.bin/tsc --build tsconfig.json --pretty false --force`
- Full `vitest run`
- Clean worktree check

All final branch results are green. Raw logs were retained during the exercise under `/tmp/pr165-validation/` and `/tmp/pr165-validation-fixes/`; those paths are ephemeral and are not part of the report branch.

## Local-only guarantee

No `git push`, `gh pr create`, merge, release, deployment, or remote Beads/Dolt synchronization was performed. The branches and this report exist only in the local repository/worktree.

The completed Beads state was exported and committed separately on local branch `split-pr165/beads-tracking`, keeping the code and assessment branches free of task-database churn.
