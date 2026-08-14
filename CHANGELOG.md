# ePDS

## 0.8.0

### Who should read this release

- **End users:**
  - [Signing in and managing your account now run on the latest AT Protocol server, which requires operators to upgrade to Node.js 22.19 or newer.](#v0.8.0-signing-in-and-managing-your-account-now-run-on-the-latest)
  - [Catch likely email-domain typos before sending a sign-in code.](#v0.8.0-catch-likely-email-domain-typos-before-sending-a-sign-in)
  - [Sign-in, recovery and handle-choice feedback is now announced automatically by screen readers.](#v0.8.0-sign-in-recovery-and-handle-choice-feedback-is-now)
  - [Sign-in code boxes now ignore stray characters pasted or typed alongside your code.](#v0.8.0-sign-in-code-boxes-now-ignore-stray-characters-pasted-or)
  - [Asking for a new sign-in code now clears the boxes and tells you the old code has stopped working.](#v0.8.0-asking-for-a-new-sign-in-code-now-clears-the-boxes-and)
  - [Sign-in and recovery email fields now work more reliably with browser autofill and password managers.](#v0.8.0-sign-in-and-recovery-email-fields-now-work-more-reliably)
  - [Sign-in pages no longer leak a malformed client_id as the displayed app name.](#v0.8.0-sign-in-pages-no-longer-leak-a-malformed-client-id-as-the)
  - [Handle-picker error wording is now accurate when the handle is reserved.](#v0.8.0-handle-picker-error-wording-is-now-accurate-when-the-handle)
  - [Sign-in errors are written in plain English instead of showing the raw failure code.](#v0.8.0-sign-in-errors-are-written-in-plain-english-instead-of)
  - [Sign-in buttons now show a visible keyboard focus ring.](#v0.8.0-sign-in-buttons-now-show-a-visible-keyboard-focus-ring)
  - [Small grey text on the sign-in page is darker and easier to read.](#v0.8.0-small-grey-text-on-the-sign-in-page-is-darker-and-easier-to)
  - [Apps you sign in to are now told that your email address is confirmed.](#v0.8.0-apps-you-sign-in-to-are-now-told-that-your-email-address-is)
  - [The sign-in button that emails you another code now says "Send a new code" instead of "Resend code".](#v0.8.0-the-sign-in-button-that-emails-you-another-code-now-says)
  - [The email sign-in button now waits until the page is ready before accepting clicks.](#v0.8.0-the-email-sign-in-button-now-waits-until-the-page-is-ready)
  - [Sign-in error messages now appear next to the field that caused them, instead of at the top of the page.](#v0.8.0-sign-in-error-messages-now-appear-next-to-the-field-that)
  - [Clickable text on the sign-in screens now looks the same wherever it appears.](#v0.8.0-clickable-text-on-the-sign-in-screens-now-looks-the-same)
  - ["Use different email" on the sign-in code page now clears the email field.](#v0.8.0-use-different-email-on-the-sign-in-code-page-now-clears-the)
- **Client app developers:**
  - [The approval and account-chooser screens now honour the handle mode your app asked for, instead of falling back to the server default.](#v0.8.0-the-approval-and-account-chooser-screens-now-honour-the)
  - [Small grey text on the sign-in page is darker and easier to read.](#v0.8.0-small-grey-text-on-the-sign-in-page-is-darker-and-easier-to)
  - [Apps you sign in to are now told that your email address is confirmed.](#v0.8.0-apps-you-sign-in-to-are-now-told-that-your-email-address-is)
  - [Clickable text on the sign-in screens now looks the same wherever it appears.](#v0.8.0-clickable-text-on-the-sign-in-screens-now-looks-the-same)
- **Operators:**
  - [Signing in and managing your account now run on the latest AT Protocol server, which requires operators to upgrade to Node.js 22.19 or newer.](#v0.8.0-signing-in-and-managing-your-account-now-run-on-the-latest)
  - [Apps you sign in to are now told that your email address is confirmed.](#v0.8.0-apps-you-sign-in-to-are-now-told-that-your-email-address-is)
  - [Both services now refuse to start unless their secret environment variables are set, instead of silently falling back to well-known development defaults.](#v0.8.0-both-services-now-refuse-to-start-unless-their-secret)
  - [Resend webhook logs now identify the email event type and provider in their message text.](#v0.8.0-resend-webhook-logs-now-identify-the-email-event-type-and)

### Minor Changes

- <a id="v0.8.0-signing-in-and-managing-your-account-now-run-on-the-latest"></a> [#233](https://github.com/hypercerts-org/ePDS/pull/233) [`ebd214e`](https://github.com/hypercerts-org/ePDS/commit/ebd214effb0072b5280f2902083f8d0ab1366e4d) Thanks [@aspiers](https://github.com/aspiers)! - Signing in and managing your account now run on the latest AT Protocol server, which requires operators to upgrade to Node.js 22.19 or newer.

  **Affects:** End users, Operators

  **End users:** the account and sign-in screens now come from a newer version of the underlying AT Protocol software, which adds changing your handle and deactivating or deleting your account through the account-management interface. The passwordless email-code sign-in and email verification you already use through ePDS are unchanged.

  **Operators:**
  - ePDS now requires **Node.js 22.19.0 or newer** (previously 20). Deployments pinned to Node 20 must upgrade; the Docker images already use `node:22-alpine`. `engines.node` is now `>=22.19.0` (the floor is set by a transitive `undici@8` runtime dependency, which fails on Node 22.0–22.18).
  - The bundled AT Protocol packages moved to their latest releases: `@atproto/pds` 0.5.23, `@atproto/oauth-provider` 0.21.1, `@atproto/oauth-provider-ui` 0.8.9.
  - No configuration changes are required, but the native `better-sqlite3` module must be built for the Node 22 ABI — a clean `pnpm install` on Node 22 handles this; an in-place Node version switch needs `pnpm rebuild better-sqlite3`.

- <a id="v0.8.0-catch-likely-email-domain-typos-before-sending-a-sign-in"></a> [#231](https://github.com/hypercerts-org/ePDS/pull/231) [`fe3b15c`](https://github.com/hypercerts-org/ePDS/commit/fe3b15c17b85319e7d7c73b036bafe90ade8c06b) Thanks [@aspiers](https://github.com/aspiers)! - Catch likely email-domain typos before sending a sign-in code.

  **Affects:** End users

  **End users:** addresses one edit away from Gmail, Hotmail, Outlook, Yahoo, or iCloud now show a “Did you mean…?” prompt as soon as they are typed. Accepting replaces the address in the email field; dismissing keeps the original. The prompt never changes or blocks an address silently.

### Patch Changes

- <a id="v0.8.0-sign-in-recovery-and-handle-choice-feedback-is-now"></a> [#224](https://github.com/hypercerts-org/ePDS/pull/224) [`610b5e6`](https://github.com/hypercerts-org/ePDS/commit/610b5e6318e363f9987adaf7846393e66cd988a0) Thanks [@aspiers](https://github.com/aspiers)! - Sign-in, recovery and handle-choice feedback is now announced automatically by screen readers.

  **Affects:** End users

  **End users:** authentication errors now use standard alert and live-region semantics across sign-in, recovery, handle selection, and the demo client, so screen-reader users hear failures without having to search the page for changed text. Repeated failures — such as entering a second incorrect one-time code — announce each time rather than falling silent, and handle availability ("Available!" / "Already taken.") is now announced as you type.

- <a id="v0.8.0-sign-in-code-boxes-now-ignore-stray-characters-pasted-or"></a> [#223](https://github.com/hypercerts-org/ePDS/pull/223) [`0637fa7`](https://github.com/hypercerts-org/ePDS/commit/0637fa77e71fc425647a67ced188372311500ef3) Thanks [@aspiers](https://github.com/aspiers)! - Sign-in code boxes now ignore stray characters pasted or typed alongside your code.

  **Affects:** End users

  **End users:** every screen that asks for a sign-in code — the main sign-in screen, Account Settings sign-in, and account recovery — now drops characters your code can't contain, so a code pasted with surrounding quotes, brackets, or a trailing full stop is accepted instead of rejected. The main sign-in screen previously ignored only spaces and line breaks. Where the operator has turned on codes that mix letters and numbers, typing them in lowercase now works too.

- <a id="v0.8.0-asking-for-a-new-sign-in-code-now-clears-the-boxes-and"></a> [#220](https://github.com/hypercerts-org/ePDS/pull/220) [`68b2104`](https://github.com/hypercerts-org/ePDS/commit/68b21040c6e823b038c2e30410288a225c680f6c) Thanks [@aspiers](https://github.com/aspiers)! - Asking for a new sign-in code now clears the boxes and tells you the old code has stopped working.

  **Affects:** End users

  **End users:** the boxes reset on **Send a new code**, so a half-typed old code no longer has to be deleted by hand before you can type the new one. The confirmation also warns that only the newest code will be accepted, and points at the spam folder — the two things most likely to be going wrong for anyone who got that far.

- <a id="v0.8.0-sign-in-and-recovery-email-fields-now-work-more-reliably"></a> [#222](https://github.com/hypercerts-org/ePDS/pull/222) [`9e12e30`](https://github.com/hypercerts-org/ePDS/commit/9e12e30edf8a9259fec8d261f8587d90d24a2e37) Thanks [@aspiers](https://github.com/aspiers)! - Sign-in and recovery email fields now work more reliably with browser autofill and password managers.

  **Affects:** End users

  **End users:** email fields now identify themselves to browsers as email addresses, while the same sign-in field identifies itself as a username after switching to handle entry. This helps browsers and password managers offer the right saved value in each mode.

- <a id="v0.8.0-sign-in-pages-no-longer-leak-a-malformed-client-id-as-the"></a> [#229](https://github.com/hypercerts-org/ePDS/pull/229) [`6f4fa2d`](https://github.com/hypercerts-org/ePDS/commit/6f4fa2dd43b32720154d0b8cc80e272f32568b7b) Thanks [@aspiers](https://github.com/aspiers)! - Sign-in pages no longer leak a malformed client_id as the displayed app name.

  **Affects:** End users

  **End users:** if you arrived at a sign-in page with a broken `client_id` parameter on the URL (e.g. from a misconfigured app or a tampered link), the page would display that raw broken value as the app's name, e.g. "Sign in to not-a-url" or "Sign in to my-local-app". The page now falls back to "an application" in that case, so a malformed value in the URL doesn't leak into the visible page text or browser tab title.

- <a id="v0.8.0-the-approval-and-account-chooser-screens-now-honour-the"></a> [#243](https://github.com/hypercerts-org/ePDS/pull/243) [`534647d`](https://github.com/hypercerts-org/ePDS/commit/534647da664abe07cf543759f94b8286dc7b81a6) Thanks [@aspiers](https://github.com/aspiers)! - The approval and account-chooser screens now honour the handle mode your app asked for, instead of falling back to the server default.

  **Affects:** Client app developers

  **Client app developers:** no action needed — `epds_handle_mode` is resolved exactly as before (the `/oauth/authorize` query parameter, then your OAuth client metadata, then the server default). Previously the resolved mode was lost on the way to the approval step, so a flow that asked for a chosen handle could still show a generated one there. The mode is now carried through `/oauth/epds-callback` and applied on the approval and chooser screens. Values that are not one of the recognised modes are ignored rather than forwarded.

- <a id="v0.8.0-handle-picker-error-wording-is-now-accurate-when-the-handle"></a> [#227](https://github.com/hypercerts-org/ePDS/pull/227) [`68b0760`](https://github.com/hypercerts-org/ePDS/commit/68b0760afa923ca2a3f3b4997137eca1a5ca0b77) Thanks [@aspiers](https://github.com/aspiers)! - Handle-picker error wording is now accurate when the handle is reserved.

  **Affects:** End users

  **End users:** if you tried to claim a handle that was on the reserved list (admin, www, …) the picker said "That handle was just taken — please choose another." That's misleading — it wasn't just taken, it's permanently unavailable. The wording is now "That handle is not available — please choose another." which doesn't imply you can wait it out.

- <a id="v0.8.0-sign-in-errors-are-written-in-plain-english-instead-of"></a> [#237](https://github.com/hypercerts-org/ePDS/pull/237) [`ddde1b2`](https://github.com/hypercerts-org/ePDS/commit/ddde1b22f89b45dfd90a38a6f34915dce9b013d3) Thanks [@aspiers](https://github.com/aspiers)! - Sign-in errors are written in plain English instead of showing the raw failure code.

  **Affects:** End users

  **End users:** a rejected code used to report "Invalid OTP", an unexplained acronym that ran straight into the recovery link beside it — "Invalid OTP Send a new code". It now reads "That code didn't work." followed by the link, and the two other common failures are similarly rewritten: an aged-out code says "That code has expired.", and one rejected after repeated wrong attempts says "Too many tries — that code is no longer usable.". Any failure outside those three is still shown as-is rather than hidden behind a generic apology, so an unexpected problem can still be reported accurately.

- <a id="v0.8.0-sign-in-buttons-now-show-a-visible-keyboard-focus-ring"></a> [#225](https://github.com/hypercerts-org/ePDS/pull/225) [`23dcd0f`](https://github.com/hypercerts-org/ePDS/commit/23dcd0f0b88ca5e87b4b465523be19d14864ea04) Thanks [@aspiers](https://github.com/aspiers)! - Sign-in buttons now show a visible keyboard focus ring.

  **Affects:** End users

  **End users:** keyboard users tabbing through the sign-in pages couldn't tell where focus was — the buttons styled out the browser default focus ring without replacing it. Verify, Resend, Use different email, Recover, Send recovery code, Continue with email, Update handle, etc. all now show a clear outline when focused via the keyboard, while still hiding the ring on a mouse click.

- <a id="v0.8.0-small-grey-text-on-the-sign-in-page-is-darker-and-easier-to"></a> [#232](https://github.com/hypercerts-org/ePDS/pull/232) [`87ef832`](https://github.com/hypercerts-org/ePDS/commit/87ef8320a169e970474747ca0e9d65b26a3984da) Thanks [@aspiers](https://github.com/aspiers)! - Small grey text on the sign-in page is darker and easier to read.

  **Affects:** End users, Client app developers

  **End users:** the 13px grey text — the terms line, the "Recover with backup email" link, the "or continue with" / "or use email" separators, and the "powered by Certified" footer — was too light to meet the WCAG AA contrast minimum against either the card or the page background behind it. It is now dark enough to pass on both.

  **Client app developers:** the `--muted-foreground` custom property on the sign-in page changes from `[#999](https://github.com/hypercerts-org/ePDS/issues/999)` to `[#666](https://github.com/hypercerts-org/ePDS/issues/666)`. If your `branding.css` sets it, check your value clears 4.5:1 against both `#F8F8F8` (the card) and `#E8E8E8` (the page) — the old default reached only 2.68:1 and 2.33:1 respectively, so a value chosen to sit alongside it may be equally low. The separator text between the social and email sign-in options now follows `--muted-foreground` too, where it previously ignored your override and stayed grey.

- <a id="v0.8.0-apps-you-sign-in-to-are-now-told-that-your-email-address-is"></a> [#234](https://github.com/hypercerts-org/ePDS/pull/234) [`3924855`](https://github.com/hypercerts-org/ePDS/commit/39248551ccaa1097cdfd569bbe4d6617ad0fed7f) Thanks [@aspiers](https://github.com/aspiers)! - Apps you sign in to are now told that your email address is confirmed.

  **Affects:** End users, Client app developers, Operators

  **End users:** Apps no longer ask you to verify an address you have already confirmed with an emailed code.

  **Client app developers:** The `email_verified` claim is now `true` for accounts that signed in through the emailed-code flow, instead of always `false`.

  **Operators:** Deploy the auth service and the PDS together — the signed handover between them carries a new required field, and a mixed pair rejects sign-in until both are updated. An older auth service is rejected with an explicit `Missing or invalid email_verified parameter` rather than a generic signature error, so a mixed-version rollout is recognisable in the logs. Accounts predating this release are repaired the next time their owner signs in **through the emailed-code flow**; a sign-in that does not prove control of the address leaves them unconfirmed. To fix the rest, see "Backfilling Email Confirmation" in `docs/deployment.md`.

- <a id="v0.8.0-both-services-now-refuse-to-start-unless-their-secret"></a> [#41](https://github.com/hypercerts-org/ePDS/pull/41) [`d4256ea`](https://github.com/hypercerts-org/ePDS/commit/d4256ea03a0982386662c3a9adb1ff7d9f347a38) Thanks [@aspiers](https://github.com/aspiers)! - Both services now refuse to start unless their secret environment variables are set, instead of silently falling back to well-known development defaults.

  **Affects:** Operators

  **Operators:** `AUTH_SESSION_SECRET` and `EPDS_CALLBACK_SECRET` are now mandatory. Previously, a deployment that omitted them would boot successfully using hardcoded placeholders such as `dev-session-secret-change-me`, leaving session cookies and the signed `/oauth/epds-callback` redirect verifiable by anyone who has read the source. The auth service and PDS Core now throw at startup with a message naming the missing variable and the `openssl rand -hex 32` command to generate one. Check that both variables are set in your deployment before upgrading, and note that `EPDS_CALLBACK_SECRET` must be identical across the two services.

  `AUTH_CSRF_SECRET` has been removed entirely. CSRF protection derives its tokens from `crypto.randomBytes` and never consumed the value, so the variable was inert; it is no longer read, no longer generated by `scripts/setup.sh`, and can be deleted from your environment.

- <a id="v0.8.0-resend-webhook-logs-now-identify-the-email-event-type-and"></a> [#209](https://github.com/hypercerts-org/ePDS/pull/209) [`0af6d7f`](https://github.com/hypercerts-org/ePDS/commit/0af6d7f690f848517269e181d18a9a6229828e79) Thanks [@aspiers](https://github.com/aspiers)! - Resend webhook logs now identify the email event type and provider in their message text.

  **Affects:** Operators

  **Operators:** Log messages use text such as `Received email event 'delivered' from Resend`, making events legible in log viewers that de-emphasize structured fields.

- <a id="v0.8.0-the-sign-in-button-that-emails-you-another-code-now-says"></a> [#236](https://github.com/hypercerts-org/ePDS/pull/236) [`e238c38`](https://github.com/hypercerts-org/ePDS/commit/e238c3830566b5e2960d4bd5bf40e474ac6db0e4) Thanks [@aspiers](https://github.com/aspiers)! - The sign-in button that emails you another code now says "Send a new code" instead of "Resend code".

  **Affects:** End users

  **End users:** each request emails a genuinely new code and stops the previous one working, so "Resend" was misleading — it suggested the code already in your inbox was still the one to type. The confirmation after clicking now starts "Sent!" rather than "Resent!", and still tells you that earlier codes no longer work. The same wording appears on the recovery and account sign-in pages, and on the link offered beside a rejected or expired code.

- <a id="v0.8.0-the-email-sign-in-button-now-waits-until-the-page-is-ready"></a> [#242](https://github.com/hypercerts-org/ePDS/pull/242) [`a0a819a`](https://github.com/hypercerts-org/ePDS/commit/a0a819af2d39288351ea17f4f4f9de62af026be8) Thanks [@aspiers](https://github.com/aspiers)! - The email sign-in button now waits until the page is ready before accepting clicks.

  **Affects:** End users

  **End users:** tapping Continue before the sign-in page finished loading could start a broken sign-in attempt that silently did nothing. The button is now disabled until the page is ready. Browsers with JavaScript disabled see a message explaining that JavaScript is required to sign in with email, instead of a button that never responds.

- <a id="v0.8.0-sign-in-error-messages-now-appear-next-to-the-field-that"></a> [#220](https://github.com/hypercerts-org/ePDS/pull/220) [`50c8620`](https://github.com/hypercerts-org/ePDS/commit/50c8620896d8c797ab629467e09701d983426468) Thanks [@aspiers](https://github.com/aspiers)! - Sign-in error messages now appear next to the field that caused them, instead of at the top of the page.

  **Affects:** End users

  **End users:** a rejected sign-in code used to report the problem above the page heading, several elements away from the boxes you had just typed into — easy to miss, and it left the **Verify** button looking like the thing to press again. The message now sits directly between the code boxes and **Verify**, and a failed email submission likewise reads under the email field rather than above it.

  A rejected code now also carries a **Send a new code** link beside the message. The standalone button below the form was easy to overlook, and "that code didn't work" often means there is no usable code left at all rather than that you mistyped it — after too many wrong attempts, after signing in from another tab, or once an old code has aged out. Retyping cannot recover any of those. The boxes still clear and refocus, so retyping remains one keystroke away when that is what you need.

- <a id="v0.8.0-clickable-text-on-the-sign-in-screens-now-looks-the-same"></a> [#237](https://github.com/hypercerts-org/ePDS/pull/237) [`43baeb5`](https://github.com/hypercerts-org/ePDS/commit/43baeb54c60402ab97050b5e4af5b143b8901640) Thanks [@aspiers](https://github.com/aspiers)! - Clickable text on the sign-in screens now looks the same wherever it appears.

  **Affects:** End users, Client app developers

  **End users:** the same action no longer renders differently depending on where it sits. "Resend code", "Use different email" and "Recover with backup email" are now all plain text that darkens when you point at it, while actions embedded in a sentence — "Send a new code" in an error message, and the Terms of Use and Privacy Policy links — stay underlined so they remain visible against the text around them. Pointing at an underlined action no longer makes its underline vanish, and every one of these actions now shows a focus outline when reached with the keyboard.

  **Client app developers:** `--muted-foreground` now also sets the colour of the `.btn-secondary` actions on the sign-in page, which previously hardcoded `#6b6b6b`. If you override that custom property in your `branding.css`, it will now recolour "Resend code" and "Use different email" alongside "Recover with backup email" and the other muted text. Choose a value that clears 4.5:1 contrast against your card background. `--recovery-link-display` is unchanged.

- <a id="v0.8.0-use-different-email-on-the-sign-in-code-page-now-clears-the"></a> [#215](https://github.com/hypercerts-org/ePDS/pull/215) [`1a90062`](https://github.com/hypercerts-org/ePDS/commit/1a900621936941066372228b423d26a6808cb21b) Thanks [@aspiers](https://github.com/aspiers)! - "Use different email" on the sign-in code page now clears the email field.

  **Affects:** End users

  **End users:** clicking **Use different email** on the code-entry page used to take you back to the email form with your previous address still filled in — exactly the opposite of what the button suggests, and forcing you to clear the field manually before you could type a new address. The form now starts empty, with the cursor in the field, so you can just type the new address and continue.

## 0.7.0

### Who should read this release

- **Operators:**
  - [Email delivery logs use a consistent recipient field.](#v0.7.0-email-delivery-logs-use-a-consistent-recipient-field)
  - [OTP send logs now record how long the email handoff took, the provider's message ID, and the SMTP server response.](#v0.7.0-otp-send-logs-now-record-how-long-the-email-handoff-took)
  - [Optional email-event logging for operators who choose the third-party Resend service to send email; ePDS continues to support other email providers.](#v0.7.0-optional-email-event-logging-for-operators-who-choose-the)

### Minor Changes

- <a id="v0.7.0-email-delivery-logs-use-a-consistent-recipient-field"></a> [#197](https://github.com/hypercerts-org/ePDS/pull/197) [`ce25beb`](https://github.com/hypercerts-org/ePDS/commit/ce25beba5e231e8300a875f1fc1d2ad37ae75527) Thanks [@aspiers](https://github.com/aspiers)! - Email delivery logs use a consistent recipient field.

  **Affects:** Operators

  **Operators:** All four email delivery paths now log the recipient as `email`: client-branded OTP, standard sign-in OTP, welcome OTP, and backup-email verification. Update structured-log queries for `Sent client-branded OTP email` to read `email` instead of `to`.

- <a id="v0.7.0-otp-send-logs-now-record-how-long-the-email-handoff-took"></a> [#203](https://github.com/hypercerts-org/ePDS/pull/203) [`2193515`](https://github.com/hypercerts-org/ePDS/commit/2193515970c56035fd026c3df2b3f44e403eb801) Thanks [@aspiers](https://github.com/aspiers)! - OTP send logs now record how long the email handoff took, the provider's message ID, and the SMTP server response.

  **Affects:** Operators

  **Operators:** every OTP email completion line (all four paths — client-branded, sign-in, welcome, backup-email verification) now carries `elapsedMs`, `messageId`, and `smtpResponse` alongside `email`. `messageId` lets these logs be joined to Resend delivery events; `elapsedMs` isolates a slow SMTP handoff from other causes of late-arriving codes. Failed sends log `elapsedMs` too, on the existing `better-auth: failed to send OTP email` error line.

- <a id="v0.7.0-optional-email-event-logging-for-operators-who-choose-the"></a> [#198](https://github.com/hypercerts-org/ePDS/pull/198) [`2bf9af4`](https://github.com/hypercerts-org/ePDS/commit/2bf9af420281c769ec88f19c9badd89f00acc03c) Thanks [@aspiers](https://github.com/aspiers)! - Optional email-event logging for operators who choose the third-party Resend service to send email; ePDS continues to support other email providers.

  **Affects:** Operators

  **Operators:** ePDS remains compatible with any SMTP provider and does not require Resend. Operators who already use Resend can opt in by registering `https://<AUTH_HOSTNAME>/webhooks/resend` for the documented email events and setting `RESEND_WEBHOOK_SECRET`; logs include delivery, open, complaint, suppression, and scheduling events. The route verifies each webhook, logs only events whose sender exactly matches `SMTP_FROM`, acknowledges unsupported click and inbound events without logging their payloads, and does not persist webhook data.

## 0.6.5

### Who should read this release

- **End users:**
  - [Signing in through the demo no longer silently fails if you take a while to enter your emailed code.](#v0.6.5-signing-in-through-the-demo-no-longer-silently-fails-if-you)
  - [Sign-in now stays active while you retrieve your emailed code and offers a clear way to restart if it times out.](#v0.6.5-sign-in-now-stays-active-while-you-retrieve-your-emailed)
- **Operators:**
  - [Signing in through the demo no longer silently fails if you take a while to enter your emailed code.](#v0.6.5-signing-in-through-the-demo-no-longer-silently-fails-if-you)

### Patch Changes

- <a id="v0.6.5-signing-in-through-the-demo-no-longer-silently-fails-if-you"></a> [#187](https://github.com/hypercerts-org/ePDS/pull/187) [`dcc9590`](https://github.com/hypercerts-org/ePDS/commit/dcc95903ffd105b30d8d15ddf9e9fd8778973c68) Thanks [@aspiers](https://github.com/aspiers)! - Signing in through the demo no longer silently fails if you take a while to enter your emailed code.

  **Affects:** End users, Operators

  **End users:** If you requested a sign-in code, then took several minutes to fetch it from your email before entering it, the demo could fail at the last step with a generic "Authentication failed" message — even though your code was correct. That happened because the demo started its 10-minute sign-in timer before it sent the code, so it could forget the sign-in while a later-issued code was still valid. The demo now remembers your sign-in for up to an hour, and if it genuinely does time out you now see "Your sign-in took too long to finish. Please sign in again." instead of a message that made it look like you typed the code wrong.

  **Operators:** The demo client's `oauth_state` cookie `maxAge` is raised from `600` (10 min) to `60 * 60` (1 hour), matching the auth service's `auth_flow` row TTL. Previously, the cookie's timer started when the OAuth flow began, while the OTP's 600-second validity started only when the code was issued, so the cookie could expire first. The OAuth callback now maps a missing/expired state cookie to `/?error=session_expired` rather than `/?error=auth_failed`; `session_expired` renders as "Your sign-in took too long to finish. Please sign in again."

- <a id="v0.6.5-sign-in-now-stays-active-while-you-retrieve-your-emailed"></a> [#187](https://github.com/hypercerts-org/ePDS/pull/187) [`e1c9d06`](https://github.com/hypercerts-org/ePDS/commit/e1c9d0651d45e5c2605cb6e698cb4ea4c4b8cf05) Thanks [@aspiers](https://github.com/aspiers)! - Sign-in now stays active while you retrieve your emailed code and offers a clear way to restart if it times out.

  **Affects:** End users

  **End users:** Previously, taking more than about five minutes to enter a code could leave the surrounding sign-in expired even though the code was still valid. The code-entry page now keeps the sign-in active while it remains open. If browser suspension or a longer interruption still makes the sign-in unrecoverable, the page disables code entry and **Use different email**, hides **Resend code**, and shows **Start over**; clicking it returns to the app you came from so you can begin again.

## 0.6.4

### Who should read this release

- **Client app developers:**
  - [The `/preview/validate` page now checks `epds_handle_login_url` on your client metadata.](#v0.6.4-the-page-now-checks-on-your-client-metadata)
- **Operators:**
  - [Failed one-time code attempts now appear in the server logs, split by reason and tagged with the account's email.](#v0.6.4-failed-one-time-code-attempts-now-appear-in-the-server-logs)

### Patch Changes

- <a id="v0.6.4-failed-one-time-code-attempts-now-appear-in-the-server-logs"></a> [#189](https://github.com/hypercerts-org/ePDS/pull/189) [`008b143`](https://github.com/hypercerts-org/ePDS/commit/008b143d160e3b0e9b0a2fae887283de464be8a0) Thanks [@aspiers](https://github.com/aspiers)! - Failed one-time code attempts now appear in the server logs, split by reason and tagged with the account's email.

  **Affects:** Operators

  **Operators:** failed OTP verifications are now logged under the `auth:better-auth` logger.
  - Each line carries an `email`, `statusCode`, and `path` field, and names the reason: `code expired`, `invalid or unrecognized code`, or `too many attempts, code invalidated`.
  - Routine failures (expired / invalid) log at `info`; too-many-attempts logs at `warn`.
  - All are visible at the default `info` level — no `LOG_LEVEL` change needed.

- <a id="v0.6.4-the-page-now-checks-on-your-client-metadata"></a> [#176](https://github.com/hypercerts-org/ePDS/pull/176) [`a00cb25`](https://github.com/hypercerts-org/ePDS/commit/a00cb2529f64fc97429e99b4e6f7bb35d0a47682) Thanks [@aspiers](https://github.com/aspiers)! - The `/preview/validate` page now checks `epds_handle_login_url` on your client metadata.

  **Affects:** Client app developers

  **Client app developers:** a new `handle-login-url` row joins the existing field checks.
  - Missing or empty value warns you that the "Or sign in with ATProto/Bluesky" button won't render.
  - An `http(s)://` value is ok, matching the `isSafeHttpUrl` gate that renders the button at runtime (`http://` accepted so localhost dev clients still pass).
  - Any other value (`javascript:`, `file:`, unparseable) errors, because the runtime gate would silently drop the button on real flows.

## 0.6.3

### Who should read this release

- **End users:**
  - [The final sign-in screen now lines up its message card with the page title.](#v0.6.3-the-final-sign-in-screen-now-lines-up-its-message-card-with)

### Patch Changes

- <a id="v0.6.3-the-final-sign-in-screen-now-lines-up-its-message-card-with"></a> [#169](https://github.com/hypercerts-org/ePDS/pull/169) [`cc65707`](https://github.com/hypercerts-org/ePDS/commit/cc65707ef4e0cfc7d4442bbb57ccd2c8639ec589) Thanks [@Kzoeps](https://github.com/Kzoeps)! - The final sign-in screen now lines up its message card with the page title.

  **Affects:** End users

  **End users:** After approving an app sign-in, the "Login complete" screen now keeps the "You are being redirected..." card visually aligned with the title instead of sitting slightly lower on the page.

## 0.6.2

### Who should read this release

- **End users:**
  - [Sign-in pages no longer strand users on a "session expired" dead end, and Resend no longer offers codes that won't work.](#v0.6.2-sign-in-pages-no-longer-strand-users-on-a-session-expired)
  - [Slow sign-ins are less likely to time out before you finish entering your code.](#v0.6.2-slow-sign-ins-are-less-likely-to-time-out-before-you-finish)

### Patch Changes

- <a id="v0.6.2-sign-in-pages-no-longer-strand-users-on-a-session-expired"></a> [#154](https://github.com/hypercerts-org/ePDS/pull/154) [`2e4d327`](https://github.com/hypercerts-org/ePDS/commit/2e4d327f01e6983ac8946cb7dff1e998edae8e34) Thanks [@aspiers](https://github.com/aspiers)! - Sign-in pages no longer strand users on a "session expired" dead end, and Resend no longer offers codes that won't work.

  **Affects:** End users

  **End users:** if your sign-in times out (you closed the tab and came back, or your wait was longer than the page can keep alive in the background), you are now taken back to the app you were signing in to so it can offer you a retry. The page also no longer offers Resend in the rare case where the new code wouldn't work — instead it tells you the sign-in has timed out and gives you a Start over button. No more typing a fresh code that fails. If for some reason the automatic return is not possible, the page shows a "Return to sign in" button so you can get back to the app yourself in one click.

- <a id="v0.6.2-slow-sign-ins-are-less-likely-to-time-out-before-you-finish"></a> [#154](https://github.com/hypercerts-org/ePDS/pull/154) [`b1fc940`](https://github.com/hypercerts-org/ePDS/commit/b1fc9400e55b661cfbd992d6f72261936ec1df5c) Thanks [@aspiers](https://github.com/aspiers)! - Slow sign-ins are less likely to time out before you finish entering your code.

  **Affects:** End users

  **End users:** if you take a few minutes to find your sign-in code in your inbox before entering it, you will no longer be bounced to a "session expired" page when you submit it. Closing the tab or walking away for a long stretch can still expire the flow, in which case the existing error pages still apply — but reading email at human speed should not.

## 0.6.1

### Who should read this release

- **End users:**
  - ["Powered by Certified" footer now appears on every auth-service page.](#v0.6.1-powered-by-certified-footer-now-appears-on-every-auth)
  - ["Use a different account" on the chooser now reliably takes you to the email form, not the code step for the previous account.](#v0.6.1-use-a-different-account-on-the-chooser-now-reliably-takes)
  - [Sign-in no longer fails with "Authentication session expired" when an OTP code is resent after the original code times out.](#v0.6.1-sign-in-no-longer-fails-with-authentication-session-expired)
  - [Terms of Use and Privacy Policy links on the sign-in page now open in a new tab.](#v0.6.1-terms-of-use-and-privacy-policy-links-on-the-sign-in-page)
  - [OAuth consent buttons stack cleanly on small screens.](#v0.6.1-oauth-consent-buttons-stack-cleanly-on-small-screens)
  - [A smoother sign-in code experience: no false error flash on a successful sign-in, no rapid-fire failures when correcting a wrong code, and tidier-looking banners.](#v0.6.1-a-smoother-sign-in-code-experience-no-false-error-flash-on)
  - [Sign-in no longer fails with a raw JSON error page when a user takes too long on the OTP step.](#v0.6.1-sign-in-no-longer-fails-with-a-raw-json-error-page-when-a)
  - [Sign-in no longer hits a dead-end on the password form](#v0.6.1-sign-in-no-longer-hits-a-dead-end-on-the-password-form)
- **Client app developers:**
  - [A smoother sign-in code experience: no false error flash on a successful sign-in, no rapid-fire failures when correcting a wrong code, and tidier-looking banners.](#v0.6.1-a-smoother-sign-in-code-experience-no-false-error-flash-on)

### Patch Changes

- <a id="v0.6.1-powered-by-certified-footer-now-appears-on-every-auth"></a> [#130](https://github.com/hypercerts-org/ePDS/pull/130) [`6a8671d`](https://github.com/hypercerts-org/ePDS/commit/6a8671d09285d6ad85fc07644cd94266a819baa3) Thanks [@s-adamantine](https://github.com/s-adamantine)! - "Powered by Certified" footer now appears on every auth-service page.

  **Affects:** End users

  **End users:** every page rendered by the auth service now displays the same "Powered by Certified" footer that the main sign-in already shows, so the branding is consistent end-to-end. New surfaces covered: the Account Settings sign-in flow at `/account/login` (email-entry and code-entry steps), the "Choose your handle" page shown to new users after email verification, both Account Recovery steps (backup-email entry and recovery-code entry), the `/account` settings dashboard, the backup-email verification confirmation, the post-deletion confirmation, and the generic error pages used by 404 / 500 / session-expired flows.

- <a id="v0.6.1-use-a-different-account-on-the-chooser-now-reliably-takes"></a> [#141](https://github.com/hypercerts-org/ePDS/pull/141) [`899346c`](https://github.com/hypercerts-org/ePDS/commit/899346c9e736881e7a024ec4778901045ff40415) Thanks [@aspiers](https://github.com/aspiers)! - "Use a different account" on the chooser now reliably takes you to the email form, not the code step for the previous account.

  **Affects:** End users

  **End users:** when you click "Another account" on the account chooser to sign in as someone else, you now always land on a fresh email entry form. Previously, if the app that started the sign-in had pre-filled an account hint, the page jumped straight to the verification-code step for the _previous_ account — leaving you stuck typing a code for an account you were trying to leave.

- <a id="v0.6.1-sign-in-no-longer-fails-with-authentication-session-expired"></a> [#122](https://github.com/hypercerts-org/ePDS/pull/122) [`dacf1d2`](https://github.com/hypercerts-org/ePDS/commit/dacf1d243f050faabbb1a18fc448f0010279d726) Thanks [@aspiers](https://github.com/aspiers)! - Sign-in no longer fails with "Authentication session expired" when an OTP code is resent after the original code times out.

  **Affects:** End users

  **End users:** Previously, if you took longer than 10 minutes to enter the one-time code emailed to you and then clicked **Resend code**, the new code would verify, but the next page would say "Authentication session expired. Please try again." and you would have to start the whole sign-in over. The OAuth session that was tracking your sign-in had the same 10-minute lifetime as the OTP code itself, so it had already gone away by the time the new code arrived.

  The OAuth session now lives long enough to outlast a typical resend cycle, so a slow first attempt followed by Resend completes normally. The OTP code's own 10-minute lifetime is unchanged.

- <a id="v0.6.1-terms-of-use-and-privacy-policy-links-on-the-sign-in-page"></a> [#127](https://github.com/hypercerts-org/ePDS/pull/127) [`8bf888b`](https://github.com/hypercerts-org/ePDS/commit/8bf888b0156ac1f1deb8bbd380953429f0241a62) Thanks [@s-adamantine](https://github.com/s-adamantine)! - Terms of Use and Privacy Policy links on the sign-in page now open in a new tab.

  **Affects:** End users

  **End users:** clicking Terms of Use or Privacy Policy on the sign-in page no longer navigates away from the in-progress sign-in. The links open in a new tab instead, so you can read the legal page and come back to finish signing in without restarting.

- <a id="v0.6.1-oauth-consent-buttons-stack-cleanly-on-small-screens"></a> [#136](https://github.com/hypercerts-org/ePDS/pull/136) [`143ff35`](https://github.com/hypercerts-org/ePDS/commit/143ff35da607b43f45615ecb659dbc7324e95510) Thanks [@Kzoeps](https://github.com/Kzoeps)! - OAuth consent buttons stack cleanly on small screens.

  **Affects:** End users

  **End users:** On phones and narrow browser windows, the consent screen now places the approve and deny buttons on separate lines so they are easier to read and tap. Larger screens keep the existing button layout.

- <a id="v0.6.1-a-smoother-sign-in-code-experience-no-false-error-flash-on"></a> [#134](https://github.com/hypercerts-org/ePDS/pull/134) [`bce65b5`](https://github.com/hypercerts-org/ePDS/commit/bce65b53706e1c5edd41d6fa4d3c583fab6de606) Thanks [@s-adamantine](https://github.com/s-adamantine)! - A smoother sign-in code experience: no false error flash on a successful sign-in, no rapid-fire failures when correcting a wrong code, and tidier-looking banners.

  **Affects:** End users, Client app developers

  **End users:**
  - A successful sign-in no longer briefly shows a red "Invalid OTP" message on its way to signing you in.
  - After entering a wrong code, the boxes clear and focus jumps back to the first one, so retyping doesn't immediately resubmit the still-wrong code on every keystroke (which previously could lock you out for spamming the server).
  - The red "Invalid OTP" and green "Code resent" banners are centred inside their coloured container instead of sitting in the corner of an empty wide box.

  **Client app developers:** the sign-in page's flash-message container now uses a stable `flash-msg` base class with `error` / `success` modifier classes, so custom client CSS can restyle either variant cleanly via `.flash-msg`, `.flash-msg.error`, and `.flash-msg.success`.

- <a id="v0.6.1-sign-in-no-longer-fails-with-a-raw-json-error-page-when-a"></a> [#128](https://github.com/hypercerts-org/ePDS/pull/128) [`0e62bd6`](https://github.com/hypercerts-org/ePDS/commit/0e62bd6c464e6660e4a890bd0f84da9c7d8f89d4) Thanks [@aspiers](https://github.com/aspiers)! - Sign-in no longer fails with a raw JSON error page when a user takes too long on the OTP step.

  **Affects:** End users

  **End users:** Previously, if you took more than five minutes between requesting your one-time code and submitting it (a slow inbox, switching tabs, fishing the code out of spam, multiple Resend cycles), sign-in could fail with a blank page showing only `{"error": "Authentication failed"}` on the PDS host — even though your OTP code itself was still valid. You now either land back inside the app you were signing into (which can offer a one-click retry), or see a styled error page on the PDS host explaining that sign-in timed out — depending on how far through the flow the timeout is detected. Either way, no more raw JSON.

- <a id="v0.6.1-sign-in-no-longer-hits-a-dead-end-on-the-password-form"></a> [#129](https://github.com/hypercerts-org/ePDS/pull/129) [`14e5033`](https://github.com/hypercerts-org/ePDS/commit/14e5033026ecebb21acdc23211d96c755cedb1e0) Thanks [@aspiers](https://github.com/aspiers)! - Sign-in no longer hits a dead-end on the password form

  **Affects:** End users

  **End users:** if you saw a "handle and password" form during sign-in with no way to enter a code, that path is gone. The email-code form will be shown instead, and after entering the code you'll be signed in normally.

## 0.6.0

### Who should read this release

- **End users:**
  - [Auth-service login page can now offer ATProto/Bluesky handle sign-in alongside email OTP.](#v0.6.0-auth-service-login-page-can-now-offer-atproto-bluesky)
  - [Trusted apps can now show their own icon in the browser tab on the sign-in page.](#v0.6.0-trusted-apps-can-now-show-their-own-icon-in-the-browser-tab)
  - [Refreshed sign-in page design, with new ways for apps to style it.](#v0.6.0-refreshed-sign-in-page-design-with-new-ways-for-apps-to)
  - [Account settings page now shows your current handle.](#v0.6.0-account-settings-page-now-shows-your-current-handle)
  - [Sign-in, account, error, and OAuth-consent pages now show an icon in the browser tab, with separate assets for light and dark browser themes.](#v0.6.0-sign-in-account-error-and-oauth-consent-pages-now-show-an)
  - [Signing in once in your browser now works across all apps that use this ePDS.](#v0.6.0-signing-in-once-in-your-browser-now-works-across-all-apps)
  - [Account recovery via backup email now completes the OAuth flow instead of dropping users into signup.](#v0.6.0-account-recovery-via-backup-email-now-completes-the-oauth)
  - [Visiting the bare auth service URL now takes you to the account page instead of a blank 404.](#v0.6.0-visiting-the-bare-auth-service-url-now-takes-you-to-the)
  - [Error pages on the sign-in service now match the rest of the signup and login look instead of showing plain default text, and apps calling the sign-in service now receive structured error responses by default instead of HTML pages.](#v0.6.0-error-pages-on-the-sign-in-service-now-match-the-rest-of)
- **Client app developers:**
  - [Auth-service login page can now offer ATProto/Bluesky handle sign-in alongside email OTP.](#v0.6.0-auth-service-login-page-can-now-offer-atproto-bluesky)
  - [Preview ePDS's auth-service screens and emails directly in your browser, without walking through the OAuth flow.](#v0.6.0-preview-epds-auth-service-screens-and-emails-directly-in)
  - [Trusted apps can now show their own icon in the browser tab on the sign-in page.](#v0.6.0-trusted-apps-can-now-show-their-own-icon-in-the-browser-tab)
  - [Trusted demo client now ships with a custom branded OTP email template.](#v0.6.0-trusted-demo-client-now-ships-with-a-custom-branded-otp)
  - [Refreshed sign-in page design, with new ways for apps to style it.](#v0.6.0-refreshed-sign-in-page-design-with-new-ways-for-apps-to)
  - [Signing in once in your browser now works across all apps that use this ePDS.](#v0.6.0-signing-in-once-in-your-browser-now-works-across-all-apps)
  - [Security fix: client-supplied email templates now require the client to be on the trusted-clients list.](#v0.6.0-security-fix-client-supplied-email-templates-now-require)
  - [Error pages on the sign-in service now match the rest of the signup and login look instead of showing plain default text, and apps calling the sign-in service now receive structured error responses by default instead of HTML pages.](#v0.6.0-error-pages-on-the-sign-in-service-now-match-the-rest-of)
- **Operators:**
  - [Auth-service login page can now offer ATProto/Bluesky handle sign-in alongside email OTP.](#v0.6.0-auth-service-login-page-can-now-offer-atproto-bluesky)
  - [Preview ePDS's auth-service screens and emails directly in your browser, without walking through the OAuth flow.](#v0.6.0-preview-epds-auth-service-screens-and-emails-directly-in)
  - [Trusted apps can now show their own icon in the browser tab on the sign-in page.](#v0.6.0-trusted-apps-can-now-show-their-own-icon-in-the-browser-tab)
  - [Trusted demo client now ships with a custom branded OTP email template.](#v0.6.0-trusted-demo-client-now-ships-with-a-custom-branded-otp)
  - [Refreshed sign-in page design, with new ways for apps to style it.](#v0.6.0-refreshed-sign-in-page-design-with-new-ways-for-apps-to)
  - [Sign-in, account, error, and OAuth-consent pages now show an icon in the browser tab, with separate assets for light and dark browser themes.](#v0.6.0-sign-in-account-error-and-oauth-consent-pages-now-show-an)
  - [Signing in once in your browser now works across all apps that use this ePDS.](#v0.6.0-signing-in-once-in-your-browser-now-works-across-all-apps)
  - [Fix a pds-core crash on the account chooser (`/account`) caused by response-rewrite middleware running after upstream had already flushed headers.](#v0.6.0-fix-a-pds-core-crash-on-the-account-chooser-caused-by)
  - [Security fix: client-supplied email templates now require the client to be on the trusted-clients list.](#v0.6.0-security-fix-client-supplied-email-templates-now-require)
  - [Auth-service rate limiter can now be disabled for single-source-IP test environments.](#v0.6.0-auth-service-rate-limiter-can-now-be-disabled-for-single)
  - [Account recovery via backup email now completes the OAuth flow instead of dropping users into signup.](#v0.6.0-account-recovery-via-backup-email-now-completes-the-oauth)
  - [Visiting the bare auth service URL now takes you to the account page instead of a blank 404.](#v0.6.0-visiting-the-bare-auth-service-url-now-takes-you-to-the)

### Minor Changes

- <a id="v0.6.0-auth-service-login-page-can-now-offer-atproto-bluesky"></a> [#115](https://github.com/hypercerts-org/ePDS/pull/115) [`7f265b7`](https://github.com/hypercerts-org/ePDS/commit/7f265b722eed721022e1b428111de44ff34b5c04) Thanks [@aspiers](https://github.com/aspiers)! - Auth-service login page can now offer ATProto/Bluesky handle sign-in alongside email OTP.

  <img width="1720" height="1640" alt="image" src="https://github.com/user-attachments/assets/d4237a4d-162c-48d2-b680-7b40d921c256" />

  **Affects:** End users, Client app developers, Operators

  **End users:**
  - When the app you came from supports it, the sign-in page now shows an "Or sign in with ATProto/Bluesky" button under the email form.
  - Clicking the button switches the form into handle-entry mode (e.g. `you.bsky.social`). Submitting a handle takes you back to your own PDS to finish signing in there.
  - Clicking the button again returns you to the email form.

  **Client app developers:** opt in by adding `epds_handle_login_url` to your OAuth client metadata.
  - The value must be an absolute https&#x3A;// URL on your client's own origin. ePDS auth-service redirects the browser to that URL with `?handle=<value>` appended when the user submits a handle.
  - Your route is responsible for resolving the handle to its PDS and starting a fresh OAuth flow against that PDS — auth-service is bound to one PDS and cannot start a PAR on your client's behalf, so off-PDS handles only work via this hand-off.
  - The reference demo client opts in by exposing `${baseUrl}/api/oauth/login?handle=...`, which already accepts a `handle` query parameter and resolves it dynamically.
  - If you do not declare `epds_handle_login_url`, the button is not rendered. Existing clients see no behaviour change.

  **Operators:** no new required configuration. The button only renders for OAuth clients that explicitly opt in via their metadata.

- <a id="v0.6.0-preview-epds-auth-service-screens-and-emails-directly-in"></a> [#103](https://github.com/hypercerts-org/ePDS/pull/103) [`226781b`](https://github.com/hypercerts-org/ePDS/commit/226781b8f137bf16731b2d4af52ac6e5790d757e) / [#93](https://github.com/hypercerts-org/ePDS/pull/93) [`d363b3d`](https://github.com/hypercerts-org/ePDS/commit/d363b3dcd40fa3603323650ccdb87527dea37147) Thanks [@aspiers](https://github.com/aspiers)! - Preview ePDS's auth-service screens and emails directly in your browser, without walking through the OAuth flow.

  <img width="1011" height="775" alt="Screenshot 2026-04-30 at 00 14 00" src="https://github.com/user-attachments/assets/d6bec2bd-e390-47e1-ae9f-46ccad6ab1e1" />

  **Affects:** Client app developers, Operators

  **Client app developers:**

  A new preview route on pds-core renders the account chooser with fixture sessions and your branding CSS, alongside the existing `/preview/consent` route. Open `/preview/chooser` (linked from the `/preview` index) to see how a returning user with one or more bound accounts will see your client. Inline controls on the index let you tweak the preview without editing the URL: a number field for `?numAccounts=N` (clamped to 1–10) grows or shrinks the fixture account list, and a dropdown for `?epds_handle_mode=` overrides the handle-picker mode the same way a real OAuth request can. The dropdown defaults to "Auto", which omits the param so client metadata (or the operator's env default) wins — exactly the production resolver order. The same `?client_id=<URL-of-your-client-metadata.json>` param the other preview routes accept also injects your branding CSS, subject to the standard trusted-clients gate. The existing `/preview/choose-handle` link on the auth-service index gains the same `?epds_handle_mode=` and `?error=` dropdowns and collapses the four enumerated handle-mode entries into a single link with bound controls.

  Three new preview routes on the auth service render the exact email HTML real users receive, inside a sandboxed iframe:
  - `/preview/emails/new-user` — welcome / email-verification code sent during signup.
  - `/preview/emails/returning-user` — sign-in OTP sent when an existing user logs in to your app.
  - `/preview/emails/recovery` — backup-email verification link sent when a user adds a recovery address.

  Each route accepts the same `?client_id=<URL-of-your-client-metadata.json>` query param as the other preview pages, so you can see how your branded template will look without walking through a real OAuth flow. Optional extras: `?otp=<code>` to override the fixture OTP, `?app=<name>` to override the fixture app name on the returning-user template, `?verify_url=<url>` to override the backup-email verification link. Links for all three are wired into the `/preview` index page on the auth service.

  **Operators:** the chooser route is gated by the existing `PDS_PREVIEW_ROUTES=1` flag on pds-core, and the email routes by the existing `AUTH_PREVIEW_ROUTES=1` flag on the auth service — no new environment variables. When the flags are off the new routes return 404, identical to the rest of `/preview/*`. The email previews do not touch SMTP; they call the same template builders the real sender uses, so what renders is bit-for-bit what production would put in the envelope. Intended for preview and development environments; leave the flags off in production.

- <a id="v0.6.0-trusted-apps-can-now-show-their-own-icon-in-the-browser-tab"></a> [#86](https://github.com/hypercerts-org/ePDS/pull/86) [`21a8bef`](https://github.com/hypercerts-org/ePDS/commit/21a8befa85bb4583aff3fe750372d3f592f9ee56) Thanks [@s-adamantine](https://github.com/s-adamantine)! - Trusted apps can now show their own icon in the browser tab on the sign-in page.

  **Affects:** End users, Client app developers, Operators

  **End users:** When signing in to a trusted app, the browser tab on the sign-in, recovery, and handle-picker pages will display that app's icon instead of the default ePDS icon. No action required.

  **Client app developers:** Add a `favicon_url` field (and optionally `favicon_url_dark`) under `branding` in your OAuth client metadata document. Each URL must be an absolute `https://` URL (no `http://`, no `data:` URIs, no userinfo credentials), at most 2048 characters, and **must share an origin (scheme + host + port) with your `client_id`**. When both light and dark variants are supplied, ePDS emits two `<link rel="icon">` tags gated by `prefers-color-scheme` so browsers automatically pick the variant matching the user's OS theme. When only the light variant is supplied, a single bare `<link>` is emitted and the browser uses it for both schemes. The browser fetches the favicons directly, so they must be reachable from end-user browsers and served with an appropriate `Content-Type` (`image/svg+xml`, `image/png`, `image/x-icon`, etc.). URLs failing any check are dropped — the page falls back to the default ePDS favicon, and a warning is logged server-side identifying the offending `client_id`. Example client metadata snippet for a `client_id` of `https://myapp.example/client-metadata.json`:

  ```json
  {
    "client_name": "My App",
    "branding": {
      "css": "...",
      "favicon_url": "https://myapp.example/favicon.svg",
      "favicon_url_dark": "https://myapp.example/favicon-dark.svg"
    }
  }
  ```

  The same-origin requirement exists because the auth-service Content-Security-Policy only widens `img-src` to the `client_id` origin. A favicon hosted on a separate CDN domain would be silently blocked by the browser, so we reject it server-side instead and log it, giving operators a clear breadcrumb. To use a favicon hosted off-origin, host or proxy it under the `client_id` origin (e.g. via a `/favicon.svg` path on the same hostname that serves your client metadata).

  Favicon injection is gated by the same `PDS_OAUTH_TRUSTED_CLIENTS` allowlist as `branding.css` — untrusted clients' favicons are ignored.

  **Operators:** No new environment variables. The existing `PDS_OAUTH_TRUSTED_CLIENTS` allowlist now also gates favicon injection in addition to CSS injection. To opt a client into custom favicons, add their `client_id` URL to that comma-separated list as before. Operators do not need to host or proxy any client icons — they are loaded by the end user's browser directly from the URL the client provides.

- <a id="v0.6.0-trusted-demo-client-now-ships-with-a-custom-branded-otp"></a> [#93](https://github.com/hypercerts-org/ePDS/pull/93) [`03ebf36`](https://github.com/hypercerts-org/ePDS/commit/03ebf365d10748582ff120305e67581b2621587c) Thanks [@aspiers](https://github.com/aspiers)! - Trusted demo client now ships with a custom branded OTP email template.

  <img width="1280" height="1126" alt="image" src="https://github.com/user-attachments/assets/cc186870-3ec4-453f-908c-e0bb614e19dd" />

  **Affects:** Client app developers, Operators

  **Client app developers:** the demo client's `client-metadata.json` now advertises `email_template_uri` (pointing at `/email-template.html` on the same origin) and `email_subject_template` (`{{code}} — your {{app_name}} code`), so operators running ePDS with the demo as a trusted client see a visually coherent login + email experience out of the box. The template is a minimal Mustache-style HTML email that respects the demo's `EPDS_CLIENT_THEME` palette: the OTP box, headings, and background all match whichever theme is active on the login and consent pages. Copy the shape from `packages/demo/src/app/email-template.html/route.ts` if you want a starting point for your own client's branded template — the supported placeholders are `{{code}}`, `{{app_name}}`, `{{logo_uri}}`, `{{email}}`, and the conditional blocks `{{#is_new_user}}…{{/is_new_user}}` / `{{^is_new_user}}…{{/is_new_user}}`.

  **Operators:** no env var change is required — the demo's branded email is served automatically when you run the bundled demo client as a trusted client on `PDS_OAUTH_TRUSTED_CLIENTS`. The template is served from the demo's own origin (`<demo-base-url>/email-template.html`) with `Cache-Control: public, max-age=300`, is capped at the same 100 KB / 5 s limits `makeSafeFetch` applies to any remote email template, and is only honoured for `client_id`s on the trusted-clients list (see the `gate-email-templates-on-trusted-clients` changeset). You can verify what your users will receive by opening `/preview/emails/returning-user?client_id=<demo-base-url>/client-metadata.json` on the auth service with `AUTH_PREVIEW_ROUTES=1`.

- <a id="v0.6.0-refreshed-sign-in-page-design-with-new-ways-for-apps-to"></a> [#110](https://github.com/hypercerts-org/ePDS/pull/110) [`f4f1040`](https://github.com/hypercerts-org/ePDS/commit/f4f104025561e5314978de450ff0a33044a19b46) Thanks [@s-adamantine](https://github.com/s-adamantine)! - Refreshed sign-in page design, with new ways for apps to style it.

  **Affects:** End users, Client app developers, Operators

  **End users:** The sign-in page is now a white card centered on a muted grey background, with rounded inputs, pill-shaped buttons, and a "Powered by Certified" footer. The one-time code step uses six segmented input boxes (with paste, arrow, backspace, and auto-submit) instead of a single text field. The underlying sign-in flow is unchanged.

  **Client app developers:** The login page now exposes its surface colors as CSS custom properties for trusted clients to override from their injected `branding.css`:

  ```css
  :root {
    --page-bg: #YOUR_OUTER_BG; /* page bg outside the card; default #E8E8E8 */
    --card-bg: #YOUR_CARD_BG; /* card surface; default #F8F8F8 */
    --input-bg: #YOUR_INPUT_BG; /* email + OTP box backgrounds; default #ffffff */
    --input-border: #YOUR_INPUT_BORDER; /* email + OTP box borders; default #e5e5e5 */
    --card-border: #YOUR_CARD_BORDER; /* card outline; default #E5E5E5 */
    --btn-secondary-border: #YOUR_BTN_BORDER; /* social / ATProto button borders; default #e5e5e5 */
    --muted-foreground: #YOUR_MUTED_TEXT; /* terms text + "Powered by" tint; default #999 */
    --focus-border: #YOUR_FOCUS; /* defaults to your client metadata's brand_color */
  }
  ```

  The page no longer reads `background_color` from your client metadata — to control the page background, set `--page-bg` from your `branding.css` instead. Pre-existing trusted clients that relied on `background_color` for the login bg need to migrate to the CSS var; clients that only used `background_color` for other rendered pages are unaffected.

  The "Recover with backup email" link on the OTP step is shown by default. To suppress it (e.g. for a client that doesn't surface backup-email recovery), set `:root { --recovery-link-display: none; }` in your `branding.css`. The recovery flow at `/auth/recover` is reachable via direct navigation regardless — only the entry point on the login page is hidden.

  **Operators:** a new terms-of-use / privacy-policy line renders below the card, driven by environment variables. Set `PDS_TERMS_OF_SERVICE_URL` and `PDS_PRIVACY_POLICY_URL` (the same vars upstream PDS reads, so they only need to be set once per deployment) to enable the line; if either is missing the line is omitted entirely. The optional `PDS_LEGAL_ENTITY_NAME` controls the possessive — when set, the copy reads "By signing in, you agree to <name>'s Terms of Use and Privacy Policy."; when unset, "By signing in, you agree to the Terms of Use and Privacy Policy."

  The upstream `@atproto/oauth-provider-ui` consent + chooser pages served by pds-core now ship with default Certified-style CSS injected by pds-core, so an unbranded ePDS deployment renders coherently with the auth-service login page (neutral grey page bg, light card surface, dark primary button) instead of the upstream's purple-on-white defaults. Trusted-client `branding.css` continues to override via cascade order — no client opt-in or migration needed.

- <a id="v0.6.0-account-settings-page-now-shows-your-current-handle"></a> [#99](https://github.com/hypercerts-org/ePDS/pull/99) [`5b74ce2`](https://github.com/hypercerts-org/ePDS/commit/5b74ce255c8980de4cf950461e1b1e03fe2ebecb) Thanks [@aspiers](https://github.com/aspiers)! - Account settings page now shows your current handle.

  **Affects:** End users

  **End users:** Visiting the account settings dashboard at `/account` on the auth service (not the PDS itself) now displays a "Current Handle:" row above the handle update form, so you can see at a glance what your current AT Protocol handle is before changing it. The auth service resolves the handle by calling the PDS's `com.atproto.repo.describeRepo` XRPC on every request, so the row reflects the authoritative value — including any pending rename that hasn't propagated to a local cache. If the PDS can't be reached the row displays `(unknown)` and the rest of the page still renders.

### Patch Changes

- <a id="v0.6.0-sign-in-account-error-and-oauth-consent-pages-now-show-an"></a> [#85](https://github.com/hypercerts-org/ePDS/pull/85) [`d48f735`](https://github.com/hypercerts-org/ePDS/commit/d48f7359569661dcb94ee55ccb3b32e343e28d1f) Thanks [@s-adamantine](https://github.com/s-adamantine)! - Sign-in, account, error, and OAuth-consent pages now show an icon in the browser tab, with separate assets for light and dark browser themes.

  **Affects:** End users, Operators

  **End users:** When signing in, recovering an account, choosing a handle, managing account settings, landing on an error page, or seeing the OAuth consent preview, your browser tab now displays a small icon next to the page title instead of the browser's generic placeholder. The icon automatically switches between a light- and dark-theme variant to match your browser's color scheme.

  **Operators:** both the auth service and pds-core now reference `/static/favicon.svg` and `/static/favicon-dark.svg` from every rendered page `<head>`, gated by `prefers-color-scheme` media queries. Both files ship by default in `packages/auth-service/public/` and `packages/pds-core/public/` (each service serves its own copy under its own origin). To use your own icons, replace those files (any SVG will do) — no config change required. The existing `/static` mounts in `packages/auth-service/src/index.ts` and `packages/pds-core/src/index.ts` serve them automatically. Each service also aliases `/favicon.ico` to its light-theme SVG so browsers that auto-request the legacy path on non-HTML responses (e.g. `/health`, XRPC JSON) still get an icon; the alias is single-variant because `prefers-color-scheme` only works via `<link>` tags in a real `<head>`.

  Upstream `@atproto/oauth-provider`-rendered pages (the account chooser at `/account*`, the OAuth authorize flow at `/oauth/*`, and upstream error pages) are also covered via a response-rewrite middleware that prepends the same two favicon `<link>` tags into the `<head>` of those responses. Same single-tenant asset as the auth-service pages: replace `packages/pds-core/public/favicon*.svg` to customise.

- <a id="v0.6.0-signing-in-once-in-your-browser-now-works-across-all-apps"></a> [#96](https://github.com/hypercerts-org/ePDS/pull/96) [`1bf9ce1`](https://github.com/hypercerts-org/ePDS/commit/1bf9ce1352c026349b26427389185ad7b01c6a2c) Thanks [@aspiers](https://github.com/aspiers)! - Signing in once in your browser now works across all apps that use this ePDS.

  **Affects:** End users, Client app developers, Operators

  **End users:**
  - After you sign in once with any app that uses this ePDS, a second app asking you to sign in skips the email code step.
  - Depending on the app, you either land straight on the "approve this app" screen or on an account chooser where you confirm which identity to reuse.
  - A "Use a different account" link on the chooser takes you back to the email form for a fresh sign-in.
  - The chooser shows your email next to your handle so accounts are easy to tell apart.
  - If your browser's leftover sign-in cookies no longer match the server, you land on the familiar email code form rather than a generic sign-in screen.
  - If an app asks you for your email and you give it one that is not one of the accounts you have already signed in to in this browser, you go straight to the email code form for that account rather than landing on a chooser of your existing accounts.

  **Client app developers:** no client-side changes required.
  - When a previous sign-in's cookies are present, the user lands on the account chooser to confirm which identity to reuse.
  - When you set `login_hint` to an email, AT Protocol handle, or DID, ePDS checks whether the hinted account is bound to the current device. If it is, the chooser still appears (with the hinted account pre-selected). If not, session reuse is disabled for this single request and the user receives an OTP for the hinted account; other accounts on the device remain reusable on subsequent un-hinted visits — no cookies are cleared.
  - To force the email code form instead, append `&prompt=login` to the authorization URL the user is redirected to. ePDS reads this from the URL query string, not from the PAR body — see the `epds-login` skill for details.

  **Operators:** no new required configuration.
  - ePDS auto-detects whether the auth service shares a parent domain with the PDS (`AUTH_HOSTNAME` ends with `.<PDS_HOSTNAME>`) and broadens the device-session cookies to that parent so both services can read them. On unrelated hostnames (e.g. Railway preview envs under `up.railway.app`) the feature self-disables.
  - Untrusted OAuth clients should be wired as confidential (`token_endpoint_auth_method=private_key_jwt`) for the "remember previous approval" path to work. The reference docker stack does this automatically and `scripts/setup.sh` generates the necessary keypairs on first run.

- <a id="v0.6.0-fix-a-pds-core-crash-on-the-account-chooser-caused-by"></a> [#96](https://github.com/hypercerts-org/ePDS/pull/96) [`1bf9ce1`](https://github.com/hypercerts-org/ePDS/commit/1bf9ce1352c026349b26427389185ad7b01c6a2c) Thanks [@aspiers](https://github.com/aspiers)! - Fix a pds-core crash on the account chooser (`/account`) caused by response-rewrite middleware running after upstream had already flushed headers.

  **Affects:** Operators

  **Operators:** The chooser-enrichment and client-CSS-injection middlewares could crash pds-core with `ERR_HTTP_HEADERS_SENT` on routes where upstream `@atproto/oauth-provider` flushes headers before `res.end()` (notably `/account`). Docker's `restart: unless-stopped` masked this as a transient 502 — users saw a blank page and the container restarted in the background. Both middlewares now skip their Content-Length / ETag rewrites once the response has started. No configuration change required.

- <a id="v0.6.0-security-fix-client-supplied-email-templates-now-require"></a> [#95](https://github.com/hypercerts-org/ePDS/pull/95) [`b04aebf`](https://github.com/hypercerts-org/ePDS/commit/b04aebf626e349fe2ac08cdd80f8435d94a5de4e) Thanks [@aspiers](https://github.com/aspiers)! - Security fix: client-supplied email templates now require the client to be on the trusted-clients list.

  **Affects:** Client app developers, Operators

  **Client app developers:** `email_template_uri`, `email_subject_template`, and the `client_name`-derived `From:` display name on OTP emails are now only honoured for clients whose `client_id` is on the PDS's `PDS_OAUTH_TRUSTED_CLIENTS` list — matching the gate that already applied to CSS branding injection. Untrusted clients receive the default ePDS OTP template with the default `From:` name. If your client isn't on the operator's trust list, advertising these fields in `client-metadata.json` has no effect; ask the operator to add your `client_id` to their trusted list.

  **Operators:** `PDS_OAUTH_TRUSTED_CLIENTS` now gates email-template branding as well as CSS injection. No config change is required — the same list is reused. If you have been relying on an untrusted client's `email_template_uri` to style OTP emails (no known such case, but worth checking), add that `client_id` to `PDS_OAUTH_TRUSTED_CLIENTS` to restore the previous behaviour. Without this fix, any registered `client_id` could (a) cause the auth service to fetch an attacker-chosen URL on every OTP send, (b) ship attacker-authored HTML in an email sent from the PDS's own `noreply@` address, and (c) spoof the sender display name via `client_name`. `EMAIL_TEMPLATE_ALLOWED_DOMAINS` still applies as an additional narrowing for trusted-client template hosts.

- <a id="v0.6.0-auth-service-rate-limiter-can-now-be-disabled-for-single"></a> [#103](https://github.com/hypercerts-org/ePDS/pull/103) [`3ccb48d`](https://github.com/hypercerts-org/ePDS/commit/3ccb48d0dcb0254e9b9d1315f5d10a97ce774167) Thanks [@aspiers](https://github.com/aspiers)! - Auth-service rate limiter can now be disabled for single-source-IP test environments.

  **Affects:** Operators

  Set `EPDS_DISABLE_RATE_LIMIT=true` to bypass the per-IP limiter (60 req/min) on the auth service. Only safe where every request shares one source IP (docker-compose, e2e). Leave unset in production.

- <a id="v0.6.0-account-recovery-via-backup-email-now-completes-the-oauth"></a> [#98](https://github.com/hypercerts-org/ePDS/pull/98) [`260113b`](https://github.com/hypercerts-org/ePDS/commit/260113b0911900e2161a1c2d103297c8b0244408) Thanks [@aspiers](https://github.com/aspiers)! - Account recovery via backup email now completes the OAuth flow instead of dropping users into signup.

  **Affects:** End users, Operators

  **End users:** signing in via the "Recover account" link and a verified backup email now redirects back to the app you came from, with a session on your real account. Previously the recovery flow would finish the OTP step and then take you to the handle-picker page as if you were a new user, leaving you stuck.

  **Operators:** no configuration changes. The bridge route `/auth/complete` now resolves a session's verified email through the `backup_email` table when there's no direct PDS account for that address, then looks up the primary email via the internal `_internal/account-by-handle` endpoint. No new environment variables, secrets, or network calls that operators need to allow beyond what auth-service already makes to pds-core.

- <a id="v0.6.0-visiting-the-bare-auth-service-url-now-takes-you-to-the"></a> [#102](https://github.com/hypercerts-org/ePDS/pull/102) [`548f4ad`](https://github.com/hypercerts-org/ePDS/commit/548f4adf29e2f43f1492d352cbcc1102a2ff607c) Thanks [@aspiers](https://github.com/aspiers)! - Visiting the bare auth service URL now takes you to the account page instead of a blank 404.

  **Affects:** End users, Operators

  **End users:** Opening the auth service at its root URL (e.g. `https://auth.example.com/`) now redirects to the account dashboard. If you are signed in you land on `/account`; if you are not, `/account` bounces you on to `/account/login` as before. Previously the root path had no handler and returned a 404 "Cannot GET /" page, which was confusing when bookmarking or mistyping a URL.

  **Operators:** The auth service now returns a `303 See Other` with `Location: /account` for `GET /`. If you have an external healthcheck pointed at `/` expecting a 404, switch it to `/health` (which already exists and returns a JSON status body). `/health` is unchanged.

- <a id="v0.6.0-error-pages-on-the-sign-in-service-now-match-the-rest-of"></a> [#97](https://github.com/hypercerts-org/ePDS/pull/97) [`f76a771`](https://github.com/hypercerts-org/ePDS/commit/f76a7713f875175e775e25c5157bcce036291afd) Thanks [@s-adamantine](https://github.com/s-adamantine)! - Error pages on the sign-in service now match the rest of the signup and login look instead of showing plain default text, and apps calling the sign-in service now receive structured error responses by default instead of HTML pages.

  **Affects:** End users, Client app developers

  **End users:** When a sign-in URL can't be found or something goes wrong on the sign-in service, the page shown now uses the same branded card layout as the rest of the sign-in flow, rather than the framework's unstyled default error page. The same applies to validation screens inside `/account` settings when a required field is missing or a verification link is malformed.

  **Client app developers:** The auth-service 404 and 500 handlers now do proper `Accept` header negotiation. Previously they returned HTML whenever the client would accept it — including `Accept: */*`, which `fetch` and `curl` send by default — so programmatic callers received HTML error bodies. The handlers now use `req.accepts(['json', 'html'])` and only return HTML when the client explicitly prefers it; anything else (including `*/*`) returns the existing JSON shape `{ "error": "not_found" | "internal_error" }`. If you were parsing HTML error responses from auth-service, switch to the JSON shape, or send `Accept: text/html` explicitly to opt back into HTML.

## 0.5.0

### Who should read this release

- **Client app developers & operators:**
  - [Add preview routes on auth-service and pds-core for iterating on client branding CSS.](#v0.5.0-add-preview-routes-on-auth-service-and-pds-core-for)
  - [Fix two preview-route cache bugs and remove long-stale debug endpoints.](#v0.5.0-fix-two-preview-route-cache-bugs-and-remove-long-stale)
- **End users of the trusted demo:**
  - [Demo amber/ocean themes now colour the OAuth consent page correctly.](#v0.5.0-demo-amber-ocean-themes-now-colour-the-oauth-consent-page)

### Minor Changes

- <a id="v0.5.0-add-preview-routes-on-auth-service-and-pds-core-for"></a> [#84](https://github.com/hypercerts-org/ePDS/pull/84) [`fe3ec90`](https://github.com/hypercerts-org/ePDS/commit/fe3ec907ae5cb6b388c3e9eb9e6797adb900c139) Thanks [@aspiers](https://github.com/aspiers)! - Add preview routes on auth-service and pds-core for iterating on client branding CSS.

  **Affects:** Client app developers, Operators

  **Client app developers:**
  - Visit `/preview` on either auth-service or pds-core for an index of every preview page. Each page renders against fixture data, so you can iterate on your `branding.css` without walking through a real OAuth flow.
  - Paste your `client-metadata.json` URL into the input field on the index page. The value is persisted in your browser and wires up every preview link, subject to the same `PDS_OAUTH_TRUSTED_CLIENTS` check as a real flow. Leave it blank to see the unbranded baseline.
  - The workflow becomes: edit `branding.css`, refresh any preview page. No OTP emails, no full flow.
  - The demo app links directly to the auth-service preview index with its own `client_id` pre-selected.

  **Operators:**
  - Two new env vars gate the preview routes, one per service: `AUTH_PREVIEW_ROUTES=1` on auth-service, `PDS_PREVIEW_ROUTES=1` on pds-core. Both are independent.
  - Safe to enable on preview deployments (Railway PR previews, `pr-base`, dev) and on local development instances. Preview routes don't affect real auth flows — they short-circuit real state — so they can technically run in production too, but they are a developer-only surface and are best left off outside preview/dev envs.
  - **Privacy:** enabling previews exposes `/preview/cache-status`, which returns the list of `client_id` URLs currently in the shared client-metadata cache — i.e. apps that have recently started an OAuth flow against this PDS. That partially leaks which third-party clients are using the instance, so **keep previews disabled in production** unless you're comfortable with that.
  - See `packages/auth-service/.env.example` and `packages/pds-core/.env.example` for the full notes.

### Patch Changes

- <a id="v0.5.0-demo-amber-ocean-themes-now-colour-the-oauth-consent-page"></a> [#83](https://github.com/hypercerts-org/ePDS/pull/83) [`cc722c4`](https://github.com/hypercerts-org/ePDS/commit/cc722c4feb98d44bc9ae07f748dda769bd33d216) Thanks [@aspiers](https://github.com/aspiers)! - Demo amber/ocean themes now colour the OAuth consent page correctly.

  **Affects:** End users of the trusted demo

  **End users:** The consent screen shown after signing in via the trusted demo now uses the demo's own warm indigo / amber palette throughout — the Authorize and Deny-access buttons, the "Authorize" header strip, and the surrounding surface all match the theme instead of falling back to the default @atproto/oauth-provider dark-mode look.

  The previous CSS targeted auth-service's hand-rolled login markup (`.btn-primary`, `.container`, `.field`), which does not exist on the consent page — that page is built from `@atproto/oauth-provider-ui`, which is a Tailwind-utility bundle whose colours are driven by CSS custom properties (`--branding-color-primary` and friends). The demo theme now overrides those variables at `:root`, so a single declaration recolours every `bg-primary` / `text-primary` / `border-primary` utility on the consent page at once, and additionally paints the card surface and body background to match.

- <a id="v0.5.0-fix-two-preview-route-cache-bugs-and-remove-long-stale"></a> [#89](https://github.com/hypercerts-org/ePDS/pull/89) [`1942ebb`](https://github.com/hypercerts-org/ePDS/commit/1942ebbae53e8fb17f6e29fa79c9c27df7d15e1d) Thanks [@aspiers](https://github.com/aspiers)! - Fix two preview-route cache bugs and remove long-stale debug endpoints.

  **Affects:** Client app developers, Operators

  **Client app developers:**
  - Preview-route fetch failures no longer poison the shared client-metadata cache. Previously, a failed preview fetch for a `client_id` with a valid 10-minute entry would overwrite that entry with a 60-second branding-less fallback, silently dropping `branding.css` on real OAuth flows for up to a minute. The in-memory cache is now only written by real-flow resolution.
  - The auth-service HTML preview pages (`/preview/login`, `/preview/login-otp`, `/preview/choose-handle`, `/preview/choose-handle-picker`, `/preview/recovery`, `/preview/recovery-otp`, and the `/preview` index) now send `Cache-Control: no-store`. Without it, a browser refresh could serve a cached page and never ask the server for fresh `branding.css`, breaking the advertised "edit `branding.css`, refresh the preview page" workflow.
  - `/preview/validate` now flags `branding.css` whose escaped size exceeds the 32 KB injection limit as an error, instead of reporting `ok` and letting the developer discover later that their CSS was silently dropped on real OAuth flows. Byte counts now match `getClientCss()`'s measurement (escaped UTF-8).

  **Operators:**
  - Removed `/_internal/debug-grants` and `/_internal/debug-recent-accounts`. These were added as temporary HYPER-270 debugging endpoints with a code comment marking them for removal before PR [#21](https://github.com/hypercerts-org/ePDS/issues/21) shipped (v0.2.2); they survived through v0.2.2, v0.3.0, v0.4.0, and the pending v0.5.0. The matching env var `EPDS_DEBUG_GRANTS` is no longer read.

## 0.4.0

### Who should read this release

- **End users:**
  - [Trusted apps can now style the sign-in and consent pages to match their own brand.](#v0.4.0-trusted-apps-can-now-style-the-sign-in-and-consent-pages-to)
- **Client app developers:**
  - [Trusted apps can now style the sign-in and consent pages to match their own brand.](#v0.4.0-trusted-apps-can-now-style-the-sign-in-and-consent-pages-to)
  - [Generate ES256 keypairs with `pnpm jwk:generate` instead of re-running full setup.](#v0.4.0-generate-es256-keypairs-with-instead-of-re-running-full)
  - [Updated login integration docs to recommend `@atproto/oauth-client-node` and confidential clients.](#v0.4.0-updated-login-integration-docs-to-recommend-and)
- **Operators:**
  - [Trusted apps can now style the sign-in and consent pages to match their own brand.](#v0.4.0-trusted-apps-can-now-style-the-sign-in-and-consent-pages-to)

### Minor Changes

- <a id="v0.4.0-trusted-apps-can-now-style-the-sign-in-and-consent-pages-to"></a> [#48](https://github.com/hypercerts-org/ePDS/pull/48) [`0c275e4`](https://github.com/hypercerts-org/ePDS/commit/0c275e44c4d60b194ba330ec92b501f1f14d5358) Thanks [@Kzoeps](https://github.com/Kzoeps) & [@aspiers](https://github.com/aspiers)! - Trusted apps can now style the sign-in and consent pages to match their own brand.

  **Affects:** End users, Client app developers, Operators

  **End users:** When signing in through an app that your ePDS operator has approved for branding, the login page, code entry page, handle picker, account recovery page, and consent page will display that app's colour scheme instead of the default look. The pages still work exactly the same way — only the visual appearance changes.

  **Client app developers:** Add a `branding.css` field inside a `branding` object in your `client-metadata.json`. The CSS is injected as a `<style>` tag into every auth-service page and the PDS stock consent page (`/oauth/authorize`) when your `client_id` is listed in the operator's `PDS_OAUTH_TRUSTED_CLIENTS`. The CSS is size-capped at 32 KB (measured in escaped UTF-8 bytes) and sanitised to prevent `</style>` tag closure. The CSP `style-src` directive is updated with a SHA-256 hash of the injected CSS. Example metadata:

  ```json
  {
    "client_id": "https://app.example/client-metadata.json",
    "client_name": "My App",
    "branding": {
      "css": "body { background: #0f1b2d; color: #e2e8f0; } .btn-primary { background: #3b82f6; }"
    }
  }
  ```

  Untrusted clients (not in `PDS_OAUTH_TRUSTED_CLIENTS`) never get CSS injection, regardless of what their metadata contains.

  **Operators:** CSS branding injection is controlled by the existing `PDS_OAUTH_TRUSTED_CLIENTS` env var on pds-core. No new env vars are required on pds-core or auth-service. The auth-service reads the same `PDS_OAUTH_TRUSTED_CLIENTS` list to decide whether to inject CSS on its pages (login, OTP, choose-handle, recovery). See `docs/configuration.md` for the full reference.

  For the demo app, a new optional `EPDS_CLIENT_THEME` env var selects a named theme preset (e.g. `ocean`) that applies consistent styling to both the demo's own pages and the CSS served in its client metadata. When unset, the demo uses the default light theme with no branding CSS. See `packages/demo/.env.example` for details.

### Patch Changes

- <a id="v0.4.0-generate-es256-keypairs-with-instead-of-re-running-full"></a> [#77](https://github.com/hypercerts-org/ePDS/pull/77) [`b3c779a`](https://github.com/hypercerts-org/ePDS/commit/b3c779a0df0e0a15c5dd8633835816eeb729d249) Thanks [@aspiers](https://github.com/aspiers)! - Generate ES256 keypairs with `pnpm jwk:generate` instead of re-running full setup.

  **Affects:** Client app developers

  **Client app developers:** A new `pnpm jwk:generate` command outputs a compact ES256 private JWK (with auto-derived `kid`) on stdout. Use this when you need a keypair for `private_key_jwt` client authentication without running the full `scripts/setup.sh`. The output is suitable for the `EPDS_CLIENT_PRIVATE_JWK` environment variable (used by the bundled demo app in `packages/demo`, not by third-party client apps) or for embedding the public half in any client metadata's `jwks` field.

- <a id="v0.4.0-updated-login-integration-docs-to-recommend-and"></a> [#77](https://github.com/hypercerts-org/ePDS/pull/77) [`0eaded0`](https://github.com/hypercerts-org/ePDS/commit/0eaded0760cb62b3e617756726ce7bd92ac17b88) Thanks [@aspiers](https://github.com/aspiers)! - Updated login integration docs to recommend `@atproto/oauth-client-node` and confidential clients.

  **Affects:** Client app developers

  **Client app developers:** The tutorial and skill reference now recommend `@atproto/oauth-client-node`'s `NodeOAuthClient` for Flow 2 (no hint, handle, or DID input), which handles PAR, PKCE, DPoP, and token exchange automatically. Flow 1 (email `login_hint`) remains hand-rolled. The default client metadata example has been flipped from `"token_endpoint_auth_method": "none"` to `"private_key_jwt"` with `jwks_uri` or inline `jwks` for publishing the public key. A new "Confidential vs public clients" section explains the trade-offs — notably that public clients force a consent screen on every login. New sections cover JWKS key generation, publishing, and rotation.

## 0.3.0

### Who should read this release

- **Client app developers and Operators:**
  - [The health endpoint now reports the running ePDS version.](#v0.3.0-the-health-endpoint-now-reports-the-running-epds-version)
  - [The upstream PDS version now appears on the stock health endpoint.](#v0.3.0-the-upstream-pds-version-now-appears-on-the-stock-health)

### Minor Changes

- <a id="v0.3.0-the-health-endpoint-now-reports-the-running-epds-version"></a> [#74](https://github.com/hypercerts-org/ePDS/pull/74) [`b46273a`](https://github.com/hypercerts-org/ePDS/commit/b46273a98762053069bb4a4a0ecfad5cfac4eb15) Thanks [@aspiers](https://github.com/aspiers)! - The health endpoint now reports the running ePDS version.

  **Affects:** Client app developers, Operators

  **Client app developers:** both `/health` endpoints (pds-core and auth-service) now include a `version` field in their JSON response (e.g. `{ "status": "ok", "service": "epds", "version": "0.2.2+f37823ee" }`). You can use this to check which ePDS release your app is running against. The demo frontend also displays the version in its page footer.

  **Operators:** in Docker and Railway deployments the version is automatically set to `<package.json version>+<8-char commit SHA>` at build time. In local dev it falls back to the root `package.json` version (e.g. `0.2.2`). To override, set the `EPDS_VERSION` environment variable on both pds-core and auth-service to any string. Docker Compose users should now build with `pnpm docker:build` instead of `docker compose build` directly — the wrapper stamps the version before building, and the build will fail if the version stamp is missing.

### Patch Changes

- <a id="v0.3.0-the-upstream-pds-version-now-appears-on-the-stock-health"></a> [#76](https://github.com/hypercerts-org/ePDS/pull/76) [`f709066`](https://github.com/hypercerts-org/ePDS/commit/f70906666955e4af7d64e429682b87ce941bdfd8) Thanks [@aspiers](https://github.com/aspiers)! - The upstream PDS version now appears on the stock health endpoint.

  **Affects:** Client app developers, Operators

  `/xrpc/_health` now returns the upstream `@atproto/pds` version in its JSON response (e.g. `{ "version": "0.4.211" }`). Previously this endpoint returned `{}`. This is independent of the ePDS version reported by `/health`.

  **Operators:** no configuration is needed — the version is read from the installed `@atproto/pds` package at startup. To override, set the `PDS_VERSION` environment variable on pds-core.

## 0.2.2

### Who should read this release

- **Everyone (end users, client app developers, operators):**
  - [The permissions shown on the sign-in consent screen now match what the app actually asked for.](#v0.2.2-the-permissions-shown-on-the-sign-in-consent-screen-now)
  - [Trusted apps can optionally skip the consent screen when new users sign up.](#v0.2.2-trusted-apps-can-optionally-skip-the-consent-screen)
- **Operators also:**
  - [Sign-in no longer fails when the login service and your data server share a domain name.](#v0.2.2-sign-in-no-longer-fails-when-the-login-service-and-your)

### Patch Changes

- <a id="v0.2.2-the-permissions-shown-on-the-sign-in-consent-screen-now"></a> [#21](https://github.com/hypercerts-org/ePDS/pull/21) [`10287ca`](https://github.com/hypercerts-org/ePDS/commit/10287cad14478ef3a877abdf0b581342ce7842c8) Thanks [@aspiers](https://github.com/aspiers)! - The permissions shown on the sign-in consent screen now match what the app actually asked for.

  **Affects:** End users, Client app developers, Operators

  **End users:** When you sign in to a third-party app through ePDS and are asked to approve what the app can do with your account, the list you see now reflects the permissions that particular app actually requested. Previously the screen always showed the same hard-coded list ("Read and write posts", "Access your profile", "Manage your follows") no matter which app you were signing in to, which was misleading. The consent screen itself also now looks and behaves like the standard AT Protocol consent screen used elsewhere in the ecosystem.

  **Client app developers:** The consent screen rendered at `/oauth/authorize` is now the stock `@atproto/oauth-provider` `consent-view.tsx`, driven by the real `scope` / `permissionSets` your client requests. The previous auth-service implementation ignored the requested scopes entirely. After OTP verification and (for new users) account creation, `epds-callback` now binds the device session via `upsertDeviceAccount()` and redirects through `/oauth/authorize`, so the upstream `oauthMiddleware` runs `provider.authorize()` — including `checkConsentRequired()` — against the actual request. Clients that only need scopes the user has already approved will now be auto-approved instead of being shown a redundant consent screen. Support for branding the consent screen is currently being worked on.

  **Operators:** No configuration changes are required. Consent state now lives in the upstream provider's `authorizedClients` tracking. The `client_logins` table is no longer used but is left in place (not dropped) to avoid breaking rollbacks in case they were ever needed.

- <a id="v0.2.2-trusted-apps-can-optionally-skip-the-consent-screen"></a> [#21](https://github.com/hypercerts-org/ePDS/pull/21) [`5110845`](https://github.com/hypercerts-org/ePDS/commit/5110845) Thanks [@aspiers](https://github.com/aspiers)! - Trusted apps can optionally skip the consent screen when new users sign up.

  **Affects:** End users, Client app developers, Operators

  **End users:** When you create a new account through a trusted app, ePDS can now send you straight back to that app without showing a separate consent screen first.

  **Client app developers:** To opt in, your client metadata must include `epds_skip_consent_on_signup: true`. The skip only applies on initial sign-up, only for trusted clients, and only when the server is configured to allow it.

  **Operators:** This feature has separate configuration from the normal consent-screen changes. To enable it, set `PDS_SIGNUP_ALLOW_CONSENT_SKIP=true` on pds-core. The skip only applies to clients already trusted via `PDS_OAUTH_TRUSTED_CLIENTS` (also on pds-core) and only when the client metadata opts in with `epds_skip_consent_on_signup: true`.

- <a id="v0.2.2-sign-in-no-longer-fails-when-the-login-service-and-your"></a> [#65](https://github.com/hypercerts-org/ePDS/pull/65) [`313c071`](https://github.com/hypercerts-org/ePDS/commit/313c07176ac04ae6f517f18cfe95cf15af1d0812) Thanks [@aspiers](https://github.com/aspiers)! - Sign-in no longer fails when the login service and your data server share a domain name.

  **Affects:** Operators

  **Operators:** Fix for an unreleased bug introduced by the above consent changes in [#21](https://github.com/hypercerts-org/ePDS/pull/21). No configuration changes are needed. This is just a heads-up in case anyone deployed an ePDS from git within a small window; if you notice logins failing on your ePDS, make sure to upgrade to v0.2.2 or newer.

  **Technical details:**

  The upstream `@atproto/oauth-provider` rejects `sec-fetch-site: same-site` on `GET /oauth/authorize`. This caused a `400 Forbidden sec-fetch-site header` error on deployments where the auth service and PDS share a registrable domain (e.g. `auth.epds1.test.certified.app` and `epds1.test.certified.app`). Browsers send `same-site` on the 303 redirect chain from the auth subdomain to the PDS, and the upstream code does not allow it.

  pds-core now includes middleware that rewrites `sec-fetch-site: same-site` to `same-origin` on `GET /oauth/authorize` when the request originates from the trusted auth subdomain.

  Additionally, DB migration v9 (which previously dropped the `client_logins` table) is now a no-op. The table is no longer used but is kept in place to avoid breaking emergency rollbacks to older code that still references it.

  This bug was missed by the comprehensive E2E test suite due to an unfortunate combination of quirks:
  1. The upstream ATProto PDS does not support `sec-fetch-site: same-site`, marked as a [`@TODO`](https://github.com/bluesky-social/atproto/blob/2a9221d244a0821490458785d70d100a6943ea91/packages/oauth/oauth-provider/src/router/create-authorization-page-middleware.ts#L75-L77) in the source. Stock ATProto never encounters `same-site` because the PDS serves its own login UI on the same origin.
  2. Railway does not allow any control over generated domains for PR preview environments. Each service gets a flat `*.up.railway.app` subdomain, and `up.railway.app` is on the Public Suffix List — so cross-service requests are `cross-site` (allowed), never `same-site`. This creates a small but ultimately significant difference in DNS topology from Certified infrastructure where all services share a registrable domain.
  3. The deliberate introduction (in PR [#21](https://github.com/hypercerts-org/ePDS/pull/21)) of a double redirect from `auth-service/auth/complete` to `pds-core/oauth/epds-callback` to `pds-core/oauth/authorize`, which sends the browser through a cross-origin hop on the same site — the exact pattern the upstream validation rejects.

## 0.2.1

### Who should read this release

- **End users:**
  - [Mask every segment of email addresses on recovery and account-login pages, including the domain and TLD (HYPER-259).](#v0.2.1-mask-every-segment-of-email-addresses-on-recovery-and)

### Patch Changes

- <a id="v0.2.1-mask-every-segment-of-email-addresses-on-recovery-and"></a> [#51](https://github.com/hypercerts-org/ePDS/pull/51) [`cfaeabe`](https://github.com/hypercerts-org/ePDS/commit/cfaeabed56d2d745335295f5a653b5358447ecca) Thanks [@aspiers](https://github.com/aspiers)! - Mask every segment of email addresses on recovery and account-login pages, including the domain and TLD (HYPER-259).

  **Affects:** End users

  Previously, the partially-masked email shown on the recovery and account-login pages left the entire domain visible (e.g. `jo***@gmail.com`), making the user's email address much easier to guess for anyone who entered a known handle on the login flow. Each dot-separated segment of both local part and domain is now masked independently, revealing only the final character of each segment (e.g. `persons.address@gmail.com` → `***s.***s@***l.***m`). Hiding the domain is important: leaving a common domain visible would make popular providers trivially identifiable, which in turn makes the local part much more guessable.

## 0.2.0

### Who should read this release

- **End users:**
  - [Configurable sign-in code length, optionally mixing letters and numbers.](#v0.2.0-configurable-otp-codes)
  - [Choose your own handle when signing up, instead of being given a random one.](#v0.2.0-choose-your-own-handle-when-signing-up-instead-of-being)
  - [Sign in faster from third-party apps that already know who you are.](#v0.2.0-sign-in-faster-from-third-party-apps-that-already-know-who)
- **Client app developers:**
  - [Choose your own handle when signing up, instead of being given a random one.](#v0.2.0-choose-your-own-handle-when-signing-up-instead-of-being)
- **Operators:**
  - [Configurable sign-in code length, optionally mixing letters and numbers.](#v0.2.0-configurable-otp-codes)
  - [Choose your own handle when signing up, instead of being given a random one.](#v0.2.0-choose-your-own-handle-when-signing-up-instead-of-being)
  - [Fail-fast validation of internal environment variables on the auth service.](#v0.2.0-fail-fast-validation-of-internal-environment-variables-on)
  - [Honour the generic `PORT` environment variable on both services, so Railway's automatic healthcheck succeeds without per-service configuration.](#v0.2.0-honour-the-generic-environment-variable-on-both-services-so)

### Minor Changes

- <a id="v0.2.0-configurable-otp-codes"></a> [#14](https://github.com/hypercerts-org/ePDS/pull/14) Thanks [@Kzoeps](https://github.com/Kzoeps)! - Configurable sign-in code length, optionally mixing letters and numbers.

  **Affects:** End users, Operators

  **End users:** depending on how the ePDS instance you sign in to is configured, sign-in codes sent to your email may now be shorter (as few as 4 characters) or longer (up to 12 characters) than the previous fixed length of 8, and may include uppercase letters as well as digits. Codes of 8 or more characters are displayed grouped in the email for readability (e.g. `1234 5678`), but you can still paste the whole code into the sign-in form as usual — the space is just a visual aid.

  **Operators:** two new environment variables on the auth service — `OTP_LENGTH` (integer, range 4–12, default 8) and `OTP_CHARSET` (`numeric` (default) or `alphanumeric`; `alphanumeric` uses uppercase A–Z plus 0–9). Values outside the range cause the service to fail on startup. The OTP form fields (input width, `pattern`, `inputmode`, `autocapitalize`) adapt automatically from the configured length and charset; no template changes are required.

  **Operators running custom email templates:** the shared email helpers now format OTPs with visual grouping when the code is 8 characters or longer — e.g. `1234 5678` in subject lines and plain text, and `<span>1234</span><span>5678</span>` with CSS spacing in HTML so that copy-paste still yields the flat code. If you render OTPs yourself rather than going through `EmailSender.sendOtpCode()`, import `formatOtpPlain()` and `formatOtpHtmlGrouped()` from `@certified-app/shared` instead of interpolating the raw code.

- <a id="v0.2.0-choose-your-own-handle-when-signing-up-instead-of-being"></a> [#13](https://github.com/hypercerts-org/ePDS/pull/13) [#29](https://github.com/hypercerts-org/ePDS/pull/29) [#33](https://github.com/hypercerts-org/ePDS/pull/33) [#36](https://github.com/hypercerts-org/ePDS/pull/36) Thanks [@Kzoeps](https://github.com/Kzoeps) & [@aspiers](https://github.com/aspiers)! - Choose your own handle when signing up, instead of being given a random one.

  **Affects:** End users, Client app developers, Operators

  **End users:** the signup flow now shows a handle picker by default instead of assigning a random handle. You can type a custom handle and the picker will check availability as you type, or click the random-handle button to take what the old flow would have given you. The picker now accepts handles as short as 5 characters and handles are validated more strictly so that some handles that used to be accepted may now be rejected up-front with a clearer error. The picker layout has been widened to accommodate long PDS domain names without truncation.

  **Client app developers (building on top of ePDS):** a new `epds_handle_mode` setting controls which variant of the signup handle picker is shown. Accepted case-sensitive values:
  - `picker` — always show the picker, no random option offered.
  - `random` — always assign a random handle, no picker (the
    pre-0.2.0 behaviour).
  - `picker-with-random` _(default)_ — show the picker but include a
    "generate random" option.

  The setting is resolved with the following precedence (first match wins), falling back to a built-in default:
  1. `epds_handle_mode` query parameter on the `/oauth/authorize` request.
  2. `epds_handle_mode` field in the OAuth **client metadata JSON** served at the client's `client_id` URL.
  3. `EPDS_DEFAULT_HANDLE_MODE` environment variable on the auth service.
  4. Built-in default: `picker-with-random`.

  This precedence was previously wrong — the env var was consulted before the client metadata, so clients could not override a server default. If you relied on that bug, your env var setting will now be overridden by whatever the client metadata says.

  To force a specific handle mode for users of your app, add the field to the client metadata JSON that your `client_id` URL returns, alongside the standard OAuth fields:

  ```json
  {
    "client_id": "https://example.com/oauth/client-metadata.json",
    "client_name": "Example",
    "redirect_uris": ["https://example.com/oauth/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "scope": "atproto transition:generic",
    "token_endpoint_auth_method": "none",
    "application_type": "web",
    "dpop_bound_access_tokens": true,
    "epds_handle_mode": "picker"
  }
  ```

  Unknown or invalid values are silently ignored and fall through to the next source. If you need to override per-request (e.g. for a specific signup campaign), append `?epds_handle_mode=picker` to your `/oauth/authorize` URL.

  **Operators:** set `EPDS_DEFAULT_HANDLE_MODE` on the auth service to change the default handle-picker variant for clients that don't specify one in their client metadata. Accepted values are the same as those listed in the Client app developers section above (`picker`, `random`, `picker-with-random`). See `.env.example` for documentation.

### Patch Changes

- <a id="v0.2.0-sign-in-faster-from-third-party-apps-that-already-know-who"></a> [#3](https://github.com/hypercerts-org/ePDS/pull/3) [#6](https://github.com/hypercerts-org/ePDS/pull/6) Thanks [@aspiers](https://github.com/aspiers)! - Sign in faster from third-party apps that already know who you are.

  **Affects:** End users

  When you sign in to a third-party AT Protocol app (anything built on top of the Bluesky account system, for example) that already knows your handle or DID, ePDS now jumps straight to the "enter your sign-in code" step. Previously you would have been asked to retype your email address first, even though the app you were using had already identified you — that extra step is gone.

  This fixes two specific situations that didn't work before: apps that identified you by handle or DID rather than email, and apps that sent the identifier over a back channel rather than in the sign-in URL.

- <a id="v0.2.0-fail-fast-validation-of-internal-environment-variables-on"></a> [#20](https://github.com/hypercerts-org/ePDS/pull/20) [#23](https://github.com/hypercerts-org/ePDS/pull/23) Thanks [@aspiers](https://github.com/aspiers)! - Fail-fast validation of internal environment variables on the auth service.

  **Affects:** Operators

  A new `requireInternalEnv()` helper runs at auth service startup and reports exactly which required internal variables are missing or malformed, replacing cryptic downstream errors like `TypeError: Failed to parse URL` on the first request.

  Checks performed:
  - `PDS_INTERNAL_URL` — must be set **and** must begin with `http://` or `https://` (matched case-insensitively). Trailing slashes are stripped automatically.
  - `EPDS_INTERNAL_SECRET` — must be set to any non-empty string.

  If you previously set `PDS_INTERNAL_URL` to a bare hostname like `core.railway.internal` or `core:3000`, the service will now refuse to start with this error:

  ```text
  PDS_INTERNAL_URL is missing the http:// or https:// scheme: "core.railway.internal"
  ```

  Add the scheme and port explicitly. The canonical Docker Compose default (shown in `.env.example`) is `http://core:3000`; for Railway's private networking the equivalent is `http://<service>.railway.internal:<PDS_PORT>`, substituting whichever service name you gave your pds-core deployment and the `PDS_PORT` you configured on it. Railway's internal network uses plain HTTP on explicit ports, not HTTPS. This previously "worked" in the sense that the service started, but then failed on the first internal request; the new behaviour surfaces the misconfiguration immediately.

- <a id="v0.2.0-honour-the-generic-environment-variable-on-both-services-so"></a> [#27](https://github.com/hypercerts-org/ePDS/pull/27) Thanks [@aspiers](https://github.com/aspiers)! - Honour the generic `PORT` environment variable on both services, so Railway's automatic healthcheck succeeds without per-service configuration.

  **Affects:** Operators

  New port-resolution precedence (first set value wins):
  - **auth service:** `AUTH_PORT` → `PORT` → `3001`
  - **pds-core:** `PDS_PORT` → `PORT` → `3000` (pds-core reads `PDS_PORT`; when `PDS_PORT` is unset, `PORT` is copied into it before `@atproto/pds` reads its environment)

  If you run ePDS on Docker Compose or another orchestrator where you set `AUTH_PORT` / `PDS_PORT` explicitly: no change — your existing settings take precedence over `PORT`.

  If you run ePDS on Railway (or any platform that injects `PORT` automatically): you can now remove service-specific `AUTH_PORT` / `PDS_PORT` overrides from your Railway variables. Each service will pick up Railway's injected `PORT` and healthchecks will bind correctly. Previously these services bound to their hardcoded defaults regardless of `PORT`, causing Railway healthchecks to fail.
