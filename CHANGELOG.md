# ePDS

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
