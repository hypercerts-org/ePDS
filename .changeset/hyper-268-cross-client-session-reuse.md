---
'epds': patch
---

Signing in once in your browser now works across all apps that use this ePDS.

**Affects:** End users, Client app developers, Operators

**End users:** After you sign in once — via email OTP — with any app that
uses this ePDS, a second app asking you to sign in can now skip the code
email step entirely. Depending on how the app starts the sign-in, either
(a) it takes you straight to the "approve this app" screen with no extra
clicks, or (b) it shows you an account chooser with your identity on it
so you can confirm "yes, use this account" (or switch to a different
one). If none of the shown accounts is the one you want, a "Use a
different account" link drops you back on the email form for a fresh
sign-in. This matches how signing in once per browser works on mainstream
identity providers.

**Client app developers:** The auth service's `/oauth/authorize` route now
detects the upstream `@atproto/oauth-provider` device-session cookie
(`dev-id`) on incoming requests and, when present, redirects the browser
to pds-core's stock `/oauth/authorize` so upstream's session-selection
middleware can handle the flow. Clients that supply a `login_hint`
matching a bound account get OIDC-style auto-sign-in ("flow 1"); clients
that do not get the upstream account chooser ("flow 2"). The OIDC
`prompt=login` parameter is honoured on the auth-service side to force
the email OTP form and bypass session reuse. pds-core's chooser is
enriched via a small HTML response-rewrite script that surfaces each
bound account's email address alongside the handle (random handles
otherwise make the chooser unusable) and injects a "Use a different
account" link pointing at the auth service with `prompt=login`.

**Operators:** No new configuration required. pds-core automatically
detects whether the auth-service shares a parent domain with the PDS
(by checking whether `AUTH_HOSTNAME` ends with `.<PDS_HOSTNAME>`) and
broadens the upstream device-session cookies (`dev-id`, `ses-id`, and
their `:hash` sidecars) to that parent domain so the auth service can
read them. When the services are on unrelated hostnames — for example
Railway preview environments where each service gets a random subdomain
under `up.railway.app` (a public suffix) — the auto-detection finds no
shared parent and the feature is silently disabled. See
`docs/design/hyper-268-session-reuse.md` for architecture details.
