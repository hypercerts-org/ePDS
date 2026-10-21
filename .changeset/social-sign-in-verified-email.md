---
'ePDS': patch
---

Signing in with Google now only works with an email address Google can vouch for, and cancelling brings you back to the sign-in page.

**Affects:** End users, Operators

**End users:** If Google cannot confirm that the address is yours (anything other than a Gmail or Google Workspace address), the sign-in page asks you to use a code sent to your email instead. Pressing Cancel at Google returns you to the sign-in page instead of an error page.

**Operators:**

- A Google sign-in counts as email-verified only when the ID token's `email_verified` is `true` (boolean or the exact string `"true"`) and the address is `@gmail.com` / `@googlemail.com` or its domain equals the token's `hd` claim (ignoring case); an `hd` naming any other domain does not count.
- A social sign-in whose provider does not vouch for the email no longer creates a better-auth user, a PDS account, or a session that `/auth/complete`, `/auth/choose-handle` or `/account` accept. A cancelled or refused sign-in returns to the login page with a fixed message.
- The redirect URI to register with Google is `https://<AUTH_HOSTNAME>/api/auth/callback/google`; the consent screen needs only `openid`, `email` and `profile` and must be published "In production". See the social providers section of `docs/configuration.md`.
