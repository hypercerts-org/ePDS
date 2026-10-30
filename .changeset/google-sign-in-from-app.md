---
'ePDS': minor
---

Signing in with Google always lets you pick your Google account, and an app can take you straight to Google without emailing you a code first.

**Affects:** End users, Client app developers

**End users:** Google now always asks which Google account to use, so a browser that is already signed in to a different Google account no longer signs you in with that one. If you entered your email address first, Google suggests the matching account. When an app has its own "Sign in with Google" button, pressing it takes you straight to Google instead of first sending a code to your email.

**Client app developers:**

- To start Google sign-in from your own page, add `epds_social_provider=google` to the `/oauth/authorize` URL you redirect to, for example `https://<AUTH_HOSTNAME>/oauth/authorize?client_id=…&request_uri=…&epds_social_provider=google`. The login page then hands off to Google on load and sends no email code. A `login_hint` email address on the same request is passed to Google as its login hint instead of receiving a code.
- The parameter only works for a provider your client lists in `epds_social_providers` and the operator has configured; otherwise it is ignored and the login page behaves as before. Like `prompt=login`, it skips the "continue as" account chooser for an existing session in the browser, because the user asked for that provider.
- If the user cancels at Google or Google is refused, the login page shows the usual message and does not start Google again on its own.
- The login page's own Google button also passes an email address typed into the field as Google's login hint.
