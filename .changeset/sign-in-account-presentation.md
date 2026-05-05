---
'ePDS': patch
---

Sign-in screens now show your email more consistently and wait until they are ready before accepting clicks.

**Affects:** End users, Client app developers

**End users:**

- Sign-in, app approval, account chooser, and account-management screens now use email as the primary identifier for accounts with generated handles, while still showing the public handle where it helps explain the account.
- The final approval step no longer briefly exposes a generated random handle when an app asked to show email first.
- The email sign-in button now waits until the page is ready before accepting clicks, so an early tap does not start a broken sign-in attempt.

**Client app developers:** `epds_handle_mode` is now applied consistently to approval and account-chooser pages from either the current `/oauth/authorize` query parameter or OAuth client metadata, including pushed authorization requests where the browser URL only contains `request_uri`. Explicit query parameters still take precedence over client metadata. Valid modes stored for an auth flow are preserved through `/oauth/epds-callback`; invalid callback values are ignored rather than forwarded; metadata lookup failures fall back to the existing default behavior.
