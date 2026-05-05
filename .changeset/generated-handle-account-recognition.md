---
'ePDS': patch
---

Accounts with automatically generated handles are easier to recognize during sign-in and app approval.

**Affects:** End users, Client app developers

**End users:** Sign-in, app approval, account chooser, and account-management screens now use email as the primary identifier for generated-handle accounts while keeping the public handle available where it helps explain the account. The final approval step no longer briefly exposes the generated random handle when an app requested email-first presentation.

**Client app developers:** `epds_handle_mode` is now applied consistently to pds-core-rendered approval and chooser pages from either the current `/oauth/authorize` query parameter or OAuth client metadata, including pushed authorization requests where the current URL only contains `request_uri`. Explicit query parameters still take precedence over client metadata, valid modes stored for an auth flow are preserved through `/oauth/epds-callback`, invalid callback values are ignored rather than forwarded, and metadata lookup failures fall back to the existing default behavior.
