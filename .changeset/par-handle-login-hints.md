---
'ePDS': patch
---

Sign-in no longer loops when an app starts from your handle.

**Affects:** End users, Client app developers

**End users:** Apps that already know your handle now take you to the email code step instead of ending in a browser "too many redirects" error.

**Client app developers:** No client-side changes required. Authorization requests that put an AT Protocol handle or DID in the PAR-body `login_hint` and omit `login_hint` from the `/oauth/authorize` URL are handled by ePDS's passwordless flow: the hint is resolved to the account email and the user lands on the code verification step.
