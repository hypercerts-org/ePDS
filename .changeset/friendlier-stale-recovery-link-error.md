---
'ePDS': patch
---

Visiting a stale account-recovery link no longer leaks an internal OAuth field name.

**Affects:** End users

**End users:** if you arrived at the account-recovery page from a stale link or a direct paste — i.e. without an active sign-in flow — the page used to say "Missing request_uri parameter", which tells you nothing useful and leaks the name of an internal OAuth field. The page now says "Account recovery has to be started from the sign-in page. Please sign in again from the app you came from." so you know what to do next.
