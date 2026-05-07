---
'ePDS': patch
---

Visiting a stale sign-in link no longer leaks an internal OAuth field name.

**Affects:** End users

**End users:** if you arrived at the sign-in page from a stale link or a direct paste — i.e. without an active sign-in flow — the page used to say "Missing request_uri parameter", which tells you nothing useful and leaks the name of an internal OAuth field. The page now says "Sign-in has to be started from the app you are signing into. Please return to that app and try again." so you know what to do next.
