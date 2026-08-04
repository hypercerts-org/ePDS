---
'ePDS': patch
---

Sign-in pages no longer leak a malformed client_id as the displayed app name.

**Affects:** End users

**End users:** if you arrived at a sign-in page with a broken `client_id` parameter on the URL (e.g. from a misconfigured app or a tampered link), the page would display that raw broken value as the app's name, e.g. "Sign in to not-a-url" or "Sign in to my-local-app". The page now falls back to "an application" in that case, so a malformed value in the URL doesn't leak into the visible page text or browser tab title.
