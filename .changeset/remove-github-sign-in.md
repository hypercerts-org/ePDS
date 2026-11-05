---
'ePDS': patch
---

Sign-in with GitHub, which never worked, is removed.

**Affects:** Operators

**Operators:** `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` are no longer read and can be removed from your environment. The GitHub button never worked (every click returned 404), so no sign-in is lost.
