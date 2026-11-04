---
'ePDS': patch
---

Sign-in with GitHub is removed. Google and email codes are the ways to sign in.

**Affects:** Client app developers, Operators

**Client app developers:** `"github"` in `epds_social_providers` is now ignored. The GitHub button never worked (every click returned 404), so no sign-in is lost.

**Operators:** `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` are no longer read and can be removed from your environment.
