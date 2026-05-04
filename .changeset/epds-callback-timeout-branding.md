---
'ePDS': patch
---

Timed-out sign-ins now keep the approved app styling on the error page.

**Affects:** End users, Client app developers

**End users:** If sign-in takes too long, the timeout page still explains that sign-in expired and now keeps the same approved app styling as the rest of the sign-in flow.

**Client app developers:** Trusted clients that already provide `branding.css` and are listed in `PDS_OAUTH_TRUSTED_CLIENTS` now have that CSS applied to the `/oauth/epds-callback` timeout fallback page. Untrusted clients still do not receive CSS injection, and no client-side changes are required.
