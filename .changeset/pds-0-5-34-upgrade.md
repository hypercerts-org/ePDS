---
'ePDS': minor
---

Update sign-in and approval screens while keeping account switching in email sign-in and preserving ePDS branding.

**Affects:** End users, Client app developers, Operators

**End users:** Selecting “Another account” continues to open the email sign-in form instead of the server's password form. Authorization and account-selection screens now use consistent ePDS colors, surfaces, and responsive controls instead of partially falling back to upstream styling.

**Client app developers:** Review consent and account-picker branding against the updated screens. Update custom `branding.css` to target provider semantic variables and `data-slot` component attributes; CSS targeting old gray/slate utility classes may no longer match. The demo themes illustrate the supported provider UI 0.10 approach. Unresolved supported handles now return `HandleNotFound`, and OAuth/account-management request bodies over 100 KiB return HTTP 413.

**Operators:** This upgrades PDS to 0.5.34 and shared safe-fetch to 0.4.0. Rebuild both core and auth images, verify startup with their bundled Node/Undici versions, and validate outbound identity/service resolution against the stricter URL policy before rollout. No new upstream database migrations were found in the assessed release range; rehearse rollback against copied data rather than assuming runtime compatibility.
