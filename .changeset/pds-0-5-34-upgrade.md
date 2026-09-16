---
'ePDS': minor
---

Update the account selection and approval screens while keeping account switching in the email sign-in flow.

**Affects:** End users, Client app developers, Operators

**End users:** Selecting “Another account” continues to open the email sign-in form instead of the server's password form.

**Client app developers:** Review consent and account-picker branding against the updated screens; CSS targeting old gray/slate utility classes may no longer match. Unresolved supported handles now return `HandleNotFound`, and OAuth/account-management request bodies over 100 KiB return HTTP 413.

**Operators:** This upgrades PDS to 0.5.34 and shared safe-fetch to 0.4.0. Rebuild both core and auth images, verify startup with their bundled Node/Undici versions, and validate outbound identity/service resolution against the stricter URL policy before rollout. No new upstream database migrations were found in the assessed release range; rehearse rollback against copied data rather than assuming runtime compatibility.
