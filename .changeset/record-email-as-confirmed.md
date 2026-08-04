---
'ePDS': patch
---

Apps you sign in to are now told that your email address is confirmed.

**Affects:** End users, Client app developers, Operators

**End users:** Apps no longer ask you to verify an address you have already confirmed with an emailed code.

**Client app developers:** The `email_verified` claim is now `true` for accounts that signed in through the emailed-code flow, instead of always `false`.

**Operators:** Deploy the auth service and the PDS together — the signed handover between them carries a new required field, and a mixed pair rejects sign-in until both are updated. Accounts predating this release are repaired on their owner's next sign-in; to fix the rest, see "Backfilling Email Confirmation" in `docs/deployment.md`.
