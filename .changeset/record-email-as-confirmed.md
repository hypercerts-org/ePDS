---
'ePDS': patch
---

Apps you sign in to are now told that your email address is confirmed.

**Affects:** End users, Client app developers, Operators

**End users:** Apps no longer ask you to verify an address you have already confirmed with an emailed code.

**Client app developers:** The `email_verified` claim is now `true` for accounts that signed in through the emailed-code flow, instead of always `false`.

**Operators:** Deploy the auth service and the PDS together — the signed handover between them carries a new required field, and a mixed pair rejects sign-in until both are updated. An older auth service is rejected with an explicit `Missing or invalid email_verified parameter` rather than a generic signature error, so a mixed-version rollout is recognisable in the logs. Accounts predating this release are repaired the next time their owner signs in **through the emailed-code flow**; a sign-in that does not prove control of the address leaves them unconfirmed. To fix the rest, see "Backfilling Email Confirmation" in `docs/deployment.md`.
