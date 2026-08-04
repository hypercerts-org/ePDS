---
'ePDS': patch
---

Apps you sign in to are now told that your email address is confirmed.

**Affects:** Client app developers, Operators

**Client app developers:** the `email_verified` claim is now `true` for accounts created through the sign-in flow, instead of always `false`. If your app gated any behaviour on `email_verified` being true, that gate will now open for new accounts — and for existing accounts once the operator runs the backfill below.

**Operators:** accounts created from now on are stamped automatically; no action required for them. Accounts created before this release keep `email_verified: false` until you backfill them:

- `pnpm --filter @certified-app/pds-core backfill:email-confirmed --dry-run` reports how many accounts would change.
- Dropping `--dry-run` performs the update. It is idempotent, so re-running is safe.
- Run it with the same environment as the server, so it targets that deployment's account database.
- It is deliberately not automatic: it marks every account that has an email address but no confirmation timestamp, so if you provisioned any accounts outside the normal sign-in flow, their addresses would be marked confirmed without having been verified. Check the dry-run count before committing.
