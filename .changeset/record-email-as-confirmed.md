---
'ePDS': patch
---

Apps you sign in to are now told that your email address is confirmed.

**Affects:** Client app developers, Operators

**Client app developers:** the `email_verified` claim is now `true` for accounts that signed in through the emailed-code flow, instead of always `false`. If your app gated any behaviour on `email_verified` being true, that gate will now open for those accounts.

**Operators:** new accounts are recorded as confirmed at sign-up, and existing accounts are repaired the next time their owner signs in — so most accounts need no action. Use the backfill for accounts whose owners have not signed in since upgrading:

- `pnpm --filter @certified-app/pds-core backfill:email-confirmed --dry-run` reports how many accounts would change.
- Dropping `--dry-run` performs the update. It is idempotent, so re-running is safe.
- Run it with the same environment as the server, so it targets that deployment's account database.
- Accounts that cannot be confirmed are listed by DID at the end and the command exits non-zero, so a scripted run does not report success after partial failure.
- It is deliberately not automatic: it marks every account that has an email address but no confirmation timestamp, so if you provisioned any accounts outside the normal sign-in flow, their addresses would be marked confirmed without having been verified. Check the dry-run count before committing.
