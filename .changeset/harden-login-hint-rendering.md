---
'ePDS': patch
---

Fixed a security flaw where a specially crafted sign-in link could run unwanted code on the sign-in page.

**Affects:** End users, Client app developers, Operators

**End users:** If a sign-in link carries an email address that isn't written correctly, you now see the normal email form and type your address, instead of going straight to the code step.

**Client app developers:** An email `login_hint` is now accepted only if it looks like a plain email address (letters, digits and `._%+-` before the `@`, a dotted domain after it with no empty labels or labels starting or ending in `-`, at most 254 characters). A malformed value containing `@` is ignored, and the user sees the normal email form instead of a pre-filled code step. Handle and DID hints are unchanged.

**Operators:** Deploy the updated auth service to pick up the fix. No configuration changes are needed.
