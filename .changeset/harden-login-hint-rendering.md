---
'ePDS': patch
---

Fixed a security flaw where a specially crafted sign-in link could run unwanted code on the sign-in page.

**Affects:** Client app developers, Operators

**Client app developers:** An email `login_hint` is now accepted only if it looks like a plain email address (letters, digits and `._%+-` before the `@`, a dotted domain after it, at most 254 characters). A malformed value containing `@` is ignored, and the user sees the normal email form instead of a pre-filled code step. Handle and DID hints are unchanged.

**Operators:** Deploy the updated auth service to pick up the fix. No configuration changes are needed.
