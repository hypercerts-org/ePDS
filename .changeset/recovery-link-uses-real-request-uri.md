---
'ePDS': patch
---

The "Recover with backup email" link no longer breaks the "Back to sign in" path.

**Affects:** End users

**End users:** clicking **Recover with backup email** on the sign-in page used to leave you on a recovery flow that couldn't return you to the original sign-in: hitting **Back to sign in** at the end landed on a "data you submitted is invalid" error page from the underlying OAuth machinery, because the link forwarded a placeholder URL instead of the real sign-in context. The link now carries the active sign-in's actual context, so the back path round-trips cleanly even if you decide not to use recovery after all.
