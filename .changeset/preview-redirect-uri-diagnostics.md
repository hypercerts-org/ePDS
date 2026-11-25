---
'ePDS': patch
---

Preview diagnostics count only redirect URI entries that sign-in can read.

**Affects:** Client app developers

The preview reports an error if `redirect_uris` has no string entries, matching the live metadata resolver. It does not validate the URLs themselves.
