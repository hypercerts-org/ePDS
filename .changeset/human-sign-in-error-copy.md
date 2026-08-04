---
'ePDS': patch
---

Sign-in errors are written in plain English instead of showing the raw failure code.

**Affects:** End users

**End users:** a rejected code used to report "Invalid OTP", an unexplained acronym that ran straight into the recovery link beside it — "Invalid OTP Send a new code". It now reads "That code didn't work." followed by the link, and the two other common failures are similarly rewritten: an aged-out code says "That code has expired.", and one rejected after repeated wrong attempts says "Too many tries — that code is no longer usable.". Any failure outside those three is still shown as-is rather than hidden behind a generic apology, so an unexpected problem can still be reported accurately.
