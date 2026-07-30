---
'ePDS': patch
---

Account-settings and account-recovery code inputs also strip out characters that aren't part of the code.

**Affects:** End users

**End users:** the same paste/keystroke filter that the main sign-in form already had now applies to the standalone Account Settings sign-in and to the account recovery flow. If you copy your code from somewhere that wraps it in punctuation, or accidentally type a letter into a digits-only code, the input drops the stray characters silently instead of letting them through and rejecting the code as invalid.
