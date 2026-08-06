---
'ePDS': patch
---

The email sign-in button now waits until the page is ready before accepting clicks.

**Affects:** End users

**End users:** tapping Continue before the sign-in page finished loading could start a broken sign-in attempt that silently did nothing. The button is now disabled until the page is ready. Browsers with JavaScript disabled see a message explaining that JavaScript is required to sign in with email, instead of a button that never responds.
