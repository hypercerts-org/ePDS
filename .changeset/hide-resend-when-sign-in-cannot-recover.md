---
'ePDS': patch
---

Sign-in no longer offers "Resend code" when the new code wouldn't have worked anyway.

**Affects:** End users

**End users:** Previously, if you sat on the email-code step long enough that the underlying sign-in had silently timed out (most often: leaving the tab in the background while reading email on your phone, or coming back after an interruption), the page would still show **Resend code**. Clicking it sent you a fresh email, but the moment you typed the new code you'd see "Sign in failed" — the code was issued for a sign-in that could no longer complete, so it never had a chance.

The page now hides the Resend button as soon as it knows the sign-in can't be recovered, and shows **Start over** in its place. Clicking Start over takes you back to the app you came from to begin again, instead of letting you waste time on a code that couldn't work.

If you're actively using the page (the tab in the foreground), nothing changes: Resend stays available and works the same way it always has.
