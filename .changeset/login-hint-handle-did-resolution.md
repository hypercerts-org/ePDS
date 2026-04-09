---
'epds': patch
---

Accept AT Protocol handles and DIDs as OAuth `login_hint` values.

**Affects:** End users

Signing in to a third-party AT Protocol app (including anything
built on top of Bluesky's OAuth flow) no longer forces you to
retype your email address when the app already knows your handle
or DID. The ePDS login page now jumps straight to the OTP step
whenever your client has passed along a handle, DID, or email as
the OAuth `login_hint`.

Previously, ePDS only recognised email-shaped hints (anything
containing `@`); hints in any other form silently fell through to
the email-entry form. Hints sent only in the Pushed Authorization
Request (PAR) body, without also being duplicated on the
authorization redirect URL, were also missed. Both cases are now
handled: handles and DIDs are resolved to the account email
server-side, and PAR-only hints are read from the stored PAR
request when absent from the query string.
