---
'ePDS': patch
---

Apps that start sign-in from your handle now show the PDS password page again.

**Affects:** End users, Client app developers

**End users:** If an app already knows your AT Protocol handle and starts sign-in from it, you will see the familiar PDS handle/password page instead of being sent to the email-code step. Email-based sign-in is unchanged.

**Client app developers:** PAR-body `login_hint` values that are AT Protocol handles or DIDs are handed back to pds-core's stock OAuth UI. Email `login_hint` values should still be placed on the `/oauth/authorize` redirect URL, not in the PAR body, and continue to use the ePDS email-code flow.
