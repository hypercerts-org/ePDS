---
'ePDS': patch
---

The sign-in page no longer reveals your email address to someone who only knows your username.

**Affects:** End users, Client app developers

**End users:** When an app already knows who you are by username, the sign-in page shows only a partly hidden address such as `al***@example.com` and still sends the code to your real email. If that sign-in has timed out, the page asks you to type your email instead.

**Client app developers:**

- The page served by `/oauth/authorize` no longer contains the account email for a handle or DID `login_hint`, whether the hint is on the URL or only in the pushed authorization request. The code is still sent to the account's email, but anything that read the address from the page's hidden `#otp-email` input, the email field, or the inline script no longer finds it.
- An email `login_hint` pre-fills the form exactly as before.
