---
'ePDS': patch
---

Sign-in error messages now appear next to the field that caused them, instead of at the top of the page.

**Affects:** End users

**End users:** a rejected sign-in code used to report the problem above the page heading, several elements away from the boxes you had just typed into — easy to miss, and it left the **Verify** button looking like the thing to press again. The message now sits directly between the code boxes and **Verify**, and a failed email submission likewise reads under the email field rather than above it.

When the code is rejected because of too many wrong attempts, the message now carries a **Resend code** link beside it. That case wipes the stored code, so retyping cannot work and a fresh code is the only way forward; the standalone **Resend code** button below the form was easy to overlook. A simple mistyped code is unchanged — the boxes clear and refocus so you can just type it again.
