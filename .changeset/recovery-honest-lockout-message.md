---
'ePDS': patch
---

Account-recovery sign-in shows useful guidance when the code can no longer be used.

**Affects:** End users

**End users:** when recovering your account via a backup email, typing the wrong code enough times locked out the original code — but the page kept saying "Invalid or expired code. Please try again.", which implied more typing might help. The page now distinguishes that case and says "That code can no longer be used. Click 'Resend code' below to get a fresh one." pointing you at the Resend button right below the error, matching the standalone Account Settings sign-in flow.
