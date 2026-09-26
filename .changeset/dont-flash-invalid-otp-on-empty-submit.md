---
'ePDS': patch
---

Verify stays disabled until the code is complete, and incomplete submits no longer flash "Invalid OTP".

**Affects:** End users

**End users:** clicking **Verify** before typing the whole code (or pressing Enter on an empty form) used to flash a red "Invalid OTP" error, which was both misleading — you didn't type an invalid code, you typed nothing — and counted against the per-account rate limit. The **Verify** button is now greyed out until every box is filled, so it's clear up front that there's nothing to submit yet. If a submit still reaches the form another way (Enter, or your password manager autofilling), it's ignored: the cursor moves to the first empty box and no fake error appears.
