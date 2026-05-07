---
'ePDS': patch
---

Empty Verify clicks no longer flash "Invalid OTP".

**Affects:** End users

**End users:** clicking **Verify** before typing the code (or pressing Enter on an empty form) used to flash a red "Invalid OTP" error, which was both misleading — you didn't type an invalid code, you typed nothing — and counted against the per-account rate limit. The form now just moves the cursor into the first empty digit box and waits for you to type, without bothering anyone with a fake error.
