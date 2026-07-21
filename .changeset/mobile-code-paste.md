---
'ePDS': patch
---

Pasting a sign-in code on mobile now fills the complete code instead of only the first character.

**Affects:** End users, Client app developers

**End users:** No action is required; long-press paste and mobile one-time-code autofill now work with the existing segmented code-field appearance. Tapping or clicking a filled code slot selects that character for replacement.

**Client app developers:** Branding CSS that styles an active code slot should use `.otp-box.active` instead of `.otp-box:focus`; the real input now keeps focus while the slots remain presentational.
