---
'ePDS': minor
---

Entering a sign-in code now works better on phones and with assistive technology.

**Affects:** End users, Client app developers

**End users:** Long-press paste and one-time-code autofill now fill the whole code. Filled positions can be selected and replaced, status messages are announced to screen readers, and the code field respects reduced-motion settings.

**Client app developers:** Existing trusted-client visual styling on direct `input` selectors and their focus or placeholder states continues to style the sign-in code slots automatically. Common `input.otp-box`, `input[data-slot]`, `.otp-box:focus`, and `.otp-box::placeholder` forms are also supported. New branding should use `.otp-box.active` for the selected position and `.otp-character.placeholder` for empty positions; `.otp-input-overlay` is internal and protected from broad `input` rules. Browser automation that previously filled each `.otp-box` should fill the single `#code` input instead; malformed CSS, mechanical input declarations, and more complex DOM-coupled selectors remain unchanged.
