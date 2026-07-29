---
'ePDS': minor
---

Entering a sign-in code now works better on phones and with assistive technology.

**Affects:** End users, Client app developers

**End users:** Long-press paste and one-time-code autofill now fill the whole code. Filled positions can be selected and replaced, status messages are announced to screen readers, and the code field respects reduced-motion settings.

**Client app developers:** This is a breaking change for branding CSS that targets the sign-in code field.

- `.otp-box` is now a `<div>` instead of an `<input>`. Selectors such as `input.otp-box`, `input[data-slot]`, and `.otp-box::placeholder` no longer match.
- `.otp-box:focus` no longer matches because one `.otp-input-overlay` now owns focus. Use `.otp-box.active` for the selected position and `.otp-character.placeholder` for empty positions.
- Broad `input` and `input:focus` rules now also match `.otp-input-overlay`. Exclude that class or override it so its background, border, outline, text, and caret stay transparent; otherwise it may cover the visible code boxes.
