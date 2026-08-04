---
'ePDS': patch
---

Clickable text on the sign-in screens now looks the same wherever it appears.

**Affects:** End users, Client app developers

**End users:** the same action no longer renders differently depending on where it sits. "Resend code", "Use different email" and "Recover with backup email" are now all plain text that darkens when you point at it, while actions embedded in a sentence — "Send a new code" in an error message, and the Terms of Use and Privacy Policy links — stay underlined so they remain visible against the text around them. Pointing at an underlined action no longer makes its underline vanish, and every one of these actions now shows a focus outline when reached with the keyboard.

**Client app developers:** `--muted-foreground` now also sets the colour of the `.btn-secondary` actions on the sign-in page, which previously hardcoded `#6b6b6b`. If you override that custom property in your `branding.css`, it will now recolour "Resend code" and "Use different email" alongside "Recover with backup email" and the other muted text. Choose a value that clears 4.5:1 contrast against your card background. `--recovery-link-display` is unchanged.
