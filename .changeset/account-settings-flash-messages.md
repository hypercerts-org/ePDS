---
'ePDS': patch
---

Account Settings now confirms every action with a visible banner.

**Affects:** End users

**End users:** when you added a backup email, removed one, changed your handle, revoked a session, or hit a validation error on any of those, the page silently bounced back to the same form with no indication that anything had changed (or what went wrong). The page now shows a green "Backup email added" / "Handle updated" / etc. banner on success, and a red "That handle is not available" / "We couldn't send the verification email" / etc. banner on error — so you know whether your action took effect.
