---
'ePDS': patch
---

Authorization and account-selection screens now keep their intended branding after the provider interface update.

**Affects:** End users, Client app developers

**End users:** The redesigned authorization screens use consistent ePDS colors, surfaces, and responsive controls instead of partially falling back to upstream styling.

**Client app developers:** Update custom `branding.css` to target provider semantic variables and `data-slot` component attributes; gray/slate utility selectors from provider UI 0.8 are no longer reliable. The demo themes now illustrate the supported provider UI 0.10 approach.
