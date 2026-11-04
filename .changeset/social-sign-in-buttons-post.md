---
'ePDS': patch
---

The "Sign in with Google" button now works, and each client app chooses whether to show it.

**Affects:** End users, Client app developers, Operators

**End users:** Clicking the button used to end on a "not found" page. If a sign-in cannot be started, the page now says so and the button can be pressed again. Only one sign-in can be in progress at a time, so pressing a second option while the first is starting no longer breaks the first.

**Client app developers:** The Google button is now opt-in per client, like the ATProto/Bluesky button. Add `"epds_social_providers": ["google"]` to your client metadata to show it. Clients that do not list it see no Google button, even when the operator has configured Google.

**Operators:** The button now POSTs `{ provider, callbackURL: '/auth/complete' }` to `/api/auth/sign-in/social` instead of linking to it with a GET, which better-auth answers with 404. The page then follows the returned URL only when it is an https URL on `accounts.google.com`; any other response shows the sign-in error instead. Configuring Google no longer adds its button to every client's login page; only clients that list it in `epds_social_providers` get it. Because the button never worked before this change (every click returned 404), no client loses a working sign-in. Branding CSS that targeted `a.btn-google` should target `.btn-google` instead.
