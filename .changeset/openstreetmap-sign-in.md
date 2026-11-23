---
'ePDS': minor
---

People can connect their OpenStreetMap account in account settings and then sign in with it.

**Affects:** End users, Client app developers, Operators

**End users:** After signing in once with an email code, you can connect your OpenStreetMap account under Account Settings → OpenStreetMap, and disconnect it again there. Apps that offer it then show "Sign in with OpenStreetMap", which signs you in to that same account. OpenStreetMap never creates a new account; an OpenStreetMap account that isn't connected yet gets a message explaining how to connect it.

**Client app developers:** Add `"openstreetmap"` to `epds_social_providers` in your client metadata to show the button, or start it directly with `epds_social_provider=openstreetmap` on `/oauth/authorize`. It takes no `login_hint`. The demo app lists it. An unconnected identity returns to the login page with `epds_social_error=not_connected`.

**Operators:** Set `OSM_CLIENT_ID` and `OSM_CLIENT_SECRET` (and optionally `OSM_ISSUER`, default `https://www.openstreetmap.org`) to enable it, and register `https://<AUTH_HOSTNAME>/api/auth/callback/openstreetmap` as the redirect URI of a confidential OpenStreetMap OAuth 2 application with only the `openid` scope. Nothing changes while these are unset. When set, better-auth's explicit `/link-social` endpoint accepts only OpenStreetMap. See `docs/configuration.md` and `docs/design/openstreetmap-login.md`.
