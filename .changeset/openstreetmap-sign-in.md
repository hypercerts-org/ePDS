---
'ePDS': minor
---

People can connect their OpenStreetMap account in account settings and then sign in with it.

**Affects:** End users, Client app developers, Operators

**End users:** After signing in once with an email code, you can connect your OpenStreetMap account under Account Settings → OpenStreetMap, and disconnect it again there. Apps that offer it then show "Sign in with OpenStreetMap", which signs you in to that same account. OpenStreetMap never creates a new account; an OpenStreetMap account that isn't connected yet gets a message explaining how to connect it.

**Client app developers:** Add `"openstreetmap"` to `epds_social_providers` in your client metadata. The simplest flow is a "Sign in with OpenStreetMap" button on your own page that adds `epds_social_provider=openstreetmap` to `/oauth/authorize`, which sends users straight to OpenStreetMap without the ePDS login page. It takes no `login_hint`. Listing it also shows the button on the ePDS login page. The demo app lists it. An unconnected identity returns to the login page with `epds_social_error=not_connected`.

**Operators:** Set `OSM_CLIENT_ID` and `OSM_CLIENT_SECRET` (and optionally `OSM_ISSUER`, default `https://www.openstreetmap.org`) to enable it, and register `https://<AUTH_HOSTNAME>/api/auth/callback/openstreetmap` as the redirect URI of a confidential OpenStreetMap OAuth 2 application with only the `openid` scope. Nothing changes while these are unset. Connections are tied to the issuer, so changing `OSM_ISSUER` (for example from the development server to production) means users connect OpenStreetMap again. When set, better-auth's explicit `/link-social` endpoint accepts only OpenStreetMap. See `docs/configuration.md` and `docs/design/openstreetmap-login.md`.
