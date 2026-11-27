---
'ePDS': minor
---

Apps that offer "Sign in with Atmosphere" can now check that the sign-in came from the same browser that started it.

**Affects:** Client app developers, Operators

**Client app developers:**

- The Atmosphere hand-off to your `epds_handle_login_url` now sets `iss` (this PDS's issuer) and `state` (the `state` from your own PAR request) alongside `handle`.
- `state` can be absent (for example, the PAR request expired or belongs to another client). Refuse the hand-off when it is.
- Before starting the Atmosphere sign-in, check that `state` matches a sign-in you started in this browser and that `iss` is this PDS. Do not rely on the `Referer` header.
- After a valid hand-off, delete the stored `state`. Refuse any later hand-off that reuses it.
- `handle`, `iss` and `state` are now reserved query params on that URL: values your URL already has for them are overwritten or, for `state`, removed.
- See [the tutorial](https://github.com/hypercerts-org/ePDS/blob/main/docs/tutorial.md#optional-offer-atmosphere-handle-sign-in).

**Operators:**

- The `iss` value is the OAuth issuer reported by pds-core (the same `issuer` as in `/.well-known/oauth-authorization-server`), no longer `PDS_PUBLIC_URL`. If pds-core does not report one, the hand-off omits `iss` and the client refuses it.
- Deploy the PDS before the auth service, otherwise `state` is left out until both are updated.
- The login page is now served with `Cache-Control: no-store`.
