# OpenStreetMap sign-in

OpenStreetMap (OSM) is an OpenID Connect provider
(`<OSM_ISSUER>/.well-known/openid-configuration`), added through
better-auth's generic OAuth plugin (`lib/openstreetmap.ts`). It registers as
an ordinary social provider, so it uses the same `/sign-in/social` and
`/callback/openstreetmap` endpoints as Google.

## Why it is different from Google

ePDS keys every PDS account by a verified email address. OSM never vouches
for one: its discovery document has no `email_verified` claim, and it shares
the address only with the extra `read_email` scope. Trusting OSM's email
would recreate the risk ePDS already refuses for Google addresses Google is
not authoritative for: an address confirmed once, long ago, may have changed
hands.

So an OSM identity is never a way to create or find an account by email. It
is a second way into an account that already proved its address with an
email code.

## How it works

1. A user signs in with an email code (creating the account if needed).
2. Under **Account Settings → OpenStreetMap** they click **Connect**, which
   calls better-auth's `/link-social`. The OAuth state carries this session,
   and better-auth checks it is still live when OSM redirects back.
3. better-auth stores the link as an `account` row keyed by
   `(providerId = openstreetmap, accountId = <issuer host>:<ID token sub>)`,
   for example `www.openstreetmap.org:30869`.
4. From then on, **Sign in with OpenStreetMap** finds the user by that key
   (`findAccountOwnerByKey`), and `/auth/complete` continues with the
   user's own verified email as for any other sign-in.

An OSM identity that is not connected ends at `?error=signup_disabled` and
the login page explains how to connect it.

## The safety argument

- **No account creation.** The provider sets `disableSignUp`, and its
  profile mapping (`mapOsmProfileToUser`) marks the email unverified, so
  the user-creation guard (`refuseUnverifiedUser`) would refuse it too.
- **No matching by email.** The mapping replaces the email with a fresh
  random `<uuid>@users.openstreetmap.invalid`. `.invalid` is reserved
  (RFC 2606), so no email code can reach it, and being random it cannot
  equal any stored address. That matters because OSM is a trusted provider
  (below): better-auth would otherwise implicitly link a sign-in to a
  verified user with the same email.
- **Keyed by issuer and `sub`.** OSM user ids are unique only within one
  OSM instance, so the account key carries the issuer's host
  (`accountSubject`). A link made against the dev server never signs in a
  production user with the same id if `OSM_ISSUER` changes. Switching
  `OSM_ISSUER` therefore means users connect OSM again.
- **Identity from a verified ID token.** `requireIdTokenVerification`
  drops the provider if discovery yields no JWKS; the ID token's signature,
  issuer, audience and nonce are checked, and the userinfo `sub` must
  equal it.
- **Narrow linking relaxations**, only while OSM is configured
  (`openStreetMapAccountLinking`):
  - `trustedProviders: ['openstreetmap']`, so the explicit link is allowed
    although OSM does not verify the email. Implicit linking is covered by
    the placeholder address above.
  - `allowDifferentEmails: true`, because the placeholder never equals the
    user's email. better-auth reads it only for explicit links, and a
    `before` hook (`refuseNonOsmLink`) refuses `/link-social` for any
    provider but OSM, so Google's behaviour is unchanged.
  - `allowUnlinkingAll: true`, so OSM can be disconnected again. Email-code
    sign-in needs no `account` row.
- **One account per identity.** better-auth refuses to link an OSM `sub`
  already linked to another user.

## Scope

ePDS asks OSM for `openid` only. It learns the OSM user id and username, not
the email, and gets no permission to edit the map: apps that edit OSM run
their own OSM OAuth with the scopes they need.

## Tests

`better-auth-osm-sign-in.test.ts` and the OpenStreetMap block of
`create-better-auth.test.ts` drive these flows through real better-auth
instances with OSM's endpoints stubbed and a signed ID token.
