---
'ePDS': patch
---

Fixed a flaw that let someone guess a sign-in code faster than the five-attempt limit should allow.

**Affects:** End users, Operators

**End users:** Sign-in codes still allow five wrong tries and expire after 10 minutes. Guesses sent at the same moment are now refused instead of being counted as a single try.

**Operators:** Upgrades `better-auth` from 1.4.18 to 1.7.26, which fixes GHSA-2f9c-7xj7-gh55 (concurrent wrong email-OTP guesses were counted as one attempt). No configuration or environment variable changes. Better Auth's database migrations run automatically at startup as before. Two behaviour changes worth knowing: a failed Google sign-in redirect to `/auth/complete` for an unverified email now also carries an `error_description` query parameter, and a state-mismatch redirect now keeps `epds_social_provider=google`. `/account/verify-otp` now shows the "invalid or expired code" message for a wrong code instead of redirecting to `/account`.
