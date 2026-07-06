---
'ePDS': patch
---

Failed sign-in code entries now show up in the server logs, split by reason.

**Affects:** Operators

**Operators:** the auth service now logs its own 4xx client errors — most usefully the sign-in code failures that the browser posts straight to `/api/auth/sign-in/email-otp`, which previously reached no log at all.

- Each failure is logged at `warn` (visible at the default `info` level, no `LOG_LEVEL` change needed) under the `auth:better-auth` logger name, with the message `better-auth API error` and a `message` field carrying the reason verbatim: `OTP expired`, `Invalid OTP`, or `Too many attempts`.
- Counting `OTP expired` vs `Invalid OTP` over time separates users whose code genuinely lapsed (late email delivery) from users retyping a stale code, so a rise in `OTP expired` points at delivery delay rather than user error.
- Only 4xx errors are logged here; 3xx redirects are filtered out and 5xx errors are already logged by the framework, so this adds no duplicate 5xx noise.
- The email address is not included: the framework hands this logging hook the instance-wide context, not the per-request body, so the address is not reliably available at that point.
