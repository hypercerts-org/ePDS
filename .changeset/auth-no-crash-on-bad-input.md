---
'ePDS': patch
---

A single malformed request or malformed client metadata can no longer shut down the login service.

**Affects:** Operators

**Operators:** Errors thrown inside auth-service route handlers (for example a repeated query parameter such as `?request_uri=a&request_uri=b`, or a client metadata document that is `null` or has a non-string `client_name`) now return a 500 response and are logged, instead of ending the process. Client metadata that is not a JSON object is treated as unavailable, and fields of the wrong type are ignored. `GET /auth/recover` returns 400 for a non-string `request_uri`. Unhandled promise rejections that still escape are now logged at error level. No configuration changes.
