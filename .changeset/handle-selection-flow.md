---
'epds': minor
---

Handle selection step in the new-user signup flow.

**Affects:** End users, Client app developers, Operators

New users can now choose their handle during signup instead of
being assigned a random one unconditionally. The behaviour is
controlled by a single setting, **handle mode**, which accepts the
following case-sensitive values:

- `picker` — always show the picker, no random option offered.
- `random` — always assign a random handle, no picker.
- `picker-with-random` _(default)_ — show the picker but include a
  "generate random" option.

**End users:** the signup flow now shows a handle picker by default
instead of assigning a random handle. You can type a custom handle
and the picker will check availability as you type, or click the
random-handle button to take what the old flow would have given
you. The picker now accepts handles as short as 5 characters and
handles are validated through `@atproto/syntax` in addition to the
PDS's own validation, so some handles that used to be accepted may
now be rejected up-front with a clearer error. The picker layout
has been widened to accommodate long PDS domain names without
truncation.

**Client app developers (building on top of ePDS):** the handle
mode is resolved from three sources with the following precedence
(first match wins):

1. `epds_handle_mode` query parameter on the `/oauth/authorize`
   request.
2. `epds_handle_mode` field in the OAuth **client metadata JSON**
   served at the client's `client_id` URL.
3. `EPDS_DEFAULT_HANDLE_MODE` environment variable on the auth
   service.
4. Built-in default: `picker-with-random`.

This precedence was previously wrong — the env var was consulted
before the client metadata, so clients could not override a server
default. If you relied on that bug, your env var setting will now
be overridden by whatever the client metadata says.

To force a specific handle mode for users of your app, add the
field to the client metadata JSON that your `client_id` URL
returns, alongside the standard OAuth fields:

```json
{
  "client_id": "https://example.com/oauth/client-metadata.json",
  "client_name": "Example",
  "redirect_uris": ["https://example.com/oauth/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "atproto transition:generic",
  "token_endpoint_auth_method": "none",
  "application_type": "web",
  "dpop_bound_access_tokens": true,
  "epds_handle_mode": "picker"
}
```

Unknown or invalid values are silently ignored and fall through to
the next source. If you need to override per-request (e.g. for a
specific signup campaign), append `?epds_handle_mode=picker` to
your `/oauth/authorize` URL.

**Operators:** set `EPDS_DEFAULT_HANDLE_MODE` in the auth service
environment to change the fallback for clients that don't specify
one. See `.env.example` for documentation.
