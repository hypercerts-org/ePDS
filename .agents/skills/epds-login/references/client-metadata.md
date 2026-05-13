# Client Metadata Reference

Your app must host a JSON document at a publicly accessible HTTPS URL.
This URL is also your `client_id`. ePDS fetches it to validate your app
and the auth service uses it for branding (name, logo, email templates).

## Choosing a client authentication method

Before you copy the examples below, decide whether your app will be a
**confidential client** (recommended) or a **public client**. The choice
is recorded in `token_endpoint_auth_method` and has a significant
user-visible consequence.

**Confidential client — `token_endpoint_auth_method: "private_key_jwt"`:**
your app holds a private key, publishes the matching public key as a JWKS
document, and signs a short-lived `client_assertion` JWT on every PAR and
token request. The PDS can verify that requests genuinely come from your
server. Under this mode, the PDS will remember a user's consent decision
and skip the consent screen on subsequent logins for the same (user,
client) pair as long as the requested scopes are a subset of what was
previously granted.

**Public client — `token_endpoint_auth_method: "none"`:** your app holds
no secret. This is simpler to set up but has an important downside: the
upstream `@atproto/oauth-provider` considers any public client that is
neither in the PDS's `PDS_OAUTH_TRUSTED_CLIENTS` allow-list nor marked
first-party to be untrusted enough that it forces `prompt=consent` on
every authorize request. Previously-stored grants are never honoured.
This is a deliberate atproto security property — a public web page has
no way to prove it is still the legitimate instance of your client, so
every session must start with an explicit human consent click. The
root cause is in `@atproto/oauth-provider`'s `isFirstPartyClient()`
check — see `packages/oauth/oauth-provider/src/client/client-manager.ts`
in the atproto repository.

**Recommendation:** use `private_key_jwt` for anything users will sign in
to more than once. Use `none` only for local development scaffolding,
one-off scripts, or apps where the per-login consent screen is genuinely
desired behaviour. The rest of this file shows the `private_key_jwt`
form as the default; see [Public client metadata](#public-client-metadata)
at the end for the shorter `none` variant.

## Minimal example (confidential client)

You must provide the public half of your signing key either via a
`jwks_uri` (remote URL) or inline as a `jwks` object. The two are
mutually exclusive — the PDS rejects metadata that has both.

**Option A — remote JWKS (`jwks_uri`):**

```json
{
  "client_id": "https://yourapp.example.com/client-metadata.json",
  "client_name": "Your App Name",
  "redirect_uris": ["https://yourapp.example.com/api/oauth/callback"],
  "scope": "atproto transition:generic",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "private_key_jwt",
  "token_endpoint_auth_signing_alg": "ES256",
  "jwks_uri": "https://yourapp.example.com/jwks.json",
  "dpop_bound_access_tokens": true
}
```

**Option B — inline JWKS (`jwks`):**

```json
{
  "client_id": "https://yourapp.example.com/client-metadata.json",
  "client_name": "Your App Name",
  "redirect_uris": ["https://yourapp.example.com/api/oauth/callback"],
  "scope": "atproto transition:generic",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "private_key_jwt",
  "token_endpoint_auth_signing_alg": "ES256",
  "jwks": {
    "keys": [
      {
        "kty": "EC",
        "crv": "P-256",
        "x": "...",
        "y": "...",
        "kid": "my-key-1"
      }
    ]
  },
  "dpop_bound_access_tokens": true
}
```

With `jwks_uri`, key rotation is simpler (update the endpoint, no client
metadata redeploy). With inline `jwks`, there is no extra endpoint to
host — useful for simpler setups. See
[Publishing the JWKS document](#publishing-the-jwks-document) below for
key generation and serving details.

## All supported fields

| Field                             | Required    | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| --------------------------------- | ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `client_id`                       | Yes         | Must match the URL where this file is hosted                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `client_name`                     | Yes         | Shown on the login page and in OTP emails                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `redirect_uris`                   | Yes         | Array of allowed callback URLs after login                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `scope`                           | Yes         | Always `"atproto transition:generic"`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `grant_types`                     | Yes         | Always `["authorization_code", "refresh_token"]`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `response_types`                  | Yes         | Always `["code"]`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `token_endpoint_auth_method`      | Yes         | `"private_key_jwt"` (recommended) or `"none"` — see above                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `token_endpoint_auth_signing_alg` | Conditional | Required when `token_endpoint_auth_method` is `"private_key_jwt"`. Must be `"ES256"`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `jwks_uri`                        | Conditional | Public JWKS URL. Required for `"private_key_jwt"` unless `jwks` is provided. Mutually exclusive with `jwks`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `jwks`                            | Conditional | Inline JWKS object (`{"keys": [...]}`). Alternative to `jwks_uri`. Mutually exclusive with `jwks_uri`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `dpop_bound_access_tokens`        | Yes         | Always `true`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `client_uri`                      | No          | Your app's homepage URL                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `logo_uri`                        | No          | URL to your app logo (shown on login page)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `email_template_uri`              | No          | URL to a custom OTP email HTML template                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `email_subject_template`          | No          | Custom email subject line with `{{code}}` placeholder                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `brand_color`                     | No          | Hex colour for buttons and input focus rings (default: `#1A130F`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `background_color`                | No          | Hex colour for the login page background (default: `#F2EBE4`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `epds_handle_mode`                | No          | ePDS extension. Handle picker variant for new users: `"picker"`, `"random"`, or `"picker-with-random"` (default). See [tutorial](../../../../docs/tutorial.md#optional-control-the-handle-picker).                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `epds_skip_consent_on_signup`     | No          | ePDS extension. When `true`, skip the consent screen on initial sign-up. Only honoured when the PDS has `PDS_SIGNUP_ALLOW_CONSENT_SKIP=true` AND the client is in `PDS_OAUTH_TRUSTED_CLIENTS`.                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `epds_handle_login_url`           | No          | ePDS extension. Absolute http(s) URL on your client's origin. When set, the auth-service login page renders an "Or sign in with ATProto/Bluesky" button; submitting a handle redirects the browser to this URL with `?handle=<value>` appended. See [tutorial](../../../../docs/tutorial.md#optional-offer-atprotobluesky-handle-sign-in).                                                                                                                                                                                                                                                                                                         |
| `branding`                        | No          | ePDS extension. Object containing a `css` string (max 32 KB) and/or `favicon_url` and `favicon_url_dark` (each HTTPS, ≤2048 chars post-normalisation, **same-origin as `client_id`** because CSP `img-src` only widens to that origin). ePDS injects the CSS into login, OTP, choose-handle, recovery, and consent pages, and replaces the default favicon on the auth-service pages — emitting two `prefers-color-scheme`-gated `<link>` tags when both light and dark URLs are supplied, otherwise a single bare `<link>`. Only honoured when the client is in `PDS_OAUTH_TRUSTED_CLIENTS`. Iterate via auth-service preview routes (see below). |

## Iterating on `branding.css`

Both auth-service and pds-core expose static `/preview/*` routes (when the
operator sets `AUTH_PREVIEW_ROUTES=1` / `PDS_PREVIEW_ROUTES=1`, typically on
preview envs and `pr-base`) that render each page with fixture data so client
devs can iterate without going through a real OAuth flow. auth-service covers
login / OTP / choose-handle / recovery; pds-core covers the consent page. See
[the client tutorial's "Iterating on `branding.css`" section](../../../../docs/tutorial.md#iterating-on-brandingcss)
for the route list and example URLs.

## Custom email templates

If you provide `email_template_uri`, the auth service fetches that URL and
uses it as the OTP email body instead of the default Certified template.

Your template must be an HTML file. Supported placeholders:

| Placeholder                           | Description                               |
| ------------------------------------- | ----------------------------------------- |
| `{{code}}`                            | The 8-digit OTP code — **required**       |
| `{{app_name}}`                        | Value of `client_name` from your metadata |
| `{{logo_uri}}`                        | Value of `logo_uri` from your metadata    |
| `{{#is_new_user}}...{{/is_new_user}}` | Block shown only on first sign-up         |
| `{{^is_new_user}}...{{/is_new_user}}` | Block shown only on subsequent sign-ins   |

Minimal template example:

```html
<!DOCTYPE html>
<html>
  <body>
    <p>Your {{app_name}} sign-in code is:</p>
    <h1>{{code}}</h1>
    {{#is_new_user}}
    <p>Welcome! Your account has been created.</p>
    {{/is_new_user}}
  </body>
</html>
```

`email_subject_template` follows the same placeholder syntax:

```
"email_subject_template": "{{code}} — Your {{app_name}} sign-in code"
```

## Publishing the JWKS document

When using `private_key_jwt`, you must make the public half of your ES256
key pair available to the PDS so it can verify `client_assertion`
signatures. You have two options: host a `jwks_uri` endpoint, or embed
the key inline in your client metadata as `jwks`.

### Generate a key pair

The ePDS repository includes a generation script:

```bash
pnpm jwk:generate
# Outputs compact JSON: {"kty":"EC","crv":"P-256","x":"...","y":"...","d":"...","kid":"..."}
```

Or use `@atproto/jwk-jose` programmatically:

```typescript
import { JoseKey } from '@atproto/jwk-jose'

const key = await JoseKey.generate(['ES256'])
const privateJwk = key.privateJwk // { kty: "EC", crv: "P-256", x, y, d, kid }
```

Store the private JWK securely (e.g. in an environment variable or secret
manager). You will need it when constructing the `NodeOAuthClient` keyset.

### Option A: Serve a `jwks_uri` endpoint

Your `jwks_uri` must return a `{"keys": [...]}` document containing only
the **public** half of each key. Strip the `d` parameter (the private
component) before publishing:

```typescript
// Example: Express endpoint
app.get('/jwks.json', (req, res) => {
  const { d, ...publicJwk } = privateJwk // strip private component
  res.json({ keys: [publicJwk] })
})
```

The response must have `Content-Type: application/json`. ePDS fetches this
URL when your app makes a PAR or token request with `client_assertion` to
verify the signature.

This approach makes key rotation simpler — update the endpoint without
redeploying your client metadata.

### Option B: Embed keys inline as `jwks`

Instead of hosting a separate endpoint, embed the public key directly in
your client metadata JSON:

```json
{
  "jwks": {
    "keys": [
      {
        "kty": "EC",
        "crv": "P-256",
        "x": "...",
        "y": "...",
        "kid": "my-key-1"
      }
    ]
  }
}
```

Strip the `d` (private) parameter before embedding — only the public
components (`kty`, `crv`, `x`, `y`, `kid`) should appear. This is
simpler for apps that don't want to host an extra endpoint, but key
rotation requires updating and redeploying the client metadata file.

### Key rotation

Whether using `jwks_uri` or inline `jwks`, you can include multiple keys
in the `keys` array. ePDS matches by `kid`. To rotate:

1. Generate a new key pair
2. Add the new public key to the JWKS array
3. Start signing with the new private key
4. After all outstanding tokens expire, remove the old public key

## Public client metadata

If you are building a local development tool, one-off script, or app
where forcing a consent screen on every login is acceptable, you can use
the simpler public client form. See
[Choosing a client authentication method](#choosing-a-client-authentication-method)
above for the trade-offs.

```json
{
  "client_id": "https://yourapp.example.com/client-metadata.json",
  "client_name": "Your App Name",
  "redirect_uris": ["https://yourapp.example.com/api/oauth/callback"],
  "scope": "atproto transition:generic",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "dpop_bound_access_tokens": true
}
```

No `jwks_uri`, `token_endpoint_auth_signing_alg`, or key management
required. The trade-off: the PDS will force a consent screen on every
login unless your `client_id` is in the PDS's `PDS_OAUTH_TRUSTED_CLIENTS`
allow-list.

## Local development

During local development you can use `http://localhost` client IDs. The
`client_id` must still be a reachable URL — ePDS fetches it at runtime.
Use a local server or `ngrok` to expose your metadata endpoint.
