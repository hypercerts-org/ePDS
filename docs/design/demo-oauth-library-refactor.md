# Demo OAuth client: refactor to `@atproto/oauth-client-node`

**Status:** planned, follow-up to PR #21
**Tracks:** [ePDS#56](https://github.com/hypercerts-org/ePDS/issues/56)

## Motivation

During PR #21 we added confidential-client (`private_key_jwt`) support to
`packages/demo` to unblock HYPER-270. The existing demo OAuth code was
already hand-rolled before that work — PKCE, DPoP, PAR assembly, token
exchange, DPoP nonce retry loops, signature DER→raw conversion — and we
extended it by hand-rolling client_assertion signing on top.

That extension surfaced exactly the class of bug the hand-rolled approach
invites:

- Forgot to send `client_assertion` on PAR at all (only added it to the
  token exchange). Error: `client authentication method "private_key_jwt"
required a "client_assertion"`.
- Used the wrong `aud` claim value — passed the endpoint URL
  (`parEndpoint`/`tokenUrl`) instead of the authorization server's
  `issuer` identifier. Error: `Validation of "client_assertion" failed:
unexpected "aud" claim value`.
- Neither mistake is caught by any unit test. Both only surface when the
  PDS rejects the request at runtime.

Each of these is a textbook case of "two uncoordinated implementations of
an OAuth detail drifting apart". The authoritative source for what ePDS
expects is `@atproto/oauth-provider`; the authoritative client-side
implementation that agrees with it is `@atproto/oauth-client-node`. If
the demo uses the library, these mistakes become impossible — the library
reads the authorization server metadata it's negotiating with and picks
the right value.

## Scope

### In scope

- Replace the hand-rolled OAuth primitives in
  `packages/demo/src/lib/auth.ts`:
  - PKCE helpers (`generateCodeVerifier`, `generateCodeChallenge`).
  - DPoP keypair generation and proof signing (`generateDpopKeyPair`,
    `restoreDpopKeyPair`, `createDpopProof`, the DER→raw `derToRaw`
    helper).
  - `discoverOAuthEndpoints`.
- Replace the hand-rolled `client_assertion` logic in
  `packages/demo/src/lib/client-jwk.ts`.
- Collapse `packages/demo/src/app/api/oauth/login/route.ts` to a thin
  wrapper around `client.authorize(input, opts)`.
- Collapse `packages/demo/src/app/api/oauth/callback/route.ts` to a thin
  wrapper around `client.callback(params)`.
- Serve `client.clientMetadata` from
  `packages/demo/src/app/client-metadata.json/route.ts`.
- Serve `client.jwks` from `packages/demo/src/app/jwks.json/route.ts`.
- Update or delete tests that exercised the hand-rolled primitives:
  - `packages/demo/src/__tests__/auth-helpers.test.ts` — delete (tests
    primitives that will cease to exist).
  - `packages/demo/src/__tests__/client-jwk.test.ts` — rewrite as a
    thin smoke test of the Keyset shim, or delete if nothing remains
    worth testing.
  - `packages/demo/src/__tests__/oauth-login-flow2.test.ts` — revisit
    to make sure its assertions still make sense against the new
    library-driven shape; rewrite or delete as needed.

### Out of scope

- Any change to pds-core, auth-service, or the consent-screen behaviour.
  The PDS side of this is already correct; only the demo is being moved
  to a standard library.
- Any change to the HYPER-270 e2e scenario. It should continue to pass
  against the refactored demo unchanged.
- Removal of `EPDS_CLIENT_PRIVATE_JWK` — the env var name stays, its
  value format stays (ES256 P-256 JWK as JSON), only the code that
  consumes it changes.
- Refactoring the auth-service or pds-core OAuth code — they already
  use `@atproto/oauth-provider` directly, which is the upstream
  counterpart to the library being introduced client-side here.

## Design sketch

### Package dependencies

Add to `packages/demo/package.json`:

- `@atproto/oauth-client-node` (latest — at time of writing, `^0.3.17`).
- `@atproto/jwk-jose` (latest — at time of writing, `^0.1.11`,
  already present transitively via `@atproto/oauth-provider`).

Remove (once the hand-rolled code is deleted):

- `jose` as a direct dep if nothing else in the demo uses it after the
  refactor. `jose` will still be present transitively through the
  atproto packages above.

### New singleton OAuth client module

Create `packages/demo/src/lib/oauth.ts` that instantiates a single
`NodeOAuthClient` for the process lifetime:

```ts
import { NodeOAuthClient } from '@atproto/oauth-client-node'
import { JoseKey } from '@atproto/jwk-jose'
import { getBaseUrl } from './auth.js'
import { makeStateStore, makeSessionStore } from './oauth-cookie-stores.js'

let _client: NodeOAuthClient | undefined

export async function getOAuthClient(): Promise<NodeOAuthClient> {
  if (_client) return _client

  const baseUrl = getBaseUrl()
  const privateJwkRaw = process.env.EPDS_CLIENT_PRIVATE_JWK
  if (!privateJwkRaw) {
    throw new Error(
      'EPDS_CLIENT_PRIVATE_JWK is required: the demo is always run as a ' +
        'confidential OAuth client in this codebase (see HYPER-270)',
    )
  }

  const clientName = process.env.EPDS_CLIENT_NAME ?? 'ePDS Demo'

  const keyset = [await JoseKey.fromImportable(privateJwkRaw)]

  _client = new NodeOAuthClient({
    clientMetadata: {
      client_id: `${baseUrl}/client-metadata.json`,
      client_name: clientName,
      client_uri: baseUrl,
      logo_uri: `${baseUrl}/certified-logo.png`,
      redirect_uris: [`${baseUrl}/api/oauth/callback`],
      grant_types: ['authorization_code', 'refresh_token'],
      scope: 'atproto transition:generic',
      response_types: ['code'],
      application_type: 'web',
      token_endpoint_auth_method: 'private_key_jwt',
      token_endpoint_auth_signing_alg: 'ES256',
      dpop_bound_access_tokens: true,
      jwks_uri: `${baseUrl}/jwks.json`,
      ...(process.env.EPDS_SKIP_CONSENT_ON_SIGNUP === 'true' && {
        epds_skip_consent_on_signup: true,
      }),
    },
    keyset,
    stateStore: makeStateStore(),
    sessionStore: makeSessionStore(),
  })

  return _client
}
```

The client is **always** a confidential client in the refactored
version. The "no keypair, fall back to public client" mode that exists
in PR #21's code is dropped because it's incompatible with running
against any PDS that honours the upstream force-consent-for-public-clients
rule (which is all of them). `scripts/setup.sh` always generates a
keypair; there is no scenario where the demo should run without one.

### State and session stores

`NodeOAuthClient` requires `stateStore` (for in-flight authorization
requests) and `sessionStore` (for post-exchange authenticated sessions).
The existing demo uses signed cookies for both — that pattern can
continue, but the stores need to be request-scoped rather than process-
global because cookies are per-request.

Two options:

1. **Per-request stores.** `login/route.ts` and `callback/route.ts`
   each construct their own `NodeOAuthClient` with stores closed over
   the current `cookies()` handle. The process-global singleton becomes
   a factory instead.

2. **Global stores with a shim.** Store entries live in a short-lived
   in-memory Map keyed by state token; a middleware reads the
   corresponding cookie before each route handler runs and populates
   the Map, writes cookie changes back before the response. Simpler in
   theory but Next.js doesn't offer a clean middleware hook for this
   shape.

Option 1 is the path. Trade-off is creating a fresh `NodeOAuthClient`
instance per request, which is lightweight: the `keyset` is shared
(import once at module load), and the rest of the client's state
(metadata, resolver caches) can be memoised on a per-process basis by
wrapping the actual instantiation behind a small factory that closes
over a `WeakMap`-keyed state store wrapper.

Rough shape of `packages/demo/src/lib/oauth-cookie-stores.ts`:

```ts
import type { NodeSavedState, Session } from '@atproto/oauth-client-node'
import type { ReadonlyRequestCookies } from 'next/dist/server/web/spec-extension/adapters/request-cookies'
import type { ResponseCookies } from 'next/dist/compiled/@edge-runtime/cookies'

export function makeStateStore(
  read: ReadonlyRequestCookies,
  write: ResponseCookies,
) {
  return {
    async set(key: string, state: NodeSavedState): Promise<void> {
      write.set(`oauth_state_${key}`, signAndEncode(state), {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        maxAge: 600,
        path: '/',
      })
    },
    async get(key: string): Promise<NodeSavedState | undefined> {
      const c = read.get(`oauth_state_${key}`)
      return c ? verifyAndDecode(c.value) : undefined
    },
    async del(key: string): Promise<void> {
      write.delete(`oauth_state_${key}`)
    },
  }
}

export function makeSessionStore(
  read: ReadonlyRequestCookies,
  write: ResponseCookies,
) {
  /* same shape, keyed by `oauth_session_${sub}` */
}
```

`signAndEncode` / `verifyAndDecode` reuse the existing HMAC-signed
cookie helpers in `packages/demo/src/lib/session.ts`.

### Login route

```ts
// packages/demo/src/app/api/oauth/login/route.ts
export async function GET(req: NextRequest) {
  const url = new URL(req.url)
  const email = url.searchParams.get('email') || ''
  const handle = url.searchParams.get('handle') || ''
  const handleMode = url.searchParams.get('handle_mode') || ''

  if (email && !validateEmail(email)) {
    return NextResponse.redirect(new URL('/?error=invalid_email', ...))
  }
  if (handle && !validateHandle(handle)) {
    return NextResponse.redirect(new URL('/?error=invalid_handle', ...))
  }

  await checkRateLimit(...)

  const response = NextResponse.redirect('/')  // placeholder, updated below
  const cookiesRead = await cookies()
  const cookiesWrite = response.cookies

  const client = getOAuthClient(
    makeStateStore(cookiesRead, cookiesWrite),
    makeSessionStore(cookiesRead, cookiesWrite),
  )

  // Input resolution: handle → library resolves identity; otherwise →
  // pass PDS_URL directly as a service URL (the library accepts this).
  const input = handle || PDS_URL
  const authorizeUrl = await client.authorize(input, {
    state: crypto.randomBytes(16).toString('base64url'),
  })

  // ePDS auth-service reads login_hint off the authorize URL query
  // string to pre-fill its OTP form. The library doesn't support
  // passing login_hint through AuthorizeOptions (it's omitted from
  // the pass-through type), so we append it manually for the
  // email-based path. The value is the user's email.
  if (email) {
    authorizeUrl.searchParams.set('login_hint', email)
  }
  if (handleMode) {
    authorizeUrl.searchParams.set('epds_handle_mode', handleMode)
  }

  response.headers.set('Location', authorizeUrl.toString())
  return response
}
```

Down from ~290 lines to ~40.

### Callback route

```ts
// packages/demo/src/app/api/oauth/callback/route.ts
export async function GET(req: NextRequest) {
  const url = new URL(req.url)
  const response = NextResponse.redirect(new URL('/welcome', getBaseUrl()))
  const cookiesRead = await cookies()
  const cookiesWrite = response.cookies

  const client = getOAuthClient(
    makeStateStore(cookiesRead, cookiesWrite),
    makeSessionStore(cookiesRead, cookiesWrite),
  )

  try {
    const { session } = await client.callback(url.searchParams)
    // session.did / session.handle come from the successful exchange.
    const userCookie = createUserSessionCookie({
      userDid: session.did,
      userHandle: await resolveDidToHandle(session.did),
      createdAt: Date.now(),
    })
    response.cookies.set(userCookie.name, userCookie.value, {...})
    return response
  } catch (err) {
    console.error('[oauth/callback] failed:', err)
    return NextResponse.redirect(new URL('/?error=auth_failed', getBaseUrl()))
  }
}
```

Down from ~220 lines to ~30.

### Metadata and JWKS routes

```ts
// packages/demo/src/app/client-metadata.json/route.ts
export async function GET() {
  const client = await getOAuthClient(...)
  return NextResponse.json(client.clientMetadata, {
    headers: { 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'public, max-age=300' },
  })
}
```

```ts
// packages/demo/src/app/jwks.json/route.ts
export async function GET() {
  const client = await getOAuthClient(...)
  return NextResponse.json(client.jwks, {
    headers: { 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'public, max-age=60' },
  })
}
```

Both are thin wrappers around what the library constructs for us.
Note that these GET handlers are called without a user-request context
(no cookies to read/write), so the `get` helper needs a variant that
builds a client without cookie stores — or we accept that the client
instance built at module load time is the one whose `clientMetadata`
and `jwks` we serve.

### Tests

- **Delete `packages/demo/src/__tests__/auth-helpers.test.ts`** —
  tests `generateCodeVerifier`, `generateCodeChallenge`,
  `generateDpopKeyPair`, `restoreDpopKeyPair`, `createDpopProof`,
  `derToRaw`. All of these functions get deleted.
- **Delete `packages/demo/src/__tests__/client-jwk.test.ts`** — tests
  the hand-rolled `jose`-based `signClientAssertion`. Replaced by
  `JoseKey` which the library handles internally.
- **Review `packages/demo/src/__tests__/oauth-login-flow2.test.ts`** —
  it tests the full login flow shape against a mocked PDS. After the
  refactor, the route handler is a different shape; the test may need
  rewriting or may become redundant if the e2e scenario covers the
  same ground with less mocking.
- Add a small integration-style test that:
  1. Stubs `NodeOAuthClient.authorize()` to return a known URL.
  2. Calls the login route with `?email=alice@example.com`.
  3. Asserts the redirect URL has `login_hint=alice%40example.com`
     appended.
     This is the one piece of ePDS-specific behaviour the library does
     NOT handle natively, so it's worth a regression test.

## Risks and open questions

1. **`NodeOAuthClient.authorize(PDS_URL)` for no-handle login.** The
   library's resolver accepts a PDS URL as `input` (see
   `oauth-resolver.ts:29`). Confirmed by reading the source; needs
   runtime verification during the implementation.

2. **Per-request client construction cost.** Creating a new
   `NodeOAuthClient` per request could be expensive if resolver caches
   are instance-scoped rather than shared. Benchmark during
   implementation; if it's a problem, cache the resolver caches via
   module-level singletons and inject them into the per-request client.

3. **`login_hint` as a URL query param.** The ePDS auth-service reads
   `login_hint` off the authorize URL query string, which is not
   something the library sets. The plan appends it manually after
   `client.authorize()` returns. That's a minor shim but it needs to
   survive any future library changes that start validating or
   rewriting the authorize URL.

4. **`epds_handle_mode` pass-through.** Same story as `login_hint` —
   it's an ePDS-specific extension on the authorize URL. Handled the
   same way.

5. **Refresh token flow.** The demo currently never uses refresh
   tokens. After the refactor, `client.restore(sub)` gives us that
   capability for free, but wiring it into the welcome page (or any
   other demo view that needs a live agent) is a separate question.
   Out of scope for this refactor unless it blocks something.

6. **Session cookie compatibility.** The existing demo's user cookie
   (`createUserSessionCookie` from `session.ts`) stores `userDid` and
   `userHandle`. The library's `session.did` is a DID but not a
   handle. Need a `resolveDidToHandle` helper — either reuse the
   existing `resolveHandleToDid` (inverted) or delete the handle from
   the user cookie and resolve on demand.

## Acceptance criteria

- `packages/demo/src/lib/auth.ts` no longer contains PKCE, DPoP, or
  endpoint-discovery code. Any remaining exports are constants (e.g.
  `PDS_URL`) and handle/DID resolution helpers that are used outside
  the OAuth flow.
- `packages/demo/src/lib/client-jwk.ts` is deleted.
- `jose` is removed from `packages/demo/package.json` direct deps
  (unless something else in the demo still imports it directly after
  the refactor).
- `packages/demo/src/app/api/oauth/login/route.ts` is under 60 lines
  of code (excluding comments and imports).
- `packages/demo/src/app/api/oauth/callback/route.ts` is under 50
  lines.
- The HYPER-270 e2e scenario
  (`features/consent-screen.feature:49`) passes against a PR
  environment running the refactored demo, with no scenario-level
  changes.
- All other e2e scenarios in the suite continue to pass against the
  refactored demo.
- `pnpm lint`, `pnpm typecheck`, `pnpm format:check`, and `pnpm test`
  all pass.

## Relationship to PR #21

PR #21's hand-rolled confidential-client code is a stepping stone: it
exists to unblock HYPER-270's e2e coverage within the scope of a PR
about consent-screen behaviour. This refactor is the follow-up that
cleans up that stepping stone and makes the demo a proper reference
implementation suitable for third parties (certified.app, etc.) to
copy. The two PRs are deliberately separate because:

- PR #21's reviewer is focused on consent-screen semantics, not
  demo-app internals.
- A full library-based rewrite would expand PR #21 well beyond its
  stated title.
- Landing PR #21 first gives us a stable consent-screen implementation
  that the refactor PR can then be evaluated against (i.e. the
  consent-screen tests continue to pass as a regression check for the
  refactor, rather than being in flight alongside it).

The refactor PR's commit message should include `Closes #56`.
