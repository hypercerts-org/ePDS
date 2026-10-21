# PDS 0.5.34 Upgrade Assessment

## Status

This document records the read-only assessment of upgrading ePDS from
`@atproto/pds` 0.5.23 to 0.5.34. It is an implementation guide, not evidence
that the upgrade has been completed.

The assessment compared local upstream release tags and ePDS source. No package
installation, build, test, database operation, deployment, or production
configuration inspection was performed.

## Source versions

| Package                       | Current ePDS version | Target companion version                |
| ----------------------------- | -------------------- | --------------------------------------- |
| `@atproto/pds`                | 0.5.23               | 0.5.34                                  |
| `@atproto/oauth-provider`     | 0.21.1               | 0.22.8                                  |
| `@atproto/oauth-provider-ui`  | 0.8.9                | 0.10.3                                  |
| `@atproto/oauth-provider-api` | 0.7.7                | 0.8.3 through the target provider graph |

Local upstream release commits used by the assessment:

- PDS 0.5.23: `5dc34f6846bad7c6f649e0a733186f4a6a467fcb`
- PDS 0.5.34: `7ca16cc6989f8247637615aca17c5abb911b8fb1`
- OAuth provider UI 0.10.3:
  `1f2604f0546754aef1cf93b7ac3855cf31751b1c`

The committed ePDS lockfile is the authority for the current dependency graph.
Local `node_modules` links were stale during the assessment and pointed to
older package versions, so runtime observations from that installation are not
trustworthy until dependencies are installed cleanly.

## Overall conclusion

The upgrade appears manageable, but it is not a PDS-only version bump.

Required work:

1. Align PDS, OAuth provider, and OAuth provider UI versions.
2. Fix the `Another account` control lookup for the redesigned provider UI.
3. Repair and validate the consent preview against the redesigned provider UI.
4. Update generic ePDS branding selectors for the provider's semantic CSS
   targets.
5. Build a temporary Ma Earth-branded MVP of the new consent layout for team
   review; do not recreate the old layout or permanently own Ma Earth CSS in
   ePDS.
6. Run full OAuth, PDS, container, and rollback validation.

No new upstream database migration was found in this release range. Core OAuth
provider methods used by ePDS remain compatible in the inspected source, but
many are private upstream interfaces and still require runtime validation.

## Required dependency alignment

Upgrade these direct dependencies together:

```json
{
  "@atproto/pds": "0.5.34",
  "@atproto/oauth-provider": "0.22.8",
  "@atproto/oauth-provider-ui": "0.10.3"
}
```

The current `0.x` caret ranges for provider and provider UI do not accept the
target companion versions. Updating only PDS can create a mixed package graph.

### `HandleUnavailableError` constructor mismatch

ePDS imports `HandleUnavailableError` and uses `instanceof` while handling
account creation. If PDS creates the error through provider 0.22.8 but ePDS
checks it against provider 0.21.1, the constructors differ. A taken or reserved
handle can fall through to the generic account-creation error instead of
redirecting to handle selection.

Alignment of the direct provider version is required. This is separate from the
upstream `HandleNotFound` response change for handle resolution.

### Provider UI manifest mismatch

ePDS preview routes resolve the provider UI bundle manifest through ePDS's
direct dependency. The provider resolves its own manifest separately. Mixed UI
versions can make preview HTML reference old asset filenames while the provider
serves new assets.

Align the direct provider UI dependency and verify chooser and consent preview
assets after lockfile regeneration.

### Shared safe-fetch dependency

Also upgrade the direct `@atproto-labs/fetch-node` dependency in
`packages/shared/package.json` from `^0.2.0` to `0.4.0`. The target PDS 0.5.34
release changelog lists fetch-node 0.4.0; 0.3.6 belongs to the current dependency
graph and is not the target companion version. Updating PDS alone does not
upgrade shared's independent `^0.2.0` dependency.

Source comparison found no incompatible use of the wrapper options in ePDS.
The shared wrapper retains HTTPS-only/private-IP protection by default, a
5-second timeout, a 100 KB response limit, and unconditional redirect rejection.
It serves client metadata, remote email templates, and preview validation.
Auth-service requests directly to `PDS_INTERNAL_URL` use ordinary fetch and are
not intercepted by this wrapper.

Fetch-node 0.4.0 applies URL policy at dispatch time, including every redirect
hop, and keeps the dispatcher guard when private-IP checks are relaxed. Because
ePDS already rejects redirects, hop validation is defense-in-depth for the
shared wrapper. Custom request dispatchers are rejected even in relaxed mode;
no current ePDS caller supplies one. The removed
`dangerouslyForceKeepAliveAgent` option is also unused. Current callers catch
fetch failures generically, so changes to error wrapping do not establish a
functional break.

Validate metadata, template and preview success/fallback behavior, HTTP and
private-IP rejection, redirect rejection, timeout and streamed response limits,
and local `EPDS_ALLOW_PRIVATE_IPS=true` behavior. This is source assessment,
not runtime validation under the new dependency graph.

### Optional dependency cleanup

Multiple `@atproto/syntax` and `@atproto/crypto` versions exist in the current
graph. No concrete constructor, singleton, or branded-type failure was found for
these packages. Deduplication or removal of an unused direct crypto dependency
is optional unless typechecking or runtime tests prove otherwise.

## Confirmed provider UI break

### `Another account` lookup

Provider UI 0.8.9 renders the control through an element with
`role="button"`. UI 0.10.3 renders a native `<button type="button">`.

The current ePDS enrichment script searches only `[role="button"]`, so it fails
to attach its custom redirect handler to the new control.

The fix must update both lookup paths:

- exact aria-label lookup should accept `button[aria-label]` and
  `[role="button"][aria-label]`;
- visible-text fallback should inspect `button, [role="button"]`.

Keep the existing capture-phase click interception and auth-service redirect.

### Unaffected chooser behavior

The native-button change does not directly break account-row email enrichment.
That code finds account identifiers through hydration data and text walking,
not the role selector. Signup hiding already searches native buttons and links.

Provider UI 0.10.3 retains the hydration globals used by ePDS. The CSP hash is
computed from the generated script, so it follows source changes automatically.
Rendered tests remain required.

## Branding impact

Provider UI 0.10.3 replaces many gray/slate utility classes with semantic
classes and variables such as:

```text
bg-primary
bg-secondary
bg-accent
text-muted-foreground
text-accent-foreground
border-border
```

ePDS default CSS and some client CSS still target old selectors such as
`bg-gray-*`, `bg-slate-*`, and `text-slate-*`. Local source comparison confirms
that many rules no longer match. It does not establish how severe the visible
change is.

Primary branding remains supported through:

```css
--branding-color-primary
--branding-color-primary-contrast
```

Render affected pages before replacing selectors. Do not treat every obsolete
rule as requiring a replacement.

### Ma Earth

Ma Earth is a trusted client, requests random handles, and production has
`PDS_SIGNUP_ALLOW_CONSENT_SKIP` enabled.

Normal exposure:

- New users complete the custom ePDS email/OTP flow and skip consent.
- Returning users with the requested scopes already granted return without
  consent.
- Existing users connecting Ma Earth for the first time can see upstream
  consent because no prior grant exists.
- Existing users can see consent again when Ma Earth requests additional
  scopes.
- The upstream account chooser is not part of Ma Earth's normal email flow.
- Handle/DID login for a user on another PDS uses that PDS's UI and branding,
  not Certified.one's UI.

Provider UI 0.10.3 is a redesigned authorization layout. The goal is no longer
to reproduce the old component geometry. Instead, build a temporary MVP that
adapts Ma Earth's current visual language to the new layout while preserving the
provider's new consent information and behavior.

Keep ownership explicit:

```text
permanent: generic ePDS preview and default-branding fixes
temporary: adapted Ma Earth CSS served by the trusted demo for review
future:    approved production CSS remains owned by the Ma Earth application
```

The temporary demo fixture must be reverted after review. ePDS must not retain a
permanent copy of Ma Earth's palette, logo rules, or client-specific stylesheet.

### Gainforest

Gainforest's own login page is rendered by its authentication service and is not
changed by the provider UI upgrade. Its ePDS client CSS mostly uses element
selectors for buttons, links, and inputs, so more of it should continue to
match. Rare upstream consent pages still need visual validation, especially
secondary controls and chooser hover states.

## Compatible upstream interfaces

No incompatible source change was found for the exact inspected versions of:

- `provider.requestManager.get()`;
- `provider.requestManager.setAuthorized()`;
- request store reads and updates used by ePDS;
- `provider.accountManager.createAccount()`;
- `provider.accountManager.setAuthorizedClient()`;
- `provider.accountManager.listDeviceAccounts()`;
- `provider.deviceManager.load()`;
- device store reads used by ePDS;
- PDS account lookup and email-confirmation methods;
- provider metadata and PDS OAuth provider access;
- relevant device and session cookie names;
- PAR inactivity-refresh behavior.

Provider 0.22.8 adds an optional `clientId` argument to `createAccount()`. Existing
three-argument ePDS calls remain valid. Passing the client ID would improve
signup-hook metadata but is not a confirmed upgrade blocker.

These interfaces include private provider stores, Express internals, and direct
PDS database access. Compatibility in this release does not make them stable
public APIs. Keep `docs/design/pds-white-boxing.md` current when implementation
finds additional dependencies.

## Auth-service and shared upgrade impact

A focused follow-up source assessment found no additional auth-service dependency
that must be upgraded beyond the PDS/provider/UI alignment and shared fetch-node
0.4.0 change above. This is not evidence that the upgraded runtime has passed
integration tests.

Auth-service does not directly import PDS. Its relevant dependencies cross two
boundaries:

```text
auth-service → shared → fetch-node / syntax / SQLite / Node crypto
auth-service → internal HTTP and signed callback → pds-core → PDS/provider
```

### Dependency decisions

- **Update:** PDS, OAuth provider, provider UI, and shared's direct fetch-node
  dependency as specified above.
- **Keep `@atproto/syntax`:** shared uses it for handle logic, while pds-core
  also uses identifier guards and types. No concrete constructor or type failure
  requiring version alignment was found. Validate handle behavior and typecheck
  the regenerated graph rather than deduplicating solely because versions differ.
- **Keep crypto behavior:** shared callback signing uses HMAC-SHA256 through
  `node:crypto`, not `@atproto/crypto`. The direct `@atproto/crypto` declaration
  in pds-core has no current source import; updating it does not update callback
  signing. Removing that declaration is optional, separate cleanup. Upstream
  packages still resolve their own crypto dependencies.
- **Keep `better-sqlite3`:** no upgrade requirement was established. Verify the
  native module loads in the actual Alpine image and both services start against
  copied existing data.
- **Leave better-auth, Express, and email libraries unchanged:** this assessment
  established no PDS-upgrade-driven reason to update them. It was not a general
  dependency-health audit.

### Internal HTTP and callback contracts

The auth-service callers and ePDS-owned handlers for the following endpoints
remain source-compatible in the inspected upgrade range:

- `/_internal/account-by-email`;
- `/_internal/account-by-handle`;
- `/_internal/par-login-hint`;
- `/_internal/ping-request`;
- `/_internal/device-accounts`;
- `/oauth/epds-callback`.

The internal endpoints continue to use `x-internal-secret`; the callback retains
its separate HMAC-signed contract. No request/response payload change was found
that requires rewriting these callers. Their handlers still depend on upstream
account, request, and device managers, including private interfaces. Source
compatibility therefore needs real-stack validation, not just mocked HTTP tests.

The known native `Another account` button incompatibility and consent styling
risks belong to the upstream UI integration in pds-core. They do not replace or
rewrite the custom auth-service email, OTP, or handle pages.

### Integration validation gaps

Existing mocked fetch/provider tests verify local request construction and
response handling; they do not prove that the upgraded provider implements the
assumed contract. Existing tests also do not constitute validation against the
new dependency graph until that graph is installed and exercised.

Prioritize these real-stack checks alongside the validation matrix below:

- Random- and chosen-handle signup, taken/reserved-handle recovery, account
  creation, and email confirmation.
- Existing-account email/handle/DID lookup, recovery, and account-settings flows,
  including not-found and upstream failure responses.
- PAR heartbeat during delayed OTP or handle selection, plus expired-request
  behavior. The inspected `requestManager.get()` refresh behavior is retained
  but is an upstream-internal dependency.
- Remembered device accounts, account-row email enrichment, and explicit account
  switching against the real provider UI.
- Signed callback completion through consent or authorization-code issuance,
  followed by token exchange.
- Internal endpoints with valid, missing, and invalid secrets; malformed inputs;
  expected response shapes; and timeout/failure handling where applicable.
- Consent/chooser previews using real target bundles: manifest entries, asset
  URLs, hydration data, CSP acceptance, and browser event interception.
- Both services starting and passing health checks in the built images, including
  safe-fetch construction and native SQLite loading.

No additional confirmed auth-side source incompatibility emerged from this
follow-up. The remaining uncertainty is primarily runtime and integration
behavior, not a demonstrated need for a broad auth dependency refresh.

## Database and rollback

Migration files are byte-identical between PDS 0.5.23 and 0.5.34 for:

- account manager;
- actor store;
- sequencer;
- DID cache.

No upgrade-specific schema migration or schema-level rollback blocker was found.
A non-migration database utility source file changed, but migration trees did
not.

Rollback guidance:

1. For startup failure before traffic or writes, preserve logs and the failed
   volume, then try the previous image against the same volume.
2. If behavior is wrong after traffic starts, stop writers and preserve the
   upgraded volume before deciding how to reconcile writes.
3. Restore a pre-upgrade snapshot only for confirmed data corruption or
   incompatible writes and only with explicit operator approval. Snapshot
   restoration discards post-snapshot writes.

## Other upstream behavior changes

### Safe outbound fetch

PDS and identity resolution now apply stronger SSRF protection, including
redirect-hop validation. Private IPs, localhost, unsafe protocols, custom ports,
or unsafe redirects in DID- or service-resolved endpoints may be rejected.

This does not intercept auth-service calls made directly to `PDS_INTERNAL_URL`.
Those use a separate fetch path. Docker and Railway internal PDS requests are
not a confirmed casualty of this change.

### Proxy response limits

Decoded proxy error bodies and affected read-after-write buffers are bounded
after decompression. Large compressed upstream responses may now be rejected.

### OAuth request body limit

OAuth and account-management request bodies are limited to 100 KiB after
decompression. Oversized requests return HTTP 413.

### Blob uploads

Blob upload streaming and backpressure were rewritten. The change is intended
to improve memory behavior but affects a critical write path. Validate normal,
large, oversized, and aborted uploads against every supported blob store.

### Proxy headers

PDS now forwards `x-atproto-*` headers through service proxies. Validate any
application flow that relies on service proxying.

### Handle resolution

Unresolved supported handles now return `HandleNotFound` rather than a generic
`InvalidRequest` in the affected path. This is a client-visible error correction,
not the same issue as ePDS account-creation handle selection.

### Branding environment variables

Upstream removed legacy color, contrast, saturation, and hue environment
variables and added background URL options. Tracked ePDS configuration does not
use the removed variables. Deployment variable names should still be checked
for obsolete entries without exposing values.

### Telemetry and lifecycle

Upstream added telemetry packaging, lifecycle helpers, and event logging. ePDS
continues to use its own pds-core entry point. No required ePDS telemetry change
was established, but startup and shutdown behavior must be tested.

## Runtime requirements

Both PDS 0.5.23 and 0.5.34 require Node 22 or newer, so Node 22 is not a new
upgrade requirement.

The target safe-fetch implementation checks bundled Undici capabilities,
including a minimum compatible version and dispatcher interceptor support.
ePDS uses a floating `node:22-alpine` image. Record the resolved Node and Undici
versions during image validation and exercise redirect-hop checks.

This requirement also applies to auth-service after the shared fetch-node
upgrade. Version 0.4.0 checks `process.versions.undici`, requires at least
6.11.1, selects a package-provided Agent matching bundled Undici major 6, 7,
or 8, and requires that Agent to expose `compose()` for dispatch interception.
A missing/unsupported bundled Undici version or missing Agent capability makes
safe-fetch construction throw rather than silently weaken SSRF protection.
The package requires Node >=22; ePDS already declares Node >=22.19.0.

Shared metadata and auth email-template modules construct their safe-fetch
wrappers during module initialization. An incompatible runtime can therefore
prevent auth-service from starting, rather than merely cause a metadata
fallback on one request. The actual target container must be tested: record
`node -p 'JSON.stringify({node: process.version, undici: process.versions.undici})'`,
construct the shared wrapper under the regenerated dependency graph, and verify
both services start and pass their health checks. A host-only check is not a
substitute for testing the built image.

`better-sqlite3` remains a native runtime dependency. Build the exact Alpine
image from a clean dependency state and verify that the module loads.

## Implementation sequence

1. Create an isolated upgrade branch from a clean dependency state.
2. Record reference behavior and screenshots for current OAuth flows and Ma
   Earth consent.
3. Pin PDS 0.5.34, provider 0.22.8, provider UI 0.10.3, and shared's direct
   fetch-node 0.4.0 dependency together.
4. Regenerate the ePDS lockfile with the repository's package manager.
5. Inspect the resolved graph for duplicate PDS/provider/UI versions.
6. Fix the native `Another account` button lookup and add a DOM-level regression
   test for old and new markup.
7. Verify provider error handling and preview asset resolution with the aligned
   graph, including updating the consent fixture to the new `selectedDid` /
   `account.did` hydration contract.
8. Update generic ePDS branding selectors to the new semantic provider targets.
9. Temporarily serve an adapted version of Ma Earth's current CSS from the
   trusted demo and render the redesigned consent page for team review.
10. Revert the temporary demo branding while retaining generic ePDS fixes.
11. Run static checks, tests, coverage, container checks, and e2e validation.
12. Rehearse rollout and rollback against copied production-like data before
    deployment.

## Validation matrix

### Dependency and static checks

```bash
pnpm install --frozen-lockfile
pnpm build
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test
pnpm test:coverage
```

Inspect the final dependency tree to confirm aligned PDS/provider/UI versions.

### OAuth flows

Validate:

- new-user random-handle signup;
- existing-user login;
- taken or reserved handle recovery;
- first client grant;
- expanded-scope consent;
- trusted signup consent skip;
- PAR keepalive during delayed interaction;
- device-session reuse;
- multiple remembered accounts;
- explicit account switching;
- consent and chooser previews;
- token exchange and authenticated XRPC.

### Rendered UI

Validate desktop and mobile rendering for:

- custom email/OTP pages;
- custom handle page;
- upstream consent page;
- upstream account chooser;
- CSP acceptance and client CSS ordering.

### Runtime and PDS behavior

Validate:

- exact Docker image Node and Undici versions;
- `better-sqlite3` loading;
- startup against copied existing data;
- health endpoints and version reporting;
- account and repository operations;
- sync and identity resolution;
- service proxy headers;
- compressed proxy responses;
- normal, large, aborted, and oversized blob uploads;
- previous-image startup against unchanged upgraded data.

## Known evidence limits

This assessment did not verify:

- published npm tarball contents independently of local release tags;
- the final regenerated ePDS dependency graph;
- live production client metadata or branding CSS;
- production environment variable values;
- rendered browser output or computed styles;
- runtime behavior under the target dependency set;
- deployed container Node and Undici versions.

Treat these as validation work, not as established failures.
