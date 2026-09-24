# Private Atmosphere in a Box e2e stack

This stack runs the ePDS end-to-end suite against the checked-out source and a
job-local private PLC. It clones the pinned Atmosphere in a Box revision,
registers this repository-owned template, creates a PDS with zero seeded users,
then builds and starts ePDS core, auth, two demo clients, Mailpit, a local
permission-set lexicon authority, and a Playwright runner.

## Run locally

Prerequisites: Git, Docker Compose v2, Node.js 24, npm, Deno 2.8.3, Python 3,
and a checkout of ePDS with pnpm dependencies available. Docker must be usable
by the current account. The runner image contains the locked Playwright
browser and imports only the sandbox's exported public CA for Node and
Chromium; it does not change host trust or DNS settings.

From the ePDS checkout:

```bash
EPDS_E2E_PROJECT=epds-e2e-local bash e2e/atmosphere/run.sh
```

The project name must use the `epds-e2e-` prefix. The orchestrator chooses a
free RFC1918 `/24` after checking Docker networks and host routes. It clones
Atmosphere in a Box at `e3640ee15a97501a0d5d01fdfcd21dde73d46be9`, installs
Node dependencies required by its tests, validates the registered app and
Compose render, builds the images, runs both e2e profiles, and removes only
the named Compose project and temporary clone on exit. Docker's Buildx
configuration is isolated under the temporary job directory; credentials
from any existing Docker configuration are not copied.

Reports are retained under `reports/`. The temporary DID proof file is
excluded from that directory when reports are copied. Runtime secrets, PLC
state, browser profiles, and other generated state are not report artifacts.

## Hosts and private network

The job-local hosts are generated from the selected sandbox domain:

| Host                               | Service                                           |
| ---------------------------------- | ------------------------------------------------- |
| `epds.<domain>`                    | ePDS core and PDS                                 |
| `auth.epds.<domain>`               | ePDS auth service                                 |
| `trusted-demo.atmosbox.internal`   | Trusted demo OAuth client                         |
| `untrusted-demo.atmosbox.internal` | Untrusted demo OAuth client                       |
| `mailpit.<domain>`                 | Mailpit UI and API                                |
| `plc.<domain>`                     | Private PLC                                       |
| `lexicons.<domain>`                | Job-local DID and permission-set record authority |

Arbitrary `<handle>.epds.<domain>` names resolve to the sandbox gateway and
are served by ePDS core with Caddy's internal TLS. The DNS fragment and Caddy
route are scoped to this handle suffix. The application attaches only to the
sandbox `atmosinabox` network, publishes no host ports, and does not create a
second gateway or network.

The test PDS sets `PDS_DISABLE_SSRF_PROTECTION=true` so its OAuth provider can
fetch trusted demo metadata from the private `.internal` route, following the
pinned sandbox's hosted-client setup. Core and auth set the source-documented
`EPDS_ALLOW_PRIVATE_IPS=true` so ePDS's own metadata resolver can fetch that
same private client metadata. The app network is internal and has no external
egress, so the test services can only use the private sandbox endpoints. These
settings are limited to this test stack, not ePDS production defaults. The stack also sets
`PDS_INVITE_REQUIRED=false` only on the PDS so account creation needs no
separately generated invite code. The application network is internal with no
host ports, trusted metadata is explicitly listed, and TLS checks stay enabled.
The untrusted client is not added to the trusted-client list.

The trusted demo requests the documented signup consent skip and the test PDS
allows it. This is needed by the existing returning-user setup flow. The
untrusted demo keeps the flag empty and remains outside the trusted-client
allowlist, so it continues to exercise the consent screen.

The test auth service sets `EPDS_DISABLE_RATE_LIMIT=true`. Its per-IP limiter
defaults to 60 requests per minute, while parallel browser scenarios share a
single container source IP and can exceed that limit. The auth-service config
documents this opt-out for Docker Compose and e2e stacks; it is not enabled in
production.

The same test auth service sets `AUTH_PREVIEW_ROUTES=1` so preview-only
branding, handle, and OTP input scenarios can exercise their fixture pages.
The auth-service configuration documents these developer preview routes; the
flag is set only on this disposable test service.

The trusted demo uses the documented `amber` theme so its OAuth client
metadata includes the branding CSS and favicons exercised by the trusted
client scenarios. The untrusted demo keeps its theme empty so the suite can
verify the trust gate's visual difference.

The local `lexicons.<domain>` service hosts `did:web` metadata and signed CAR
responses for the two complete permission-set schemas required by the existing
OAuth scopes. CoreDNS returns `_lexicon.hypercerts.org` and
`_lexicon.certified.app` TXT records pointing to that job-local DID. The JSON
schema fixtures are copied byte-for-byte from
`hypercerts-org/hypercerts-lexicon` at commit
`645177d67752834ae0e8a2876c118489b50c0a50`; the authority adds only the
AT record `$type` envelope and generates a fresh signing key per job. This
keeps permission contents and application scopes unchanged without public
lexicon access.

The PDS and both demo clients point `PLC_DIRECTORY_URL` / `PDS_DID_PLC_URL` to
`https://plc.<domain>`. The job creates one test account, confirms its DID
resolves through that private PLC, then performs a read-only lookup on the
public PLC and requires HTTP 404.

## CI and profiles

The `E2E tests` workflow invokes `run.sh` on the PR head source for pull
requests, pushes to `main`, and manual dispatch. The required workflow profile
is `default`; the separate session-reuse profile is not wired as a required
job while its baseline failure remains. Reports are retained on success or
failure. The orchestrator has passed account creation, private PLC resolution,
and a read-only public PLC absence check.

The local orchestrator defaults to running the default profile followed by
`session-reuse`; set `EPDS_E2E_PROFILE=default` to run only the required CI
profile. Both profiles use a fresh job-local PDS/PLC stack. The latest default
profile passed 83 of 83 scenarios and 544 of 544 steps. It had zero skipped,
pending, or failed scenarios. Tag counts from the retained JUnit and feature
tags:

| Tag                   | Tagged scenarios | Executed and passed |       Excluded by profile | Runtime skipped, pending, or failed |
| --------------------- | ---------------: | ------------------: | ------------------------: | ----------------------------------: |
| `@otp-expiry`         |                2 |                   2 |                         0 |                                   0 |
| `@par-callback-error` |                1 |                   1 |                         0 |                                   0 |
| `@untrusted-client`   |               12 |                  10 | 2 (`@pending`, `@manual`) |                                   0 |

The latest session-reuse profile passed 19 of 20;
after confirming identity for a second client, the browser remained on that
untrusted client's consent page instead of reaching `/welcome`. Scoped logs
showed normal delegation to PDS consent for the untrusted client, and no
supported template-only setting was found to change that behavior. The
session-reuse failure is retained in its local JUnit report and is not a
required CI gate while it fails.

Before building, the runner executes focused mutation tests for the template
validator. The validator checks canonical route hosts, private PLC URLs on core
and both demo clients, absence of host-published ports, the internal network,
and the pinned sandbox registry schema. The same checks run against the
rendered Compose config before any services start.

## Cleanup and troubleshooting

Cleanup targets only the Compose project passed through `EPDS_E2E_PROJECT`.
It removes that project's containers, network, and volumes, plus its temporary
clone and secret files. For a local diagnostic only,
`EPDS_E2E_KEEP_FAILED_STATE=1` preserves temporary state after failure so
scoped logs can be inspected; remove the exact Compose project and temporary
directory as soon as diagnosis is complete. Never copy generated `.env`, app
secret state, or the CA private key into reports or artifacts.

- **No free subnet:** stop or reconfigure the conflicting Docker project or
  route, then rerun. The script does not assume the default sandbox subnet.
- **Image build fails:** check disk space, Docker availability, and network
  access for pinned base images and package registries.
- **TLS fails in the runner:** confirm the `public-ca` volume is mounted
  read-only and that the runner entrypoint imports its exported root into the
  ephemeral Node and Chromium trust stores. Do not disable certificate checks.
- **Private PLC proof fails:** inspect only the scoped project health and
  redacted service errors. Never print generated `.env`, app secret JSON, or
  expanded Compose configuration.
