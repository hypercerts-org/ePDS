# Private Atmosphere in a Box e2e stack

This harness runs ePDS end-to-end tests against a job-local Atmosphere in a Box
0.7.0 checkout at `26cf1f60f81b491b065dfc830efd27aba8b89a54`. AiaB provisions
the private PLC, DNS, internal TLS, wildcard handle routes, lexicon fixtures,
typed OAuth client keys, and a zero-built-in-PDS network. CI builds the ePDS
images before isolated runtime execution, runs the existing Cucumber command,
uploads reports, and removes its own Compose project.

## Run locally

Install Docker Compose v2, Node.js 24, Deno 2.8.3, Python 3, and the ePDS pnpm
dependencies. Docker must be available to the current account.

```bash
EPDS_E2E_PROJECT=epds-e2e-local EPDS_E2E_PROFILE=default pnpm test:e2e:atmosphere
```

The runner creates a fresh zero-PDS sandbox with `--subnet auto`, copies and
registers the ePDS stack in AiaB's `stacks/` directory, validates it, builds
the ePDS images, starts services, and runs `sandbox seed`. `seed` creates the
managed local lexicon-authority account, publishes the two schema fixtures, and
verifies TXT, DID, HTTPS, and record readback before the tests run.

The profile defaults to `both`; CI uses `default`. `session-reuse` remains
available for its known returning-user baseline. `EPDS_E2E_KEEP_FAILED_STATE=1`
preserves the exact temporary sandbox root for investigation after a failure.

## Provisioned endpoints

The ePDS application declares these AiaB routes:

| Route                                                     | Service                                  |
| --------------------------------------------------------- | ---------------------------------------- |
| `epds.atmosbox.test`                                      | ePDS core PDS                            |
| `*.epds.atmosbox.test`                                    | dynamically created ePDS account handles |
| `auth.epds.atmosbox.test`                                 | ePDS auth                                |
| `authority.atmosbox.test` and `*.authority.atmosbox.test` | managed lexicon PDS                      |
| `trusted-demo.atmosbox.internal`                          | trusted OAuth demo                       |
| `untrusted-demo.atmosbox.internal`                        | untrusted OAuth demo                     |
| `mailpit.atmosbox.test`                                   | Mailpit                                  |

AiaB provides private TXT delegations for `_lexicon.hypercerts.org` and
`_lexicon.certified.app`. It publishes the fixture records through a real local
PDS; no custom CAR server, public lexicon access, public PLC writes, networking
patches, or disabled TLS verification are used.

The runner is a managed service on the internal network. Its image installs
pnpm and Playwright before runtime execution, receives only AiaB's public CA,
and imports that CA into Node and Chromium. Host DNS or trust is never changed.

## CI boundary and cleanup

AiaB owns provisioning. CI owns the runner image, test command, reports, and
cleanup. The harness uses `sandbox access --json` as a non-secret connection
projection, then invokes the normal test container with Docker Compose.

The GitHub workflow performs clone, registration, provisioning, fixture seed,
access validation, health checks, private-PLC proof, Cucumber, report copying,
and cleanup in separate named steps. `pnpm test:e2e:atmosphere` provides the
same sequence for local use.

Generated state, generated secrets, private CA keys, authority state, and the
private PLC proof file are never copied to `reports/`. Cleanup targets only the
project named by `EPDS_E2E_PROJECT`; the workflow repeats label-scoped cleanup
when a job is interrupted.

The test creates an ePDS account, verifies its DID through the private PLC, and
requires a read-only public PLC lookup for that DID to return 404.
