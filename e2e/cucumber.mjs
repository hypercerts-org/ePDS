// Shared config for the cucumber-js e2e runner.
//
// Two profiles are exported:
//
//   default         — the normal PR-CI run against a Railway preview
//                     environment. Excludes scenarios that the Railway
//                     topology cannot satisfy (see per-tag notes below).
//
//   session-reuse   — only the HYPER-268 @session-reuse scenarios. Intended
//                     for runs against a docker-compose (or equivalently-
//                     topologised) stack where auth-service is a subdomain
//                     of pds-core (AUTH_HOSTNAME ends with .<PDS_HOSTNAME>),
//                     so device-session cookies are sharable across the two
//                     services. Railway preview envs can't satisfy this
//                     (random hostnames under the .up.railway.app public
//                     suffix), so these scenarios are excluded from the
//                     default profile.
//
// Invoke via `pnpm test:e2e` (default) or `pnpm test:e2e -p session-reuse`.
//
// Scenarios tagged @untrusted-client drive the untrusted demo OAuth client
// (see e2e/README.md#two-demo-clients). They are only runnable against
// environments that provide a second demo — reflect that in the tag
// expression by excluding the tag when E2E_DEMO_UNTRUSTED_URL is unset.
//
// Scenarios tagged @otp-expiry or @par-callback-error call
// /_internal/test/* hooks (auth-service for @otp-expiry, pds-core for
// @par-callback-error) which require EPDS_TEST_HOOKS=1 on the server
// side and the matching EPDS_INTERNAL_SECRET on the client side.
// Exclude both when E2E_INTERNAL_SECRET is unset so they don't fail
// at run time on environments that haven't enabled the hooks.
const hookTagExclusions = process.env.E2E_INTERNAL_SECRET
  ? []
  : ['not @otp-expiry', 'not @par-callback-error']

const defaultTagExclusions = [
  'not @manual',
  'not @docker-only',
  'not @pending',
  'not @risk-of-disruption',
  'not @session-reuse',
  ...(process.env.E2E_DEMO_UNTRUSTED_URL ? [] : ['not @untrusted-client']),
  ...hookTagExclusions,
]

const shared = {
  paths: ['features/**/*.feature'],
  import: ['e2e/step-definitions/**/*.ts', 'e2e/support/**/*.ts'],
  strict: true,
}

// Cucumber supports the `default: () => ({...})` form to declare multiple
// profiles including names that aren't valid JS identifiers (e.g. hyphenated).
// See @cucumber/cucumber's from_file.ts: handleDefaultFunctionDefinition.
export default () => ({
  default: {
    ...shared,
    format: ['pretty', 'html:reports/e2e.html', 'junit:reports/e2e.junit.xml'],
    tags: defaultTagExclusions.join(' and '),
  },
  'session-reuse': {
    ...shared,
    format: [
      'pretty',
      'html:reports/e2e-session-reuse.html',
      'junit:reports/e2e-session-reuse.junit.xml',
    ],
    tags: '@session-reuse and not @pending',
  },
})
