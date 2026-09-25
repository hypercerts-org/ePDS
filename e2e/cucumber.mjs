// Shared config for the cucumber-js e2e runner.
//
// Three profiles are exported:
//
//   default         — the standard PR-CI run against the private Atmosphere
//                     in a Box stack. Excludes session-reuse and OTP-expiry
//                     scenarios, which run separately below.
//
//   otp-expiry      — only the @otp-expiry scenario. It runs with one worker
//                     because better-auth's expired-verification cleanup is
//                     global to the shared database.
//
//   session-reuse   — only the HYPER-268 @session-reuse scenarios. Intended
//                     for runs against a docker-compose (or equivalently-
//                     topologised) stack where auth-service is a subdomain
//                     of pds-core (AUTH_HOSTNAME ends with .<PDS_HOSTNAME>),
//                     so device-session cookies are sharable across the two
//                     services. These scenarios are excluded from the default
//                     profile and run separately against the managed private stack.
//
// Invoke via `pnpm test:e2e` (default), `pnpm test:e2e -p otp-expiry`, or
// `pnpm test:e2e -p session-reuse`.
//
// Scenarios tagged @untrusted-client drive the untrusted demo OAuth client
// (see e2e/README.md#two-demo-clients). They are only runnable against
// environments that provide a second demo — reflect that in the tag
// expression by excluding the tag when E2E_DEMO_UNTRUSTED_URL is unset.
//
// Scenarios tagged @otp-expiry or @par-callback-error call /_internal/test/*
// hooks, which require EPDS_TEST_HOOKS=1 and E2E_INTERNAL_SECRET.
const hookTagExclusions = process.env.E2E_INTERNAL_SECRET
  ? []
  : ['not @par-callback-error']

const defaultTagExclusions = [
  'not @manual',
  'not @docker-only',
  'not @pending',
  'not @risk-of-disruption',
  'not @session-reuse',
  'not @otp-expiry',
  ...(process.env.E2E_DEMO_UNTRUSTED_URL ? [] : ['not @untrusted-client']),
  ...hookTagExclusions,
]

const parsedCucumberRetry = Number.parseInt(
  process.env.CUCUMBER_RETRY ?? '0',
  10,
)
const cucumberRetry =
  Number.isFinite(parsedCucumberRetry) && parsedCucumberRetry >= 0
    ? parsedCucumberRetry
    : 0

const parsedDefaultParallel = Number.parseInt(
  process.env.E2E_PARALLEL ?? '3',
  10,
)
const defaultParallel =
  Number.isFinite(parsedDefaultParallel) && parsedDefaultParallel >= 0
    ? parsedDefaultParallel
    : 3

const otpExpiryTags = process.env.E2E_INTERNAL_SECRET
  ? '@otp-expiry and not @pending'
  : 'not @otp-expiry'

const shared = {
  paths: ['features/**/*.feature'],
  import: ['e2e/step-definitions/**/*.ts', 'e2e/support/**/*.ts'],
  retry: cucumberRetry,
  strict: true,
}

// Cucumber supports the `default: () => ({...})` form to declare multiple
// profiles including names that aren't valid JS identifiers (e.g. hyphenated).
// See @cucumber/cucumber's from_file.ts: handleDefaultFunctionDefinition.
export default () => ({
  default: {
    ...shared,
    format: ['pretty', 'html:reports/e2e.html', 'junit:reports/e2e.junit.xml'],
    parallel: defaultParallel,
    tags: defaultTagExclusions.join(' and '),
  },
  'otp-expiry': {
    ...shared,
    format: [
      'pretty',
      'html:reports/e2e-otp-expiry.html',
      'junit:reports/e2e-otp-expiry.junit.xml',
    ],
    parallel: 1,
    tags: otpExpiryTags,
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
