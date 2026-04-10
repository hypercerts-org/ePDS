export default {
  paths: [
    'features/passwordless-authentication.feature',
    'features/automatic-account-creation.feature',
    'features/consent-screen.feature',
    'features/account-settings.feature',
    'features/security.feature',
  ],
  import: ['e2e/step-definitions/**/*.ts', 'e2e/support/**/*.ts'],
  format: ['pretty', 'html:reports/e2e.html', 'junit:reports/e2e.junit.xml'],
  // @session-reuse (HYPER-268) requires auth-service to be on a
  // subdomain of pds-core (AUTH_HOSTNAME ends with .<PDS_HOSTNAME>)
  // so device-session cookies are shared. Railway preview envs can't
  // satisfy this (random hostnames under a public suffix), so these
  // scenarios are excluded from the default run. Enable them locally
  // against a docker-compose stack where both services share a parent
  // domain, by overriding this tag filter.
  tags: 'not @manual and not @docker-only and not @pending and not @session-reuse',
  strict: true,
}
