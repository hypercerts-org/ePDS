export default {
  paths: [
    // 'features/passwordless-authentication.feature',
    // 'features/automatic-account-creation.feature',
    // 'features/consent-screen.feature',
    // 'features/internal-api.feature',
    'features/account-settings.feature:46',
  ],
  import: ['e2e/step-definitions/**/*.ts', 'e2e/support/**/*.ts'],
  format: ['pretty', 'html:reports/e2e.html'],
  tags: 'not @manual and not @docker-only and not @pending',
  strict: true,
}
