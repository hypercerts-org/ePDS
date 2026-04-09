export default {
  paths: ['features/**/*.feature'],
  import: ['e2e/step-definitions/**/*.ts', 'e2e/support/**/*.ts'],
  format: ['pretty', 'html:reports/e2e.html', 'junit:reports/e2e.junit.xml'],
  tags: 'not @manual and not @docker-only and not @pending and not @risk-of-disruption and not @not-implemented',
  strict: true,
}
