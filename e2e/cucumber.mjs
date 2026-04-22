// Scenarios tagged @untrusted-client drive the untrusted demo OAuth client
// (see e2e/README.md#two-demo-clients). They are only runnable against
// environments that provide a second demo — reflect that in the tag
// expression by excluding the tag when E2E_DEMO_UNTRUSTED_URL is unset.
const tagExclusions = [
  'not @manual',
  'not @docker-only',
  'not @pending',
  'not @risk-of-disruption',
  ...(process.env.E2E_DEMO_UNTRUSTED_URL ? [] : ['not @untrusted-client']),
]

export default {
  paths: ['features/**/*.feature'],
  import: ['e2e/step-definitions/**/*.ts', 'e2e/support/**/*.ts'],
  format: ['pretty', 'html:reports/e2e.html', 'junit:reports/e2e.junit.xml'],
  tags: tagExclusions.join(' and '),
  strict: true,
}
