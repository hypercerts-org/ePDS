import { config } from 'dotenv'
import { resolve } from 'node:path'

config({ path: resolve('e2e/.env') })

function required(name: string): string {
  const value = process.env[name]
  if (!value) {
    throw new Error(
      `E2E configuration error: ${name} is not set.\n` +
        `Copy e2e/.env.example to e2e/.env and fill in the required values.`,
    )
  }
  return value
}

export const testEnv = {
  pdsUrl: required('E2E_PDS_URL'),
  authUrl: required('E2E_AUTH_URL'),
  // `demoUrl` is the trusted demo client — kept under this name for
  // backwards compatibility with existing scenarios that just say
  // "the demo client". New consent-skip scenarios that need to
  // distinguish trusted from untrusted should use the explicit
  // `demoTrustedUrl` / `demoUntrustedUrl` accessors below.
  demoUrl: required('E2E_DEMO_URL'),
  demoTrustedUrl: required('E2E_DEMO_URL'),
  demoUntrustedUrl: process.env.E2E_DEMO_UNTRUSTED_URL,
  mailpitUrl:
    process.env.E2E_MAILPIT_URL ??
    'https://mailpit-e2e-karma-test.up.railway.app',
  mailpitUser: process.env.E2E_MAILPIT_USER ?? 'karma',
  mailpitPass: process.env.E2E_MAILPIT_PASS ?? '',
  otpLength: Math.min(12, Math.max(4, Number(process.env.OTP_LENGTH ?? '8'))),
  otpCharset: (process.env.OTP_CHARSET ?? 'numeric') as
    | 'numeric'
    | 'alphanumeric',
  headless: process.env.E2E_HEADLESS === 'true',
}
