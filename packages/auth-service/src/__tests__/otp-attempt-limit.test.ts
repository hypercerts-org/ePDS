/**
 * Email OTP attempt accounting on the real better-auth instance
 * (createBetterAuth) over a temporary SQLite file: 5 allowed attempts,
 * 600 s expiry, single use.
 *
 * Regression for better-auth GHSA-2f9c-7xj7-gh55: before 1.7.16, concurrent
 * wrong guesses all read the same attempt counter, so a burst of N guesses
 * counted as one attempt and the 5-attempt limit could be outrun. The same
 * limits are exercised through the POST /account/verify-otp route, which
 * wraps signInEmailOTP.
 */
import { randomBytes } from 'node:crypto'
import * as fs from 'node:fs'
import type { AddressInfo } from 'node:net'
import * as os from 'node:os'
import * as path from 'node:path'
import Database from 'better-sqlite3'
import { getMigrations } from 'better-auth/db/migration'
import cookieParser from 'cookie-parser'
import express from 'express'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { EpdsDb } from '@certified-app/shared'
import { createBetterAuth, type BetterAuthInstance } from '../better-auth.js'
import type { AuthServiceContext } from '../context.js'
import type { EmailSender } from '../email/sender.js'
import { csrfProtection } from '../middleware/csrf.js'
import { createAccountLoginRouter } from '../routes/account-login.js'

vi.mock('../lib/get-did-by-email.js', () => ({
  getDidByEmail: vi.fn(() => Promise.resolve(null)),
}))

const EMAIL = 'alice@example.com'
const CONCURRENT_GUESSES = 20
const ALLOWED_ATTEMPTS = 5

const codes = new Map<string, string>()
const emailSender = {
  sendOtpCode: vi.fn((opts: { to: string; code: string }) => {
    codes.set(opts.to, opts.code)
    return Promise.resolve()
  }),
} as unknown as EmailSender
const epdsDb = { getAuthFlow: vi.fn(() => undefined) } as unknown as EpdsDb
const ctx = {
  config: { otpLength: 6, otpCharset: 'numeric' },
} as unknown as AuthServiceContext

let dbPath: string
let auth: BetterAuthInstance
let digestSpy: { mockRestore: () => void } | undefined
let server: ReturnType<ReturnType<typeof express>['listen']> | undefined

beforeEach(async () => {
  dbPath = path.join(
    os.tmpdir(),
    `otp-attempts-${Date.now()}-${randomBytes(4).toString('hex')}.db`,
  )
  vi.stubEnv('DB_LOCATION', dbPath)
  vi.stubEnv('AUTH_HOSTNAME', 'auth.example')
  vi.stubEnv('AUTH_SESSION_SECRET', 'test-secret-test-secret-test-secret')
  auth = createBetterAuth(emailSender, epdsDb, 6)
  const { runMigrations } = await getMigrations(auth.options)
  await runMigrations()
})

afterEach(async () => {
  digestSpy?.mockRestore()
  digestSpy = undefined
  vi.useRealTimers()
  vi.unstubAllEnvs()
  codes.clear()
  if (server) {
    const s = server
    server = undefined
    await new Promise<void>((resolve) => {
      s.close(() => {
        resolve()
      })
    })
  }
  for (const suffix of ['', '-wal', '-shm']) {
    fs.rmSync(dbPath + suffix, { force: true })
  }
})

/** Send a code and return it; the stub sender captures the plaintext. */
async function issueCode(): Promise<string> {
  await auth.api.sendVerificationOTP({
    body: { email: EMAIL, type: 'sign-in' },
  })
  const code = codes.get(EMAIL)
  if (!code) throw new Error('no code was sent')
  return code
}

/** A 6-digit code that differs from the real one. */
function wrongCode(real: string, n: number): string {
  const candidate = String(100000 + n)
  return candidate === real ? '999999' : candidate
}

/** The stored attempt counter, or null once the code has been removed. */
function storedAttempts(): number | null {
  const sqlite = new Database(dbPath, { readonly: true })
  try {
    const row = sqlite
      .prepare('SELECT value FROM verification WHERE identifier = ?')
      .get(`sign-in-otp-${EMAIL}`) as { value: string } | undefined
    if (!row) return null
    return Number(row.value.slice(row.value.lastIndexOf(':') + 1))
  } finally {
    sqlite.close()
  }
}

/**
 * Counts wrong guesses that reached the code comparison, independently of
 * the stored attempt counter. The plugin runs with storeOTP: 'hashed', so
 * every guess it compares is SHA-256 hashed; a guess refused before
 * comparison (1.7.16+ does this while another guess holds the code) is not.
 * The real code is hashed once when issued and is not counted.
 */
function countEvaluatedGuesses(realCode: string): () => number {
  const subtle = globalThis.crypto.subtle
  const digest = subtle.digest.bind(subtle)
  let evaluated = 0
  digestSpy = vi.spyOn(subtle, 'digest').mockImplementation((alg, data) => {
    const text = new TextDecoder().decode(data as Uint8Array)
    if (text !== realCode && /^\d{6}$/.test(text)) evaluated++
    return digest(alg, data)
  })
  return () => evaluated
}

interface Verifier {
  /** Resolves true when the code signs in, false when it is refused. */
  verify: (otp: string) => Promise<boolean>
}

const direct: Verifier = {
  verify: (otp) =>
    auth.api.signInEmailOTP({ body: { email: EMAIL, otp } }).then(
      () => true,
      () => false,
    ),
}

/** POST /account/verify-otp; a sign-in redirects to /account. */
async function startWrapper(): Promise<Verifier> {
  const app = express()
  app.disable('x-powered-by')
  app.use(cookieParser())
  app.use(express.urlencoded({ extended: false }))
  app.use(csrfProtection())
  app.use(createAccountLoginRouter(auth, ctx))
  const s = app.listen(0, '127.0.0.1')
  server = s
  await new Promise<void>((resolve, reject) => {
    s.once('error', reject)
    s.once('listening', () => {
      resolve()
    })
  })
  const base = `http://127.0.0.1:${(s.address() as AddressInfo).port}`
  const csrf = 'c'.repeat(64)
  return {
    verify: async (otp) => {
      const res = await fetch(`${base}/account/verify-otp`, {
        method: 'POST',
        redirect: 'manual',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          cookie: `epds_csrf=${csrf}`,
        },
        body: new URLSearchParams({ email: EMAIL, otp, csrf }),
      })
      await res.text()
      return res.status === 303
    },
  }
}

const surfaces: [string, () => Promise<Verifier>][] = [
  ['Better Auth sign-in endpoint', () => Promise.resolve(direct)],
  ['/account/verify-otp route', startWrapper],
]

describe('OTP attempt limit via Better Auth sign-in endpoint', () => {
  // Reproduces the 1.4.18 race (the correct code is accepted). Direct calls
  // all start before any of them finishes, so every racer is refused while
  // the first wrong guess holds the code. Over HTTP the requests are
  // staggered: a later correct guess may legitimately arrive after that
  // guess restores the code and succeed with budget left, so this is not
  // run against /account/verify-otp. The next test covers that route.
  it('does not evaluate a burst of concurrent guesses in parallel', async () => {
    const verifier = direct
    const code = await issueCode()

    // 19 wrong guesses and then the correct code, all in flight at once.
    // Better Auth 1.4.18 let every one read the same attempt counter and
    // compare itself, so the burst was not limited and the correct code
    // got in. Since 1.7.16 only one guess at a time can compare against
    // the stored code; the rest are refused unevaluated.
    const results = await Promise.all(
      Array.from({ length: CONCURRENT_GUESSES }, (_, i) =>
        verifier.verify(
          i === CONCURRENT_GUESSES - 1 ? code : wrongCode(code, i),
        ),
      ),
    )

    expect(results).not.toContain(true)
    // null: the burst arrived slowly enough to be evaluated one by one and
    // used up the code. Either way it never exceeded the allowance.
    const used = storedAttempts()
    expect(used === null || (used >= 1 && used <= ALLOWED_ATTEMPTS)).toBe(true)
  })
})

describe.each(surfaces)('OTP attempt limit via %s', (_name, makeVerifier) => {
  it('spends the 5-attempt budget on every guess a burst evaluates', async () => {
    const verifier = await makeVerifier()
    const code = await issueCode()
    const evaluated = countEvaluatedGuesses(code)

    await Promise.all(
      Array.from({ length: CONCURRENT_GUESSES }, (_, i) =>
        verifier.verify(wrongCode(code, i)),
      ),
    )
    // Top up with sequential wrong guesses until 5 have been evaluated in
    // total. Better Auth 1.4.18 evaluated the whole burst but recorded it as
    // one attempt, so the code was still live after 20 evaluated guesses.
    // Only the direct-endpoint run fails on 1.4.18. Over HTTP the requests
    // are staggered, so the route run guards the 5-attempt budget through
    // /account/verify-otp, not the race itself.
    for (let i = 0; evaluated() < ALLOWED_ATTEMPTS; i++) {
      expect(i).toBeLessThan(ALLOWED_ATTEMPTS)
      expect(await verifier.verify(wrongCode(code, 1000 + i))).toBe(false)
    }

    expect(await verifier.verify(code)).toBe(false)
  })

  it('refuses the correct code after 5 sequential wrong guesses', async () => {
    const verifier = await makeVerifier()
    const code = await issueCode()

    for (let i = 0; i < ALLOWED_ATTEMPTS; i++) {
      expect(await verifier.verify(wrongCode(code, i))).toBe(false)
    }
    expect(await verifier.verify(code)).toBe(false)
  })

  it('still accepts the correct code on the 5th attempt', async () => {
    const verifier = await makeVerifier()
    const code = await issueCode()

    for (let i = 0; i < ALLOWED_ATTEMPTS - 1; i++) {
      expect(await verifier.verify(wrongCode(code, i))).toBe(false)
    }
    expect(await verifier.verify(code)).toBe(true)
  })

  it('refuses the correct code after 600 seconds', async () => {
    const verifier = await makeVerifier()
    const code = await issueCode()

    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + 601_000 })

    expect(await verifier.verify(code)).toBe(false)
  })

  it('accepts the correct code just inside the 600 second window', async () => {
    const verifier = await makeVerifier()
    const code = await issueCode()

    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + 590_000 })

    expect(await verifier.verify(code)).toBe(true)
  })

  it('consumes the code on success so it cannot be reused', async () => {
    const verifier = await makeVerifier()
    const code = await issueCode()

    expect(await verifier.verify(code)).toBe(true)
    expect(await verifier.verify(code)).toBe(false)
  })
})
