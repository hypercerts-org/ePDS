/**
 * Tests for buildEpdsCallbackUrl — the HMAC-signed callback URL that
 * /auth/complete (and /auth/choose-handle) emit to bridge the user
 * from auth-service into pds-core. Covers the two contracts that
 * matter beyond round-trip: client_id is signed in, and the
 * random-mode handle sentinel is preserved.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'

const ORIGINAL_PDS_URL = process.env.PDS_INTERNAL_URL
const ORIGINAL_SECRET = process.env.EPDS_INTERNAL_SECRET

beforeAll(() => {
  // Importing complete.ts pulls in lib/clean-exit.js which calls
  // requireInternalEnv() at router-creation time. We don't actually
  // call createCompleteRouter from these tests, but the import side
  // effects still fire, so satisfy them.
  process.env.PDS_INTERNAL_URL = 'https://core:3000'
  process.env.EPDS_INTERNAL_SECRET = 'test-secret'
})

afterAll(() => {
  if (ORIGINAL_PDS_URL === undefined) delete process.env.PDS_INTERNAL_URL
  else process.env.PDS_INTERNAL_URL = ORIGINAL_PDS_URL
  if (ORIGINAL_SECRET === undefined) delete process.env.EPDS_INTERNAL_SECRET
  else process.env.EPDS_INTERNAL_SECRET = ORIGINAL_SECRET
})

import { buildEpdsCallbackUrl } from '../routes/complete.js'
import { verifyCallback, type CallbackParams } from '@certified-app/shared'

const PDS_PUBLIC_URL = 'https://pds.example'
const SECRET = 'test-callback-secret'
const REQUEST_URI = 'urn:ietf:params:oauth:request_uri:req-abc'
const EMAIL = 'user@example.com'
const CLIENT_ID = 'https://demo.example/client-metadata.json'

function paramsFromUrl(url: string): URLSearchParams {
  return new URL(url).searchParams
}

/**
 * Read a required URL param. Throws if absent — tests that get here
 * have already asserted the param was set, so a missing value is a
 * test-fixture bug, not a runtime branch we want to handle silently.
 * Avoids the non-null `!` assertion on every `.get()` call.
 */
function requiredParam(q: URLSearchParams, name: string): string {
  const v = q.get(name)
  if (v === null) throw new Error(`expected URL param ${name} to be set`)
  return v
}

describe('buildEpdsCallbackUrl', () => {
  it('targets pds-core /oauth/epds-callback at the configured public URL', () => {
    const url = buildEpdsCallbackUrl({
      flowRequestUri: REQUEST_URI,
      flowClientId: CLIENT_ID,
      email: EMAIL,
      isNewAccount: false,
      pdsPublicUrl: PDS_PUBLIC_URL,
      epdsCallbackSecret: SECRET,
    })
    const u = new URL(url)
    expect(u.origin).toBe(PDS_PUBLIC_URL)
    expect(u.pathname).toBe('/oauth/epds-callback')
  })

  it('round-trips via verifyCallback for an existing user', () => {
    const url = buildEpdsCallbackUrl({
      flowRequestUri: REQUEST_URI,
      flowClientId: CLIENT_ID,
      email: EMAIL,
      isNewAccount: false,
      pdsPublicUrl: PDS_PUBLIC_URL,
      epdsCallbackSecret: SECRET,
    })
    const q = paramsFromUrl(url)
    expect(q.get('approved')).toBe('1')
    expect(q.get('new_account')).toBe('0')
    expect(q.get('email')).toBe(EMAIL)
    expect(q.get('request_uri')).toBe(REQUEST_URI)
    expect(q.get('client_id')).toBe(CLIENT_ID)

    const ts = requiredParam(q, 'ts')
    const sig = requiredParam(q, 'sig')
    const params: CallbackParams = {
      request_uri: REQUEST_URI,
      email: EMAIL,
      approved: '1',
      new_account: '0',
      client_id: CLIENT_ID,
    }
    expect(verifyCallback(params, ts, sig, SECRET)).toBe(true)
  })

  it('round-trips via verifyCallback for a new account', () => {
    const url = buildEpdsCallbackUrl({
      flowRequestUri: REQUEST_URI,
      flowClientId: CLIENT_ID,
      email: EMAIL,
      isNewAccount: true,
      pdsPublicUrl: PDS_PUBLIC_URL,
      epdsCallbackSecret: SECRET,
    })
    const q = paramsFromUrl(url)
    expect(q.get('new_account')).toBe('1')
    const params: CallbackParams = {
      request_uri: REQUEST_URI,
      email: EMAIL,
      approved: '1',
      new_account: '1',
      client_id: CLIENT_ID,
    }
    expect(
      verifyCallback(
        params,
        requiredParam(q, 'ts'),
        requiredParam(q, 'sig'),
        SECRET,
      ),
    ).toBe(true)
  })

  it('omits client_id from the URL when flowClientId is null', () => {
    const url = buildEpdsCallbackUrl({
      flowRequestUri: REQUEST_URI,
      flowClientId: null,
      email: EMAIL,
      isNewAccount: false,
      pdsPublicUrl: PDS_PUBLIC_URL,
      epdsCallbackSecret: SECRET,
    })
    const q = paramsFromUrl(url)
    expect(q.has('client_id')).toBe(false)
    // And it still round-trips via verifyCallback (the signed payload
    // uses the empty-string sentinel for absent client_id).
    const params: CallbackParams = {
      request_uri: REQUEST_URI,
      email: EMAIL,
      approved: '1',
      new_account: '0',
    }
    expect(
      verifyCallback(
        params,
        requiredParam(q, 'ts'),
        requiredParam(q, 'sig'),
        SECRET,
      ),
    ).toBe(true)
  })

  it('preserves the random-mode handle sentinel: omitting `handle` is the trigger for pds-core to call generateRandomHandle()', () => {
    // Neither the inputs to buildEpdsCallbackUrl nor the output URL
    // carry a `handle` field — the absence is the signal. This pins
    // the contract documented in the function's JSDoc.
    const url = buildEpdsCallbackUrl({
      flowRequestUri: REQUEST_URI,
      flowClientId: CLIENT_ID,
      email: EMAIL,
      isNewAccount: true,
      pdsPublicUrl: PDS_PUBLIC_URL,
      epdsCallbackSecret: SECRET,
    })
    const q = paramsFromUrl(url)
    expect(q.has('handle')).toBe(false)
    // verifyCallback with absent handle accepts the signature, mirroring
    // the sentinel test in shared/src/__tests__/crypto.test.ts.
    const params: CallbackParams = {
      request_uri: REQUEST_URI,
      email: EMAIL,
      approved: '1',
      new_account: '1',
      client_id: CLIENT_ID,
    }
    expect(
      verifyCallback(
        params,
        requiredParam(q, 'ts'),
        requiredParam(q, 'sig'),
        SECRET,
      ),
    ).toBe(true)
  })

  it("rejects a tampered client_id at the verifier (the value is signed, an attacker cannot redirect a victim's flow at a different OAuth client)", () => {
    const url = buildEpdsCallbackUrl({
      flowRequestUri: REQUEST_URI,
      flowClientId: CLIENT_ID,
      email: EMAIL,
      isNewAccount: false,
      pdsPublicUrl: PDS_PUBLIC_URL,
      epdsCallbackSecret: SECRET,
    })
    const q = paramsFromUrl(url)
    const tampered: CallbackParams = {
      request_uri: REQUEST_URI,
      email: EMAIL,
      approved: '1',
      new_account: '0',
      client_id: 'https://attacker.example/client-metadata.json',
    }
    expect(
      verifyCallback(
        tampered,
        requiredParam(q, 'ts'),
        requiredParam(q, 'sig'),
        SECRET,
      ),
    ).toBe(false)
  })
})
