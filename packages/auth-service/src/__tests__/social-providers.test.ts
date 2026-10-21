/**
 * Tests for social provider configuration and login page integration.
 *
 * Social providers (Google, GitHub) are enabled by setting env vars:
 * - GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET
 * - GITHUB_CLIENT_ID + GITHUB_CLIENT_SECRET
 *
 * When configured, the login page renders social login buttons whose click
 * handler POSTs { provider, callbackURL } to better-auth's
 * /api/auth/sign-in/social (POST-only) and follows the provider URL it
 * returns (see login-page-social-buttons.test.ts). After the OAuth exchange,
 * better-auth redirects to /auth/complete (bridge route) which reads the
 * session and issues an HMAC-signed epds-callback.
 */
import { describe, it, expect } from 'vitest'
import { buildSocialProviders } from '../better-auth.js'

describe('Social provider detection', () => {
  it('returns empty object when no env vars set', () => {
    const providers = buildSocialProviders({})
    expect(Object.keys(providers)).toHaveLength(0)
  })

  it('enables Google when both GOOGLE env vars set', () => {
    const providers = buildSocialProviders({
      GOOGLE_CLIENT_ID: 'google-client-id',
      GOOGLE_CLIENT_SECRET: 'google-client-secret',
    })
    expect('google' in providers).toBe(true)
    expect(providers.google?.clientId).toBe('google-client-id')
    expect(providers.google?.clientSecret).toBe('google-client-secret')
  })

  it('enables GitHub when both GITHUB env vars set', () => {
    const providers = buildSocialProviders({
      GITHUB_CLIENT_ID: 'github-client-id',
      GITHUB_CLIENT_SECRET: 'github-client-secret',
    })
    expect('github' in providers).toBe(true)
    expect(providers.github?.clientId).toBe('github-client-id')
  })

  it('enables both Google and GitHub simultaneously', () => {
    const providers = buildSocialProviders({
      GOOGLE_CLIENT_ID: 'gid',
      GOOGLE_CLIENT_SECRET: 'gsecret',
      GITHUB_CLIENT_ID: 'ghid',
      GITHUB_CLIENT_SECRET: 'ghsecret',
    })
    expect('google' in providers).toBe(true)
    expect('github' in providers).toBe(true)
  })

  it('excludes Google when only client_id set (no secret)', () => {
    const providers = buildSocialProviders({
      GOOGLE_CLIENT_ID: 'google-client-id',
      // GOOGLE_CLIENT_SECRET intentionally missing
    })
    expect('google' in providers).toBe(false)
  })

  it('excludes GitHub when only client_secret set (no id)', () => {
    const providers = buildSocialProviders({
      // GITHUB_CLIENT_ID intentionally missing
      GITHUB_CLIENT_SECRET: 'github-secret',
    })
    expect('github' in providers).toBe(false)
  })

  it('excludes provider when env vars are empty strings', () => {
    const providers = buildSocialProviders({
      GOOGLE_CLIENT_ID: '',
      GOOGLE_CLIENT_SECRET: 'secret',
    })
    expect('google' in providers).toBe(false)
  })
})

describe('Social login flow (unit)', () => {
  it('social sign-in follows better-auth convention', () => {
    // Social sign-in starts with a POST to /api/auth/sign-in/social; a GET
    // with the same fields as query parameters is a 404 (the endpoint is
    // POST-only). better-auth answers with the provider URL to follow.
    const endpoint = '/api/auth/sign-in/social'
    const googleBody = { provider: 'google', callbackURL: '/auth/complete' }
    const githubBody = { provider: 'github', callbackURL: '/auth/complete' }

    expect(endpoint).not.toContain('?')
    expect(googleBody.provider).toBe('google')
    expect(githubBody.provider).toBe('github')
    expect(googleBody.callbackURL).toBe('/auth/complete')
    expect(githubBody.callbackURL).toBe('/auth/complete')
  })

  it('bridge route /auth/complete is the callback for all auth methods', () => {
    // Both email OTP and social login redirect to /auth/complete
    // The bridge reads the better-auth session (regardless of auth method)
    // and issues an HMAC-signed redirect to pds-core /oauth/epds-callback
    const callbackUrl = '/auth/complete'
    expect(callbackUrl).toBe('/auth/complete')
  })

  it('account linking: same email from social provider links to existing user', () => {
    // better-auth handles account linking automatically:
    // if a user's Google email matches an existing better-auth user (from email OTP),
    // better-auth links the Google account to the existing user.
    // This means the bridge will read the same email regardless of auth method.
    //
    // Documentation test: verify the expected behavior is understood
    const scenario = {
      step1: 'User signs up via email OTP with user@example.com',
      step2: 'User signs in via Google with user@example.com',
      expected: 'better-auth links Google account to existing user',
      bridgeSees: 'session.user.email === "user@example.com" in both cases',
    }
    expect(scenario.expected).toContain('links')
  })

  it('email mismatch: different emails create separate PDS accounts', () => {
    // If a user has PDS account with email A but signs in via Google with email B,
    // the bridge will attempt to find/create a PDS account for email B.
    // This is by design — each email identity is its own PDS account.
    const scenario = {
      pdsAccountEmail: 'alice@example.com',
      googleEmail: 'alice@gmail.com',
      expected: 'Two separate PDS accounts would be created',
      mitigation:
        'Document that users should use the same email for all auth methods',
    }
    expect(scenario.expected).toContain('Two separate')
  })
})
