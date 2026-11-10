'use client'

import { useSearchParams } from 'next/navigation'
import type { CSSProperties } from 'react'
import { useState } from 'react'
import { ForceLoginCheckbox } from './ForceLoginCheckbox'

const ERROR_MESSAGES: Record<string, string> = {
  auth_failed: 'Authentication failed. Please try again.',
  session_expired:
    'Your sign-in took too long to finish. Please sign in again.',
  par_failed:
    'Could not start login — the PDS rejected the request. Check server logs.',
  invalid_email: 'Please enter a valid email address.',
  invalid_handle: 'Please enter a valid handle (e.g. you.bsky.social).',
  invalid_login_hint: 'Invalid login hint format.',
  token_failed: 'Login could not be completed — token exchange failed.',
  state_mismatch:
    'Login session expired or was tampered with. Please try again.',
}

const dividerLineStyle: CSSProperties = {
  flex: 1,
  height: '1px',
  background: 'var(--theme-input-border, #e5e7eb)',
}

/** Blue "@" on the Atmosphere button; same size as {@link GoogleIcon}. */
function AtmosphereIcon() {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">
      <path
        fill="#527FF1"
        d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10h5v-2h-5c-4.34 0-8-3.66-8-8s3.66-8 8-8 8 3.66 8 8v1.43c0 .79-.71 1.57-1.5 1.57s-1.5-.78-1.5-1.57V12c0-2.76-2.24-5-5-5s-5 2.24-5 5 2.24 5 5 5c1.38 0 2.64-.56 3.54-1.47.65.89 1.77 1.47 2.96 1.47 1.97 0 3.5-1.6 3.5-3.57V12c0-5.52-4.48-10-10-10zm0 13c-1.66 0-3-1.34-3-3s1.34-3 3-3 3 1.34 3 3-1.34 3-3 3z"
      />
    </svg>
  )
}

/** Same paths as the Google icon on the auth-service login page. */
function GoogleIcon() {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">
      <path
        fill="#4285F4"
        d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
      />
      <path
        fill="#34A853"
        d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
      />
      <path
        fill="#FBBC05"
        d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z"
      />
      <path
        fill="#EA4335"
        d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
      />
    </svg>
  )
}

/** Shared by "Sign in with Atmosphere" and "Sign in with Google" so they pair. */
function secondaryButtonStyle(disabled: boolean): CSSProperties {
  return {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '8px',
    width: '100%',
    maxWidth: '290px',
    margin: '0 auto',
    padding: '12px 28px',
    fontSize: '15px',
    fontWeight: 500,
    color: 'var(--theme-text, #1a1a2e)',
    background: 'var(--theme-input-bg, #fff)',
    border: '1px solid var(--theme-input-border, #e5e7eb)',
    borderRadius: '8px',
    cursor: disabled ? 'default' : 'pointer',
  }
}

/**
 * Interactive login form (client component). Picks up theme colours via
 * CSS custom properties set by PageShell on the parent div.
 */
export function LoginForm() {
  const searchParams = useSearchParams()
  const errorCode = searchParams.get('error')
  const errorMessage = errorCode
    ? ERROR_MESSAGES[errorCode] || `Unexpected error: ${errorCode}`
    : null
  const [submitting, setSubmitting] = useState(false)
  const [mode, setMode] = useState<'email' | 'handle'>('email')

  const switchMode = (newMode: 'email' | 'handle') => {
    setMode(newMode)
    setSubmitting(false)
  }

  return (
    <>
      {errorMessage && (
        <div
          role="alert"
          style={{
            background: 'var(--theme-error-bg, #fef2f2)',
            color: 'var(--theme-error-text, #dc2626)',
            padding: '12px 16px',
            borderRadius: '8px',
            fontSize: '14px',
            marginBottom: '16px',
            maxWidth: '290px',
            margin: '0 auto 16px',
          }}
        >
          {errorMessage}
        </div>
      )}

      <form
        id="login-form"
        action="/api/oauth/login"
        method="GET"
        style={{ margin: '0 auto', maxWidth: '290px' }}
        onSubmit={() => {
          setTimeout(() => {
            setSubmitting(true)
          }, 0)
        }}
      >
        <div style={{ marginBottom: '16px', textAlign: 'left' }}>
          <label
            htmlFor={mode === 'email' ? 'email' : 'handle'}
            style={{
              display: 'block',
              fontSize: '14px',
              fontWeight: 500,
              color: 'var(--theme-text, #1a1a2e)',
              marginBottom: '6px',
            }}
          >
            {mode === 'email' ? 'Email address' : 'Handle'}
          </label>
          {mode === 'email' ? (
            <input
              type="email"
              id="email"
              name="email"
              required
              autoFocus
              placeholder="you@example.com"
              readOnly={submitting}
              style={{
                width: '100%',
                padding: '12px 14px',
                fontSize: '16px',
                border: '1px solid var(--theme-input-border, #e5e7eb)',
                borderRadius: '8px',
                outline: 'none',
                boxSizing: 'border-box',
                background: 'var(--theme-input-bg, #fff)',
                color: 'var(--theme-text, #1a1a2e)',
              }}
            />
          ) : (
            <input
              type="text"
              id="handle"
              name="handle"
              required
              autoFocus
              placeholder="you.bsky.social"
              readOnly={submitting}
              style={{
                width: '100%',
                padding: '12px 14px',
                fontSize: '16px',
                border: '1px solid var(--theme-input-border, #e5e7eb)',
                borderRadius: '8px',
                outline: 'none',
                boxSizing: 'border-box',
                background: 'var(--theme-input-bg, #fff)',
                color: 'var(--theme-text, #1a1a2e)',
              }}
            />
          )}
        </div>
        <ForceLoginCheckbox disabled={submitting} />
        <button
          type="submit"
          disabled={submitting}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '100%',
            padding: '14px 28px',
            fontSize: '16px',
            fontWeight: 500,
            color: 'var(--theme-primary-text, #ffffff)',
            background: submitting
              ? '#4a4a4a'
              : 'var(--theme-primary, #2563eb)',
            border: 'none',
            borderRadius: '8px',
            cursor: submitting ? 'default' : 'pointer',
            letterSpacing: '0.3px',
            opacity: submitting ? 0.7 : 1,
          }}
        >
          {mode === 'email' ? (
            submitting ? (
              // Neutral copy rather than "Sending verification code..." —
              // the demo redirects to auth-service which decides whether
              // to send an OTP or auto-sign-in via an existing device
              // session (HYPER-268). Claiming we're sending a code is
              // inaccurate in the reuse path.
              'Redirecting...'
            ) : (
              <>
                <img
                  src="/certified-logo.png"
                  alt=""
                  style={{ height: '20px', marginRight: '12px' }}
                />
                Sign in with Certified
              </>
            )
          ) : submitting ? (
            'Redirecting...'
          ) : (
            'Sign in'
          )}
        </button>
      </form>

      {/* Alternatives to the email form, under one "or" divider: Atmosphere
          (handle login) first, then Google. */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          maxWidth: '290px',
          margin: '20px auto',
          color: 'var(--theme-text-muted, #6b7280)',
          fontSize: '13px',
        }}
      >
        <span style={dividerLineStyle} />
        or
        <span style={dividerLineStyle} />
      </div>

      <button
        type="button"
        onClick={() => {
          switchMode(mode === 'email' ? 'handle' : 'email')
        }}
        style={secondaryButtonStyle(false)}
      >
        {mode === 'email' ? (
          <>
            <AtmosphereIcon />
            Sign in with Atmosphere
          </>
        ) : (
          'Sign in with email'
        )}
      </button>

      {mode === 'email' && (
        // Submits the email form with social_provider=google, skipping its
        // required-email check: the auth server starts Google straight
        // away (no email code), using the email as Google's login hint
        // when one was entered.
        <button
          type="submit"
          form="login-form"
          name="social_provider"
          value="google"
          formNoValidate
          disabled={submitting}
          style={{ ...secondaryButtonStyle(submitting), marginTop: '12px' }}
        >
          <GoogleIcon />
          Sign in with Google
        </button>
      )}
    </>
  )
}
