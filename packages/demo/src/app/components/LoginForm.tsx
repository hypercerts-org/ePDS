'use client'

import { useSearchParams } from 'next/navigation'
import { useState } from 'react'

const ERROR_MESSAGES: Record<string, string> = {
  auth_failed: 'Authentication failed. Please try again.',
  par_failed:
    'Could not start login — the PDS rejected the request. Check server logs.',
  invalid_email: 'Please enter a valid email address.',
  invalid_handle: 'Please enter a valid handle (e.g. you.bsky.social).',
  token_failed: 'Login could not be completed — token exchange failed.',
  state_mismatch:
    'Login session expired or was tampered with. Please try again.',
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
            color: '#ffffff',
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
              'Sending verification code...'
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

      <button
        type="button"
        onClick={() => {
          switchMode(mode === 'email' ? 'handle' : 'email')
        }}
        style={{
          background: 'none',
          border: 'none',
          padding: 0,
          color: 'var(--theme-text-muted, #6b7280)',
          fontSize: '13px',
          cursor: 'pointer',
          marginTop: '16px',
        }}
      >
        {mode === 'email'
          ? 'Sign in with ATProto/Bluesky'
          : 'Sign in with Certified'}
      </button>
    </>
  )
}
