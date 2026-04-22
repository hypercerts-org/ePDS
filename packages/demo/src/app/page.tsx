import { Suspense } from 'react'
import { PageShell } from './components/PageShell'
import { LoginForm } from './components/LoginForm'

// Force runtime rendering so EPDS_CLIENT_THEME is read at request time
export const dynamic = 'force-dynamic'

/**
 * Login page — Flow 1 (email or handle).
 *
 * The user enters an email address or ATProto handle. The form submits to
 * /api/oauth/login which starts the OAuth flow via PAR.
 *
 * This is a server component. PageShell reads EPDS_CLIENT_THEME and sets
 * CSS custom properties; child client components pick them up via var().
 */
export default function Home() {
  return (
    <PageShell>
      <p
        style={{
          fontSize: '14px',
          color: 'var(--theme-text-muted, #6b7280)',
          margin: '0 0 24px',
        }}
      >
        Sign in with your AT Protocol identity
      </p>
      <Suspense>
        <LoginForm />
      </Suspense>

      <a
        href="/flow2"
        style={{
          display: 'block',
          marginTop: '8px',
          color: 'var(--theme-text-hint, #9ca3af)',
          fontSize: '12px',
          textDecoration: 'none',
        }}
      >
        Test Flow 2 (no email form, picker-with-random)
      </a>
      <a
        href="/flow3"
        style={{
          display: 'block',
          marginTop: '4px',
          color: 'var(--theme-text-hint, #9ca3af)',
          fontSize: '12px',
          textDecoration: 'none',
        }}
      >
        Test Flow 3 (random handle)
      </a>
      <a
        href="/flow4"
        style={{
          display: 'block',
          marginTop: '4px',
          color: 'var(--theme-text-hint, #9ca3af)',
          fontSize: '12px',
          textDecoration: 'none',
        }}
      >
        Test Flow 4 (plain picker)
      </a>
    </PageShell>
  )
}
