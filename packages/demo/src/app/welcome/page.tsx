/**
 * Welcome page — post-login dashboard.
 *
 * Shows the user's handle and DID after successful OAuth login.
 * Provides a sign-out button that clears the session cookie.
 */

import { cookies } from 'next/headers'
import { redirect } from 'next/navigation'
import { getSessionFromCookie, SESSION_COOKIE } from '@/lib/session'
import { AppLogo } from '../components/AppLogo'
import { getPageTheme } from '@/lib/theme'

// Force runtime rendering so EPDS_CLIENT_THEME is read at request time
export const dynamic = 'force-dynamic'

async function signOut() {
  'use server'

  const cookieStore = await cookies()
  cookieStore.delete(SESSION_COOKIE)
  redirect('/')
}

export default async function Welcome() {
  const cookieStore = await cookies()
  const session = getSessionFromCookie(cookieStore)

  if (!session) {
    redirect('/')
  }

  const t = getPageTheme()

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '100vh',
        padding: '20px',
        background: t?.bg ?? '#f8f9fa',
      }}
    >
      <div
        style={{
          maxWidth: '520px',
          width: '100%',
          textAlign: 'center',
        }}
      >
        <AppLogo size={64} logoBg={t?.logoBg} />
        <h1
          style={{
            fontSize: '22px',
            fontWeight: 600,
            color: t?.text ?? '#1a1a2e',
            margin: '12px 0 4px',
          }}
        >
          {process.env.EPDS_CLIENT_NAME ?? 'ePDS Demo'}
        </h1>
        <p
          style={{
            fontSize: '17px',
            color: t?.textMuted ?? '#6b7280',
            lineHeight: 1.6,
            margin: '0 0 24px 0',
          }}
        >
          You are signed in.
        </p>

        <div
          style={{
            background: t?.surface ?? '#fff',
            borderRadius: '12px',
            padding: '28px 32px',
            textAlign: 'left',
            boxShadow: t?.surfaceShadow ?? '0 1px 4px rgba(0,0,0,0.06)',
            marginBottom: '32px',
          }}
        >
          <div style={{ marginBottom: '16px' }}>
            <div
              style={{
                fontSize: '12px',
                fontWeight: 600,
                color: t?.textMuted ?? '#6b7280',
                textTransform: 'uppercase',
                letterSpacing: '0.5px',
                marginBottom: '4px',
              }}
            >
              Handle
            </div>
            <div style={{ fontSize: '17px', color: t?.text ?? '#1a1a2e' }}>
              @{session.userHandle}
            </div>
          </div>
          <div>
            <div
              style={{
                fontSize: '12px',
                fontWeight: 600,
                color: t?.textMuted ?? '#6b7280',
                textTransform: 'uppercase',
                letterSpacing: '0.5px',
                marginBottom: '4px',
              }}
            >
              DID
            </div>
            <div
              style={{
                fontSize: '13px',
                color: t?.textMuted ?? '#6b7280',
                fontFamily: "'SF Mono', Menlo, Consolas, monospace",
                wordBreak: 'break-all',
              }}
            >
              {session.userDid}
            </div>
          </div>
        </div>

        <form action={signOut} style={{ textAlign: 'center' }}>
          <button
            type="submit"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '14px 28px',
              fontSize: '16px',
              fontWeight: 500,
              color: '#ffffff',
              background: t?.primary ?? '#2563eb',
              border: 'none',
              borderRadius: '8px',
              cursor: 'pointer',
              letterSpacing: '0.3px',
            }}
          >
            Sign out
          </button>
        </form>
      </div>
    </div>
  )
}
