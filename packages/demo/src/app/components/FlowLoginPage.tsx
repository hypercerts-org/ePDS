'use client'

import { useSearchParams } from 'next/navigation'
import { useState, Suspense } from 'react'
import { SignInButton } from './SignInButton'

export interface FlowLink {
  href: string
  label: string
}

interface FlowLoginPageProps {
  subtitle: string
  /** Value passed as ?handle_mode=... to /api/oauth/login. Omit for Flow 2
   *  (no handle_mode param — auth server uses its configured default). */
  handleMode?: string
  navLinks: FlowLink[]
}

function FlowLogin({ subtitle, handleMode, navLinks }: FlowLoginPageProps) {
  const searchParams = useSearchParams()
  const error = searchParams.get('error')
  const [submitting, setSubmitting] = useState(false)

  return (
    <>
      <p
        style={{
          fontSize: '13px',
          color: 'var(--theme-text-muted, #6b7280)',
          marginBottom: '24px',
        }}
      >
        {subtitle}
      </p>

      {error && (
        <div
          style={{
            background: 'var(--theme-error-bg, #fef2f2)',
            color: 'var(--theme-error-text, #dc2626)',
            padding: '12px 16px',
            borderRadius: '8px',
            fontSize: '14px',
            marginBottom: '16px',
          }}
        >
          {decodeURIComponent(error)}
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
        {handleMode && (
          <input type="hidden" name="handle_mode" value={handleMode} />
        )}
        <SignInButton submitting={submitting} />
      </form>

      {navLinks.map((link) => (
        <a
          key={link.href}
          href={link.href}
          style={{
            display: 'block',
            marginTop: '8px',
            color: 'var(--theme-text-muted, #6b7280)',
            fontSize: '13px',
            textDecoration: 'none',
          }}
        >
          {link.label}
        </a>
      ))}
    </>
  )
}

export function FlowLoginPage(props: FlowLoginPageProps) {
  return (
    <Suspense>
      <FlowLogin {...props} />
    </Suspense>
  )
}
