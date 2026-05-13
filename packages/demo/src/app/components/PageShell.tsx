import { AppLogo } from './AppLogo'
import { getAuthPreviewUrl } from '@/lib/auth'
import { getPageTheme } from '@/lib/theme'

interface PageShellProps {
  children: React.ReactNode
}

/**
 * Shared outer layout used by all demo login pages: full-viewport centred
 * container with the ePDS Demo logo and h1.
 *
 * When EPDS_CLIENT_THEME is set, the shell sets CSS custom properties on
 * the root div. Child components (including client components) pick them
 * up via `var(--theme-xxx, <fallback>)` — no prop threading required.
 */
export function PageShell({ children }: PageShellProps) {
  const t = getPageTheme()

  // CSS custom properties that child components can reference.
  // Only set when a theme is active; otherwise children use their fallbacks.
  const cssVars: Record<string, string> = t
    ? {
        '--theme-bg': t.bg,
        '--theme-surface': t.surface,
        '--theme-surface-shadow': t.surfaceShadow,
        '--theme-text': t.text,
        '--theme-text-muted': t.textMuted,
        '--theme-text-hint': t.textHint,
        '--theme-primary': t.primary,
        '--theme-primary-text': t.primaryText,
        '--theme-primary-hover': t.primaryHover,
        '--theme-input-bg': t.inputBg,
        '--theme-input-border': t.inputBorder,
        '--theme-focus-border': t.focusBorder,
        '--theme-error-text': t.errorText,
        '--theme-error-bg': t.errorBg,
        '--theme-logo-bg': t.logoBg,
      }
    : {}

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        height: '100vh',
        padding: '20px',
        overflow: 'hidden',
        background: t?.bg ?? '#f8f9fa',
        ...cssVars,
      }}
    >
      <div
        style={{
          maxWidth: '440px',
          width: '100%',
          textAlign: 'center',
        }}
      >
        <div style={{ marginBottom: '24px' }}>
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
        </div>
        {children}
        <a
          href={getAuthPreviewUrl()}
          style={{
            display: 'block',
            marginTop: '24px',
            color: t?.textHint ?? '#9ca3af',
            fontSize: '12px',
            textDecoration: 'none',
          }}
        >
          Preview pages with this client's branding
        </a>
        {process.env.NEXT_PUBLIC_EPDS_VERSION && (
          <p
            style={{
              marginTop: '32px',
              fontSize: '12px',
              color: t?.textHint ?? '#999',
            }}
          >
            ePDS {process.env.NEXT_PUBLIC_EPDS_VERSION}
          </p>
        )}
      </div>
    </div>
  )
}
