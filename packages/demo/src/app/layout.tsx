import type { Metadata } from 'next'
import { getPageTheme } from '@/lib/theme'

export const dynamic = 'force-dynamic'

export const metadata: Metadata = {
  title: 'ePDS Demo',
  description: 'ePDS Demo — Sign in with your AT Protocol identity',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const t = getPageTheme()

  return (
    <html lang="en">
      <body
        style={
          {
            margin: 0,
            fontFamily:
              '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
            WebkitFontSmoothing: 'antialiased',
            MozOsxFontSmoothing: 'grayscale',
            background: t?.bg ?? '#f8f9fa',
            color: t?.text ?? '#1a1a2e',
            minHeight: '100vh',
          } as React.CSSProperties
        }
      >
        {children}
      </body>
    </html>
  )
}
