import { describe, expect, it } from 'vitest'

import { DEFAULT_BRANDING_CSS } from '../lib/default-branding.js'

describe('DEFAULT_BRANDING_CSS', () => {
  it('themes provider UI 0.10 semantic color roles', () => {
    expect(DEFAULT_BRANDING_CSS).toContain('--background: #F8F8F8')
    expect(DEFAULT_BRANDING_CSS).toContain('--card: #F8F8F8')
    expect(DEFAULT_BRANDING_CSS).toContain('--secondary: #FFFFFF')
    expect(DEFAULT_BRANDING_CSS).toContain('--muted: #E8E8E8')
    expect(DEFAULT_BRANDING_CSS).toContain('--muted-foreground: #6B6B6B')
    expect(DEFAULT_BRANDING_CSS).toContain('--accent: #FAFAFA')
    expect(DEFAULT_BRANDING_CSS).toContain('--border: #E5E5E5')
  })

  it('styles the provider card through its data-slot contract', () => {
    expect(DEFAULT_BRANDING_CSS).toContain('[data-slot="card"]')
    expect(DEFAULT_BRANDING_CSS).toContain(
      'box-shadow: 0 1px 2px rgba(0,0,0,0.03)',
    )
  })

  it('does not depend on provider UI 0.8 gray/slate layout utilities', () => {
    expect(DEFAULT_BRANDING_CSS).not.toContain('.md\\:bg-slate-100')
    expect(DEFAULT_BRANDING_CSS).not.toContain('.text-slate-')
    expect(DEFAULT_BRANDING_CSS).not.toContain('.bg-gray-')
    expect(DEFAULT_BRANDING_CSS).not.toContain(
      '.flex.flex-row-reverse.flex-wrap.items-center',
    )
  })
})
