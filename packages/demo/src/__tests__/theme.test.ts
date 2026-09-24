import { afterEach, describe, expect, it } from 'vitest'

import { getPageTheme, getTheme } from '../lib/theme'

const originalTheme = process.env.EPDS_CLIENT_THEME

afterEach(() => {
  if (originalTheme === undefined) {
    delete process.env.EPDS_CLIENT_THEME
    return
  }

  process.env.EPDS_CLIENT_THEME = originalTheme
})

describe('getTheme', () => {
  it('returns null when no theme is configured', () => {
    delete process.env.EPDS_CLIENT_THEME

    expect(getTheme()).toBeNull()
  })

  it('returns null for an unknown theme', () => {
    process.env.EPDS_CLIENT_THEME = 'forest'

    expect(getTheme()).toBeNull()
  })

  it('returns the ocean theme with page values and injected CSS', () => {
    process.env.EPDS_CLIENT_THEME = 'ocean'

    const theme = getTheme()

    expect(theme?.page.primary).toBe('#8b5cf6')
    expect(theme?.injectedCss).toContain('--branding-color-primary: 139 92 246')
    expect(theme?.injectedCss).toContain('--background: #251845')
    expect(theme?.injectedCss).toContain('--card: #251845')
    expect(theme?.injectedCss).toContain('--secondary: #1a1033')
    expect(theme?.injectedCss).toContain('--muted: #1a1033')
    expect(theme?.injectedCss).toContain('--border: #3d2a5c')
    expect(theme?.injectedCss).toContain('[data-slot="card"]')
    expect(theme?.injectedCss).not.toContain(String.raw`.md\:bg-slate-100`)
    expect(theme?.injectedCss).not.toContain('.text-slate-')
    expect(theme?.injectedCss).not.toContain('.bg-gray-')
    expect(theme?.injectedCss).toContain(
      '.account-info { background: #2d1a4f; color: #c4b5fd; }',
    )
  })

  it('returns the amber page theme', () => {
    process.env.EPDS_CLIENT_THEME = 'amber'

    expect(getPageTheme()).toMatchObject({
      bg: '#1a1208',
      primary: '#f59e0b',
      primaryText: '#1a1208',
    })
  })
})
