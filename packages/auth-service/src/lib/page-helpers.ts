export function renderOptionalStyleTag(css?: string | null): string {
  if (!css) return ''
  return `\n  <style>${css}</style>`
}
