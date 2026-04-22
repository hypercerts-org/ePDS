import { PageShell } from '../components/PageShell'
import { FlowLoginPage } from '../components/FlowLoginPage'

export const dynamic = 'force-dynamic'

export default function Flow4Page() {
  return (
    <PageShell>
      <FlowLoginPage
        subtitle="Flow 4 — plain picker (user must choose a handle)"
        handleMode="picker"
        navLinks={[
          { href: '/', label: 'Switch to Flow 1 (email form)' },
          { href: '/flow2', label: 'Switch to Flow 2 (no email form)' },
          { href: '/flow3', label: 'Switch to Flow 3 (random handle)' },
        ]}
      />
    </PageShell>
  )
}
