import { PageShell } from '../components/PageShell'
import { FlowLoginPage } from '../components/FlowLoginPage'

export const dynamic = 'force-dynamic'

export default function Flow2Page() {
  return (
    <PageShell>
      <FlowLoginPage
        subtitle="Flow 2 — auth server collects email (picker-with-random default)"
        navLinks={[
          { href: '/', label: 'Switch to Flow 1 (email form)' },
          { href: '/flow3', label: 'Switch to Flow 3 (random handle)' },
          { href: '/flow4', label: 'Switch to Flow 4 (plain picker)' },
        ]}
      />
    </PageShell>
  )
}
