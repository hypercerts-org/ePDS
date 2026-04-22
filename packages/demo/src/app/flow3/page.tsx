import { PageShell } from '../components/PageShell'
import { FlowLoginPage } from '../components/FlowLoginPage'

export const dynamic = 'force-dynamic'

export default function Flow3Page() {
  return (
    <PageShell>
      <FlowLoginPage
        subtitle="Flow 3 — random handle (server assigns, no picker)"
        handleMode="random"
        navLinks={[
          { href: '/', label: 'Switch to Flow 1 (email form)' },
          { href: '/flow2', label: 'Switch to Flow 2 (no email form)' },
          { href: '/flow4', label: 'Switch to Flow 4 (plain picker)' },
        ]}
      />
    </PageShell>
  )
}
