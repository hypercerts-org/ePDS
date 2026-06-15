---
'ePDS': patch
---

Docker Caddy deployments now ignore nested random hostnames before they can overload on-demand TLS.

**Affects:** Operators

**Operators:** The default `Caddyfile` now serves only `PDS_HOSTNAME` and one-label subdomains of `PDS_HOSTNAME` (`*.PDS_HOSTNAME`) instead of using a catch-all `:443` on-demand TLS listener. This preserves the PDS apex, `auth.PDS_HOSTNAME`, and normal hosted handles while preventing nested SNI scans from forcing large `/tls-check` storms. If you run extra hosted handle domains, add each domain explicitly as an apex plus one-label wildcard pair rather than restoring `:443`.
