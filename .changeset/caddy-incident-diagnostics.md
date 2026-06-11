---
'ePDS': minor
---

Better diagnostics for investigating Caddy memory spikes and TLS permission-check slowdowns.

**Affects:** Operators

**Operators:** pds-core now emits `tls-check summary` aggregate logs while Caddy's on-demand TLS permission endpoint is active, plus targeted `tls-check slow`, `tls-check aborted`, and `tls-check failed` logs capped at 50 individual warnings per category per summary window. The summary includes in-flight counts, status-code buckets, hostname-shape buckets, request-duration percentiles, account-lookup duration percentiles, event-loop lag, process memory, and suppressed individual-log counts. A new read-only `scripts/caddy-oom-snapshot.sh` watcher can capture Caddy `/debug/vars`, `/metrics`, heap and goroutine profiles, container stats, selected container state without environment variables, connection state, recent compose logs, and recent kernel logs when Caddy memory crosses `THRESHOLD_MIB`.
