---
'ePDS': minor
---

Add standalone tooling and a runbook for rotating a shared PLC rotation key across hosted DIDs.

**Affects:** Operators

**Operators:** Run `scripts/rotate-plc-key.ts` with Deno 2.8.3, an explicit PLC directory and DID inventory, and protected old/new key files. Follow `docs/plc-key-rotation.md` to preview and add the new key, manually switch the PDS signing configuration, then remove the old key. The script runs independently of ePDS; it does not change deployment secrets or eliminate PLC's historical recovery window.
