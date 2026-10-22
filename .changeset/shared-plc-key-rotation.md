---
'ePDS': minor
---

Adds a standalone PLC key rotation tool and a separate Railway identity notification helper.

**Affects:** Operators

**Operators:** Use Deno 2.8.3 with `scripts/rotate-plc-key.ts` to preview/add/remove keys for an explicit verified DID inventory, and independently run `scripts/publish-identity-railway.ts --project ID --environment ID --service ID --did-file PATH --apply` to queue identity notifications on the hosting PDS. Follow `docs/plc-key-rotation.md`: during deployment outages add only while retaining the old signing configuration; once deployments recover, freeze writers, reconcile accounts created during the outage, manually switch and verify all PDS replicas, then remove the old key and notify again. The Railway helper requires compatible remote runtime/storage/user access; notification failure exits nonzero and can be retried without PLC writes. Neither tool changes deployment secrets, redeploys services, or eliminates PLC's historical recovery window.
