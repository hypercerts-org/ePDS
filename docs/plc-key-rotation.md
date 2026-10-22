# Rotate a shared PLC key

Two independent scripts: `rotate-plc-key.ts` changes only the PLC directory; `publish-identity-railway.ts` queues `#identity` on the hosting PDS through Railway SSH. Deployment cutover is always manual.

## Prepare

- Use a clean trusted operator machine, an explicitly verified hosted DID inventory (whitespace-separated), and the trusted HTTPS PLC URL. Split inventory by hosting PDS. Do not test against public PLC.
- Obtain both exportable secp256k1 keys as 64-character hex in separate operator-owned `0600` regular files, not symlinks. Generate the new key with established secret tooling. Never put private keys in arguments, logs or history. Keep input directories protected.
- Review recovery owners, key priority and capacity (maximum five keys). Addition inserts the new key immediately after the old key without evicting recovery keys; an existing new key is not moved. This is not a recovery/fork tool and does not support `did:web` or HSM keys.
- Use Deno **2.8.3** on Linux/macOS. Copy both scripts and this runbook outside the repository. Cache/review dependencies before the incident:

```bash
deno cache --no-config --no-lock --node-modules-dir=none rotate-plc-key.ts
deno run --no-prompt --no-config --no-lock publish-identity-railway.ts --help
```

PLC dependencies are pinned to `npm:@did-plc/lib@0.0.4` and `npm:@atproto/crypto@0.4.5`; transitive versions resolve at caching, so retain the reviewed cache. Do not enable npm lifecycle scripts or `--allow-all`.

Set canonical absolute input paths and your trusted directory URL:

```bash
PLC_URL='https://YOUR-TRUSTED-PLC-HOST'
DIDS='/secure/rotation-dids.txt'
OLD='/secure/rotation-old.hex'
NEW='/secure/rotation-new.hex'
rotate() {
  deno run --no-prompt --cached-only --no-config --no-lock --node-modules-dir=none \
    --allow-sys=hostname,uid --allow-net="${PLC_URL#https://}" \
    --allow-read="$DIDS,$OLD,$NEW" \
    --allow-env=LOG_SYSTEMS,LOG_ENABLED,LOG_LEVEL,LOG_DESTINATION,PLC_ROTATION_OLD_KEY_HEX,PLC_ROTATION_NEW_KEY_HEX \
    ./rotate-plc-key.ts --plc-url "$PLC_URL" --did-file "$DIDS" \
    --old-key-file "$OLD" --new-key-file "$NEW" "$@"
}
```

Grant only selected files, including their canonical targets, not a directory. Do not set `PLC_ROTATION_OLD_KEY_HEX` / `PLC_ROTATION_NEW_KEY_HEX` with files; secret-manager injection of those variables is an alternative (omit the corresponding file arguments/read permissions). No `.env` loading occurs. The PLC logger needs the shown hostname and `LOG_*` permissions. `--did DID` repeated can replace `--did-file` in either script.

## NOW: add only, including during a deployment outage

Run one rotation job at a time; coordinate other PLC writers where possible.

```bash
rotate --phase add
rotate --phase add --apply
```

Preview must show `planned` or `unchanged` for every intended DID. Save the apply JSON; require `updated` or `unchanged` for each DID and verify directory heads: both keys present, unrelated keys/order, aliases, services and verification methods unchanged. `missing-old` is not a successful migration; it and `failed` exit 1. Requests have 15-second deadlines and up to four attempts per DID, reconciling raced heads and ambiguous POSTs. Repeating a completed change does not POST again. No identity event is emitted by this script.

**ADD-ONLY STOP: while deployments are unavailable, leave the old signing configuration active. Do not remove the old key, change secrets, or redeploy.** Overlap is not revocation: a compromised old key still has authority. Accounts created meanwhile may contain only the old key; final inventory reconciliation is mandatory. Notify now using the second script if SSH works; if SSH is also down, notification remains pending, not successful.

## Notify through Railway (independent and repeatable)

Verify the project/environment/service explicitly and, when needed, choose `--instance ID` (`--deployment-instance` on Railway). Use an installed trusted Railway CLI supporting `ssh -p/-e/-s/-d`. Do not mutate linked state. `railway run` is local execution with injected variables, **not remote execution**, and is not used here.

```bash
PROJECT='YOUR-PROJECT-ID'
ENVIRONMENT='YOUR-ENVIRONMENT-ID'
SERVICE='YOUR-HOSTING-PDS-SERVICE-ID'
notify() {
  deno run --no-prompt --no-config --no-lock --allow-read="$DIDS" --allow-run=railway \
    ./publish-identity-railway.ts --project "$PROJECT" --environment "$ENVIRONMENT" \
    --service "$SERVICE" --workdir /app/packages/pds-core --did-file "$DIDS" "$@"
}
notify
notify --apply
```

Default is an offline plan: no Railway process or remote connection. Supply only DIDs whose PLC heads you have verified, not a guessed inventory or failed PLC results. Limit each batch to 1,000 DIDs. The script does not independently read PLC or accept a PLC JSON report.

**Before apply:** verify the package workdir (ePDS currently `/app/packages/pds-core`; override explicitly for other images), exact deployed `@atproto/pds` version exporting public `AppContext`, service user, runtime environment and mounted storage. The SSH process must use the same user/storage/config as the running PDS; do not copy secrets locally. `AppContext.fromEnv()` can initialize/migrate databases: stop if compatibility or permissions are uncertain. This does not start a server or add an admin endpoint. Deno's subprocess permission trusts the Railway executable; it does not sandbox it.

One SSH session handles the batch. Each DID must be a local active account with a handle; unknown, deactivated and taken-down accounts fail. Strict `sequenceIdentity` errors propagate (the upstream helper that swallows errors is not used). Only safe DID/status results are returned; arbitrary remote logs/stderr are suppressed. `queued` means sequencer persistence and successful cleanup, **not relay delivery**. Observe fresh `#identity` on both PDS and relay streams before declaring notification complete.

Each remote setup/DID/cleanup has a 10-second deadline; expiry aborts the batch. The local deadline is 20 seconds plus 11 seconds per DID. Failed/ambiguous transport, timeout, missing reports or cleanup failure exit 1 and conservatively mark the batch failed. Other per-DID errors are isolated and return individual `failed` results with exit 1. Retry independently with a reviewed inventory; at-least-once delivery can duplicate events, but never writes PLC. If SSH cannot reach the correct runtime, stop and retain pending notification; no fallback reports success.

## When deployments recover: freeze, reconcile, cut over

1. Freeze signups **and all other PLC writers**. Obtain the final inventory, including accounts created during the outage. Preview/add the new key to every missing DID with the first script; verify every head, then publish with the second. Stop on any failure.
2. Manually update `PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX` and redeploy **all replicas**. Verify a normal handle/account PLC update signed by the new key and a newly created account using it. Include that test account in final checks; keep other writers frozen. Neither script performs or verifies this gate.
3. Only after those checks, remove and notify:

```bash
rotate --phase remove
rotate --phase remove --apply --confirm-cutover
rotate --phase remove
notify --apply
```

Require removal success, final preview `unchanged`, old key absent, unrelated DID data unchanged, and fresh identity events on both streams. Unfreeze only after all checks pass.

## Stop / rollback

Stop cutover/removal on any failure. Partial success is possible: inspect heads and retry only reviewed DIDs. Notification retry never requires another PLC write. Before removal, leave overlap while investigating (restore old deployment secret only if appropriate). After removal, **do not restore an old-key-only deployment**; engage recovery owners.

**72-hour caveat:** old-key rejection at the current head is not irreversible revocation. A historical key strictly higher priority than the first nullified operation's signer can recover from its parent within PLC's recovery window; equal priority is insufficient. Review audit history and monitor heads with recovery owners. Private testing does not establish elapsed 72-hour expiry or public acceptance.
