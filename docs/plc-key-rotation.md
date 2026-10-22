# Rotate a shared PLC key

Rotate the shared secp256k1 rotation key for an explicit inventory of PLC DIDs on any PDS; deployment cutover is manual.

## Before starting — STOP if any check fails

- Use a trusted operator machine; after compromise, use a clean machine and involve recovery owners.
- Obtain the exact DID inventory and trusted HTTPS PLC directory URL. Freeze signup and other PLC writers; run one rotation job only.
- Have both exportable private keys as 64-character hex in separate owner-only (`0600`), operator-owned regular files, not symlinks. Generate the new key with established secret tooling. Never put hex in arguments, logs or shell history.
- Check recovery owners and key priority. Adding needs a free slot (maximum five keys); this script never evicts recovery keys.
- This handles `did:plc`, not `did:web` or non-exportable/HSM keys. It needs no PDS database, repository, build or package manifest.

## Set up once

Use Deno **2.8.3** on Linux/macOS. Copy `rotate-plc-key.ts` and this runbook anywhere outside the repository. From that directory:

```bash
deno --version
deno cache --no-config --no-lock --node-modules-dir=none rotate-plc-key.ts
deno run --no-prompt --allow-sys=hostname,uid \
  --allow-env=LOG_SYSTEMS,LOG_ENABLED,LOG_LEVEL,LOG_DESTINATION --no-config --no-lock --node-modules-dir=none rotate-plc-key.ts --help
```

The script pins `npm:@did-plc/lib@0.0.4` and `npm:@atproto/crypto@0.4.5`; review/cache dependencies before the incident. The PLC library’s logger needs hostname and the four `LOG_*` environment permissions shown below. Deno does not run npm lifecycle scripts without explicit approval: do not enable scripts or use `--allow-all`. Transitive versions are resolved during caching; keep the reviewed cache for the operation.

Set these values yourself (absolute paths; inventory is whitespace-separated DIDs):

```bash
PLC_URL='https://YOUR-TRUSTED-PLC-HOST'
DIDS='/secure/rotation-dids.txt'
OLD='/secure/rotation-old.hex'
NEW='/secure/rotation-new.hex'
rotate() {
  deno run --no-prompt --allow-sys=hostname,uid --cached-only --no-config --no-lock --node-modules-dir=none \
    --allow-net="${PLC_URL#https://}" --allow-read="$DIDS,$OLD,$NEW" \
    --allow-env=LOG_SYSTEMS,LOG_ENABLED,LOG_LEVEL,LOG_DESTINATION,PLC_ROTATION_OLD_KEY_HEX,PLC_ROTATION_NEW_KEY_HEX \
    ./rotate-plc-key.ts --plc-url "$PLC_URL" --did-file "$DIDS" \
    --old-key-file "$OLD" --new-key-file "$NEW" "$@"
}
```

Do not set `PLC_ROTATION_OLD_KEY_HEX` / `PLC_ROTATION_NEW_KEY_HEX` when using files. Secret-manager injection of those variables is an alternative: omit the corresponding file arguments/read permissions. No `.env` loading occurs. `--did DID` (repeatable) can replace `--did-file`.

## 1. Add overlap, then check every DID

```bash
rotate --phase add
rotate --phase add --apply
```

First command must report `planned` or already `unchanged` for every intended DID; it never POSTs. Review before applying. Apply must report `updated` or `unchanged` for every DID. Save JSON reports; both `failed` and `missing-old` exit 1. **Missing-old is not a successful migration:** reconcile the inventory before proceeding.

Verify directory data: both keys present, unrelated recovery keys/order, verification methods, aliases and services unchanged. The new key is inserted immediately after the old key; an existing new key is not moved.

## 2. Manual deployment gate — do not skip

Update the PDS secret to the new key (`PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX` on upstream PDS). Restart/redeploy **all replicas** using your PDS's procedure. Verify a normal handle/account PLC update signed by the new key and that a newly created account uses it. Reconcile the final inventory, including any test signup; keep other writers frozen. The script neither performs nor verifies this gate.

## 3. Remove the old key

```bash
rotate --phase remove
rotate --phase remove --apply --confirm-cutover
rotate --phase remove
```

Review the preview before applying. Removal uses the new signer and requires overlap. Verify old key absent, unrelated DID data unchanged, and final preview `unchanged` for every DID. Restore signup/other writers only after all checks pass.

## Failure / rollback

- Stop cutover/removal on any failure or unexplained status. Partial success is possible. Inspect directory heads and rerun only reviewed inventory; repeats do not write already-completed changes.
- Requests time out after 15 seconds; four attempts maximum per DID reconcile stale heads and ambiguous POST results. No raw HTTP errors or keys are printed. Capture JSON, not shell tracing.
- Before removal: restore the old deployment secret if necessary; leave overlap while investigating. After removal: **do not restore an old-key-only deployment**. Engage recovery owners; this is not a recovery/fork tool.
- **72-hour caveat:** old-key rejection at the current head is not irreversible revocation. A historical key strictly higher priority than the first nullified operation's signer can recover from its parent within PLC's recovery window; equal priority is insufficient. Review audit history with recovery owners and monitor heads through the window.

Validation uses disposable private PLC DIDs only; never test against public directories. Private AiaB validation covers three key-order layouts and protocol cutover, not a real PDS deployment or elapsed 72-hour expiry.
