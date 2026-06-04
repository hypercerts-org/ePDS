# Cold standby copy for test ePDS

This guide describes the one-shot cold standby workflow for the Railway-hosted test ePDS.

The current scripts intentionally **do not implement continuous sync**. They create one point-in-time copy, normalize SQLite files locally, and optionally validate that a standby service can serve the copied data over XRPC.

## Safety model

The clone script uses Railway only for read-only volume downloads:

```text
railway volume ... files --volume <volume-id> download / <local-path> --json
```

It does not use:

- `railway ssh`
- `railway run`
- `railway link`
- deploy/restart/redeploy
- config or variable reads
- volume mutation commands

The script is pinned to the known `test` ePDS IDs and refuses other IDs unless `--allow-custom-target` is passed. It also requires release timestamps in `YYYYMMDDTHHMMSSZ` format so `--force` cannot delete outside the standby release directory.

Known test target:

```text
Project:        ePDS
Project ID:     17980f2b-0913-439f-a53e-472969130b6d
Environment:    test
Environment ID: 23b4bc8e-faa1-4777-8e5f-436c6f626a2d
Source URL:     https://epds1.test.certified.app
```

Volumes:

```text
pds-core volume:
  9039f826-8b9b-4fb4-8ef2-5a9a22655e59

auth-service volume:
  c3fa8de2-971a-4aff-99ef-f8183f29e6f5
```

## Scripts

```text
scripts/standby-clone.mjs
scripts/standby-normalize-sqlite.mjs
scripts/standby-local-services.mjs
scripts/standby-validate-xrpc.mjs
```

### `standby-clone.mjs`

Creates a timestamped release directory, downloads both Railway volumes, normalizes SQLite, writes reports, and updates `current` after success.

Default output:

```text
/tmp/epds-standby/
  releases/<timestamp>/
  current -> releases/<timestamp>
```

Run against the pinned test ePDS target:

```bash
ALLOW_RAILWAY_DOWNLOAD=1 node scripts/standby-clone.mjs \
  --output-dir /tmp/epds-standby
```

For a Google VM, use a persistent path:

```bash
ALLOW_RAILWAY_DOWNLOAD=1 node scripts/standby-clone.mjs \
  --output-dir /opt/epds-standby
```

The script prints:

```text
Target verification: test-epds
Release directory: <output>/releases/<timestamp>
```

If it does not say `Target verification: test-epds`, stop and check the IDs.

Before a first real download, use `--dry-run` to verify the exact Railway target without calling Railway:

```bash
node scripts/standby-clone.mjs \
  --dry-run \
  --output-dir /tmp/epds-standby-script-test \
  --timestamp 20260604T000000Z
```

Expected dry-run output includes these exact test IDs:

```text
Target verification: test-epds
railway volume -p 17980f2b-0913-439f-a53e-472969130b6d -e 23b4bc8e-faa1-4777-8e5f-436c6f626a2d files --volume 9039f826-8b9b-4fb4-8ef2-5a9a22655e59 download / <release>/pds-core/raw --json
railway volume -p 17980f2b-0913-439f-a53e-472969130b6d -e 23b4bc8e-faa1-4777-8e5f-436c6f626a2d files --volume c3fa8de2-971a-4aff-99ef-f8183f29e6f5 download / <release>/auth-service/raw --json
```

### `standby-normalize-sqlite.mjs`

Normally called by `standby-clone.mjs`. It can also be run manually:

```bash
node scripts/standby-normalize-sqlite.mjs /tmp/epds-standby/current --force
```

Normalization means:

1. Preserve the raw volume download.
2. Copy `raw` to `normalized`.
3. Open each `*.sqlite` with its copied WAL/SHM files present.
4. Run a local WAL checkpoint.
5. Run `VACUUM INTO` to create a clean standalone SQLite file.
6. Remove copied `-wal` and `-shm` files from the normalized copy.
7. Compare raw vs normalized integrity and table counts.

Reports:

```text
sqlite-integrity-report.json
sqlite-integrity-summary.md
```

### `standby-local-services.mjs`

Starts or stops local validation services against a normalized release. This helper keeps the auth-service rate limiter enabled, verifies PID files before stopping processes, and is not the public failover runner.

Start:

```bash
node scripts/standby-local-services.mjs start /tmp/epds-standby/current
```

Status:

```bash
node scripts/standby-local-services.mjs status /tmp/epds-standby/current
```

Stop:

```bash
node scripts/standby-local-services.mjs stop /tmp/epds-standby/current
```

Default local endpoints:

```text
pds-core:     http://localhost:3100
auth-service: http://localhost:3101
```

The helper loads secrets from the repo `.env` file by default. On a Google VM, make sure the standby has the correct ePDS secrets configured before using it for a real failover test. For public Cloudflare failover, run the real services under your VM service manager rather than this local validation helper.

### `standby-validate-xrpc.mjs`

Compares source and target PDS instances over XRPC.

Example after starting local services:

```bash
node scripts/standby-validate-xrpc.mjs \
  --release-dir /tmp/epds-standby/current \
  --source-url https://epds1.test.certified.app \
  --target-url http://localhost:3100 \
  --describe-repo did:plc:fjitforajocxssw732gzsf22 \
  --record at://did:plc:fjitforajocxssw732gzsf22/org.hypercerts.claim.activity/3mgchesr7js2y
```

Checks include:

- `com.atproto.sync.listRepos`
- repo count and cursor
- repo head/rev/status fields
- sample `getRepoStatus`
- sample `getLatestCommit`
- sample `getRepo` CAR byte hashes
- optional `describeRepo`
- optional `getRecord`

Reports:

```text
xrpc/xrpc-compare-report.json
xrpc/xrpc-compare-summary.md
```

## Expected one-shot local validation flow

```bash
ALLOW_RAILWAY_DOWNLOAD=1 node scripts/standby-clone.mjs \
  --output-dir /tmp/epds-standby

node scripts/standby-local-services.mjs start /tmp/epds-standby/current

node scripts/standby-validate-xrpc.mjs \
  --release-dir /tmp/epds-standby/current \
  --target-url http://localhost:3100 \
  --describe-repo did:plc:fjitforajocxssw732gzsf22 \
  --record at://did:plc:fjitforajocxssw732gzsf22/org.hypercerts.claim.activity/3mgchesr7js2y

node scripts/standby-local-services.mjs stop /tmp/epds-standby/current
```

## Known-good local verification

The JS scripts were run locally against the pinned test ePDS target.

Clone command:

```bash
ALLOW_RAILWAY_DOWNLOAD=1 node scripts/standby-clone.mjs \
  --output-dir /tmp/epds-standby-js-run
```

The manifest recorded:

```text
targetVerifiedAs: test-epds
projectId:        17980f2b-0913-439f-a53e-472969130b6d
environmentId:    23b4bc8e-faa1-4777-8e5f-436c6f626a2d
pdsVolumeId:      9039f826-8b9b-4fb4-8ef2-5a9a22655e59
authVolumeId:     c3fa8de2-971a-4aff-99ef-f8183f29e6f5
```

SQLite result:

```text
DBs checked:              173
Raw integrity OK:         173 / 173
Normalized integrity OK:  173 / 173
Integrity changes:        0
Table-count changes:      0
```

Local services were then started from the cloned release and validated against the source:

```bash
node scripts/standby-local-services.mjs start /tmp/epds-standby-js-run/current

node scripts/standby-validate-xrpc.mjs \
  --release-dir /tmp/epds-standby-js-run/current \
  --target-url http://localhost:3100 \
  --describe-repo did:plc:fjitforajocxssw732gzsf22 \
  --record at://did:plc:fjitforajocxssw732gzsf22/org.hypercerts.claim.activity/3mgchesr7js2y

node scripts/standby-local-services.mjs stop /tmp/epds-standby-js-run/current
```

XRPC result:

```text
overallMatch:              true
repoCountSource:           169
repoCountTarget:           169
cursorMatch:               true
missingTargetCount:        0
extraTargetCount:          0
fieldDiffCount:            0
sampleMismatchCount:       0
recordMismatchCount:       0
describeRepoMismatchCount: 0
```

After stopping, local ports `3100` and `3101` were clear.

## Google VM cold standby flow

1. Install repo dependencies and build the app on the VM.
2. Install and authenticate Railway CLI for read-only volume downloads.
3. Configure the VM with the same runtime secrets needed to boot ePDS.
4. Run the clone script into a persistent directory:

   ```bash
   ALLOW_RAILWAY_DOWNLOAD=1 node scripts/standby-clone.mjs \
     --output-dir /opt/epds-standby
   ```

5. Start standby services against `/opt/epds-standby/current` on private/local ports.
6. Validate against the source with `standby-validate-xrpc.mjs`.
7. For a Cloudflare failover test, point the proxied DNS record origin IP from the active PDS to the standby VM IP.

## Required runtime secrets on the standby VM

Volume data alone is not enough for full promotion. The standby VM needs matching runtime secrets, including:

```text
PDS_JWT_SECRET
PDS_DPOP_SECRET
PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX
PDS_ADMIN_PASSWORD
EPDS_CALLBACK_SECRET
EPDS_INTERNAL_SECRET
AUTH_SESSION_SECRET
AUTH_CSRF_SECRET
```

Do not print these values into logs or commit them to the repo.

## Cloudflare failover test expectation

For the first failover test, changing the Cloudflare-proxied origin IP is a reasonable next step because clients still resolve Cloudflare edge IPs. This avoids a client-facing DNS TTL race for the test.

The test validates:

- standby runtime setup,
- current copied data,
- SQLite promote/boot path,
- pds-core XRPC serving through the real hostname,
- auth-service if its hostname is switched too,
- Cloudflare origin routing and TLS/host handling.

It does not yet validate continuous replication or write reconciliation.

## Caveats

This workflow creates a practical point-in-time copy, not a perfect atomic snapshot.

Because we avoid Railway SSH and do not quiesce writes, Railway may download `.sqlite` and `-wal` files while the source service is active. The normalization and integrity reports are designed to catch obvious inconsistencies, but they cannot make a non-atomic copy perfectly atomic.

For stricter backups later, consider:

1. source-side SQLite backup / `VACUUM INTO`,
2. a short read-only or maintenance window,
3. repeatable sync with drift checks,
4. eventually a purpose-built replication or proxy/failover layer.
