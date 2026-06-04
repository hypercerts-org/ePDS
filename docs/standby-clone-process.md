# ePDS test standby clone: process, validation, and lessons

Date: 2026-06-04

Local clone directory:

```text
/tmp/epds-standby-20260604T060434Z
```

Source service:

```text
https://epds1.test.certified.app
```

## 1. Scope and safety boundaries

We explicitly kept this run read-only against Railway.

Constraints:

- No Railway mutation.
- No Railway SSH.
- No deploy, restart, redeploy, config edit, variable edit, volume edit, service link, or environment change.
- Use Railway only for read-only context confirmation and volume file downloads.
- Validate live data through public XRPC calls against `https://epds1.test.certified.app`.

## 2. Railway target confirmation

Railway CLI was confirmed to be linked to the expected test ePDS environment.

```text
Workspace:       hypercerts
Project:         ePDS
Project ID:      17980f2b-0913-439f-a53e-472969130b6d
Environment:     test
Environment ID:  23b4bc8e-faa1-4777-8e5f-436c6f626a2d
Linked service:  @certified-app/pds-core
Service ID:      16bd3666-68ae-4537-95fb-ac516e60e9c8
URL:             https://epds1.test.certified.app
```

Relevant test volumes:

```text
pds-core volume:
  Name:       @certified-app/pds-core-volume
  ID:         9039f826-8b9b-4fb4-8ef2-5a9a22655e59
  Mount path: /data
  Size:       about 1.1 GB reported by Railway

auth-service volume:
  Name:       @certified-app/auth-service-volume
  ID:         c3fa8de2-971a-4aff-99ef-f8183f29e6f5
  Mount path: /data
  Size:       about 1.0 GB reported by Railway
```

## 3. Volume copy

Both volumes were downloaded with `railway volume files download`.

pds-core:

```bash
railway volume \
  -p 17980f2b-0913-439f-a53e-472969130b6d \
  -e 23b4bc8e-faa1-4777-8e5f-436c6f626a2d \
  files \
  --volume 9039f826-8b9b-4fb4-8ef2-5a9a22655e59 \
  download / /tmp/epds-standby-20260604T060434Z/pds-core/raw --json
```

auth-service:

```bash
railway volume \
  -p 17980f2b-0913-439f-a53e-472969130b6d \
  -e 23b4bc8e-faa1-4777-8e5f-436c6f626a2d \
  files \
  --volume c3fa8de2-971a-4aff-99ef-f8183f29e6f5 \
  download / /tmp/epds-standby-20260604T060434Z/auth-service/raw --json
```

Downloaded raw sizes on disk:

```text
auth-service/raw: 576K
pds-core/raw:     71M
```

Normalized sizes on disk:

```text
auth-service/normalized: 520K
pds-core/normalized:     57M
```

## 4. Raw data shape

The pds-core raw volume contained:

```text
account.sqlite
account.sqlite-shm
account.sqlite-wal
did_cache.sqlite
did_cache.sqlite-shm
did_cache.sqlite-wal
sequencer.sqlite
sequencer.sqlite-shm
sequencer.sqlite-wal
actors/<shard>/<did>/store.sqlite
actors/<shard>/<did>/key
blobs/<did>/<cid>
blobs/tempt/<did>/<temp-key>
```

The auth-service raw volume contained:

```text
epds.sqlite
epds.sqlite-shm
epds.sqlite-wal
```

## 5. What “normalization” meant

SQLite can run in WAL mode, where a database’s latest committed state may be split across three files:

```text
db.sqlite
db.sqlite-wal
db.sqlite-shm
```

For the local standby copy, normalization meant:

1. Copy the raw downloaded volume into a separate `normalized` directory.
2. For each `*.sqlite` file, open it locally while its downloaded WAL/SHM sidecars are present.
3. Run a WAL checkpoint locally so committed WAL frames are folded into the main DB file.
4. Run `VACUUM INTO` to produce a clean standalone SQLite DB file.
5. Replace the copied DB with that clean DB file.
6. Remove local `-wal` and `-shm` sidecars from the normalized copy.

After normalization, the standby runs from standalone `*.sqlite` files rather than a copied live WAL triplet.

Important finding: normalization did not repair anything in this run. The raw copy already passed integrity checks.

## 6. SQLite integrity checks

SQLite integrity was checked before and after normalization.

Results:

```text
DBs checked:                              173
Raw integrity OK:                        173 / 173
Normalized integrity OK:                 173 / 173
Integrity result changed after normalize: 0 DBs
Table counts changed after normalize:     0 DBs
Normalization failures:                   0 DBs
Post-serve integrity OK:                  173 / 173
```

Conclusion: the raw clone was already internally consistent for this run. The normalized copy remained identical in integrity and table counts.

Reports:

```text
/tmp/epds-standby-20260604T060434Z/sqlite-integrity-summary.md
/tmp/epds-standby-20260604T060434Z/sqlite-integrity-report.json
/tmp/epds-standby-20260604T060434Z/sqlite-integrity-post-serve.json
```

## 7. Local standby boot

Local services were started without Docker Compose, pointed directly at the cloned data.

Local endpoints:

```text
pds-core:     http://localhost:3100
auth-service: http://localhost:3101
```

Health check results:

```text
pds-core:     {"status":"ok","service":"epds","version":"0.6.3"}
auth-service: {"status":"ok","service":"auth","version":"0.6.3"}
```

Startup scripts were saved in the clone directory:

```bash
/tmp/epds-standby-20260604T060434Z/start-local.sh
/tmp/epds-standby-20260604T060434Z/stop-local.sh
```

Node/native-module note:

- pds-core used Node 20 because the relevant `better-sqlite3@10.1.0` native module was compiled for Node ABI 115.
- auth-service used Node 22 because `better-sqlite3@12.6.2` was compiled for Node ABI 127.

## 8. XRPC validation: repo list

Compared live source against local standby using:

```text
com.atproto.sync.listRepos?limit=1000
```

Source:

```text
https://epds1.test.certified.app/xrpc/com.atproto.sync.listRepos?limit=1000
```

Local:

```text
http://localhost:3100/xrpc/com.atproto.sync.listRepos?limit=1000
```

Results:

```text
Live repos:             169
Local repos:            169
Cursor matched:         yes
Missing locally:        0
Extra locally:          0
Head/rev/status diffs:  0
```

The live `listRepos` response was checked again after validation and did not drift.

## 9. XRPC validation: sample repo status, commits, and CAR exports

For sample repos, these endpoints were compared:

```text
com.atproto.sync.getRepoStatus
com.atproto.sync.getLatestCommit
com.atproto.sync.getRepo
```

Sample DIDs checked:

```text
did:plc:24mskcdskqqtl6w55yljqv5i
did:plc:ilur5amlztscgbum4qa7mn2x
did:plc:zyz7h7voxlrdwdtblzwqsres
```

Results:

```text
Sample repos checked: 3
Endpoint mismatches:  0
CAR exports:          matched byte-for-byte
```

Report:

```text
/tmp/epds-standby-20260604T060434Z/xrpc/xrpc-compare-summary.md
/tmp/epds-standby-20260604T060434Z/xrpc/xrpc-compare-report.json
```

## 10. XRPC validation: collections

Used:

```text
com.atproto.repo.describeRepo
```

First checked a DID with no collections:

```text
did:plc:24mskcdskqqtl6w55yljqv5i
```

Result:

```text
collection_count: 0
remote/local body match: true
```

Then checked a DID with non-empty collections:

```text
did:plc:fjitforajocxssw732gzsf22
handle: kzoepsaa.epds1.test.certified.app
```

Collections matched exactly on source and local:

```text
app.certified.actor.profile
app.certified.location
org.hypercerts.claim.activity
org.hypercerts.claim.attachment
org.hypercerts.claim.contribution
org.hypercerts.claim.contributorInformation
org.hypercerts.claim.evaluation
org.hypercerts.claim.measurement
org.hypercerts.claim.rights
org.hypercerts.context.attachment
org.hypercerts.context.evaluation
org.hypercerts.context.measurement
```

Comparison:

```text
same_body:             true
same_collections:      true
same_collection_count: true
same_handle:           true
sha256:                3bc4a77b0c9eb20b76809c5fabe990b0457de8c850bb804e1e251497c8e3c913
```

Report:

```text
/tmp/epds-standby-20260604T060434Z/xrpc/collections-check/describeRepo-nonempty-compare.json
```

## 11. XRPC validation: specific record

Queried this record on both source and local:

```text
at://did:plc:fjitforajocxssw732gzsf22/org.hypercerts.claim.activity/3mgchesr7js2y
```

Endpoint:

```text
com.atproto.repo.getRecord
```

Source request:

```text
https://epds1.test.certified.app/xrpc/com.atproto.repo.getRecord?repo=did%3Aplc%3Afjitforajocxssw732gzsf22&collection=org.hypercerts.claim.activity&rkey=3mgchesr7js2y
```

Local request:

```text
http://localhost:3100/xrpc/com.atproto.repo.getRecord?repo=did%3Aplc%3Afjitforajocxssw732gzsf22&collection=org.hypercerts.claim.activity&rkey=3mgchesr7js2y
```

Results:

```text
Source status: 200
Local status:  200
Same data:     true
Same SHA256:   dc2a0239d3f043797c79a6803b44d84bf96fcf721cdc3ce4199dddc7b19f7ff5
```

Record summary:

```text
CID:   bafyreiggbcoihleht6alniwvhdddz4bk4swcp4xdt4bvlkr44433pmfiti
URI:   at://did:plc:fjitforajocxssw732gzsf22/org.hypercerts.claim.activity/3mgchesr7js2y
Type:  org.hypercerts.claim.activity
Title: Clean Energy Community Initiative 100
```

Report:

```text
/tmp/epds-standby-20260604T060434Z/xrpc/record-check/getRecord-compare.json
```

## 12. What worked

- Railway volume file download worked without SSH.
- The raw SQLite clone was already consistent in this run.
- Local normalization produced clean standalone DB files and did not change integrity results or table counts.
- pds-core could serve real XRPC traffic from the cloned data.
- auth-service booted successfully from the cloned auth DB.
- Source and local matched at repo-list level, sample repo/CAR level, collection level, and specific-record level.

## 13. What we learned

- For this dataset, direct Railway volume download was sufficient for a practical standby validation.
- The SQLite “promote” equivalent here is simple:
  1. copy volume data,
  2. normalize/checkpoint SQLite files,
  3. point services at restored `/data`,
  4. boot services,
  5. validate over XRPC.
- Normalization is useful operational hygiene, but it did not fix anything this time.
- Keeping raw and normalized copies is useful:
  - `raw` preserves the exact downloaded volume state, including WAL/SHM sidecars.
  - `normalized` is easier to boot, archive, and reason about.
- XRPC validation is the most meaningful check for pds-core because it confirms the service can actually serve repo data, not just that SQLite files open.

## 14. Caveats

This was not a perfectly atomic backup.

Because we avoided Railway SSH and did not quiesce writes, the raw volume download could theoretically capture `.sqlite` and `-wal` files at incompatible moments. In that case, raw integrity checks could fail or data could drift.

That did not happen in this run:

- raw integrity passed for all DBs,
- normalized integrity passed for all DBs,
- table counts did not change during normalization,
- live `listRepos` did not drift before/after validation,
- source and local XRPC checks matched.

For a stricter backup, use one of these approaches:

1. Run SQLite backup / `VACUUM INTO` on the source side before download.
2. Temporarily quiesce writes before copying.
3. Implement an app-level read-only/maintenance window for standby snapshotting.

Those stricter options involve either remote execution or service mutation, which were intentionally out of scope for this run.

## 15. Operational notes

The local clone contains sensitive service data, actor key files, and auth data. Keep it local and delete it when no longer needed.

To stop local services:

```bash
/tmp/epds-standby-20260604T060434Z/stop-local.sh
```

To start them again:

```bash
/tmp/epds-standby-20260604T060434Z/start-local.sh
```

To remove the clone after use:

```bash
rm -rf /tmp/epds-standby-20260604T060434Z
```

Only run the removal command after confirming the local clone is no longer needed.
