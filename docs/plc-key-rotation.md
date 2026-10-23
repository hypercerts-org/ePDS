# Rotate a shared PLC key

Use these scripts when rotating the PLC signing key shared by accounts on one PDS:

- `rotate-plc-key.ts` adds or removes the key in the PLC directory.
- `publish-identity-railway.ts` or `publish-identity-docker.ts` asks the PDS to publish `#identity` events through Railway SSH or Docker after you have verified the directory changes.

None of these scripts changes deployed secrets or redeploys the PDS. You perform that deployment step yourself.

## Prepare

List active DIDs without an admin password (active means not deactivated or taken down):

```bash
deno run --no-config --no-lock --allow-net=YOUR-TRUSTED-PDS-HOST scripts/list-active-dids.ts --pds-url https://YOUR-TRUSTED-PDS-HOST > dids.txt
```

- Use a trusted machine. Prepare a checked list of the PDS's DIDs, with **one DID per line**. Run a separate batch for each PDS. Do not test against the public PLC directory. Use Atmosphere in a Box instead.
- Store the old and new exportable secp256k1 keys as 64-character hexadecimal values in two separate regular files, not symlinks. Use your normal secret-management tooling to generate and protect the new key.
- Check recovery owners, key order, and available key slots before starting. PLC allows at most five rotation keys. The script places the new key immediately before the old key, so the new key has higher priority. It does not remove recovery keys. It cannot recover or fork a DID, rotate a `did:web`, or use an HSM-held key.
- Install Deno **2.8.3** on Linux or macOS. Copy both scripts and the wrapper to your operator workspace, then cache and review their dependencies before an incident.

```bash
deno cache --no-config --no-lock --node-modules-dir=none rotate-plc-key.ts
deno run --no-prompt --no-config --no-lock publish-identity-railway.ts --help
```

The rotation script uses fixed versions of `@did-plc/lib` and `@atproto/crypto`. Deno resolves their indirect dependencies when you cache them, so keep and review that cache. Do not enable npm lifecycle scripts or use `--allow-all`.

## Configure the rotation wrapper

Set `PLC_URL` and the three absolute file paths below, then run `scripts/rotate-plc-key.sh`. The helper launches Deno with scoped permissions. `REPORT_DIR` defaults to `./reports/`.

Each run produces:

- One full `rotation-<timestamp>-<id>.json`. Stdout shows an outcome table, not JSON.
- A matching `.log` with timestamped progress, retries, and outcomes, also shown on stderr. Secrets and request payloads are excluded.

Files are saved directly in the report directory without overwriting previous runs. New directories are owner-only (0700), and files are owner-only (0600). Use a trusted directory, not a symlink.

Both filenames are printed at startup and completion. The JSON includes every DID, completed outcomes, unfinished work, target, mode, public key identities, and timestamps. Failed or missing-old results exit 1. Ctrl+C or SIGTERM stops processing, aborts requests and waits, saves the full report, prints the table, and exits 130. An interrupted submission is marked uncertain: inspect its PLC head before resuming. Startup errors before inventory preparation produce only a log; SIGKILL, power loss, or storage failure cannot guarantee a final report.

```bash
export PLC_URL='https://YOUR-TRUSTED-PLC-HOST'
export DIDS='/secure/rotation-dids.txt'
export OLD='/secure/rotation-old.hex'
export NEW='/secure/rotation-new.hex'
export REPORT_DIR='/secure/rotation-reports'
```

For example, `rotation-dids.txt` contains one complete DID on each line. Do not add labels, comments, or multiple DIDs to a line:

```text
did:plc:aaaaaaaaaaaaaaaaaaaaaaaa
did:plc:bbbbbbbbbbbbbbbbbbbbbbbb
did:plc:cccccccccccccccccccccccc
```

Give Deno read access to these exact three files, not their parent directory. If any path is a symlink, grant access to the file it resolves to as well. The key files must be owned by the operator and readable only by that operator.

The Deno script reads key files. As an alternative, you may inject `PLC_ROTATION_OLD_KEY_HEX` and `PLC_ROTATION_NEW_KEY_HEX` from a secret manager when running `rotate-plc-key.ts` directly. Choose one method for each key: file **or** environment variable, never both. Neither script loads a `.env` file.

For direct Deno use, pass `--report-dir PATH` (default `./reports`) and grant read/write access to that directory. See the helper for the remaining scoped permissions and `--help` for script options.

## Add the new key, including during a deployment outage

Run only one rotation job at a time. Coordinate with any other service or operator that can write to the PLC directory.

```bash
scripts/rotate-plc-key.sh --phase add
scripts/rotate-plc-key.sh --phase add --apply
```

The first command is a preview.
The table counts Updated, Missing old key, Failed after retries, Interrupted/not completed, and Total, plus Unchanged, Planned, or Skipped when present. Preview results should be planned or unchanged. Apply results should be updated or unchanged; resumed successes may be skipped with the original outcome preserved in JSON. Stop cutover on missing-old, failed, or unfinished results.

### Resume or start fresh

Every preview and apply run displays the final inventory count and how many DIDs it will process or skip, then requires you to type yes at a native terminal prompt before any PLC read or write. Cancel, refusal, EOF, or nonterminal input stops safely; unattended execution is not supported.

With matching rotation reports in REPORT_DIR, Deno first lists numbered filenames and readable UTC timestamps. Choose a report, or 0 for a fresh inventory, including when moving from add to remove. Report selection is separate from the mandatory execution confirmation.

Resume requires the same PLC URL, phase, preview/apply mode, and public keys. It uses the saved inventory, skips only previous successful outcomes, and retries failed, unfinished, planned, and missing-old DIDs. Repeated resumes retain the original success provenance. Preview reports never skip work during apply. Old reports without full resume metadata and identity-notification reports are not eligible.

To bypass report selection only, choose explicitly; both commands still require execution confirmation:

```bash
scripts/rotate-plc-key.sh --phase add --apply --no-resume
scripts/rotate-plc-key.sh --phase add --apply --resume-report "$REPORT_DIR/rotation-<timestamp>-<id>.json"
```

Direct Deno users must grant read access to an explicit report outside the report directory. Treat saved reports as trusted operator records, not independent proof of current PLC state.

Then inspect the PLC directory heads yourself. Confirm that both keys exist, the new key is directly before the old key, and aliases, services, verification methods, and unrelated keys have not changed. `missing-old` and `failed` are failures. The script waits up to 15 seconds per request and retries temporary conflicts or network failures up to three times. Re-running a completed change does not submit another PLC operation. This script does not publish an identity event.

**During an outage, stop after adding the new key.** Keep the old deployment secret and the old key active. Do not remove the old key, change the deployed secret, or redeploy until service is restored. Adding the new key does not revoke the old one. Any account created during the outage may still have only the old key, so you must rebuild the inventory before cutover. You may publish identity events now if Railway SSH works; otherwise leave that notification pending.

## Publish identity events

- Use a reviewed inventory of 1–1,000 PLC DIDs whose directory heads you have verified. Publishers do not read PLC or accept rotation reports as evidence.
- Install Deno **2.8.3** and a trusted Railway or Docker CLI. Keep the chosen publisher's `.sh` launcher beside its matching `.ts` file; no other publisher files are needed.
- Each DID must belong to an active local account with a handle. Preview is offline; `--apply` publishes events without writing to PLC.

`AppContext.fromEnv()` may initialize or migrate databases: stop unless the deployed PDS version, runtime permissions, configuration, and storage match; do not copy production secrets locally.

### Railway

```bash
export PROJECT='YOUR-PROJECT-ID'
export ENVIRONMENT='YOUR-ENVIRONMENT-ID'
export SERVICE='YOUR-HOSTING-PDS-SERVICE-ID'
export DIDS='/secure/rotation-dids.txt'
export REPORT_DIR='/secure/rotation-reports'

scripts/publish-identity-railway.sh
scripts/publish-identity-railway.sh --apply
```

- Set all three target IDs explicitly; add `--instance ID` if needed. Use Railway SSH, not `railway run` or commands that link local CLI state.
- `WORKDIR` / `--workdir` defaults to `/app`.
- Railway uses the SSH login user without switching users or checking an expected username. `EXEC_USER` is ignored; `--user` is not supported.

### Docker

```bash
export CONTAINER='epds-core'
export DIDS='/secure/rotation-dids.txt'
export REPORT_DIR='/secure/rotation-reports'

scripts/publish-identity-docker.sh
scripts/publish-identity-docker.sh --apply
```

- Set `CONTAINER` or `--container NAME_OR_ID` explicitly.
- `WORKDIR` / `--workdir` defaults to `/app`.
- Docker uses the container's configured user by default. Override with `EXEC_USER` or `--user USER[:GROUP]` (names or numeric IDs).

**Error: `chdir to cwd … no such file or directory`** — no events were queued. Check the configured workdir and set `WORKDIR` / `--workdir` if it differs from `/app`:

```bash
docker inspect --format '{{.Config.WorkingDir}}' "$CONTAINER"
```

### Reports and resume

- `REPORT_DIR` (default `./reports`) holds `identity-<transport>-<timestamp>-<id>.json` and a matching `.log`; paths are printed at startup and completion. Stdout shows an outcome summary, not JSON. Files are owner-only (0600), new directories 0700; existing parent permissions stay unchanged. Use a trusted operator-owned directory without symlinks or group/other write access. **Raw logs may contain secrets.**
- Every preview/apply run shows inventory/process/skip counts, then requires exactly `yes` at a native terminal. Refusal or nonterminal input stops safely; there is no `--yes` bypass.
- Choose a numbered report or `0` for a fresh run. `--no-resume` skips selection; `--resume-report PATH` selects explicitly. Neither skips confirmation.
- Resume requires the same transport, target, workdir, Docker user override, preview/apply mode, and ordered deduplicated inventory. Queued successes are skipped; failures and unfinished work are retried. Preview reports cannot skip apply work. The obsolete expected-user field in Railway reports is ignored; project, environment, service, instance, and workdir must still match. Reports are not proof of current remote state.
- Use `DIDS` / `--did-file PATH`, or repeated `--did DID` flags, not both. For direct Deno use, grant report-directory read/write access, `--allow-sys=uid`, and the scoped transport permission; see the launcher and `--help`.
- `queued` means PDS storage and batch cleanup succeeded, **not relay receipt**. Check PDS and relay streams. Failures, timeouts, or lost connections exit 1; leave notification pending if you cannot verify the intended runtime.

**Interruption:** Ctrl+C/SIGTERM stops the local client, saves the full report, and exits 130; it **does not ensure the remote process stopped**. Inspect the runtime and wait for it to stop before retrying uncertain work; duplicate events are possible. SIGKILL, power loss, or storage failure cannot guarantee a final report.

## When deployments recover: freeze, reconcile, and cut over

1. Freeze signups and every other PLC writer. Build the final DID inventory, including accounts created during the outage. Preview and add the new key for each missing DID, verify every directory head, then publish identity events. Stop if anything fails.
2. Change `PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX` to the new key and redeploy **every** PDS replica. Confirm a normal handle or account update is signed by the new key. Create a test account and confirm it uses the new key. Add that account to the final checks. Keep all PLC writers frozen. Neither script performs these checks for you.
3. Only after those checks succeed, remove the old key and publish identity events again:

```bash
scripts/rotate-plc-key.sh --phase remove
scripts/rotate-plc-key.sh --phase remove --apply --confirm-cutover
scripts/rotate-plc-key.sh --phase remove
scripts/publish-identity-railway.sh --apply
```

The first and third commands are previews. Require a successful removal, then confirm that the final preview reports `unchanged`, the old key is absent, unrelated directory data is unchanged, and both streams show fresh identity events. Unfreeze writers only after all checks pass.

## Stop or roll back safely

Stop before or during removal if any check fails. Some DIDs may already have changed. Inspect their PLC heads and retry only a reviewed list. Retrying notification never requires another PLC operation.

Before removal, leave both keys in place while you investigate. Restore the old deployment secret only if that is appropriate for the incident. After removal, **do not redeploy a service that has only the old key**. Involve the DID recovery owners instead.

**The 72-hour recovery window matters:** rejecting the old key at the current PLC head does not make it permanently unusable immediately. For roughly 72 hours, a historical key can recover from the parent operation only when its priority is strictly higher than the key that signed the first operation being replaced. Equal priority is not enough. Once the new key is present in a historical parent, placing it ahead of the old key gives it the priority needed to recover a later old-key-signed removal of the new key. It cannot retroactively undo the operation that first introduced it: that operation’s parent did not authorize the new key. Review the DID audit history with recovery owners and monitor the heads throughout that window. Private tests do not prove that the public PLC directory will accept recovery after the full 72 hours.
