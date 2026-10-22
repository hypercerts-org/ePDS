# Rotate a shared PLC key

Use these two scripts when rotating the PLC signing key shared by accounts on one PDS:

- `rotate-plc-key.ts` adds or removes the key in the PLC directory.
- `publish-identity-railway.ts` asks the PDS to publish `#identity` events through Railway SSH after you have verified the directory changes.

Neither script changes deployed secrets or redeploys the PDS. You perform that deployment step yourself.

## Prepare

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

Set these four shell variables to absolute paths and the PLC directory URL, then run `scripts/rotate-plc-key.sh`. The wrapper passes those values to the TypeScript script with the smallest set of Deno permissions it needs. It prints the JSON result to the terminal and saves the same result in a new private report file under `./reports/`. Set `REPORT_DIR` to use a different local report directory.

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

The wrapper reads key files. As an alternative, you may inject `PLC_ROTATION_OLD_KEY_HEX` and `PLC_ROTATION_NEW_KEY_HEX` from a secret manager when running `rotate-plc-key.ts` directly. Choose one method for each key: file **or** environment variable, never both. Neither script loads a `.env` file.

The wrapper also permits hostname access and a small set of `LOG_*` environment variables because the PLC dependency needs them for logging. This does not grant general system or environment access.

## Add the new key, including during a deployment outage

Run only one rotation job at a time. Coordinate with any other service or operator that can write to the PLC directory.

```bash
scripts/rotate-plc-key.sh --phase add
scripts/rotate-plc-key.sh --phase add --apply
```

The first command is a preview. Every DID should report `planned` or `unchanged`. For example:

```json
{"phase":"add","apply":false,"results":[{"did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","status":"planned"},{"did":"did:plc:bbbbbbbbbbbbbbbbbbbbbbbb","status":"planned"}]}
```

The wrapper saves the JSON result locally and prints `Saved report: …` on stderr. Each DID in the apply report must show `updated` or `unchanged`:

```json
{"phase":"add","apply":true,"results":[{"did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","status":"updated"},{"did":"did:plc:bbbbbbbbbbbbbbbbbbbbbbbb","status":"unchanged"}]}
```

`updated` means this run submitted the change. `unchanged` means the DID already had the required key order. Any `missing-old` or `failed` result stops the cutover.

Then inspect the PLC directory heads yourself. Confirm that both keys exist, the new key is directly before the old key, and aliases, services, verification methods, and unrelated keys have not changed. `missing-old` and `failed` are failures. The script waits up to 15 seconds per request and retries temporary conflicts or network failures up to three times. Re-running a completed change does not submit another PLC operation. This script does not publish an identity event.

**During an outage, stop after adding the new key.** Keep the old deployment secret and the old key active. Do not remove the old key, change the deployed secret, or redeploy until service is restored. Adding the new key does not revoke the old one. Any account created during the outage may still have only the old key, so you must rebuild the inventory before cutover. You may publish identity events now if Railway SSH works; otherwise leave that notification pending.

## Publish identity events through Railway

Use this only after you have verified the PLC directory heads. It is independent of rotation and can be re-run without another PLC write.

Set the Railway project, environment, and PDS service IDs explicitly. If Railway requires a specific deployment instance, add `--instance ID`. Use a trusted Railway CLI that supports `ssh -p`, `-e`, `-s`, and `-d`. Do not run `railway link`, `railway environment link`, or `railway service link`; those change your local CLI state. `railway run` executes locally with injected environment variables, so it is not suitable here.

```bash
export PROJECT='YOUR-PROJECT-ID'
export ENVIRONMENT='YOUR-ENVIRONMENT-ID'
export SERVICE='YOUR-HOSTING-PDS-SERVICE-ID'
export WORKDIR='/app/packages/pds-core'
export REPORT_DIR='/secure/rotation-reports'

scripts/publish-identity-railway.sh
scripts/publish-identity-railway.sh --apply
```

Without `--apply`, the command only validates the request and does not open an SSH connection. The wrapper prints the JSON result to the terminal and saves the same result in a new private report file under `REPORT_DIR`, then prints `Saved report: …` on stderr. Use only DIDs whose PLC heads you have already checked. Do not use a guessed inventory or copy failed results from the rotation script. Process no more than 1,000 DIDs at a time. The notification script does not read PLC itself and will not accept a PLC JSON report as evidence.

The preview reports one `planned` result per DID:

```json
{"apply":false,"results":[{"did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","status":"planned"},{"did":"did:plc:bbbbbbbbbbbbbbbbbbbbbbbb","status":"planned"}]}
```

After `notify --apply`, each successful DID reports `queued`:

```json
{"apply":true,"results":[{"did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","status":"queued"},{"did":"did:plc:bbbbbbbbbbbbbbbbbbbbbbbb","status":"queued"}]}
```

`queued` means the PDS accepted and stored the event. It does not confirm that relays have received it. A `failed` result makes the command exit unsuccessfully; retry only the reviewed failed DIDs.

Before applying, verify all of the following:

- `/app/packages/pds-core` is the correct package directory for the deployed image. Override `--workdir` for a different image.
- The deployed `@atproto/pds` version exports the public `AppContext` API expected by the script.
- Railway SSH starts under the same user, storage, configuration, and runtime environment as the running PDS.

Do not copy production secrets to your machine. The script's `AppContext.fromEnv()` call may initialize or migrate databases, so stop if you are unsure that it has the required permissions or matches the deployed version. The script does not start a server or create an admin endpoint. `--allow-run=railway` trusts the Railway executable, so install it from a trusted source.

The script uses one SSH session for the batch. Each DID must belong to an active local account with a handle. Unknown, deactivated, and taken-down accounts fail. A `queued` result means that the PDS stored the event and cleaned up successfully; it does **not** mean relays have received it. Watch both PDS and relay streams for fresh `#identity` events before treating notification as complete.

Remote setup, each DID, and cleanup each have a 10-second deadline. A timeout, missing result, failed cleanup, or uncertain SSH connection fails the whole batch. Other per-DID errors appear as individual `failed` results and also produce a nonzero exit status. Retry failed notifications with a reviewed inventory. Delivery may happen more than once, but notification never writes to PLC. If SSH cannot reach the intended PDS runtime, stop and keep notification pending. Do not treat another environment's result as success.

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

**The 72-hour recovery window matters:** rejecting the old key at the current PLC head does not make it permanently unusable immediately. For roughly 72 hours, a historical key can recover from the parent operation only when its priority is strictly higher than the key that signed the first operation being replaced. Equal priority is not enough. This is why the new key is placed ahead of the old key during overlap: if the old key is used to remove the new key, the new key retains the priority needed to recover. Review the DID audit history with recovery owners and monitor the heads throughout that window. Private tests do not prove that the public PLC directory will accept recovery after the full 72 hours.
