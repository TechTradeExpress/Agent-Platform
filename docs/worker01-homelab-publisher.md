# PUB-03 worker01 root-supervised Draft pilot

Source handoff for [Issue #170](https://github.com/TechTradeExpress/Agent-Platform/issues/170). The Debian Worker P1 package carries the operator CLI and the two existing one-shot units. This procedure requires a reviewed package and a separately approved worker01 pilot. It does not require a global worker doctor PASS. Native and legacy run/resume still refuse execution at exit 13, and Gate #73 stays blocked.

## Before the pilot

1. After the implementation merges, export a **new** #169 commit whose single parent is the then-current verified GitHub `main`. Keep the old #169 artifact at `/etc/ap-publisher/candidate.json` and its review archive intact. Obtain independent review of the new commit, tree, parent, feature ref and AP-WP/1 SHA-256. Stage the new bytes at `/etc/ap-publisher/homelab-candidate.json` under root ownership with Publisher read access only as needed. Use the [AP-WP/1 exporter](worker-publisher.md) as `agentdev`.
2. As trusted `devops` with `sudo -n`, install the separately reviewed Worker P1 candidate, reconcile any conffile prompts, and load the approved Publisher and Signer profiles in enforce mode. Preserve both existing journal files and their ownership, even when empty. The packages and operator CLI are inert on upgrade. Keep the worker01 PEM in the existing root-only `/etc/ap-publisher-keys/worker.pem` location, with a root-only parent and no extra ACL grants. Systemd transfers it into the Signer credential mount. Publisher receives only a job-bound JWT.
3. In authenticated GitHub settings, verify the pinned worker01 App and installation, the App registration owner's numeric ID, single selected installation repository `TechTradeExpress/Agent-Platform`, the minimal grants and no App bypass. Verify classic push restrictions or an equivalent enforced rule deny the App any update of `main`, including merge, while retaining the maintainer's manual merge path. A public `protected` flag or required CI alone does not prove this. Before authorizing, also verify the accounts' sudo/group assignments, the effective AppArmor profiles, systemd credential isolation between both units and `agentdev`, and cgroup BPF availability. Use metadata and disposable inert probes for host checks. Readiness checks configuration and journal metadata, not running isolation or BPF attachment.

## Preview and approve one operation

Run this on worker01. Set each shell value from the new independent review and the authenticated App settings. The Issue number is the pilot Issue, not the implementation Issue.

```bash
operator=/usr/libexec/ap-worker-publisher-operator
sudo -n "$operator" readiness

exact=(
  --issue 169 --ref "$reviewed_ref"
  --head "$reviewed_head" --tree "$reviewed_tree" --parent "$reviewed_parent"
  --artifact-sha256 "$reviewed_artifact_sha256"
  --app-owner-id "$verified_app_owner_id"
)
sudo -n "$operator" preview "${exact[@]}"
# After inspecting the exact dry-run and confirming the authenticated App policy:
sudo -n "$operator" approve-create "${exact[@]}" --confirm-app-policy
```

Readiness is local and read-only. It requires the packaged units to be inactive,
loaded without pending daemon reload, and free of drop-ins before staging.
The operator checks the effective command lines, credential mappings, isolation
and network settings again before launch. Preview validates the artifact and reads the fixed GitHub endpoints for repository identity, open Issue, current protected main, absent feature ref, existing PRs and unchanged workflows. `approve-create` repeats those checks, prints the exact proposed operation, then durably stages one `root:root` manifest at the existing `job.json` path in mode `0440`,
with exactly two named read ACLs for Publisher and Signer. It verifies the file
and ACL before and after staging. The job expires after five minutes. The operator confirms both the single-repository installation grants and the App's inability to update `main` with `--confirm-app-policy`. Only trusted root administrators may invoke this approval. Do not delegate it to `agentdev` or give that account a systemd or sudo trigger.

The operator resolves one public IPv4 address for `api.github.com` with a bounded resolver command, and selects that address for the job. It configures the existing Publisher unit's runtime-only /32 allowlist and checks it before starting the two units. Stop on an inconsistent unit configuration. Verify effective BPF separately on the worker. The operator and Publisher require normal system-CA verification of the GitHub TLS hostname. The Publisher connects to that exact IPv4 with fixed SNI. Neither process uses a proxy, follows redirects, rotates addresses mid-operation or accepts caller-supplied origins. The strict job format retains its certificate pin and receipts. Homelab is create-only on worker01.

The Publisher authenticates the App ID/slug, registration owner, installation and restricted token scope before GitHub object/ref/PR writes. It creates the approved feature branch with an absent-tip CAS and makes one Draft against `main`. Before confirming success it reads back the remote commit and verifies exact head/base, App bot attribution and native linkage to the Issue, then revokes the installation token. Independently confirm those facts from GitHub in the maintainer session. Review the Draft separately. Only the human maintainer merges.

## Stop and reconcile

- `BLOCKED` before staging means the CLI made no publication attempt. Correct the named check and use a fresh preview and explicit approval. A stale base requires a new artifact and independent review.
- If staging or unit launch is uncertain, or GitHub may have applied an effect, preserve the manifest, pending file, candidate, both journals and sanitized service outcomes. Check whether either unit is still running before touching files. Reconcile token issuance/revocation, objects, ref, App attribution and Draft linkage with authenticated GitHub observations. No automatic retries, rollbacks, journal resets or self-repair are provided. An unfinished journal blocks even a new job ID. Treat a lost token issuance/revocation response as potentially valid until its expiry is established. If in doubt, stop.
- After a verified successful attempt, root may archive the nonsecret manifest and logs and retire the expired JWT without copying its contents to the archive. Keep both journals. Before reuse of the units check or restore the separately approved egress configuration. The runtime allowlist remains until manually changed or reboot. A fresh homelab run requires returning both units to the packaged baseline before approval.

`external_rollback_protection=NOT_PROVIDED` reflects the local trust model. Distinct role-owned journals use a held lock, fsync and readback around UNKNOWN/confirmed effects. They cannot withstand trusted root or hypervisor rollback, deletion or compromise. A copied installation token may be usable offline until revoked or expired, outside this tool's local controls. Packaged tests use fabricated credentials and simulated GitHub effects. Live host isolation, live token behavior and the worker01/worker02 pilot outcomes remain NOT_RUN until separately observed.
