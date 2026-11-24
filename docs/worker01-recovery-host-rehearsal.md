# PUB-09 recovery rehearsal and Worker P1 upgrade

**SOURCE_ONLY / LIVE NO-GO.** Exact-unit rehearsal and production upgrade
are **NOT_EXECUTED / BLOCKED_BY_HOST_APPROVAL**. Review this procedure and
authorize each host-changing operation separately. #183 is evidence for
synthetic PID 1 credential delivery, ACL/cross-role denial, IPv4/IPv6 BPF
denial and packaged AppArmor enforcement on worker01. Its combined probe
used adapted unit and credential paths. Exact-unit recovery remains
**NOT_TESTED**.

## Actual PID 1 rehearsal in a disposable VM

1. Use a separately approved disposable Debian 13 amd64 VM running
   systemd 257 with AppArmor and cgroup v2 BPF. Record VM ID, clean image
   identity, kernel, systemd version, package version, source commit/tree
   and independently approved archive digest. Require a disconnected
   virtual NIC and no host shares, credential forwarding or production
   disk snapshots. Stop if the VM cannot meet those requirements.
2. Before installing the verified candidate in the VM, check the exact
   recovery unit names in PID 1, fragment/drop-in paths and the loaded
   AppArmor profile inventory. Reject loaded aliases, unexpected profiles,
   queued jobs, previous package state or a reused fixture. Check
   `/etc/ap-publisher-keys/worker.pem`, `/etc/ap-publisher-recovery-169`,
   `/var/lib/ap-publisher-recovery`, both recovery journal directories,
   and the recovery grant, liveness, runtime and credential trees in
   `/run` for collisions and symlinks. A known image and durable fixture
   inventory establish provenance. Empty directory listings alone are
   insufficient. On worker01, the same PEM path may contain the real App
   key. Its presence blocks exact rehearsal there.
3. Prepare a new fixture in that approved VM with VM-generated RSA App
   material, separate synthetic observer and operator signing keys and
   fabricated v4 evidence. Use a separately reviewed fixture builder
   for the frozen case pins. The source pins identify real v4 state, so
   an unmodified recovery operator with arbitrary synthetic v4 evidence
   must STOP. For a positive VM role test, independently validate fabricated
   grants and stage controller inputs using the format from the existing
   dispatcher. Keep the packaged wrappers, profiles, unit names, key paths
   and role code byte-identical. This exercises PID 1 and the roles.
   Record separately that the fabricated controller inputs do not establish
   production v4 admission. No copy of a real key, JWT or journal is needed.
4. Give the two service accounts distinct UID/GID and no supplementary
   groups. Set root-private mode `0700` on the staging directory and
   `0600` on its `signer.json` and `publisher.json`. Stage the synthetic
   pin at `/etc/ap-publisher-recovery-169/approval-pin` and synthetic App key
   at `/etc/ap-publisher-keys/worker.pem`, root-owned, mode `0600`, no extra
   ACL. Journals must start empty, owned by the corresponding service account,
   with `0600` files in private directories. Use exact `LoadCredential`
   names and verify PID 1's read-only leaf/directory ACL or UID-owned fallback.
   Never add a direct role read of the source key or root grants.
5. In the separately approved VM run, use the exact units and signed grants
   in Signer then Publisher order. Record UID/GID, effective profile, cgroup
   and credential metadata without bytes. Confirm the Signer accesses only
   its key copy and outputs; verify cross-role, staging, real-source path
   and old-journal denials. Confirm both units deny IPv4/IPv6, remain private
   and have `Restart=no`. Require only `HANDOFF_VERIFIED` and
   `publication=DISABLED` on Publisher success.
6. Interrupt the fixture controller or unit before claim, after UNKNOWN and
   after durable completion before acknowledgment. Inspect redacted state,
   and check that a second start never replays a consumed operation. Use a
   fresh VM/fixture for each run. Capture bounded evidence, verify all child
   PIDs and jobs have exited, and retire only the inventoried disposable VM
   after approval. Unknown processes, unexpected paths or incomplete
   cleanup mean STOP. Preserve evidence and quarantine the VM.

## Worker01 upgrade procedure

1. Obtain separate approval for the exact source-qualified Worker P1
   candidate and maintenance window. Build with `--revision 9` from the
   approved clean commit. Pin HEAD/tree, manifest, package SHA-256, embedded
   provenance, architecture and installed predecessor
   `0.1.0-8~git73bb2d521347ec87fb2c584ada8ee86a0ab3eaba`. Inspect the Debian
   control archive, maintainer scripts and conffile choices before touching
   worker01. Verify `dpkg --compare-versions` with candidate `gt` installed.
   PKG-18/#168 final release and artifact custody remain separate and blocked.
2. Establish enforced maintenance exclusion before inspecting unit state.
   Restrict privileged manager access to the upgrade operator, suspend
   activation automation and other privileged sessions outside the units,
   and confirm no activation socket, timer, path, dependency or queued job
   can start any historical or recovery unit. Hold the existing operator
   configuration exclusion across the package transaction to block cooperating
   clients. A lock cannot block arbitrary PID 1 callers. If the access
   fence cannot exclude every other start path, STOP. Do not mask or
   reset-failed the legacy unit. Preserve its runtime allowlist and evidence.
3. Under that exclusion, confirm the historical Publisher is failed and
   quiescent, Signer inactive, and all jobs, PIDs and service cgroups idle.
   Compare locally retained v4 identities and securely held integrity
   records for journals, job, artifact, runtime allowlist and unit provenance.
   Use metadata-only evidence for keys, JWTs and credential copies. Do not hash
   or read their contents. Do not export
   any credential or rotate, rewrite, remove or copy state as part of this
   runbook. Keep a separately authorized rollback plan and secure backup
   reference if already available. Rolling back a package never resets a
   journal or reverses a remote effect.
4. While maintaining exclusion, the authorized operator may perform the
   normal package transaction on the exact verified file. Honor `preinst`
   and approved conffile decisions. STOP on unexpected prompts, unsafe
   state, missing evidence, new process/job, failed preinst or a partial
   transaction. Preserve package status and evidence for human
   reconciliation. No blind retry, downgrade, failed-state reset, profile
   reload or service start. Inspect package status before any repair.
5. Verify version, provenance, package integrity and conffile decisions,
   compare historical v4 identities against the pre-upgrade evidence, and
   reread frozen state and effective unit metadata. Confirm recovery
   remains disabled for publication and deny-all networking remains
   configured. A mismatch is STOP. Keep exclusion until review of this
   verification. Upgrade approval does not authorize a recovery run.

The version and archive checks can run offline before the maintenance window.
Use the actual reviewed archive and manifest filenames.

```sh
sha256sum --check SHA256SUMS
dpkg-deb --field "$candidate" Package Version Architecture
dpkg --compare-versions "$(dpkg-deb --field "$candidate" Version)" gt \
  '0.1.0-8~git73bb2d521347ec87fb2c584ada8ee86a0ab3eaba'
dpkg-deb --ctrl-tarfile "$candidate" | tar -tvf -
```

With maintenance exclusion in place, record state read-only on the target.
Compare the failed status with the existing record before and after upgrade.

```sh
systemctl show --all \
  --property=ActiveState,SubState,LoadState,MainPID,ControlPID,Job,Transient,Type,Restart,ControlGroup \
  ap-worker-publisher.service ap-worker-publisher-signer.service
dpkg-query -W -f='${Package} ${Version} ${Status}\n' agent-platform-worker
dpkg --verify agent-platform-worker
```

## Evidence states

| Boundary | Evidence for this change |
| --- | --- |
| Debian payload, declarations and offline unit syntax | See review validation |
| Synthetic grant, journal, partial-write and lost-reply tests | See review validation |
| Fixture writer fault and actual kernel crash or power-loss durability | Source checks only; real durability NOT_TESTED |
| Exact PID 1 units, ACL/AppArmor/BPF combined | NOT_TESTED / BLOCKED_BY_HOST_APPROVAL |
| Production Worker P1 upgrade and recovery | NOT_EXECUTED |
| GitHub writes and final release | LIVE NO-GO |
