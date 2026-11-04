# Debian 13 candidate package and lifecycle — Issue #65

The package is an **unreleased CLI distribution candidate**, not an activated
Agent Platform service. Target: Debian 13 **trixie, amd64**, system Python >=3.12
(trixie supplies 3.13). Development checks continue using the established Python
3.12 environment. No runtime Python dependencies are declared or bundled.
The package depends on **python3 (>= 3.12), git, gh**: local inspection uses Git;
explicit read-only GitHub operations use gh. No authentication is configured.
Bubblewrap, Codex, runtime images, privileged helpers and API credentials are
neither dependencies nor included. Missing optional runtime prerequisites remain
blocked; packaging does not admit them.

## Build and provenance

Use a clean committed source checkout and existing Debian tools; no dependency
solver or network is called by the builder:

```sh
python3 packaging/build_deb.py --revision 2 --output /tmp/ap-candidate-next
python3 packaging/build_deb.py --revision 1 --output /tmp/ap-candidate-baseline
# Alternative single candidate target: make -f debian/rules binary
```

Output directories must be new, preventing overwrite of retained evidence. The
builder refuses dirty/untracked build inputs, unsupported version/dependencies,
nonregular/symlink/hardlinked inputs and unknown revisions. No Git tag is required
or created. Provenance uses exact committed HEAD and its timestamp as
SOURCE_DATE_EPOCH. Copying the source into an unversioned directory is not this
build interface; use the reviewed committed checkout. No wheel or pip execution.

`dpkg-deb --root-owner-group -Zxz -z6 --uniform-compression --build` produces a real
ar archive with control/data members. Standard `debian/control`, changelog,
copyright and a small stdlib staging recipe are version controlled. This is a
binary-package recipe, **not** a claim of a Debian archive-ready source upload,
.dsc/.buildinfo/signature or complete debhelper/dpkg-buildpackage integration.
The source metadata also supplies autopkgtest's test tree. Keep packaging logic
small; reevaluate debhelper/dh-python if Python dependencies or services appear.

Application version stays **0.1.0**, with no epoch. Debian mapping is
`<application SemVer>-<positive packaging revision>`; current reviewed revisions
are **0.1.0-1 (N)** and **0.1.0-2 (N+1)**. Revisions never masquerade as an upstream
release bump. Both are separately built installable controlled pre-release
profiles from the same exact source, not invented historical releases:

- N supplies inert package_schema=1 inventory and schema-v1 sample; no migration
  helper is installed.
- N+1 supplies package_schema=2 defaults and introduces the explicit private
  synthetic migration helper. The lifecycle test migrates actual data bytes to
  schema 2 after a real dpkg upgrade; it is not a filename/version-only test.

Artifacts are `agent-platform_0.1.0-{1,2}_amd64.deb`, SHA256SUMS and provenance.json.
The package embeds `/usr/share/doc/agent-platform/build.json`, exact source commit,
epoch, version and source/recipe input SHA-256 values. External provenance adds
archive SHA-256 and dpkg-deb version. Checksums correlate bytes, not signatures or
independent provenance. CI retains both candidates and evidence for 14 days in
Actions artifacts; it publishes no Release, tag or APT repository.

Rebuild candidate twice with identical source, timestamp and toolchain and compare
bytes. CI requires equality. This establishes repeatability **within that pinned
image/toolchain**, not universal reproducible-build certification. Python gzip,
xz/dpkg versions and inputs can affect bytes; local Python 3.12 and trixie 3.13
are not asserted to yield identical files. The official Debian amd64 manifest is
pinned in Dockerfile; [input provenance](debian-package-inputs.json) records image
index/manifest and action source/ref verification. Signed Debian trixie APT
indexes/packages resolve only at CI image construction, are currently mutable,
and exact installed versions are saved. Hosted runner, image registry, tool
binaries and dependency supply chain remain trust inputs. A signed snapshot
package lock and cross-builder independent reproduction are future work.

## Installed paths and ownership

| Path | Policy |
| --- | --- |
| /usr/bin/agent-platform{,-broker,-native-canary,-native-artifact} | root:root 0755 isolated system-Python wrappers for exactly the four pyproject entry points. `--help` delegates unchanged; package-only `--version` reports app and Debian revision. All other args delegate to existing main functions. |
| /usr/lib/agent-platform/agent_platform/*.py | root:root 0644 private stdlib-only application sources, not a global dist-packages installation. Wrappers use `python3 -I`, insert only this fixed private path and disable bytecode writes. |
| /usr/lib/agent-platform/agent_platform-0.1.0.dist-info | Standard METADATA, entry_points.txt and INSTALLER=dpkg. Application metadata version remains 0.1.0. No wheel/dist dependency resolution or Python-cache maintainer hook. |
| /usr/lib/agent-platform/migrate-example | N+1 only, root:root 0755 standalone explicit synthetic helper described below. Never invoked by dpkg or the runtime. |
| /usr/share/doc/agent-platform, /usr/share/man/man1 | Copyright/license, Debian changelog, build provenance, operator notes and four command manuals. No secrets or native executables. |
| /etc/agent-platform/package.conf | root:root 0644 Debian conffile: **inert inventory**, not runtime config or trusted target authorization. Admin edits use ordinary dpkg conffile resolution; no secrets belong here. |
| /var/lib/agent-platform, /run/agent-platform, /var/log/agent-platform | Not created: no installed service owns state, runtime files or logs. No system account, tmpfiles rule, daemon, journald integration or systemd unit is installed. |
| Operator homes, repositories, worktrees, checkpoints, HOLD/UNKNOWN journals, credentials and backups | Entirely outside packaging authority. No discovery, copying, migration or deletion. Existing per-user CLI storage policy is unchanged. |

All package paths use dpkg ownership; there are **no preinst/postinst/prerm/postrm,
triggers or service hooks**. Install/upgrade/remove cannot start Codex, scheduler,
broker, GitHub writer, reviewer or native canary. Historical broker/canary tools
remain explicit guarded helpers; their presence grants no live execution rights.
Native subscription stays SUBSCRIPTION_ISOLATION_BLOCKED / exit 13. Public
run/resume/doctor stays pre-I/O legacy_execution_quarantined / exit 13. A package
inventory field or local config cannot release these gates or authorize a project.

## Explicit synthetic migration contract (AP-PKG-SYNTHETIC)

No production checkpoint, TargetProject, authorization, HOLD or journal migration
contract exists here. The helper supports only an **explicitly provided dedicated
synthetic directory**, owner=current UID, mode 0700, non-mount, no symlink ancestors;
all files regular, singly linked, same owner and mode 0600, bounded to 4096 bytes.
It never scans default state paths, takes an arbitrary deletion target or creates
/var/lib state. It rejects extra files and unsafe aliases before writes.

For a disposable example only, create a NEW directory and marker `EXAMPLE_ONLY`
containing exactly `AP-PKG-EXAMPLE-ONLY v1\n`, plus `example.json`:

```json
{"format":"AP-PKG-SYNTHETIC","schema":1,"label":"offline demo"}
```

The label accepts only bounded ASCII alphanumeric/space/underscore/hyphen text;
it is not a secret or command. Run explicitly as the owner:

```sh
/usr/lib/agent-platform/migrate-example --directory /absolute/private/example
```

Output schema 2 replaces `label` with `display_name`. Strict duplicate/unknown
keys, unsupported schemas (including boolean), aliases, mismatched evidence or
lost history fail with fixed BLOCKED/exit 13. All retained evidence is validated
before writes and again under a nonblocking file lock. Before replacement, retain
exact `v1.backup` and fsynced `migration.json` with from/to and before/after hashes.
Use exclusive temp creation, atomic replace and directory fsync; rerun validates
output plus backup/intent and returns already_migrated. No deletion/reset path.

| Interruption / failure | Required recovery |
| --- | --- |
| Validation rejection | Data/evidence unchanged, including no new lock; correct only the explicitly owned fake input after inspecting it. |
| Exact backup or complete intent retained before temp creation | Rerun revalidates current v1 and every retained byte, then safely completes. Missing evidence for v2 or contradictory history blocks. |
| next.tmp retained, partial backup/intent, unknown extra file or fsync uncertainty | BLOCKED for explicit owner reconciliation; no automatic cleanup, overwrite, retry of unknown effects or guessed rollback. Preserve all bytes. |
| Atomic rename completed; intact matching v2+backup+intent | Rerun can verify already_migrated. A prior write error is not reported as success before reconciliation. |
| Unsupported production data | BLOCKED. Do not rename/copy real security state into this directory to force migration. |

This tests a bounded example under a trusted local operator, not isolation from
hostile code sharing its UID or a durable production migration service. Restoration
uses a **new** marked directory and retained known-good v1 backup, then verifies
the deterministic v2 result; it never overwrites existing UNKNOWN state.

## Package lifecycle and operator recovery

[Debian maintainer-script policy](https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html)
requires idempotent/error-aware hooks; avoiding custom hooks removes that authority
here. [Debian files/conffile policy](https://www.debian.org/doc/debian-policy/ch-files.html)
leaves administrator configuration handling to dpkg. Package defaults, admin
configuration, secrets and application data are distinct: no secret provisioning
or production state conversion occurs at install/upgrade.

For separately authorized target machines only (never dev01 in this task), apt
install the exact verified candidate and its declared dependencies. On upgrade,
choose dpkg's normal conffile prompt behavior; unattended CI deliberately uses
`--force-confdef --force-confold`, preserving local edits and modes and retaining
a new distributor version separately where dpkg chooses. Never silently replace
an edited config. The inert package_schema field can remain 1 after upgrade;
it is not authoritative state-schema discovery.

A corrupt archive rejection leaves installed N unchanged. CI deliberately stops
a real N+1 transaction after `dpkg --unpack`, verifies `install ok unpacked`, then
recovers with `dpkg --force-confdef --force-confold --configure agent-platform`; this is a controlled staged
interruption, not a power-loss durability claim. No application code runs during
configure. Validate versions/files/config before proceeding. For uncertain package
manager operations, inspect dpkg status/audit and retained evidence first; do not
blindly rerun state migration. Host recovery actions need their own operator scope.

- **Remove:** dpkg removes shipped program files, retains modified conffile and
  all unowned data; no cleanup hook. Reinstall restores programs, preserving config.
- **Purge:** dpkg removes its conffile (and standard associated dpkg variants),
  but unowned `/etc/agent-platform/operator-notes`, user data and backups remain.
  A nonempty unowned config directory may remain; purge is **not complete erasure**.
- **Reinstall after purge:** fresh distributor config, retained synthetic/user data
  unchanged. Restore nonsecret sample backup only to a new marked directory and
  explicitly reconcile it; do not infer production format compatibility.
- **Downgrade:** no synthetic reverse migration. Existing v2 stays v2; N has no
  helper. Preserve/reconcile separately; no automatic schema rollback is promised.

## CI acceptance and evidence limits

[Debian package workflow](../.github/workflows/debian-package.yml) uses read-only
permissions, pinned checkout/upload actions and disabled persisted Git credentials.
Packaging checkout explicitly pins the event feature HEAD (also for PR events),
so embedded provenance does not silently bind a synthetic merge commit. Existing
Python CI retains its original merge-result behavior.
Docker is used only on GitHub-hosted ubuntu-24.04, never installed/used on dev01.
No privileged container, Docker socket, auth home or host infrastructure is mounted.
Build receives read-only source and a dedicated output mount; destructive tests
see only disposable image files, read-only packages and a fresh evidence mount.
Lifecycle runs with network=none, no-new-privileges and process/memory bounds.
Dependencies are predownloaded into the isolated image, then **actually installed
by apt** on the clean testbed with --no-download. Local .deb installation then
uses ordinary apt local-file handling inside network=none (APT no-download local
archive handling failed in the first CI run). Missing cache inputs fail rather
than enabling network. Network setup is separate.

Required implemented checks (failure/missing evidence fails the job):

1. Build N, N+1 and a second N+1; compare bytes; save hashes/provenance.
2. Inspect real dpkg-deb info/content, owner/modes/conffiles/no hooks; run lintian
   with `--fail-on error`. Warnings remain visible. The candidate retains
   initial-upload-closes-no-bugs: this private project has no Debian BTS upload
   or Debian bug to close; inventing a BTS number would be misleading. Initial
   amd64-only support is intentional; architecture expansion is deferred.
3. Real clean apt dependency/package installation; all help/package-version checks,
   inert canary report and legacy/native exit-13 gates. Fake Codex/service tripwires
   and absence of any unit/state directory deny activation; no real native tools.
4. Mutate admin config/mode, safe example and separate fake checkpoint/UNKNOWN
   journal/backup; record content/ownership/mode and verify retention at transitions.
5. Reject corrupt archive, stage N+1 unpack/configure recovery, preserve config,
   explicitly migrate v1 -> v2, prove idempotency and unsupported-schema no-write.
6. Real apt remove/reinstall/purge/reinstall; check configuration differences,
   retained/unowned data and restore-to-new-directory reconciliation.
7. Separate disposable quality container runs **autopkgtest -- null** on the
   installed binary; its smoke summary must explicitly PASS. Null is safe here
   only because the entire testbed is already a disposable guarded container.

`lifecycle.json` requires eight phases and explicitly labels live runtime,
systemd boot and piuparts NOT_RUN. Installed/quality package version inventories,
archive info/files, lintian and autopkgtest logs accompany artifacts. Local pytest
builds/inspects archives and tests migration on temporary fake directories only;
it does **not** execute apt/dpkg installation or container lifecycle on dev01.

**Piuparts NOT_RUN:** its chroot/mount or Docker-driver authority is not granted to
these bounded containers; no SYS_ADMIN/privileged fallback or runner-host install.
The custom real apt/dpkg matrix is implemented evidence, not a piuparts PASS.
**Systemd boot NOT_RUN:** no unit is shipped and container PID1 is not systemd.
A future service requires separately approved disposable VM/boot tests before any
service activation claim. This milestone does not provision that fixture.

## Future release design — not implemented

After independent exact-SHA review and human merge, separately authorize immutable
candidate release selection, source archive/.buildinfo/SBOM/license audit,
independent rebuild comparison and offline signing-key custody. A future Release
would attach verified .deb/provenance/checksums; a signed APT repository requires
scoped upload identity, signed Release/InRelease, rotation/revocation, transport
and retention policy, never secrets in workers. No tag, Release, real signature,
APT feed, new writer, deployment or auto-merge is created here. Packaging PASS is
not native isolation, account readiness, downstream authorization or deployment GO.
