# Worker P1 provisioning (PKG-04)

INSTALL_INERT / LIVE_NO_GO. Revisions -3/-4 retain P0; -5/-6 add Worker P1.
Installation is separate from explicit root-only configuration, authentication,
profile attachment and activation. No maintainer script creates accounts or
state, fetches Codex, loads profiles, starts/restarts/enables a unit or imports keys.

After separately authorized installation, an operator may run:

```text
agent-platform-worker provision --approve --initialize-journals
agent-platform-worker provision --approve
agent-platform-worker provision --approve --recover
agent-platform-worker codex install --version 0.166.0 --approve --operator-path /usr/local/bin:/usr/bin:/bin
```

Codex accepts the same explicit offline `--archive` and upgrade/rollback/recover
contract as #116. No vendor binary or Codex APT dependency is supplied. Native
run/resume and legacy doctor --issue remain exit 13. Bare doctor is the separate
[PKG-05 diagnostic](worker-doctor.md), also fail-closed at exit 13.
No command logs in or starts the Publisher.

The explicit root tool is the justified equivalent to sysusers/tmpfiles here:
global boot-time processing of permissive declarations could adopt occupied
accounts/paths without the mandatory preflight. No automatic sysusers/tmpfiles
file is installed. P1 package manifests explicitly include this reviewed command.
Existing principal IDs are verified, never reassigned. Group/user creation uses
fixed Debian groupadd/useradd system-account commands only after whole-plan
validation and durable intent. Partial identity/path creation requires human
reconciliation; no blind retry, deletion or automatic chown is supplied.

## Closed P1 payload and installation

The existing builder accepts synthetic revisions `0.1.0-5` and `0.1.0-6`
(N/N+1). Control remains P0; Worker adds exactly the five AP-WP/1 modules,
generated empty initializer, three existing isolated wrappers, two unchanged
oneshot units and two unchanged AppArmor profiles. P0 revisions -3/-4 retain
their exact closed C/W inventories. No Control authorization/custody/credential
loader is included. The private operator tools are installed under
`/usr/lib/agent-platform-worker/provisioning/`: `provision.py`, the unchanged
#116 `codex_upstream.py`, its pinned release lock and explicitly verified public
evidence files. Job/receipt examples and this document are nonsecret payload.

P1 adds the reviewed ADR dependencies plus Debian `passwd` for fixed account
commands; it has no Codex dependency. `preinst` performs read-only metadata,
dpkg ownership, closed code-tree and inactive-unit checks before replacing P1
paths. Foreign leaves, symlinks, aliases, manual overrides/enabling links and
unknown code-tree entries block unpack. There is no postinst, prerm, postrm,
trigger, automatic sysusers/tmpfiles processing, profile load or manager reload.
Administrator edits to profiles remain dpkg conffiles, and block subsequent
provisioning hash validation. Baseline Debian dependency maintainer scripts can
configure the AppArmor/systemd framework; that is distinct from attaching these
profiles or starting these units. The disposable CI image uses policy-rc.d=101.

## Explicit configuration and identities

Run configuration only under separately approved root operator control on a
quiescent host. This implementation never creates or changes `agentdev`, reads
its home/authentication data, changes PATH or supplies an invocation socket.
NSS must use bounded local files/systemd sources; accounts must also be local,
locked, no-login system principals with distinct private groups, no foreign
primary/supplementary memberships or numeric aliases. Existing UID 999/GID 989
is accepted only when all checks succeed; these numbers are not defaults.
New free UID/GIDs are selected from the observed system range before writes,
pinned in durable intent, and verified after fixed groupadd/useradd calls.
Existing users, groups and directories are never chowned, chmodded or repaired.

`/var/lib/ap-publisher` and `/var/lib/ap-publisher-signer` must be separate 0700
role-owned directories with singly linked 0600 journals. Safe existing journal
and continuity files are preserved without reading their content; unknown types,
ACLs, capabilities, ownership, mounts or modes block. New journals require
`--initialize-journals`: an explicit operator assertion that these are new stores,
not permission to reconstruct missing history. Empty existing correctly owned
directories may receive an exclusively created new journal only with that flag;
nonempty directories missing a journal and known ledgers missing state block.
Root-owned `/etc/ap-publisher` is 0750 with exact named read/traverse ACLs for
both identities; only newly created configuration receives ACL setup. No jobs,
receipts, artifacts, authorizations, key directories or credentials are generated.

All whole-plan checks precede writes, under a nonblocking directory flock.
`/var/lib/agent-platform-worker-provisioning` is root-only and records intent
before identity/state creation. Completed receipts bind numeric identities,
path device/inode/owner/mode and the exact intent hash. Normal reruns verify,
without rewriting receipts or journal history. An interrupted creation retains
intent/staging and blocks retries. `--recover` only acknowledges an already
completed receipt with the exact intent and unchanged resources; it never
finishes partially created identities/paths or deletes unknown state. Other
interruptions require explicit human reconciliation, outside this command.
The host must exclude concurrent administrator/NSS/filesystem mutation; this
local lock is not an authorization service or independent rollback protection.

Remove and purge remove dpkg payload/conffiles as usual but retain accounts,
state directories, journals, anchors, operator configuration, credentials and
the provisioning ledger. Reinstall verifies these resources; it does not erase,
reset or adopt lost continuity. P0-to-P1 is a deliberate later layer, not
retroactive activation of #102. Downgrading payload does not undo configuration.

## Codex and activation boundaries

The explicit `codex install`, `rollback` and `recover` dispatch uses only fixed
`/usr/bin/python3 -IB` and the installed #116 provisioner. Its release lock,
HTTPS limits, hashes, offline archive validation, root-owned version store,
collision/shadowing checks and recovery contract are unchanged. Supply the real
operator PATH via `--operator-path`; the command never edits shell files or
user installations. See [upstream provisioning](codex-upstream-provisioner.md).
A successful download/install is not authentication, a coding turn or runtime GO.

Provisioning verifies packaged code hashes and invokes AppArmor parser with
`--skip-kernel-load --skip-cache` only. This is **syntax validation**, not enforce
attachment, network BPF validation or a protected-main/readiness assessment.
No service is started, enabled, stopped or restarted. Both oneshots remain
static/inactive. Root job/candidate/receipt installation, key custody, per-worker
App identity, independently retained journal anchors, effective AppArmor/BPF,
negative access probes and separate explicit activation/pilots remain required.
#112 owns read-only readiness. #108 remains open until both approved worker
pilots. This package cannot grant `READY_FOR_SUPERVISED_PUBLISHING`.

## Validation and limits

Unit tests explicitly model different owners; they are not multi-UID kernel
isolation evidence. Archive tests inspect real .deb bytes, fixed dependencies,
exact manifests, unchanged Publisher/#116 inputs and deterministic N/N+1 builds.
Existing P0 lifecycle/security cases remain. The new disposable Docker Debian 13
CI target tests clean and pre-existing 999/989 identities, actual provisioning,
post-receipt interruption/recovery, upgrade, conffile conflict and remove/purge.
It has no credentials, host socket or network during lifecycle. Kernel AppArmor
attachment, reboot/BPF and real App/host operations remain NOT_RUN.
