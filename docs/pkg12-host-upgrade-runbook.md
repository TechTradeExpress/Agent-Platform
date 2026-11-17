# PKG-12 per-host release, backup and recovery runbook — NOT EXECUTED

SOURCE_ONLY / NO DEPLOY / HOST_NOT_RUN / LIVE_NO_GO. This is a proposal for a
future separately authorized human operator, not commands for a coding agent.
No SSH, host inventory, backup, package transaction, service operation, private
state inspection or credential access occurs in #155. Final archive generation,
publication and each host transaction require separate decisions described in
[release readiness](pkg12-release-readiness.md). Native/public execution stays
SUBSCRIPTION_ISOLATION_BLOCKED / exit 13; Gate #73 and Publisher #108 stay BLOCKED.

## Host matrix: no inherited state or authority

| Host | Intended role, subject to fresh verification | Starting evidence | Required separate decision |
| --- | --- | --- | --- |
| control01 | Control only; Worker absence must be checked | Installed version/configuration/continuity UNKNOWN | Exact Control artifact/hash, dependency and protected Control-state backup/restore plan; no Worker install or activation |
| worker01 | Worker only; Control absence must be checked | Historical operator-reported -7 from PKG-10, not a fresh observation | Exact current -7 provenance/state and approved -8 Worker hash, continuity/backup/STOP plan; no inherited no-backup exception |
| worker02 | Worker only; harness selected by operator | Package version, UID/GID, state, harness and continuity UNKNOWN | Independent baseline and host-specific approved Worker artifact/plan; worker01 numeric identities or approvals do not transfer |

The role table is intended topology, not discovery. Unexpected roles/packages,
unknown source, mismatched canonical host identity or absent scoped authorization
is STOP. Never infer installation from a package filename, fixture or inventory
example. No account, harness, HOME/PATH, provider, Codex/Claude installation or
personal CLI authentication is changed by the upgrade.

## Gate 0: source, release and operation authorization

Before even scheduling a host change, the human release operator must obtain:

- a new observed approved post-merge source commit/tree, exact recipes/environment,
  independent actual-bit review, verified immutable frozen two-role release bundle
  and explicit human publication decision; CI_ONLY files are forbidden;
- separately authenticated, host-specific human installation scope naming canonical
  host, exact role, archive path/size/SHA-256, old/new versions and expected APT
  plan, approved backup/restore identity, maintenance window and STOP conditions;
- explicit decision on permitted read-only preflight and protected-state collection
  by a trusted operator, without giving coding tools private access;
- an independently verified continuity/restore plan. Missing backup or recovery
  proof is STOP. The old PKG-10 no-backup exception is not inherited or counted PASS;
  any proposed exception needs a new explicit reviewed risk decision, not this text.

Source review/merge, a tag, green CI, a saved checklist or release approval alone
cannot authorize a host transaction. Final source is unknown in #155. No installer,
service/reload permission or automatic next-host action follows from an earlier gate.

## Gate 1: read-only preflight, performed only under that later scope

Record timestamp/collector identity and privacy-safe evidence references. Verify
canonical host and role before collecting anything. Limit local collection to
fixed approved facts; no environment dump, command injection from package/Issue
text, raw diagnostic logs or wildcard scans of private directories.

1. Installed package names, exact version/configured status, dpkg audit and package
   verification result; verify the peer role is absent as expected. Proposed local
   read-only primitives are `dpkg-query -W`, `dpkg --audit`, `dpkg --verify`, and
   `dpkg-deb -f` for the **approved** archive. They are not executed here. Export
   fixed outcomes/expected public fields, not arbitrary paths or raw stderr.
2. Verify archive SHA-256/size and source/tree/epoch/recipe/tool inventory against
   the frozen release index, per-role provenance, embedded build/manifest and
   retained trust evidence. Obtain authenticated custody evidence, not hashes alone.
   Independently recheck the host's old installed source/manifest; a newly rebuilt
   old .deb is not the actual installed archive. Original archive unavailability
   or mismatched metadata prevents claiming rollback/install identity.
3. Package conffile metadata/hash and approved administrator differences; account
   identities, numeric UID/GID, group membership, owners/modes and named ACLs.
   On workers verify publisher/signer separation against that host's approved
   configuration, not hardcoded worker01 values. Include coding user's denied
   access and independently held enforcement evidence; UID differences alone do
   not prove isolation.
4. Worker unit/profile hashes, package ownership, allowed systemd properties
   (loaded/static/inactive, daemon-reload need, expected unit/drop-in identity)
   and approved AppArmor observation. No daemon reload, enable/start/stop/restart,
   profile parse/load/repair, attachment, BPF change or kernel probe is authorized.
   Active units, unexpected drop-ins or manager uncertainty is STOP, not permission
   to stop services automatically. Static files are not effective confinement.
5. Protected state metadata and continuity references. Worker receipt/journal
   observations must be limited to operator-held metadata, protected hashes or
   privacy-safe signed reports; coding tools never open/export raw contents.
   Keep journal UNKNOWN/external-effect status explicit. Unresolved UNKNOWN means
   STOP; the CI retention test is not a waiver. For Control, inventory only its
   actually admitted checkpoint/queue/HOLD/review/custody/freeze state domains and
   external anchors; absent/unadmitted domains remain UNKNOWN, never initialized.
6. Confirm no runtime job, external publisher action, pending mutation or unresolved
   recovery intent. A free lock or recorded COMPLETED state does not establish idle
   or replay safety. Use separately reviewed trusted read-only evidence. Do not
   launch product doctor/run/resume, signal processes or probe private sessions.

Historical worker01 reference only: PKG-10 reported Worker -7 from
`0fbc940ae94144f8cc29c9a0fd98afc704f58168`, archive
`91784281d9f9d438bcd48ee10dab45b73ab9bc1d93d44301efef7305cddbbfe0`, manifest
`9174f8ee35499b76d9b9f781d64826029c22cd802e3223015a32e53040afcfa9`, publisher
999:989 and signer 995:987, inactive/static units. All require fresh verification;
none proves current state, a backup, recovery or approval for worker02/control01.
Historical -7 reconstruction uses only its pinned original source/recipe and must
never substitute present source under final -7.

## Gate 2: protected backup and independently verified restore plan

The later authorized administrator/custodian owns backup access and execution.
Do not copy private journals, receipts, anchors, keys, auth/session data or backups
into a source checkout, CI artifact or coding UID. Do not hash/export credential
material as package evidence. Any credential backup need is a separate protected
custody decision; this package runbook grants no access.

Before the transaction, retain the exact old archive and verified provenance if
available; dpkg bookkeeping; package conffiles and approved administrator edits;
accounts/groups, UID/GID/modes/ACL metadata; unit/profile/drop-in metadata; all
admitted protected state/receipt/journal/anchor domains and freeze history needed
for consistent recovery. Preserve a coherent point-in-time relation to external
effects and independently retained anchors. Quiescence must be independently
established; creating it via process/service changes needs its own scope.

Record an opaque backup ID, creation time, protected manifest digest, custody and
retention policy, last independently verified restore exercise and compatibility
with old/new code/state. Retain backups through the agreed verification and
recovery window; no automatic expiration/cleanup in the upgrade path. Verify
restore only in a separately authorized isolated nonproduction environment with
no credentials or external-effect ability. No restore exercise happens here.

A checksum or snapshot alone does not prove restore success, durability, consistent
journal lineage or safety after an external action. Restoring local state cannot
undo GitHub/Telegram/API effects. Unknown effects/anchors or incomplete backup
are STOP. Do not solve this with journal deletion, receipt regeneration or a new
empty continuity store. No new host privileges/storage/snapshot tooling is supplied.

## Gate 3: simulation and narrowly scoped transaction — future operator only

Recheck source/frozen bytes, authorization, installed state and backup/continuity
immediately before the proposed transaction. A separate authorized read-only
`apt-get --simulate --no-install-recommends install <approved-absolute-local-deb>`
must show exactly the reviewed role/version change and expected dependencies,
without peer role, removals, unexpected installs/downloads or downgrade. Unknown
baseline means no guessed expected counts. On a verified existing Worker -7 with
preconfigured dependencies, the expected shape is one Worker upgrade only; do not
apply that count blindly to Control or an unverified worker02.

An unexpected simulation, changed hash/size/source, unresolved conffile decision,
active service, insufficient backup/space or continuity drift is STOP before any
write. Do not run autoremove, force options, purge, reset IDs/ACLs, download vendor
tools or treat a simulation as preinst/configure proof. A future real transaction
is a separate administrator operation over the exact local file, not a command
provided or executed by this preparation tool. Distribution/download authorization
must be explicit too; a URL or copied checksum is insufficient.

Upgrade Workers one independently authorized host at a time, with evidence and
human disposition before considering the other. This ordering is maintenance
coordination, not launching an agent or rotating harness/account selection.
Control has its own package/state/backup and compatibility decision; its upgrade
is neither a prerequisite silently applied to Workers nor implied by their PASS.
No combined unattended host rollout is defined.

## Gate 4: interruption, STOP and explicit recovery

If unpack/configure stops, a conffile prompt appears, or return/effect is uncertain:

- retain package state, protected data and all logs locally under trusted custody;
  export only redacted fixed outcomes, hashes and references;
- record exactly which role/version is installed, unpacked, half-configured or
  pending, and whether a maintainer script/effect is unknown. Do not infer success
  from a newer file or absence of terminal output;
- refuse service/runtime activity and all automated retry/cleanup. Do not use a
  broad configure-all, forced downgrade, same-version replacement or reinstall as
  generic repair. Do not purge or clear UNKNOWN/temporary/checkpoint/receipt state;
- require human reconciliation of exact archive/state/lineage and continuity before
  any narrowly named completion operation. If explicit configure completion is
  separately approved, bind it to the same artifact and host; recheck every gate;
- if restoration is proposed, stop until a separate human decision covers the
  protected backup, consistent point-in-time anchors, external effects and exact
  compatible code/state. A package-code downgrade alone is not rollback. Prefer a
  separately reviewed forward repair/new revision to forcing old code onto unknown
  state; no automatic restore or journal migration is implemented.

PKG-11 CI covers controlled unpack/configure cuts, not kill/power-loss durability,
real systemd boot, a new final-recipe payload or complete host recovery. Its
synthetic UNKNOWN case proves retention only. No recovery success is inferred
from offline parser tests, recreated state or a matching filename/version.

## Gate 5: post-change evidence and per-host disposition

Under the later operator's read-only scope, independently verify configured dpkg
status, exact new source/provenance/manifest/payload, audit/verification result,
unchanged IDs/groups/ACLs/receipt/journal bytes and continuity, conffile decisions,
unit/profile/drop-in metadata and zero unauthorized activation. Recheck role
separation and original harness/account selection. An approved future bounded
Worker Doctor observation must still be BLOCKED/exit 13, launch_allowed=false,
LIVE_NO_GO/HOST_NOT_RUN; package installability does not pass Gate #73/#108.
Public product run/resume/doctor stay quarantined; do not invoke them as readiness
or use private login stores to obtain a green result.

Retain old/new archive and evidence identities, backup/continuity reference,
actual authorization, performed operations, each NOT_RUN and unresolved finding.
A required manager reload or kernel profile change is a separate authorization,
not a package post-step. Drift or unexpected result means STOP with retained data,
not automatic correction. Only the human gives this host's disposition; no PASS
implies the next host, Publisher pilot, runtime use or release-signing permission.
