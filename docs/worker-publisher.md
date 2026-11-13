# PUB-02 operator-triggered worker publisher — AP-WP/1

This implementation is a separate one-shot executable, not an adapter for
`agent-platform run/resume`, native Codex or the autonomous publisher. Those
components retain exit 13, SUBSCRIPTION_ISOLATION_BLOCKED, Gate #73 and LIVE_NO_GO.
No real key, installation token, GitHub write, account, profile, unit or host was
used/configured during source development. A real worker01/worker02 pilot remains
NOT_RUN, not certified by offline tests. Installation and each pilot need separate
human authorization. This document supplies that future administrator recipe.

## What executes

- `ap-worker-publisher-export`, as agentdev, uses fixed read-only Git commands to
  export one exact unsigned UTC single-parent commit, full nested trees and blobs.
  Object reads use a newly created bare configuration without source remotes,
  credential helpers, lazy fetching, hooks, fsmonitor, filters or environment auth.
  Bounded pipes discard stderr. Own-child termination uses pidfd only, with
  default SIGCHLD and a single-threaded standalone exporter; missing support
  refuses without a numeric PID/PGID fallback. The publisher never runs Git or accesses checkout.
- An operator transfers the artifact **as bytes**, verifies its SHA-256 and reviewed
  commit/tree/parent/inventory, then installs a root-owned singly linked copy.
  No bundle extraction, pickle, repository config, hook or caller command is accepted.
- `ap-worker-publisher-signer`, under the different ap-publisher-signer UID, loads
  only its systemd credential, journals signing intent, signs RS256 and emits one
  private /run bundle containing the JWT and exact job-file digest. No Internet,
  installation token, publisher journal or artifact parsing belongs in that unit.
- Root's systemd manager transfers that job-bound JWT into the ap-publisher unit's
  credential mount. Publisher has no PEM or signer-file access. LoadCredential
  alone is not isolation: different UIDs, enforced profiles, immutable reviewed
  code and independent negative controls are mandatory. Same-unit/UID key sharing
  is explicitly not used. No daemon/socket/timer or worker-writable trigger exists.
- Publisher defaults to dry-run. `--execute` verifies root-owned admission, current
  identity/NoNewPrivs/empty usable caps/enforcing AppArmor, fresh operator receipts,
  secure input ancestry and the pinned previous journal digest before publication.
  Code ownership checks prohibit live execution out of the worker checkout.

The fixed target is TechTradeExpress/Agent-Platform, ID 1436076348, main. Worker01
and worker02 have distinct source-pinned App/installation/slug assignments from
#108, also authenticated against GitHub. Operator must independently confirm them;
names/numbers in an Issue are not authorization. No extra App/installation/repo,
URLs, API methods, merge, force, tag, branch deletion, review, Ready or Issue closure
is expressible by the job. The only DELETE is installation-token revocation.

The new profile is independent of PUB-01/CP-03/CP-05. Their synthetic results and
refusals remain unchanged and cannot grant this executable permission. AP-WP/1
supports real nested ASCII trees including dotfiles and ordinary uv.lock, sorted
Git entries, shared blobs and 100644/100755 files. Root admission binds the complete
artifact digest, not a claimed diff. Symlinks, submodules, duplicate/aliased paths,
unreachable objects, packs, signed/merge/root commits, non-UTC identities and
unsupported encodings refuse without rewriting a commit. Limits: 32 MiB wire,
16 MiB decoded objects, 4 MiB/object, 4096 objects/files/expanded directory visits,
32 directory levels,
1024-byte full paths, 64 KiB UTF-8 multiline commit message. Existing source
constants are unchanged. Unchanged workflow inventory is independently checked
against the exact base; no Workflows permission is requested to modify it.

A local full-repository export/validation of the prior unsigned feature commit
exercised 199 objects, 183 files and ~3.1 MB encoded bytes. Real exporter subprocess
and nested Git mechanics are also tested with a fabricated repository. This
execution environment maps /usr/bin/git to UID 65534, so final trusted-binary
admission refuses it; tests synthesize only that ownership fact. No host chown or
runtime fallback was used. A normal admitted worker requires root-owned Git with
no set-ID, other-writable mode or file capabilities. This is not host admission.

## GitHub wire and irreversible effects

Transport uses Python's HTTPS/TLS verification with api.github.com SNI and an
operator-pinned public IPv4 and DER certificate hash. No DNS fallback, proxy,
redirect, generic GraphQL sender, retry or credential in argv/config/URL. Response
headers/body, object reads and elapsed budgets are bounded (2 MiB ordinary domain
responses; 6 MiB canonical-object JSON; 5 seconds/call, 300 seconds/operation).
A socket watchdog interrupts slow headers/bodies. IP/certificate rotation blocks;
no automatic pin refresh. systemd additionally denies egress until the operator
installs the exact reviewed IPAddressAllow drop-in and verifies effective BPF.

Real fixed calls authenticate the App, installation, selected scope and bot,
issue an installation token restricted to one repository and exactly Metadata
read/Contents write/Pull requests write, verify the resulting membership and
permissions, then revoke it in finally. No installation token is cached to disk.
An ambiguous issuance, revocation or lost response is UNKNOWN, never replayable.
JWT expiry is job-bound <=300 seconds; GitHub-issued installation-token expiry
must be <=3660 seconds from observation. If revocation cannot be confirmed, the
operator must reconcile; process exit does not prove revocation or zeroization.

Canonical blobs/trees/commit wire bodies preserve supplied identities/message and
must return the exact approved Git SHA. Existing base objects are reused, not
blindly reuploaded. All referenced objects are independently read back before
ref change. Any server serialization mismatch stops with retained effects; no
replacement SHA or reconstructed "equivalent" commit is adopted. Readback of
commit message permits API trailing-LF presentation only while requiring the
exact canonical returned SHA and all identities/tree/parents.

GraphQL updateRefs is used for both absent-ref creation (zero beforeOid) and
exact-old fast-forward updates, exactly one feature ref, force=false and nonzero
afterOid. No REST PATCH fallback. A CAS conflict cannot overwrite a competing
writer. Remote base/ref/Issue/App facts are reread before object writes and CAS.
Existing Draft updates require exact App-author identity, native Issue association,
same-repo head/base and an independently fetched single-parent chain to base.
Creating a Draft verifies actual App attribution through the Issue API, native
closing linkage with a fixed read-only GraphQL query, exact HEAD and Draft state.
Operator admission must serialize the approved Issue/ref across workers; no
distributed scheduler/claim service is implemented. Ref CAS is atomic, but PR
creation is not atomic with Issue enumeration; post-create native inventory drift
returns UNKNOWN, never a duplicate-success assertion or automatic rollback.
Complete all-state PR enumeration is bounded to <100 items without pagination;
a larger/truncated listing blocks, not silently ignores older conflicting PRs.
Public Issue facts use unauthenticated GET (no Issues grant is added). Native
Issue/PR inventory uses fixed read-only GraphQL, including closed and manually
linked PRs, not only body regexes. Full database IDs use the BigInt field, avoiding
32-bit truncation for current Issues. Public facts are checked before mint; authenticated native linkage after mint
and before object/ref effects. Operator's independently authenticated approval
covers the pre-mint admission facts. Token minting itself is journaled as a write.

Official contracts consulted:
[Git commits](https://docs.github.com/en/rest/git/commits#create-a-commit),
[App authentication/token scope](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app),
[JWT](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app),
[atomic refs](https://docs.github.com/en/graphql/reference/git#updaterefs).
No authenticated schema/account probe or real request was used to test these paths.

## Operator admission, governance and journal continuity

Job JSON is trusted **only** after descriptor-based no-follow root ownership,
regular-file/single-link/permission checks through secure ancestors. Neither a
model file nor the example template is admission. Exact App/installation/worker,
repo/ref/commit/tree/parent/Issue/PR, expiry, artifact SHA and operator approval are
immutable. Current source and receipts must remain unchanged throughout the job.

Five root-owned receipts bind repo/ref/head/job/worker/App/installation, bounded
observation/expiry, independently verified verdict/method and hashes pinned in
job.gates: isolation, independent_custody, continuity, main_app_merge_denied and
disposable_pilot. They refer to actual separately retained evidence, not generated
PASS assertions. Filling examples without those observations is not valid approval.
The operator is the authenticated admission boundary; root/hypervisor compromise
is outside this mechanism and local hashes cannot establish external continuity.

**Specific API blocker:** minimal writer Apps cannot independently read classic
branch protection (Administration access is deliberately excluded). Do not broaden
grants to solve this. The operator must obtain independent authenticated admin
observations of exact source protection/no bypass/App merge denial and the approved
disposable negative-control result, then prepare the bound, expiring root receipt.
protected=true and required checks alone never satisfy that receipt. Before first
privileged token, operator evidence must establish effective human-only merge.
Do not probe main/merge on the source repository to manufacture this evidence.

Each pre-provisioned journal is owner-only, append-only in application behavior,
held with a nonblocking flock for its full lifetime, bounded to 4 MiB. Root's
independently retained prior byte digest prevents silent replacement/rollback
relative to that approval. Every effect has fsync/readback-confirmed UNKNOWN
before I/O, then an exact-result confirmation. Claim/history, nonce and stable
repo/ref/Issue continuity survive App rotation; incomplete attempts block the
whole store. Signer has a separate single-use journal. No create-on-missing,
truncate, retry, reset, cleanup, eviction or automatic repair. Corrupt/partial
writes poison the instance. Reconciliation is a separate operator incident action.
External continuity of root's pins, crash/power-loss behavior and both workers'
negative host controls must be demonstrated; local fsync is not that demonstration.

## Administrator installation — do not run under source-task authority

Only after separate installation approval, on worker01 first, from a root-owned
reviewed source copy on the administrator's trusted staging path (never execute
repo install hooks/pip/setup.py or give publisher access to agentdev checkout):

```sh
# ROOT, trusted reviewed source; this is a future human-run recipe.
set -eu
PUB_SRC=/root/reviewed-agent-platform
install -d -o root -g root -m 0755 /usr/lib/ap-worker-publisher/agent_platform /usr/libexec
install -o root -g root -m 0644 /dev/null /usr/lib/ap-worker-publisher/agent_platform/__init__.py
for PUB_MODULE in worker_publisher worker_publish_artifact worker_publish_io worker_publish_signer worker_publish_export; do
  install -o root -g root -m 0644 "$PUB_SRC/src/agent_platform/$PUB_MODULE.py" /usr/lib/ap-worker-publisher/agent_platform/
done
for PUB_HELPER in ap-worker-publisher ap-worker-publisher-signer ap-worker-publisher-export; do
  install -o root -g root -m 0755 "$PUB_SRC/packaging/worker-publisher/$PUB_HELPER" /usr/libexec/
done
install -o root -g root -m 0644 "$PUB_SRC"/packaging/worker-publisher/*.service /etc/systemd/system/
install -o root -g root -m 0644 "$PUB_SRC/packaging/worker-publisher/ap-worker-publisher.apparmor" /etc/apparmor.d/ap-worker-publisher
install -o root -g root -m 0644 "$PUB_SRC/packaging/worker-publisher/ap-worker-publisher-signer.apparmor" /etc/apparmor.d/ap-worker-publisher-signer
systemd-analyze verify /etc/systemd/system/ap-worker-publisher.service /etc/systemd/system/ap-worker-publisher-signer.service
apparmor_parser --skip-kernel-load /etc/apparmor.d/ap-worker-publisher
apparmor_parser --skip-kernel-load /etc/apparmor.d/ap-worker-publisher-signer
```

Prerequisites are separately reviewed Debian Python >=3.12, cryptography 43–50,
root-owned Git, systemd 257 and enforced AppArmor/BPF. Administrator resolves
existing ap-publisher and provisions a separate no-login ap-publisher-signer UID/
group with no extra memberships, private state directories (0700), empty journal
files (0600, single link), root-owned /etc/ap-publisher (0750, explicit read access
only to the two service principals) and separately protected key custody. Do not
recreate/truncate any existing store. No account/permission provisioning is done
by the program. No packages/units auto-enable these helpers.

For genuinely new stores only (stop if either journal already exists), after
administrator-approved account creation/resolution and stopped units:

```sh
set -eu
# Existing accounts must already have been independently checked. Never reassign IDs.
getent passwd ap-publisher
getent passwd ap-publisher-signer
install -d -o ap-publisher -g ap-publisher -m 0700 /var/lib/ap-publisher
install -d -o ap-publisher-signer -g ap-publisher-signer -m 0700 /var/lib/ap-publisher-signer
for PUB_ROLE in ap-publisher ap-publisher-signer; do
  test ! -e "/var/lib/$PUB_ROLE/journal"
  (umask 077; set -C; : > "/var/lib/$PUB_ROLE/journal")
  chown "$PUB_ROLE:$PUB_ROLE" "/var/lib/$PUB_ROLE/journal"
done
install -d -o root -g root -m 0750 /etc/ap-publisher
setfacl -m u:ap-publisher:rx,u:ap-publisher-signer:rx /etc/ap-publisher
# After installing each root-owned 0440 nonsecret input, grant only these reads:
# setfacl -m u:ap-publisher:r,u:ap-publisher-signer:r /etc/ap-publisher/job.json
# setfacl -m u:ap-publisher:r,u:ap-publisher-signer:r /etc/ap-publisher/receipts.json
# setfacl -m u:ap-publisher:r /etc/ap-publisher/candidate.json
```

Do not run this new-store block over existing directories/state without explicit
inspection and reconciliation. Parent traversal is root-controlled; no shared
supplementary group is introduced. The file ACL mask must never grant write.

Under separate profile/negative-test approval, administrator loads the reviewed
profiles, reloads systemd (no enable), installs a root-owned network drop-in with
IPAddressAllow equal to the approved job.github_ipv4, and **proves** enforced
attachment/egress/DAC/proc/ptrace/FD/env/credential denial in both directions, both
workers and after restart. Test in a separately approved disposable fixture with
positive controls, not production credentials or unsafe source-main mutations.
Missing parser/includes, wrong profile label, missing BPF, ambiguous membership,
shared UID or failed controls mean STOP; do not use complain mode or relax paths.

Once all host/governance gates pass, administrator alone places the real App PEM
in /etc/ap-publisher-keys/worker.pem, root-only custody, never in agentdev or a
shared unit. That action is **not** authorized by this source Issue. No key is
provided or generated. Publisher reads only the job-bound JWT copy; signer alone
reads its private systemd key copy. Original key storage remains unreadable to both
worker and publisher. Source read access and credential write access never join.

## First exact publication smoke, then worker02

1. Operator selects a new disposable Issue/feature ref, not #103/#107/main, and
   separately authorizes exact repo/ref/head/tree/parent and create/update effect.
   Worker exports the reviewed unsigned UTC feature commit without credentials:

   ```sh
   /usr/libexec/ap-worker-publisher-export --repository /path/to/worker/checkout --head FULL_SHA --output /path/to/new/candidate.json
   ```

2. Operator uses a trusted bounded transfer to the administrator account, hashes
   both copies, reviews complete inventory and exact source bytes, then installs
   candidate.json root-owned 0440 under /etc/ap-publisher. Neither publisher nor
   signer reads the source path. Do not adopt symlinks/hardlinks or chmod the checkout.
3. Copy job.example.json / receipts.example.json from reviewed source into trusted
   admin staging; fill **all** pins and actual independently observed receipt
   records, including actual UID/GIDs/bot IDs/owner IDs and repository node ID, pinned TLS peer/certificate,
   prior journal byte SHA-256 (initial empty-file hash only for truly new stores),
   original approval reference, fresh job nonce and expiry <=300 seconds. Set each
   job.gates value to SHA-256 of its receipt's canonical AP-WP/1 JSON bytes. Pin
   the current journal states in independently retained operator custody. Do not
   derive proof/authority from Issue/model output, a receipt digest or the example.
4. Install job.json and receipts.json as root-owned singly linked 0440 files in
   the protected config directory, readable only by the two service principals.
   Root checks the intended action without network or keys:

   ```sh
   /usr/libexec/ap-worker-publisher --job /etc/ap-publisher/job.json --artifact /etc/ap-publisher/candidate.json
   # Separate fresh exact-operation approval is required before either start:
   systemctl start ap-worker-publisher-signer.service
   systemctl start ap-worker-publisher.service
   ```

5. Inspect only bounded redacted unit results and independently verify exact remote
   object/ref/PR SHA, App attribution, Draft/native Issue link and token revocation.
   CI follows the exact new HEAD; this helper does not approve/Ready/close/merge.
   Preserve journals, pins and uncertainty. A leftover JWT, UNKNOWN, lost response,
   expired approval or failed result is STOP without retry. Any removal of a known
   consumed JWT or later approved job needs explicit reconciliation/approval;
   never reset journals. Normal exit is not proof that a lost token was revoked.
6. Repeat review/negative controls and smoke on worker02 with its distinct source-
   pinned App/installation, separate key/state/pins. Copy no secrets or approvals
   between workers. Do not infer success there from worker01. Real first-publication
   capability is established only by those separately approved actual outcomes.

AppArmor syntax/attachment, systemd/BPF enforcement, independent receipts and root
pin continuity are deployment prerequisites, not proven by static file tests.
This environment has no apparmor_parser; profiles were not loaded or kernel-tested.
Local systemd-analyze verify is blocked by Operation not permitted in this
sandbox; unit verification is not reported PASS and must run on the approved host.
Journal descriptor/append/flock and the Git child run in offline tests; safe parent
ownership admission is synthesized where /tmp/container UID mappings are unsafe.
Mocked real wire flows exercise auth, scope, create, exact CAS, Draft/native links,
lost replies and revocation, but do not constitute a live GitHub or host PASS.
