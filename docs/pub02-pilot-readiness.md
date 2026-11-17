# PUB-02 pilot readiness and operator runbook (#108)

SOURCE_ONLY / OFFLINE_ONLY / HOST_NOT_RUN / LIVE_NO_GO. This document is a
readiness assessment and a future operator procedure. It is **not** approval to
install, provision, generate a key, start a unit or write to GitHub. Gate #73
stays BLOCKED, native/legacy runtime stays `SUBSCRIPTION_ISOLATION_BLOCKED` /
exit 13, merge stays human-only and #108 stays open until both real pilots pass.

## 1. Baseline and evidence classes

Assessed source: `main` `c27d0ef9bb1a07f56bbaa1fce9811827636c054f`, tree
`cd9edf4c42f347c7a48b8634a17e80078dff66fd`. The five AP-WP/1 modules and
`packaging/worker-publisher/` are byte-identical to `0fbc940…`, the source of
the worker01 `0.1.0-7` installation reported in #143. Every pre-fix finding
below therefore applies to those reported installed bytes. No host was observed.

| Class | Meaning in this document |
| --- | --- |
| SOURCE | Repository code and offline pytest with fabricated credentials and mocked wire |
| VENDOR_SOURCE | systemd `v257.13` `src/core/exec-credential.c`, `src/shared/acl-util.c`, `src/shared/mount-util.c`; Linux `v6.12` `security/apparmor/lsm.c`, `fs/open.c`; Debian 13 `apparmor 4.1.0` abstractions as installed on worker02 |
| PUBLIC_READ | Unauthenticated read-only GitHub GETs, 2026-11-17, API version `2026-03-10` |
| OFFLINE_SIM | Real exporter on a disposable unsigned UTC commit over the full `c27d0ef` tree, then `publish()` against the test wire mock |

None of these is host, App-authentication or live-publication evidence.

## 2. Readiness matrix

| Area | Status | Basis |
| --- | --- | --- |
| Worker exporter (`ap-worker-publisher-export`) | SOURCE_PASS | OFFLINE_SIM: 342 objects, 5,727,091-byte artifact, `EXPORTED`; worker hosts HOST_NOT_RUN |
| AP-WP/1 artifact, job and receipt validation | SOURCE_PASS | Existing and new negative tests |
| Signer/Publisher credential intake | SOURCE_PASS after F-01 | Was deterministic BLOCKED on systemd 257 |
| AppArmor coverage of the code's own file walk | **BLOCKED** (F-02) | Scope dependency on packaging, see section 3 |
| PR enumeration | SOURCE_PASS after F-03 | Was within ~10 PRs of a hard block |
| Object readback within the 300 s budget | SOURCE_PASS after F-04 | Was ~165 s of 300 s for a 5-object pilot |
| Journal after a read-only admission failure | SOURCE_PASS after F-05 | Was a permanently stuck store |
| Journal reconciliation after UNKNOWN effects | NOT_IMPLEMENTED | Operator incident procedure only (section 9) |
| systemd sandbox, `LoadCredential` root transfer, restart | HOST_NOT_RUN | PKG-08 inert transient fixture never run |
| Job-bound egress drop-in (#122) and live cgroup BPF | SOURCE_PASS / HOST_NOT_RUN | Doctor contract exists; no running attachment observed |
| GitHub wire shapes | SOURCE_PASS + PUBLIC_READ | Public endpoints match; authenticated endpoints NOT_RUN |
| App registration, grants, events, installation scope | HOST_NOT_RUN | Operator-only GitHub settings |
| Protected `main` / App merge denial | **BLOCKED** (G-01) | Needs admin observation; ruleset alone is insufficient |
| Key custody, PEM, JWT, installation token | NOT_RUN | Operator-only, after reviewed code is deployed |
| Delivery of these fixes to hosts | **BLOCKED** | Requires a new reviewed package containing this change |
| worker01 / worker02 App-authored Draft pilot | NOT_RUN / NOT_RUN | #108 remains open |
| Autonomous Agent Platform runtime | LIVE_NO_GO | Unchanged |

## 3. Source findings

**F-01, credential layout (fixed).** systemd 257.13 `write_credential()` writes
each credential `0400` as root and first tries `fd_add_uid_acl_permission(uid,
ACL_READ)`; only where ACLs are unsupported (ramfs) does it chown to the unit
user. The store directory is made read-only and gets an `r-x` ACL the same way.
Kernel 6.12 supports tmpfs `noswap`, so `mount_credentials_fs()` uses tmpfs, and
Debian's kernel has `CONFIG_TMPFS_POSIX_ACL=y`. The real layout is therefore a
root-owned `0440` (ACL mask) file in a root-owned `0550` directory. The former
`read_file(..., owner=self, writable_parent=True, private=True)` required the
unit user as owner and no group bits, so it could never read either credential.
For the signer this happened after `UNKNOWN sign` was journaled: the first real
attempt would have poisoned the signer store. `read_file(..., credential=True)`
now accepts exactly two layouts: root owner with an ACL of only `USER_OBJ` (no
write), `USER=<own uid>`, `GROUP_OBJ=---`, `MASK`, `OTHER=---`; or the ramfs
fallback owned by the unit user with no ACL and no group/other bits. No write bit,
set-ID/sticky bit, other access, named group, third user, symlink or hard link is
accepted. The ACL is read from the open descriptor.

**F-02, AppArmor ancestor mediation (BLOCKED, not changed here).** `read_file()`
opens every ancestor with `O_RDONLY|O_DIRECTORY` and `fstat`s it. Linux 6.12
`apparmor_file_open()` mediates directory opens with `MAY_READ` and
`apparmor_inode_getattr()` mediates `fstat`; `r` on the directory path grants
both. (`O_PATH` skips only the open hook, not getattr.) Both profiles grant only
leaf files, and Debian 13 `abstractions/base` and `abstractions/python` grant no
`/`, `/etc/`, `/run/`, `/var/` or `/usr/` directory. Under the enforcing profile
that `confinement()` itself requires, the first `os.open("/")` is denied, so
neither role can read `job.json`. This was never exercised: earlier probes opened
paths directly. The minimal fix is these exact directory rules (machine-checked
against the code's read paths by `tests/test_worker_publisher.py`):

```text
AP-PUB02-F02 ap-worker-publisher
/ r,
/etc/ r,
/etc/ap-publisher/ r,
/run/ r,
/run/credentials/ r,
/run/credentials/ap-worker-publisher.service/ r,
/usr/ r,
/usr/lib/ r,
/usr/lib/ap-worker-publisher/ r,
/usr/lib/ap-worker-publisher/agent_platform/ r,
/var/ r,
/var/lib/ r,
/var/lib/ap-publisher/ r,
AP-PUB02-F02 ap-worker-publisher-signer
/ r,
/etc/ r,
/etc/ap-publisher/ r,
/run/ r,
/run/credentials/ r,
/run/credentials/ap-worker-publisher-signer.service/ r,
/usr/ r,
/usr/lib/ r,
/usr/lib/ap-worker-publisher/ r,
/usr/lib/ap-worker-publisher/agent_platform/ r,
/var/ r,
/var/lib/ r,
/var/lib/ap-publisher-signer/ r,
```

F-02 status: BLOCKED_SCOPE_DEPENDENCY. The profiles are dpkg conffiles of the
Worker P1 package. `packaging/debian/worker_upgrade_lifecycle.py` asserts that
both profile digests are unchanged after the historical `-7` to new-package
upgrade, so this edit also requires a reviewed lifecycle-test change, and it
changes future `0.1.0-8` content governed by PKG-13 (#157). It is left to a
coordinated decision. A local host edit is not a workaround: an edited conffile
blocks provisioning hash validation. `r` on these directories also permits
listing them; the directories are world-listable by DAC already, except the
role's own state directory.

**F-03, PR enumeration (fixed).** The Publisher listed every PR in the
repository on each observation and blocked at 100 items, any `Link` header or a
2 MiB body. PUBLIC_READ: 75 PRs were 1,859,724 bytes. It now requests
`/pulls?state=all&head=TechTradeExpress:<branch>&per_page=2` (0 or 1 PR, any
state) and blocks on any second or foreign-head entry. Closing-Issue claims are
checked only by the existing authenticated native `INVENTORY` query, after token
issuance and before every object, ref and PR effect, including closed and
manually linked PRs. Deliberate narrowing: textual `Closes #N` in a PR whose base
is not `main` is no longer seen; GitHub does not link or close from such a PR.

**F-04, object readback budget (fixed).** After uploads the Publisher read back
every object in the full candidate tree, including objects the exact base
commit's untruncated recursive listing already proves present. OFFLINE_SIM on a
5-object change: 458 calls (348 object reads, 10 whole-repository listings),
~165 s at measured latencies (0.35 s per small call, 0.81 s per listing), inside
a 300 s job, receipt and process
window that also covers the operator ceremony. Now only objects absent from the
base listing are read, once after upload and once before the ref CAS: 121 calls,
11 object reads, ~42 s. A truncated base listing still blocks before the token.

**F-05, read-only failure after CLAIM (fixed).** `CLAIM` used to be appended
before the pre-token reads, so any mismatch there (for example App `events`,
permissions or a public read error) left a non-`COMPLETE` tail and blocked every
later job with no supported recovery. `Journal.admissible()` now performs the
replay/continuity check (no network) first. `CLAIM` is appended after read-only
admission, immediately before the token-mint effect, so a read-only failure
leaves the journal byte-identical. The CLI reports `BLOCKED` only when no journal
record was appended or attempted; otherwise `UNKNOWN_NEEDS_HUMAN`.

## 4. Governance observation G-01

PUBLIC_READ of `rules/branches/main`: ruleset `26772477` has deletion,
non-fast-forward, linear history, required `checks` and `lifecycle` from
integration 15368 (strict) and a pull-request rule with
`required_approving_review_count: 0`. That ruleset alone does not stop an App
holding `contents:write` and `pull_requests:write` from merging a green PR through
the API. Human-only merge rests on the operator-reported classic restriction
(pushes to `main` only by `su-17`, no bypass, no Apps), which the minimal App
cannot read. The `main_app_merge_denied` receipt therefore needs a fresh
independent administrator observation of that restriction, never `protected=true`
or required checks. PUBLIC_READ also showed: repository public, ID `1436076348`
(matches the source pin), node `R_kgDOVZjJPA`, owner ID `276109898`, bot users
`tte-agent-worker01[bot]` `356363817` and `tte-agent-worker02[bot]` `356363845`.
These are observations to re-verify, not authorization.

## 5. Residual risks (not changed here)

- **R-1 unauthenticated rate limit.** Issue, user and pre-token reads are
  unauthenticated (60/hour per egress IP, shared with any other client behind it).
  OFFLINE_SIM: a 5-object create makes 23 of them. Exhaustion blocks.
- **R-2 eventual consistency.** A new PR may lag in the head listing or native
  closing linkage; the `draft` effect then ends UNKNOWN with the PR existing.
- **R-3 update path.** Updates require the old head to chain to the current
  `main`; once `main` moves, a Draft cannot be updated. The first pilot is create.
- **R-4 serialization.** GitHub may normalize the PR body or commit fields; any
  mismatch stops after the effect (UNKNOWN), never a rewritten commit.
- **R-5 pins.** IPv4 and leaf-certificate pins rotate; a mismatch blocks.
- **R-6 poisoned journal.** If a journal append fails, token revocation is not
  attempted; the token stays in process memory until expiry (at most one hour).
- **R-7 time window.** Job, receipts, network approval and JWT all expire within
  300 s, so staging must be scripted and rehearsed.

## 6. GO / STOP for the first live attempt

GO requires all of the following, each separately evidenced: a reviewed package
containing this change and an F-02 fix installed with exact hashes; doctor
showing package, state, units and AppArmor `CONFIGURED`, where overall exit 13
and the network/BPF items handled in phase G are the only expected blockers;
PKG-08 inert transient fixture results for both roles (file access, credential
transfer, opposite-role denial, restart, BPF positive and negative controls);
App settings observed by an administrator (exactly Metadata read, Contents write,
Pull requests write, no events, selected repository only); G-01 classic
restriction observed; a new disposable open Issue with no PR; journals at a
pinned digest; and an explicit human approval of the exact repo, ref, head, tree,
parent and create effect for one worker.

STOP on any mismatch, UNKNOWN, expired item, unexpected drop-in, retained JWT,
profile not in enforce mode, doctor blocker other than the expected ones,
non-UTC or signed commit, or any doubt. Never retry, edit a journal, widen a
profile, add a grant or switch worker, App or harness to get past a STOP.

## 7. Runbook, worker01 first (future, separately approved)

Phases A to D need no key and no GitHub write; each still needs its own approval.

**A. Source and package.** Verify the reviewed `main` commit, the package's
embedded source and the `.deb` SHA-256 against independent CI evidence. Install
only through the PKG-12 per-host procedure. `-7` contains the pre-fix code
(F-01, F-03 to F-05) and the F-02 profiles: do not attempt a pilot on it.

**B. Read-only preflight (root, bounded output).**

```sh
dpkg-query -W agent-platform-worker
agent-platform-worker doctor
systemctl show -p ActiveState,UnitFileState,DropInPaths,NeedDaemonReload \
  ap-worker-publisher.service ap-worker-publisher-signer.service
grep -E '^ap-worker-publisher(-signer)? \(enforce\)$' /sys/kernel/security/apparmor/profiles
getfacl -cp /etc/ap-publisher
sha256sum /var/lib/ap-publisher/journal /var/lib/ap-publisher-signer/journal
test ! -e /run/ap-publisher-signer/app-jwt
```

Record the journal digests in independent custody; they become `journal_sha256`
and `signer_journal_sha256`. A fresh store's digest is that of the empty file.

**C. Inert fixture.** Run the PKG-08 bounded procedure
(`publisher-isolation-readiness.md`) with fabricated bytes only. Confirm that
both roles can open their files through the profile (this is where F-02 shows),
that the credential layout matches section 3 and that the opposite role is denied.

**D. App and governance (administrator, GitHub UI).** Record App ID, slug,
owner, installation ID, `repository_selection=selected` with only this
repository, exact permissions and no events. Observe the G-01 classic restriction.
Generate the PEM only now, into root-only `/etc/ap-publisher-keys/worker.pem`;
never into a home, worktree, Issue, log or the other worker.

**E. Candidate (agentdev, no credentials).** Commit on the exact current `main`:

```sh
TZ=UTC git -c commit.gpgsign=false commit -m "..."
git cat-file commit HEAD | head -4   # tree, one parent, author/committer +0000
/usr/libexec/ap-worker-publisher-export --repository "$PWD" \
  --head "$(git rev-parse HEAD)" --output /path/to/new/candidate.json
```

The exporter prints head, tree, parent and `artifact_sha256`; it refuses signed,
merge or non-UTC commits and symlinks or submodules anywhere in the tree.

**F. Transfer (root).** Copy the bytes over a trusted path, compare SHA-256 on
both sides, review the inventory, then stage `job.json`, `receipts.json` and
`candidate.json` exactly as in the PKG-08 table (root `0440`, single link,
named-reader ACLs, mask `r--`). Each `job.gates` value is the SHA-256 of the
compact sorted-key JSON of its receipt:

```sh
python3 -I -c 'import hashlib,json,sys; d=json.load(open(sys.argv[1])); [print(k, hashlib.sha256(json.dumps(v,sort_keys=True,separators=(",",":")).encode()).hexdigest()) for k,v in sorted(d.items())]' receipts.json
```

A receipt records an observation that exists and is retained elsewhere; never
write one to satisfy the check.

**G. Live window (at most 300 s from the earliest receipt).** Write the
`AP-WORKER-NETWORK/1` record and the three-line drop-in (`worker-doctor.md`),
`systemctl daemon-reload`, rerun `agent-platform-worker doctor`, run the dry run
`/usr/libexec/ap-worker-publisher --job /etc/ap-publisher/job.json --artifact
/etc/ap-publisher/candidate.json`, then with the fresh approval for this exact
action:

```sh
systemctl start ap-worker-publisher-signer.service
systemctl start ap-worker-publisher.service
journalctl -u ap-worker-publisher.service -o cat -n 3 --no-pager
```

**H. Verification and close-out.** Independently confirm the remote ref SHA,
the Draft PR author `tte-agent-worker01[bot]`, `performed_via_github_app`, the
native closing link, and revocation (the token must fail). Remove the network
record and drop-in, `systemctl daemon-reload`, record the new journal digests and
reconcile the consumed `/run/ap-publisher-signer/app-jwt` before removing it.
CI runs on the new head; the Publisher never marks Ready, approves or merges.

## 8. worker02

Repeat B to H on worker02 with its own approval, App `5748675`, installation
`181691061`, bot, key, journals, pins and evidence. Copy nothing from worker01
except reviewed source and package bytes. worker01 success proves nothing there.

## 9. After a failure

`BLOCKED` with unchanged journal digests: nothing was appended. Remove the
consumed JWT output only after reconciliation, then start again from a new job,
receipts and approval. `UNKNOWN_NEEDS_HUMAN` or a changed digest: STOP. Preserve
both journals (copy and hash, never edit), the staged inputs, the unit logs and
the remote state as observed. If revocation is not proven, an administrator
suspends the App installation until the token's reported expiry has passed.
No supported tool appends a reconciliation record yet
(NOT_IMPLEMENTED); continuing on that store needs a separately reviewed design.
