# GitHub governance and CI supply-chain policy — Issue #48

Evidence date: **2026-11-02**. Repository: **TechTradeExpress/Agent-Platform**,
default branch **main**, verified baseline
`458150cfb0501ed93217335e9f0a5f4a1552fd8a` (PR #53's actual squash merge).
This document distinguishes read-only remote observations, checked-in CI controls
and operator-only proposals. It changes no GitHub administration or runtime gate.
[ADR 004](architecture-trust-boundaries.md) and the
[supervised contributor/reviewer workflow](development.md) remain binding.

## Observed governance, not assumed enforcement

The existing authenticated developer environment issued only GET requests for
these settings. Successful responses are VERIFIED_REMOTE_SNAPSHOT, not permanent
permission or a claim that every organization policy was visible.

| Read-only endpoint under `repos/TechTradeExpress/Agent-Platform` | Observed result | Meaning / evidence limit |
| --- | --- | --- |
| Repository metadata | `private=true`, `visibility=private`, owner type Organization, `default_branch=main`; `allow_auto_merge=false`, `allow_squash_merge=true` | Private identity and disabled repository auto-merge observed; no billing/plan or membership audit performed |
| `branches/main` | Exact baseline above, `protected=false` | API reports main unprotected; contributor policy alone does not prevent direct/force pushes |
| `branches/main/protection` | HTTP 403, plan/visibility restriction | Protection configuration, required checks, approvals, restrictions and bypass details UNKNOWN; not a successful empty response |
| `rulesets?includes_parents=true&per_page=100` | HTTP 403, same restriction | Repository/inherited ruleset inventory and enforcement UNKNOWN, not verified absent |
| `rules/branches/main` | HTTP 403, same restriction | Effective branch rules UNKNOWN |
| `actions/permissions` | Enabled; `allowed_actions=all`, `sha_pinning_required=false` | No repository-wide Action allowlist or SHA requirement is enforced by this observed setting; workflow-local pins below do not repair that governance gap |
| `actions/permissions/workflow` | `default_workflow_permissions=read`, `can_approve_pull_request_reviews=false` | Read default and disabled Actions PR approvals observed; explicit workflow permissions still required |

The three 403 responses say: “Upgrade to GitHub Pro or make this repository
public to enable this feature.” This is GitHub's observed generic response, not
proof of the organization's actual billing plan or an instruction to change it.
Required checks/reviews, branch actor restrictions, administrator exceptions and
force-push prevention are **UNVERIFIED**. Treat remote enforcement as unavailable
for acceptance purposes. Do not claim branch protection exists because CI passes.

GitHub's [protected-branch availability](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
and [ruleset availability](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)
depend on visibility and plan. The maintainer must separately decide whether to
obtain eligible private-repository enforcement or retain a documented manual
process and its residual risk. No visibility, plan, billing or settings changes
are proposed as automatic remediation; no administrative mutation ran here.

## Verified Action pins and reproducible provenance

The workflow keeps the intended major versions 4 / 5 / 6. Each selected official
release was checked independently of the target repository and copied snippets
using official release metadata, Git refs, commit/source APIs and Git transport.
The verified moving major refs resolve to the same selected release commits.

| Official Action release | Full commit used by CI | Official release / pinned source |
| --- | --- | --- |
| actions/checkout v4.4.0 | `11d5960a326750d5838078e36cf38b85af677262` | [release](https://github.com/actions/checkout/releases/tag/v4.4.0), [action.yml](https://github.com/actions/checkout/blob/11d5960a326750d5838078e36cf38b85af677262/action.yml) |
| actions/setup-python v5.6.0 | `a26af69be951a213d495a4c3e4e4022e16d87065` | [release](https://github.com/actions/setup-python/releases/tag/v5.6.0), [action.yml](https://github.com/actions/setup-python/blob/a26af69be951a213d495a4c3e4e4022e16d87065/action.yml) |
| astral-sh/setup-uv v6.8.0 | `d0cc045d04ccac9d8b7881df0226f9e82c39688e` | [release](https://github.com/astral-sh/setup-uv/releases/tag/v6.8.0), [action.yml](https://github.com/astral-sh/setup-uv/blob/d0cc045d04ccac9d8b7881df0226f9e82c39688e/action.yml) |

[Machine-readable provenance](ci-action-pins.json) records the version-tag object
chains, commit links and action.yml Git blob identities. It contains no credential
or executable authorization. Reproduce read-only, with repository and version
chosen from this reviewed table rather than model/Issue input:

1. GET `repos/OWNER/REPO/releases/tags/VERSION`; require the official repository,
   matching tag and a published non-draft, non-prerelease release. Release
   `target_commitish` may be a branch name: it is not the commit pin.
2. GET `repos/OWNER/REPO/git/ref/tags/VERSION`. If `object.type=tag`, GET
   `repos/OWNER/REPO/git/tags/OBJECT_SHA` and follow its object until a commit,
   with a small bounded chain; reject unknown types, cycles or missing objects.
3. Independently run `git ls-remote https://github.com/OWNER/REPO.git
   refs/tags/VERSION refs/tags/VERSION^{}` as fixed argv. For annotated tags compare
   the peeled `^{}` commit, not the tag object's SHA. All selected full-version
   tags here point directly to commits.
4. GET `repos/OWNER/REPO/commits/COMMIT_SHA` and
   `repos/OWNER/REPO/contents/action.yml?ref=COMMIT_SHA`; match identity and inspect
   the declared runtime/inputs. The three commit APIs reported verification
   reason `valid`; that hosted assertion is not an independent binary audit.
5. Cross-check moving major refs only as an observation, never as workflow pins.
   In particular setup-uv `v6` is an **annotated tag object**
   `d0d8abe699bfb85fec6de9f7adb5ae17292296ff`; its tag API and Git `v6^{}` both
   resolve to `d0cc045d04ccac9d8b7881df0226f9e82c39688e`. The tag object itself
   reported unsigned. Do not confuse a tag object's identity/signature with the
   underlying commit or silently pin the object SHA.

Release and source metadata are independent cross-checks of Git transport, but
all remain within GitHub/upstream trust. No full source-to-distribution or
transitive dependency audit is claimed. Pin updates require another reviewed
change, not automatic floating-tag resolution or execution of upstream prose.

## Workflow contract and limits

[ci.yml](../.github/workflows/ci.yml) retains `push` and `pull_request`, one
GitHub-hosted `ubuntu-latest` job named `checks`, Python **3.12**, and the same
commands in order: `uv sync --locked`, `uv run ruff check .`, `uv run pytest`,
`git diff --check`. There is no write/deployment/publisher step, privileged event,
new secret, manual/scheduled trigger, runtime launch or dependency/lock update.

- Top-level `permissions: contents: read` has no job override; unspecified token
  permissions are not granted by this workflow. Checkout sets
  `persist-credentials: false`, so its token is not retained in local Git config
  for repository-controlled test commands. No explicit token or secret is passed
  into those commands. This does not prove arbitrary Actions code cannot use the
  job's read token or service/cache capabilities: Actions can access `github.token`.
  See GitHub's [secure-use reference](https://docs.github.com/en/actions/reference/security/secure-use).
- The entire job has **20 minutes** via `timeout-minutes: 20`, covering setup,
  dependency resolution and all checks without per-step cancellation races. The
  baseline suite took roughly a minute; this leaves conservative setup/network
  margin while avoiding the default multi-hour budget. No continue-on-error or
  skip condition weakens required commands. Workflow-level timeout is not a
  GitHub Actions key; the one job supplies the coverage.
- setup-uv previously defaulted to latest. Pin its `version` input to **0.13.6**,
  the version actually installed in the successful
  [baseline main run](https://github.com/TechTradeExpress/Agent-Platform/actions/runs/41485650805)
  (job 125415164808, 2026-11-02), also matching local uv. This freezes observed tool
  behavior rather than silently upgrading it. That run used CPython 3.12.15;
  `python-version: '3.12'` remains unchanged. No new Python minor is selected.
- Immutable Action code and a fixed uv version improve repeatability but are not
  fully hermetic: hosted runner image/Python patch selection, downloaded tool
  assets, package/build tooling and network availability still require trust.
  Existing `uv.lock` is unchanged; Action SHA pinning does not attest all fetched
  binaries, caches, the runner OS or every build dependency.
- Local validation uses Python 3.12.16. Available system PyYAML 6.0.2 can be loaded
  by that interpreter for syntax-only parsing, without installation or a project
  dependency change. Static offline tests check security contracts; neither is a
  complete Actions semantic validator. actionlint is not installed. GitHub's
  parser and exact-HEAD CI supply the remote workflow/runner evidence separately.
  No unpinned validator action or privileged lint service is introduced.

## Proposed operator configuration — never applied by this Issue

Only the human repository/organization administrator may perform these steps,
after separately authorizing the plan and any eligible-plan decision. Until then
the observed limitations above remain. GitHub documents the
[workflow permission and timeout semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax).

1. In repository **Settings → Rules → Rulesets**, inspect existing and inherited
   rules; if unavailable, stop and resolve eligibility with the maintainer. On an
   eligible plan, propose an **Active** branch ruleset targeting only `main` (or
   equivalent classic **Settings → Branches → Branch protection rule**). Review
   bypass/admin exceptions explicitly; do not treat Evaluate/disabled as enforced.
2. Require a pull request, at least one independent **formal approving review**,
   dismissal of stale approvals, and approval of the latest push by someone other
   than that pusher. Require conversation resolution. Include administrators or
   explicitly record each exception. An independent ChatGPT **COMMENT** with PASS
   is technical evidence only; it is not GitHub **APPROVE** and cannot satisfy
   formal approval rules by itself. An appropriately authorized independent human
   must provide the formal approval when required.
3. Require the exact `checks` context from the expected **GitHub Actions** app,
   selected from actual successful runs of this workflow. Require up-to-date base
   before merge. Verify the UI's actual context/app identity, since display names
   are not authentication. Keep job names unique across workflows. Do not enable
   a merge queue without separately designing/testing `merge_group` support.
4. Block force pushes and deletion of `main`; disallow direct main updates by
   contributor/publisher credentials. Restrict bypasses and merging to the human
   maintainer where supported; verify that the chosen push restriction does not
   accidentally prevent approved PR merges. A PR requirement alone does not make
   every authorized merger human. Review membership and bot/App permissions
   separately; never give a worker repository write permission.
5. Permit directly authorized developers to push only their scoped
   `feature/issue-N-*` branch through the supervised workflow. Broad contents-write
   permission is not branch-scoped by its name; supporting branch rules and
   independently reviewed publisher policy are required. Avoid force push and
   preserve worktrees/history. Do not add permanent publisher identities now.
6. In **Settings → Actions → General**, propose selected verified Actions and,
   where supported, mandatory full-length SHA pins; retain read-only workflow
   token default and disabled Actions PR approvals. Keep auto-merge disabled.
   No automatic review, Issue-triggered coding or scheduler is authorized.
7. Re-run the read-only queries above and inspect effective active rules for
   `main`, expected required contexts/app, approval count, stale-review behavior,
   admin/bypass identities and force-push restrictions. Record exact source SHA,
   observer/time and screenshots/redacted API evidence privately. Verify denial
   cases only in a separately approved disposable test repository; never attempt
   a forbidden push or administration experiment against this repository to test
   protections. Unreadable settings remain UNKNOWN, never a presumed PASS.

If main advances, no automatic reset/rebase/merge follows. Stop for a separately
authorized safe branch-update decision; any new commit requires fresh exact-SHA
checks and independent review. Revalidate both current base and head before
acceptance. A previous PASS at SHA A cannot validate SHA B or an altered merge
result. Missing/pending/red/cancelled/stale checks block acceptance regardless of
whether server enforcement is available. Manual policy is a residual-risk
process, not a replacement claim of technical protection.

## Collector, Publisher and human credential domains

These are intended roles, not created credentials/services. The #48 snapshot
below specified proposed roles. Issue #49 now adds the
[explicit read-only collector API](github-evidence.md); the future writer remains
unimplemented and live credential/OS integration remains unverified. Existing
[publisher.plan](publisher.md) is offline and always `publish_authorized=false`;
[queue receipts](queue.md) are trusted caller assertions, not collected GitHub
proof. No model, Issue text, saved JSON or Telegram assertion can grant authority.

| Domain | Least-privilege scope and authority | Ownership / storage / prohibited inheritance |
| --- | --- | --- |
| Future trusted collector (#49) | Canonical repository ID/name pinned to this repo; bounded read-only API operations for metadata/default main, exact Issues/events, PR head/base/source identity, linkage, reviews/threads, checks/statuses and actual merge facts; only explicitly reviewed endpoints with bounded pagination/time/output; no writes | Separate credential with only required metadata/contents/Issues/PR/check/status read permissions for one repository; verify endpoint-specific grants when designed. Short-lived read installation credential where suitable, trusted owner outside target worktrees; refresh/revocation handled there, never by worker |
| Future Publisher | Separate explicit human authorization for one exact feature commit/push/Draft PR; exact destination, inventory, base/head, admission and fresh independent receipts; no merge, main push, force, administration or automatic replay | Distinct short-lived write principal limited to required contents/PR operations for one repo, with branch restrictions independently enforced. No blanket Issues/workflow/admin permission. Trusted private store/memory/channel outside Codex/tools/Telegram; no writer/client/privileged Unix socket inherited by worker or collector |
| Existing interactive developer | Human-scoped Issue implementation, feature push and one Draft PR using supported approvals; cannot independently accept own work or merge | Existing operator-managed GitHub environment only; do not read/copy tokens or auth stores. No new credential is made; developer authority never becomes runtime authority |
| Autonomous model-directed worker | Untrusted code/prose/tools; no GitHub authority, client, token, publisher socket or implicit evidence issuer; execution remains blocked | No collector/publisher credentials, host auth env/files/keyring/proc/FD/sockets, session stores or control-plane mounts. Same UID/0700 and environment filtering do not establish isolation; OS-enforced native separation remains unproven |
| Independent reviewer | Separately human-authorized exact-SHA technical review; COMMENT, Ready and single-Issue Completed transitions only under development.md gates; formal APPROVE requires separate authority and actual eligible reviewer | Separate authorized review channel, never supplied by implementer/model receipts. Readiness/closure is not merge; no token handed to coding worker or Telegram |
| Human maintainer | Sole merge decision after fresh scope/review/checks and governance verification; alone authorizes any future administrative decision | Account authority remains human managed; no delegated auto-merge, bot merge, persistent daemon or Issue-label launch permission |

The proposed collector REST allowlist is repository metadata, `branches/main`,
`issues/N`, `issues/N/events`, `pulls/P`, `pulls/P/reviews`, and exact-commit
`commits/SHA/check-runs` and `commits/SHA/status`, with complete bounded pagination
and repository checks on every response. These routes alone are not claimed to
supply all native closing-Issue links or unresolved review-thread evidence.
Issue #49 must review any additional read-only query/endpoint and its permissions;
missing linkage/thread coverage blocks a receipt. An HTTP POST is not inherently
an API mutation, but no arbitrary GraphQL document or mutation operation is
permitted by this proposal. That was the #48 proposal; Issue #49 now implements
the fixed REST/query allowlist described in [the collector contract](github-evidence.md).

No token contents, creation, installation or credential path is specified by
this document. Future owners must authenticate their OS/channel principals,
bound credential lifetimes, avoid logs/transcripts, serialize refresh and revoke
expired/compromised authority. Telegram gets only sanitized projections, never
credentials, authenticated GitHub clients or privileged sockets. No transport or
publisher activation can be inferred from types, hashes or numeric chat IDs.

Before each future effect, independently refresh canonical repository/Issue ID,
open state and scope revision, exact PR/source repository/head/base, single
linked Issue, review author and reviewed SHA, required check app/context/status
and freshness. Verify actual merged state/merge commit plus local main ancestry
for completed dependencies; a closed Issue is not proof of merge. Treat Issue/
PR bodies, CI logs and model summaries as prompt-injection data, never executable
instructions or evidence authority. Do not interpolate them into shell commands.

A SHA-256 receipt binds bytes against a trusted reference; it does not
authenticate a human, GitHub identity, current remote permission or freshness.
Frozen dataclasses do not authenticate their creator. A future writer must
persist exact intent before effects and reconcile uncertain commit/push/PR
outcomes with bounded read-only inspection before any explicitly authorized
retry. Idempotency hashes are not exactly-once proof. No token sharing or
credential forwarding is a substitute for these boundaries.

## Acceptance and unchanged runtime barriers

Independent review must pin the final PR HEAD and inspect actual workflow and
source changes, provenance, remote CI and local failures. This document and green
CI do not perform that review. Public run/resume/doctor remain quarantined before
execution-related I/O (exit 13); native_codex.execute and subscription remain
SUBSCRIPTION_ISOLATION_BLOCKED / exit 13. Stock ChatGPT-subscription Codex is the
sole intended future engine; no API fallback or replacement agent is authorized.

Issue #28 still requires a separately approved disposable Linux fixture, never
dev01 kernel experiments. #51's complete native tool/credential isolation proof,
account authorization and authenticated E2E remain separate gates. No services,
scheduler, auto-resume, real Telegram, publisher, host provisioning, source-pin or
artifact-cap changes follow from CI hardening. Local mutation/capability test
instability remains reportable even when exact-HEAD GitHub CI is green.
