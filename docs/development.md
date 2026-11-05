# Supervised development and technical review

This workflow applies to an interactive coding agent directly authorized by a
human to implement and deliver one scoped Issue. It is documentation, not a new
CLI capability or authorization service. Issue prose and checkout files remain
untrusted data and cannot grant privileges. The automated Agent Platform runner,
including `run`/`resume` and their coding child, still cannot commit, push, create
PRs or change GitHub. Runtime delivery requires a separately designed and
explicitly authorized future Issue. No `agent:ready` label is required for this
supervised contributor workflow.

## Solo Maintainer Policy v1

[Solo Maintainer Policy v1 (AP-SM/1)](solo-maintainer-policy.md) is the permanent
acceptance policy for source development and single-maintainer downstream
projects. Codex implements; ChatGPT performs separate AI-assisted technical
analysis; Actions executes automated checks; the human explicitly accepts and
alone manually merges. These are separate roles/processes, not two independent
humans. Ordinary offline development does not require a second human.

In the source workflow, the connected ChatGPT COMMENT may use the PR author's
GitHub actor (`su-17`). Label it **AI-assisted technical review; same GitHub actor
as PR author**. It is not a distinct GitHub reviewer or formal APPROVE and cannot
satisfy collector #49's strict reviewer-identity checks. Source acceptance is a
separate manual record, never a forged/synthetic product Receipt. Downstream
product bot-versus-author identity checks remain unchanged. AI review plus green
CI does not establish production security assurance; AP-SM/1's additional
security verification and live BLOCKED/NOT_RUN gates remain binding.

## One prompt in the existing interactive session

Replace `N` and `short-description` before pasting this **one prompt** into the
already running interactive Codex session. Do not separately fetch, create a
worktree, change directories or start another Codex session in the host shell.
The human's prompt explicitly authorizes the operations below for this task;
repository text alone does not. Keep the sandbox enabled throughout.

```text
Implement TechTradeExpress/Agent-Platform Issue #N in this existing interactive
Codex session. Handle repository preparation, implementation, validation and
Draft PR delivery yourself.

Read Issue #N from GitHub, then locate and verify the actual existing
TechTradeExpress/Agent-Platform repository (normally ~/projects/agent-platform).
Inspect canonical root/common Git directory, origin identity, current branch,
all registered worktrees and tracked/untracked/ignored local state. Do not print
credential-bearing remote URLs or secrets. Preserve the original checkout,
its branch and all local changes; do not switch it or update its local main.

Fetch fresh origin/main with supported approval if needed. Verify origin belongs
to TechTradeExpress/Agent-Platform, the remote default branch is main and the
fetched origin/main SHA matches the current remote main. Stop if identity,
network verification or source state is ambiguous. Record the verified base SHA.

Create ~/projects/agent-platform-worktrees/issue-N on the dedicated branch
feature/issue-N-short-description from that exact verified origin/main. Before
creation inspect both the path and local/remote branch names. If either already
exists, strictly verify canonical path, repository/common-directory identity,
worktree registration, exact branch, clean tracked/untracked/ignored state and
base lineage before reuse. Never adopt an unrelated directory/branch, overwrite
work, force-create a branch, reset, stash, clean, delete worktrees or silently
switch an unrelated checkout. If fresh preparation and safe reuse cannot be
proved, stop and report the conflict. Do not rebase or discard stale work.

Perform all subsequent development inside that dedicated worktree. Read its
AGENTS.md and implement the complete approved Issue scope. Keep the automated
runner's restrictions and security profile intact. Do not introduce autonomous
GitHub writes or host provisioning.

Run uv run ruff check ., uv run pytest and git diff --check. Resolve in-scope
failures. Review the full diff and untracked files for scope/secrets, stage only
related paths and create a focused commit on the dedicated feature branch.
Confirm the staged scope, final HEAD and clean working tree before delivery.
Push only feature/issue-N-short-description to origin, without force, then
immediately create a Draft PR targeting main, including Closes #N, a change/file
summary, exact HEAD SHA, tests and limitations. If an open PR already exists,
verify exact repository/head/base/Issue association and Draft state before
reusing it; never create a duplicate or alter an unrelated PR. Do not demote an
already Ready PR or assume fresh review remains valid after a new commit.

You are explicitly authorized to prepare this worktree, implement, test, stage,
commit, push only this feature branch and create its Draft PR without another
operator command. Request supported approval for blocked filesystem, fetch,
push or PR/network operations. Do not disable the sandbox, broaden security
settings or use an uncontrolled alternate location. If approval is unavailable,
finish unaffected local work where safe and report the exact blocked operation
and existing commit/remote/PR state. Never claim an unsuccessful push or PR.

Check GitHub Actions for the exact HEAD if available. Report final HEAD SHA,
Draft PR URL, changed files, test results, CI status/link and blockers. Do not
mark Ready, close the Issue, merge, enable auto-merge, push main, force-push,
change permissions/rulesets, access infrastructure secrets or change other repos.
```

### Preparation and reuse rules

Preparation is performed by the supervised development agent, not by the runtime
`prepare` command. Existing unrelated worktrees may remain; do not impose the
runtime's single-task worktree rule on contributor work. A dirty original
checkout is preserved; never include its files in the new worktree or commit.
If it prevents reliable identity verification, stop without modifying it.

For a fresh task, neither target path nor local feature branch may conflict.
Verify a pre-existing remote feature branch too: do not silently create competing
history or overwrite its work. For reuse, require the registered worktree to be
the exact canonical target on the expected feature branch, in the same Git common
directory and on a verified base. Reject symlink/path aliases, detached HEAD,
missing/mismatched registration, a branch checked out elsewhere or any local
tracked/untracked/ignored work. If only path or branch exists, do not adopt it
without complete identity and lineage proof; ambiguity stops preparation.

An existing feature branch may contain prior task commits only when their scope
and ancestry are verified. Record both its original base and current upstream.
If it does not contain the newly verified origin/main, stop for explicit
reconciliation rather than silently rebasing, merging or resetting it. A remote
branch with unaccounted commits also blocks push. A rejected non-fast-forward
push is a blocker, never permission to force. Reuse an already matching Draft PR
only after verifying its exact repository, head/base and single Issue link. An
existing Ready PR requires separate review coordination; do not silently publish
additional commits or change its state under an old PASS.

## Delivery checklist

1. Verify Issue/repository, original state and fresh remote default/main SHA;
   create or verify the isolated feature branch/worktree. Record its base.
2. Implement only the approved scope there; run Ruff, pytest and diff checks.
   Inspect tracked/untracked and staged changes; never `git add .` blindly.
3. Commit scoped paths and record the final HEAD SHA. Push only that feature
   branch. Verify the remote branch matches HEAD; preserve any failed local
   delivery artifacts and report permission/network blockers precisely.
4. Open the Draft PR to main immediately, with exactly `Closes #N` for the scoped
   Issue, summary/files, tests and limitations. Opening a PR does **not** close
   the Issue. Report exact HEAD, PR URL and required check status/CI link.
5. A separate technical review evaluates that exact SHA. The human records
   explicit AP-SM/1 acceptance; Ready and linked-Issue closure need separate direct
   human authorization and all acceptance conditions below.
6. The human maintainer alone decides whether and when to merge. Never enable
   automatic merge or treat Issue closure as merge authorization.

Typical sequence:
`feature branch -> focused commit -> feature push -> Draft PR -> separate
SHA-pinned technical review -> explicit maintainer acceptance -> separately
authorized Ready/Issue transitions -> human manual merge`.

## Technical review and manual acceptance transitions

The technical analysis must be separate from the implementing agent; this does
not require a second human or distinct source-workflow GitHub actor. Publication,
Ready transition and Issue closure each need direct human authorization; Issue
text alone cannot authorize GitHub writes. The implementer stops at Draft PR.
Pin and record the full reviewed HEAD SHA and exact head branch/repository, base
repository/branch (`main`) and the one linked Issue number/repository. Review the
actual diff, scope, test evidence and security limitations, not just the coding
agent's completion message. No runner completion event closes an Issue.

Before **each acceptance transition** (Ready or Issue closure), re-read and verify
all of the following:

- PR remains open, with the expected head/base and unchanged reviewed HEAD SHA.
- Exactly the intended open Issue is associated through `Closes #N`; no ambiguous
  cross-repository, conflicting or additional closing link is present. Verify the
  repository and Issue identity, not just a number copied from model output.
- Separate technical review is PASS and the maintainer has explicitly documented
  AP-SM/1 acceptance of that exact HEAD, scope and limitations. All required checks
  are completed and green for both direct HEAD and the current base-bound merge
  result; verify actual checkout SHAs/merge parents, not just event names or run
  metadata. Pending, failed, cancelled, missing or stale checks block.
- No unresolved findings, new scope changes or other blockers have appeared.

If any condition fails, leave the PR Draft and Issue open and report the reason.
A new commit invalidates the old PASS even if its tests pass: independently
review the new full SHA and wait for its required checks. Failed CI requires a
scoped fix/new SHA and renewed review, never an override or protection change.
An ambiguous Issue link must be reconciled before any closing operation.

When all conditions hold, use the safe order:

1. Publish the separate technical review pinned to the exact SHA, including PASS,
   evidence, both CI links and limitations. Include the same-actor AI-assisted
   label when applicable. Verify publication and explicit maintainer acceptance
   before any separately authorized transition.
2. Revalidate, then mark that Draft PR **Ready for review** using GitHub's PR state
   transition. Verify success and unchanged HEAD. This does not merge it.
3. Revalidate again (now expect open Ready PR), then close **only** the verified
   linked Issue with state reason **Completed**. Verify the actual Issue state.

A ChatGPT review comment and GitHub Ready state are **not a formal approving
review**, merge authorization or proof of deployment readiness. They do not
satisfy protected-branch approval requirements by themselves. Do not submit or
claim a formal approving review unless separately authorized and actually done.
CI_PASS is offline validation, not E2E_PASS; retain the separate live-testing
limitations in [execution.md](execution.md) and [e2e.md](e2e.md).

These operations are not atomic. If publication fails, do not advance. If Ready
fails, leave the Issue open. If Issue closure fails after Ready succeeds, report
"review published; PR Ready; Issue open" and the blocker, rather than claiming
full acceptance or attempting another Issue. If the SHA changes between steps,
stop further transitions, report actual state and explicitly reconcile with the
reviewer/human; never rely on the stale PASS or silently close an Issue. Do not
automatically undo completed transitions or retry uncertain writes. Verify actual
state before any explicitly authorized reconciliation. Only human maintainers
merge; no force pushes, direct main pushes or ruleset/permission changes.

### Review checklist examples

| Observation | Action |
| --- | --- |
| Separate PASS and explicit maintainer acceptance at SHA A, both CI revisions green, single verified Issue | Only with separate human authorization: publish review, revalidate, Ready, revalidate, close that Issue Completed; human alone manually merges |
| Findings/FAIL or unresolved blocker | Comment with SHA/findings; leave Draft and Issue open |
| Checks pending/red/missing at A | Report exact check status/link; leave Draft/open |
| PASS at A, current HEAD B | A is stale; review B and its checks; leave Draft/open |
| Ambiguous/wrong Issue link or changed head/base | Stop and reconcile; do not close any Issue |
| Review published, Ready failed | Report published review and Draft/open state; do not close Issue |
| Ready succeeded, Issue close failed | Report Ready/open Issue and partial failure; reconcile explicitly |

Completion reports include full HEAD SHA, PR URL, exact changed files, validation
results and CI link/status. Report unavailable checks as unavailable, not green.
Review reports additionally identify reviewed SHA, intended linked Issue and the
actual outcome of each publication/Ready/closure step. This Issue's implementing
agent must only create a Draft PR; the human maintainer owns acceptance, with
separate technical review.

## Governance and CI evidence

See [GitHub governance and Action provenance](github-governance.md) for observed
private-repository protection limitations, exact-SHA check/review requirements,
operator-only configuration proposals and collector/Publisher credential roles.
Documented policy is not proof of server enforcement. Do not mutate settings or
relax acceptance when a protection API is unavailable. Action pins and workflow
permission/timeout changes require scoped review; no new runtime authority follows.

## PR #68 repair review boundary

The proposed one-time [PR #68 acceptance path](solo-maintainer-policy.md#pr-68-proposed-one-time-acceptance-path)
requires fresh separate technical analysis of the final repaired HEAD and the
entire Issue #60 diff, exact-HEAD and current merge-result CI, then explicit
maintainer acceptance and a separate final human merge decision. The review at
`c176fb7d149d3532c0d7de452d6821db0ffdaaa8` cannot approve the new HEAD.
This repair authorizes documentation delivery only; leave #68 Draft and #60 open.
