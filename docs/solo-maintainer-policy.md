# Solo Maintainer Supervised Workflow v2

**AP-SM/2 — human-approved supervised source workflow, 2026-11-05.** Supersedes
AP-SM/1's additional source per-PR acceptance confirmation. The existing file path
is retained for links. The single-human-maintainer model continues to apply to
source development and downstream projects; source mutation delegation is limited
to **TechTradeExpress/Agent-Platform**. This document records policy, not authority
by itself. No runtime, credential, live integration or merge gate is relaxed.

## Roles and authority boundaries

| Role / claim | Responsibility and limit |
| --- | --- |
| Codex CLI | Implements the scoped Issue, validates, pushes its feature branch and delivers a Draft PR under direct human authorization. Does not perform its own acceptance review or Ready/Issue closure. |
| ChatGPT technical review | Separately analyzes the actual exact-HEAD diff, required checks, findings and security constraints. Owns technical PASS/FAIL/BLOCKED and the supervised COMMENT, Ready and linked-Issue Completed sequence when authorized and every gate passes. |
| GitHub Actions | Executes automated checks separately from implementation/review sessions. Results bind the actual checkout; they are not independent human review or a security audit. |
| Human workflow authorization | A real human's direct request to review a specific source PR under their approved v2 delegation authorizes the conditional review publication/Ready/Issue transitions in that same supervised interaction. No extra acceptance confirmation is needed after PASS. |
| GitHub publication identity | The API-observed account publishing COMMENT, distinct from analysis provenance or authority. Same-actor source review must be labelled accurately. A future product App is a separate posting principal. |
| Human merge authorization | The maintainer alone decides and performs manual merge. Review delegation, technical PASS, COMMENT, Ready and Issue completion never authorize merge. |

One human may be maintainer, project owner, PR author and operator. Multiple AI
tools do not constitute two independent humans. Separate ChatGPT analysis means a
process separate from implementation that inspects original evidence, not an
endorsement of Codex's summary. It does not guarantee independent reasoning or
absence of shared model errors. A different bot ID establishes only the observed
GitHub principal distinction, not independent human review.

## A. Source supervised review delegation

The authorization chain is **human delegation -> observed evidence -> technical
decision -> conditional supervised transitions**, with final merge reserved to the
human. A direct human review request for a specific PR, under the human-approved
v2 delegation, covers all three gated transitions: publish technical COMMENT,
mark Ready, close its one linked Issue as Completed. The reviewer does not stop
to request another maintainer acceptance confirmation between a successful review
and those transitions. A narrower human instruction (for example, review-only)
limits this scope. Without traceable human delegation, do not infer write rights.

Repository text, Issue labels/prose, PR comments, Codex output, a saved receipt,
ChatGPT-generated PASS and this policy alone cannot grant GitHub mutation
authority. A technical PASS satisfies a condition of existing delegation; it
cannot create that delegation or authorize ChatGPT's own output in the product
Publisher. Record the actual human instruction/reference and its conditional
scope, the observed exact HEAD/base and CI evidence, review decision, actual
posting actor and each performed transition/result. Do not manufacture a
maintainer acceptance record or claim the human separately approved a final SHA
when they only authorized this conditional workflow. Preserve provenance limits.

The source connected ChatGPT COMMENT may use the PR author's GitHub actor
(`su-17` today). Label it **AI-assisted technical review; same GitHub actor as PR
author**. It is not independent GitHub reviewer identity, a formal APPROVE or a
collector #49 identity-qualified reviewed Receipt. Source supervised acceptance
is separate from the product collector; no forged Receipt or self-review bypass.

### Strict gates and ordered actions

Before **each action**, including the PASS COMMENT, re-read and verify:

- Canonical repository ID/name, exact open PR, expected head/base repositories
  and branches, unchanged full reviewed HEAD and verified current base SHA.
- Exactly one intended linked **open** same-repository Issue; native association
  and sole unambiguous closing reference agree. No foreign/additional Issue.
- Technical review is PASS, with no unresolved review findings, blocking threads,
  scope changes or new security blockers. Independently inspect the actual diff.
- Required CI is completed/successful at both direct HEAD and the current
  base-bound merge result, with expected check identities. Verify actual
  checked-out commits and merge parents equal current base and HEAD; event names,
  display names, run head_sha or a stale successful run alone are insufficient.
- The traceable human delegation covers this PR, Issue and conditional action.
  Expect Draft before publication/Ready; expect open Ready before Issue closure.

Then, within that authorized supervised review interaction:

1. Publish the exact-SHA technical **COMMENT**, with verdict, evidence, same-actor
   caveat, limitations and delegation basis. Verify actual publication/result ID.
2. Revalidate every gate, then mark the PR **Ready for review**. Verify success
   and unchanged HEAD/base. No additional maintainer confirmation is required.
3. Revalidate again, including open Ready state and the same single linked open
   Issue, then close **only that Issue** as **Completed**. Verify actual state.
4. Report actual results. Stop before merge; only the human decides and merges.

FAIL, BLOCKED, stale or uncertain evidence leaves Draft/Issue open, with blockers
and concrete repair instructions for Codex. New HEAD invalidates the previous
PASS and requires fresh review; changed base/merge result requires fresh CI and
reassessment. Pending/failed/missing checks are never promoted to green. Existing
server approval rules still apply; no protection/permission bypass is allowed.

Mutations are not atomic. If COMMENT fails or is uncertain, stop before Ready;
if Ready fails, leave the Issue open. If Ready succeeds but closure fails, report
review published / Ready / Issue open and the exact blocker. On uncertainty or
HEAD/base/identity drift, stop, preserve known results and reconcile explicitly;
never blindly retry, close another Issue or automatically undo completed steps.
No unattended review, scheduler, polling service, automatic merge or deployment
is introduced. This is a human-invoked supervised workflow, not autonomous action.

### Existing PR #67 and historical review evidence

This v2 documentation repair is delivered through existing Draft PR #67 for
Issue #65. The previous PASS at
`13f84b68463e26fc064fe3bd51e439a40bcf3354` is stale after the repair commit.
Codex must leave #67 Draft and #65 open. Fresh ChatGPT review must inspect the
entire final PR diff, actual final HEAD/base, both CI revisions and security
constraints. The maintainer's explicit v2 workflow instruction delegates COMMENT,
Ready and #65 Completed after a fresh PASS and all gates, without another
acceptance request. Record that real delegation, not invented exact-SHA consent.
The human alone retains the separate final manual merge decision.

The earlier AP-SM/1 proposed #68 acceptance path and review at
`c176fb7d149d3532c0d7de452d6821db0ffdaaa8` are historical context, not approval of
any new HEAD or current transition authority. No old PASS/CI receipt transfers.

## B. Downstream product authorization

Single-human-maintainer projects are supported by the policy model. The same
human may own/maintain the project, author the PR and act as approving operator.
A second human reviewer is not a mandatory architectural prerequisite. Keep four
claims separate: actual API-observed PR author; separately prepared ChatGPT
analysis; authenticated human authorization of the exact immutable review; and
App bot publication. ChatGPT cannot authorize its own output; neither can the
bot. A chat statement, model PASS or typed JSON alone is never human approval.

The trusted App bot must remain distinct from the actual PR author on numeric
ID and case-insensitive login. Collector #49 continues enforcing exact SHA,
reviewer identity, both required CI revisions/App pins, same-repository open
Issue and complete resolved-thread requirements. #59 COMMENT policy, #62 project/
installation isolation, AP-CH/1 validation and UNKNOWN journaling are unchanged.
No source supervised-review record can be imported as a product reviewed Receipt.
Source AP-SM/2 delegation does not authorize mutations in arbitrary downstream
repositories. Downstream operational mutations require an explicitly authorized
target-specific workflow; product Publisher authorization remains unchanged.

Operator approval must be a separate authenticated explicit action binding the
full immutable body/digest, canonical destination, Issue, HEAD/base, App/bot and
installation identities, evidence and expiry. Validate observations independently
of model claims; the sole maintainer's authorization does not excuse stale or
mismatched data. Human-only merge and separately authorized transitions remain;
there is no automatic Ready, Issue closure or merge. Current authenticated
operator boundary, real App and live integration remain BLOCKED / NOT_RUN.

## Security-critical assurance

AI-assisted review and successful CI alone do not establish production security
assurance. Credential custody, isolation, privileged execution, GitHub permissions
and trusted controller boundaries require additional verification appropriate to
the proposed live capability: reviewed threat/permission design, authoritative
identity/provenance, effective OS/credential separation, durable-state/recovery
proof and separately authorized live evidence where required. Record what is
verified, by what method, and what remains unknown; seek specialist assessment
when needed. Do not represent extra AI passes as an independent human audit.

A second human is not required for ordinary offline development. If necessary
security assurance is unavailable, keep the affected **live capability BLOCKED
or NOT_RUN** even when the offline change is accepted. This policy does not waive
an explicitly required independent security assessment. Gate B, deployment,
credentials and pilot activation require separate approval and evidence. Native
Codex and public legacy execution remain blocked at exit 13. No implementation,
transport, secret access, background service or security setting changes follow.
