# Solo Maintainer Policy v1

**AP-SM/1 — permanent project policy, 2026-11-05.** Applies to Agent Platform
source development and explicitly authorized downstream projects. This policy
supersedes an assumed second-human prerequisite for ordinary offline development.
It grants no execution, credential, publication, deployment or merge authority.
Existing server-enforced rules and all runtime/product gates still apply.

## Roles and limits

| Role | Responsibility and boundary |
| --- | --- |
| Codex CLI | Implements the human-scoped change and reports validation. The implementing agent cannot accept its own work or issue its own technical-review approval. |
| ChatGPT | Performs a separate AI-assisted technical analysis of the actual exact-HEAD diff, scope, tests and CI evidence. Analysis is input for human judgment, never authorization. |
| GitHub Actions | Executes automated checks separately from the implementation/review sessions. Successful checks are evidence of those commands at the observed checkout, not independent human review or a security audit. |
| Human maintainer | Accepts or rejects the review, explicitly authorizes exact actions and alone decides and performs manual merge. May also be project owner, PR author and operator. |
| Dedicated GitHub App | Future downstream COMMENT posting principal, distinct from the actual PR author. Cannot approve its own request or merge. Live identity/transport remains a separate Gate B requirement. |

One person may hold the human roles. Multiple AI tools do not constitute two
independent humans. Separate ChatGPT analysis means a review process separate
from implementation, inspecting original evidence rather than endorsing the
implementer's summary. It does not guarantee independent reasoning, account
independence, absence of shared model errors or independent security assurance.
A different bot ID proves only the observed GitHub principal distinction.

## A. Source repository manual acceptance

The source development workflow may use Codex implementation, separate ChatGPT
technical COMMENT review, successful direct-HEAD and current base-bound
merge-result CI, explicit documented maintainer acceptance, then manual merge.
The same GitHub actor (`su-17` today) may author the PR and publish the connected
ChatGPT review. Label that review **AI-assisted technical review; same GitHub
actor as PR author**. Never describe it as an independent GitHub reviewer, formal
APPROVE or a collector #49 identity-qualified review.

This is a separate manual acceptance policy. It creates no synthetic, forged or
substitute #49 reviewed Receipt, and does not call the product collector with a
self-review bypass. The human need not invent a second account/person to develop
offline code. The implementing agent still stops at Draft PR delivery.

Before acceptance the maintainer must record on the PR, via a separately explicit
human action or directly human-authorized publication:

- Full final HEAD and current base SHA, exact branch/repository and linked Issue.
- A fresh separate technical-review COMMENT at that HEAD, its findings/verdict
  and same-actor caveat where applicable. Old-SHA review is historical only.
- Successful CI links and checked-out revisions for **both** direct HEAD and the
  current synthetic merge result; verify its parents bind the exact base and HEAD.
  Event names or a run's head_sha alone do not prove its checked-out revision.
- Disposition of local failures, remaining limitations, resolved findings/threads
  and explicit acceptance of the scoped offline change. Missing, stale, failed or
  pending required evidence blocks acceptance; do not relabel it green.
- An explicit maintainer acceptance statement for that exact scope/revision,
  acknowledging the AI-assisted and same-actor limits. Acceptance of offline
  code does not authorize live capability activation.

A new HEAD invalidates prior review and acceptance. A changed base/merge result
requires fresh CI and reassessment of affected review evidence. Revalidate before
each separately authorized state transition. No automated Ready, Issue closure
or merge follows a review or CI result. Ready/closure, if requested later, remain
separate explicit human-authorized steps under [development.md](development.md).
The final merge is a separate human decision and manual action. Do not bypass
formal approval rules, change permissions or claim server enforcement from this
manual policy; an applicable unmet server rule remains a blocker.

### PR #68 proposed one-time acceptance path

For [PR #68](https://github.com/TechTradeExpress/Agent-Platform/pull/68), first
complete this documentation repair and pin its final full HEAD in the PR.
The earlier review at `c176fb7d149d3532c0d7de452d6821db0ffdaaa8` is **stale for
any repaired HEAD**. Obtain a fresh separate ChatGPT technical review of the
entire final Issue #60 diff and final CI evidence, transparently labelled if
published by `su-17`. Then obtain the explicit maintainer acceptance record
above, subject to all checks and resolved blockers, and a separate final human
manual merge decision. This is a proposed one-time source acceptance path under
AP-SM/1, not an approval already granted, not a #49 exception and not Gate B.
This repair leaves #68 Draft and Issue #60 open for that fresh review.

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
No manual source acceptance record can be imported as a product reviewed Receipt.

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
