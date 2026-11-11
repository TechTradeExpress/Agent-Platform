"""CP-04/1 pure synthetic eligibility advice; no collector, reviewer or writer.

Only a trusted caller may construct qualified fixture observations. Types and
hashes validate consistency, never authenticate their origin or prove isolation.
"""

from dataclasses import asdict, dataclass, replace

from . import codex_assignment as assignment
from . import github_evidence as evidence
from . import issues, publisher
from . import review_comment as review

MAX_RECORDS = 128
MAX_DESCRIPTOR = 8192
MAX_OBSERVATIONS = 65536
MAX_AGE = 300


class InvalidEvidence(ValueError):
    def __init__(self):
        super().__init__("invalid_handoff_evidence")


def _need(condition):
    if not condition:
        raise InvalidEvidence()


def _time(value):
    _need(type(value) is int and 0 <= value < 2**63)


def _bool(value):
    _need(type(value) is bool)


def _tuple(values, cls):
    _need(type(values) is tuple and len(values) <= MAX_RECORDS)
    _need(all(type(v) is cls for v in values))
    _need(len(set(values)) == len(values))


def _app(app, installation):
    _need(type(app) is review.AppIdentity)
    _need(type(installation) is review.InstallationIdentity)
    replace(app)
    replace(installation)
    _need(app.installation_id == installation.identifier)


@dataclass(frozen=True, slots=True)
class Worker:
    worker_id: str
    agent_id: str
    session_id: str
    context_id: str
    worktree_id: str

    def validate(self):
        assignment.agent(self.worker_id)
        assignment.agent(self.agent_id)
        for value in (self.session_id, self.context_id, self.worktree_id):
            _need(publisher.hex_digest(value))


@dataclass(frozen=True, slots=True)
class Contributor:
    job_id: str
    revision: str
    worker: Worker
    app: review.AppIdentity
    installation: review.InstallationIdentity


@dataclass(frozen=True, slots=True)
class Handoff:
    """Trusted policy pins, never parsed from candidate/model/Issue data.

    This is an existing-PR context. No fabricated pre-PR TargetProject or Receipt.
    Contributor history covers the entire candidate, including previous jobs.
    """

    job_id: str
    pull_request_id: int
    assignment: assignment.CodexAssignment
    policy: evidence.Policy
    implementer: Worker
    reviewer: Worker
    contributors: tuple[Contributor, ...]
    source_sha256: str
    ci_sha256: str
    issued_at: int
    expires_at: int
    schema_version: int = 1


@dataclass(frozen=True, slots=True)
class LinkedIssue:
    repo_id: int
    issue_id: int
    number: int
    state: str


@dataclass(frozen=True, slots=True)
class CheckRun:
    identifier: int
    check: evidence.Check
    commit_sha: str
    checkout_sha: str | None
    status: str
    conclusion: str
    completed_at: int


@dataclass(frozen=True, slots=True)
class ReviewRecord:
    identifier: int
    author: evidence.Principal
    commit_sha: str
    blocking: bool


@dataclass(frozen=True, slots=True)
class Thread:
    identifier: int
    resolved: bool


@dataclass(frozen=True, slots=True)
class Observations:
    """Independently qualified synthetic facts, NOT a live evidence adapter.

    Flags are trusted-caller assertions, not model claims or verified host facts.
    Inventory counts and completeness include all pages and retained history.
    Stable canonical source/CI retrieval is asserted, never performed here.
    """

    handoff_sha256: str
    project_sha256: str
    source_sha256: str
    ci_sha256: str
    repo_id: int
    repository: str
    head_repo_id: int
    base_repo_id: int
    base_branch: str
    pull_request: int
    pull_request_id: int
    head_sha: str
    base_sha: str
    merge_sha: str
    merge_parents: tuple[str, ...]
    author_app: review.AppIdentity
    author_installation: review.InstallationIdentity
    reviewer_app: review.AppIdentity
    reviewer_installation: review.InstallationIdentity
    reviewer: Worker
    linked_issues: tuple[LinkedIssue, ...]
    checks: tuple[CheckRun, ...]
    reviews: tuple[ReviewRecord, ...]
    threads: tuple[Thread, ...]
    contributors: tuple[Contributor, ...]
    contributor_count: int
    review_count: int
    thread_count: int
    check_count: int
    linked_issue_count: int
    observed_at: int
    source_observed_at: int
    ci_observed_at: int
    qualified: bool
    complete: bool
    contributors_complete: bool
    reviews_complete: bool
    threads_complete: bool
    checks_complete: bool
    links_complete: bool
    stable: bool
    fresh_worktree: bool
    fresh_session: bool
    isolated_context: bool
    independent_source: bool
    transcript_access: bool
    shared_writable_worktree: bool
    reviewer_edited: bool
    unresolved_findings: bool
    security_blockers: bool
    pr_open: bool
    pr_draft: bool
    final_statuses_successful: bool
    provenance: str = "synthetic_trusted_caller"
    schema_version: int = 1


@dataclass(frozen=True, slots=True)
class Result:
    status: str
    reason: str
    handoff_sha256: str | None = None
    observations_sha256: str | None = None
    head_sha: str | None = None
    base_sha: str | None = None
    merge_sha: str | None = None
    schema_version: int = 1
    review_authorized: bool = False
    comment_authorized: bool = False
    approve_authorized: bool = False
    ready_authorized: bool = False
    issue_closure_authorized: bool = False
    merge_authorized: bool = False
    publish_authorized: bool = False
    launch_allowed: bool = False
    resume_authorized: bool = False


def digest(value):
    """Correlation only; callers must validate before trusting any pins."""
    _need(type(value) in (Handoff, Observations))
    return publisher.digest(asdict(value))


def _validate(h, o, now):
    _need(type(h) is Handoff and type(o) is Observations)
    _time(now)
    _need(issues.positive_int(h.pull_request_id))
    for value in (h, o):
        _need(type(value.schema_version) is int and value.schema_version == 1)
    _need(type(h.assignment) is assignment.CodexAssignment)
    replace(h.assignment)
    _need(type(h.policy) is evidence.Policy)
    replace(h.policy)
    replace(h.policy.admission)
    for worker in (h.implementer, h.reviewer, o.reviewer):
        _need(type(worker) is Worker)
        worker.validate()
    for value in (
        h.job_id,
        h.source_sha256,
        h.ci_sha256,
        o.handoff_sha256,
        o.project_sha256,
        o.source_sha256,
        o.ci_sha256,
    ):
        _need(publisher.hex_digest(value))
    for value in (
        h.issued_at,
        h.expires_at,
        o.observed_at,
        o.source_observed_at,
        o.ci_observed_at,
    ):
        _time(value)
    _need(h.issued_at < h.expires_at <= h.issued_at + MAX_AGE)
    _need(type(o.provenance) is str and len(o.provenance) <= 64)
    _need(type(o.repository) is str and len(o.repository) <= 256)
    for value in (
        o.repo_id,
        o.head_repo_id,
        o.base_repo_id,
        o.pull_request,
        o.pull_request_id,
    ):
        _need(issues.positive_int(value))
    _need(type(o.base_branch) is str and 0 < len(o.base_branch) <= 64)
    for value in (o.head_sha, o.base_sha, o.merge_sha):
        _need(evidence.sha(value))
    _need(type(o.merge_parents) is tuple and len(o.merge_parents) <= 2)
    _need(all(evidence.sha(v) for v in o.merge_parents))
    for name in (
        "qualified",
        "complete",
        "contributors_complete",
        "reviews_complete",
        "threads_complete",
        "checks_complete",
        "links_complete",
        "stable",
        "fresh_worktree",
        "fresh_session",
        "isolated_context",
        "independent_source",
        "transcript_access",
        "shared_writable_worktree",
        "reviewer_edited",
        "unresolved_findings",
        "security_blockers",
        "pr_open",
        "pr_draft",
        "final_statuses_successful",
    ):
        _bool(getattr(o, name))
    _app(o.author_app, o.author_installation)
    _app(o.reviewer_app, o.reviewer_installation)
    groups = (
        (h.contributors, Contributor),
        (o.contributors, Contributor),
        (o.linked_issues, LinkedIssue),
        (o.checks, CheckRun),
        (o.reviews, ReviewRecord),
        (o.threads, Thread),
    )
    for values, cls in groups:
        _tuple(values, cls)
    _need(sum(len(v) for v, _ in groups[1:]) <= MAX_RECORDS)
    for c in h.contributors + o.contributors:
        _need(publisher.hex_digest(c.job_id) and evidence.sha(c.revision))
        _need(type(c.worker) is Worker)
        c.worker.validate()
        _app(c.app, c.installation)
    for values in (h.contributors, o.contributors):
        keys = [(c.job_id, c.revision, c.worker) for c in values]
        _need(len(set(keys)) == len(keys))
    for values, count in (
        (o.contributors, o.contributor_count),
        (o.reviews, o.review_count),
        (o.threads, o.thread_count),
        (o.checks, o.check_count),
        (o.linked_issues, o.linked_issue_count),
    ):
        _need(type(count) is int and 0 <= count <= MAX_RECORDS)
        _need(
            len({v.identifier for v in values}) == len(values)
            if values and type(values[0]) in (CheckRun, ReviewRecord, Thread)
            else True
        )
    for link in o.linked_issues:
        _need(
            all(
                issues.positive_int(v)
                for v in (link.repo_id, link.issue_id, link.number)
            )
        )
        _need(type(link.state) is str and link.state in ("open", "closed"))
    for run in o.checks:
        _need(issues.positive_int(run.identifier))
        _need(type(run.check) is evidence.Check)
        replace(run.check)
        _need(evidence.sha(run.commit_sha))
        _need(run.checkout_sha is None or evidence.sha(run.checkout_sha))
        _need(
            type(run.status) is str
            and run.status in ("completed", "pending", "queued", "in_progress")
        )
        _need(
            type(run.conclusion) is str
            and run.conclusion
            in ("success", "failure", "cancelled", "pending", "skipped", "neutral")
        )
        _time(run.completed_at)
    for record in o.reviews:
        _need(issues.positive_int(record.identifier))
        _need(type(record.author) is evidence.Principal)
        replace(record.author)
        _need(evidence.sha(record.commit_sha))
        _bool(record.blocking)
    for thread in o.threads:
        _need(issues.positive_int(thread.identifier))
        _bool(thread.resolved)
    # Bound individual fields/collections before canonical serialization.
    _need(len(publisher.encoded(asdict(h))) <= MAX_DESCRIPTOR)
    _need(len(publisher.encoded(asdict(o))) <= MAX_OBSERVATIONS)


def _independent(h, o):
    a = h.assignment
    _need(h.contributors and o.contributors == h.contributors)
    _need(h.implementer.agent_id == a.agent_id)
    _need(
        any(
            c.worker == h.implementer
            and c.app == a.coding_app
            and c.installation == a.installation
            and c.job_id == h.job_id
            and c.revision == h.policy.head_sha
            for c in h.contributors
        )
    )
    _need(o.reviewer == h.reviewer)
    _need(o.author_app == a.coding_app and o.author_installation == a.installation)
    _need(o.reviewer_app == a.reviewer_app)
    _need(o.reviewer_installation.account == a.installation.account)
    _need(o.reviewer_installation.account_type == a.installation.account_type)
    _need(o.reviewer_installation.identifier == a.reviewer_app.installation_id)
    _need(not any((o.transcript_access, o.shared_writable_worktree, o.reviewer_edited)))
    for c in h.contributors:
        for field in (
            "worker_id",
            "agent_id",
            "session_id",
            "context_id",
            "worktree_id",
        ):
            _need(getattr(h.reviewer, field) != getattr(c.worker, field))
        # Check historical Apps as well as the current assignment; role rotation
        # cannot erase a contributing worker, principal or installation.
        _need(c.app.app_id != a.reviewer_app.app_id)
        _need(c.app.slug.casefold() != a.reviewer_app.slug.casefold())
        _need(c.app.bot.identifier != a.reviewer_app.bot.identifier)
        _need(c.app.bot.login.casefold() != a.reviewer_app.bot.login.casefold())
        _need(c.app.installation_id != a.reviewer_app.installation_id)
        _need(c.installation.account == a.installation.account)
        _need(c.installation.account_type == a.installation.account_type)


def assess(handoff, observations=None, *, now):
    """Deterministic advice only. No I/O, callbacks, clock or mutable global state.

    Unsupported/missing qualification is INSUFFICIENT_EVIDENCE. Malformed,
    conflicting, stale, partial or unsafe evidence is BLOCKED. No exception text
    or unvalidated input is returned. No live provenance source is supported.
    """
    insufficient = Result("INSUFFICIENT_EVIDENCE", "qualified_fixture_required")
    if observations is None:
        return insufficient
    try:
        h, o = handoff, observations
        _validate(h, o, now)
        if o.provenance != "synthetic_trusted_caller" or not o.qualified:
            return insufficient
        if h.policy.project is None:
            return Result("INSUFFICIENT_EVIDENCE", "project_context_unsupported")
        a, p = h.assignment, h.policy
        a.for_project(p.project)
        _need(h.job_id == a.assignment_id and p.purpose == "reviewed")
        _need(p.head_sha != p.base_sha)
        _need(h.issued_at <= now < h.expires_at)
        _need(a.issued_at <= now < a.expires_at)
        _need(issues.timestamp(a.admission.scope_revision).timestamp() <= now)
        _need(
            all(
                0 <= now - t <= MAX_AGE
                for t in (o.observed_at, o.source_observed_at, o.ci_observed_at)
            )
        )
        _need(
            o.source_observed_at <= o.observed_at and o.ci_observed_at <= o.observed_at
        )
        _need(
            all(
                (
                    o.complete,
                    o.contributors_complete,
                    o.reviews_complete,
                    o.threads_complete,
                    o.checks_complete,
                    o.links_complete,
                    o.stable,
                    o.fresh_worktree,
                    o.fresh_session,
                    o.isolated_context,
                    o.independent_source,
                )
            )
        )
        _need(o.handoff_sha256 == digest(h))
        _need(o.project_sha256 == p.project.digest)
        _need((o.source_sha256, o.ci_sha256) == (h.source_sha256, h.ci_sha256))
        _need(
            (o.repo_id, o.repository, o.pull_request)
            == (p.admission.repo_id, p.admission.repository, p.pull_request)
        )
        _need(
            (o.head_sha, o.base_sha, o.merge_sha)
            == (p.head_sha, p.base_sha, p.merge_sha)
        )
        _need(o.head_repo_id == o.base_repo_id == p.admission.repo_id)
        _need(o.base_branch == p.base_branch)
        _need(o.merge_parents == (p.base_sha, p.head_sha))
        _need(o.pull_request_id == h.pull_request_id)
        _need(o.pr_open and o.pr_draft)
        _need(
            o.linked_issues
            == (
                LinkedIssue(
                    p.admission.repo_id, p.admission.issue_id, p.admission.issue, "open"
                ),
            )
        )
        for values, count in (
            (o.contributors, o.contributor_count),
            (o.reviews, o.review_count),
            (o.threads, o.thread_count),
            (o.checks, o.check_count),
            (o.linked_issues, o.linked_issue_count),
        ):
            _need(len(values) == count)
        _independent(h, o)
        _need(not o.unresolved_findings and not o.security_blockers)
        _need(all(t.resolved for t in o.threads))
        _need(all(not r.blocking for r in o.reviews))
        _need(o.final_statuses_successful)
        _need({c.name for c in p.checks} == {"checks", "lifecycle"})
        expected = {
            (sha, check) for sha in (p.head_sha, p.merge_sha) for check in p.checks
        }
        _need(len(o.checks) == len(expected))
        _need({(r.commit_sha, r.check) for r in o.checks} == expected)
        for run in o.checks:
            _need(run.checkout_sha == run.commit_sha)
            _need(run.status == "completed" and run.conclusion == "success")
            _need(0 <= now - run.completed_at <= MAX_AGE)
            _need(run.completed_at <= o.ci_observed_at)
        return Result(
            "ELIGIBLE_OFFLINE_FIXTURE",
            "independent_fixture_only",
            digest(h),
            digest(o),
            p.head_sha,
            p.base_sha,
            p.merge_sha,
        )
    except Exception:
        return Result("BLOCKED", "handoff_evidence_blocked")
