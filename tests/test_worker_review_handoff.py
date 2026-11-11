"""CP-04 synthetic trusted-caller facts only, without Git, Apps or accounts."""

import builtins
import socket
import subprocess
from dataclasses import FrozenInstanceError, asdict, fields, replace

import pytest

from agent_platform import codex_assignment as assignment
from agent_platform import github_evidence as evidence
from agent_platform import publisher
from agent_platform import review_comment as review
from agent_platform import worker_review_handoff as handoff

NOW = 1800000000
HEAD, BASE, MERGE = (c * 40 for c in "abc")


def worker(number):
    return handoff.Worker(
        f"worker0{number}",
        f"agent-{number}",
        str(number) * 64,
        str(number + 2) * 64,
        str(number + 4) * 64,
    )


def app(number):
    return review.AppIdentity(
        100 + number,
        f"worker-{number}",
        200 + number,
        evidence.Principal(20, "registrar"),
        evidence.Principal(300 + number, f"worker-{number}[bot]"),
    )


def fixture(reverse=False):
    """Separate assignment/candidate and lineage when roles rotate."""
    owner = evidence.Principal(10, "example")
    implementer, reviewer = (
        (worker(2), worker(1)) if reverse else (worker(1), worker(2))
    )
    coding, reviewing = (app(2), app(1)) if reverse else (app(1), app(2))
    installation = review.InstallationIdentity(
        coding.installation_id, owner, "Organization"
    )
    reviewer_installation = replace(installation, identifier=reviewing.installation_id)
    job = "2" * 64 if reverse else "1" * 64
    head = "d" * 40 if reverse else HEAD
    pin = publisher.Admission(
        12, "example/project", 92, 192, "a" * 64, "2026-11-01T00:00:00Z", "b" * 64, BASE
    )
    checks = (
        evidence.Check(33, "github-actions", "checks"),
        evidence.Check(33, "github-actions", "lifecycle"),
    )
    a = assignment.CodexAssignment(
        pin,
        "main",
        implementer.agent_id,
        job,
        "c" * 64,
        NOW - 10,
        NOW + 290,
        coding,
        installation,
        reviewing,
    )
    project = evidence.TargetProject(
        "d" * 64,
        pin,
        owner,
        "Organization",
        "main",
        head,
        101,
        checks,
        "/synthetic/source",
        "e" * 64,
        coding.bot,
        (reviewing.bot,),
        review.publication_context(reviewing, reviewer_installation, coding.bot),
    )
    policy = evidence.Policy(
        pin, 101, head, BASE, "reviewed", (reviewing.bot,), checks, MERGE, project
    )
    contributors = (handoff.Contributor(job, head, implementer, coding, installation),)
    h = handoff.Handoff(
        job,
        201,
        a,
        policy,
        implementer,
        reviewer,
        contributors,
        "f" * 64,
        "0" * 64,
        NOW - 10,
        NOW + 290,
    )
    runs = tuple(
        handoff.CheckRun(i + 400, check, sha, sha, "completed", "success", NOW - 2)
        for i, (sha, check) in enumerate(
            (sha, check) for sha in (head, MERGE) for check in checks
        )
    )
    o = handoff.Observations(
        handoff_sha256=handoff.digest(h),
        project_sha256=project.digest,
        source_sha256=h.source_sha256,
        ci_sha256=h.ci_sha256,
        repo_id=12,
        repository=pin.repository,
        head_repo_id=12,
        base_repo_id=12,
        base_branch="main",
        pull_request=101,
        pull_request_id=201,
        head_sha=head,
        base_sha=BASE,
        merge_sha=MERGE,
        merge_parents=(BASE, head),
        author_app=coding,
        author_installation=installation,
        reviewer_app=reviewing,
        reviewer_installation=reviewer_installation,
        reviewer=reviewer,
        linked_issues=(handoff.LinkedIssue(12, 192, 92, "open"),),
        checks=runs,
        reviews=(),
        threads=(),
        contributors=contributors,
        contributor_count=1,
        review_count=0,
        thread_count=0,
        check_count=4,
        linked_issue_count=1,
        observed_at=NOW,
        source_observed_at=NOW - 1,
        ci_observed_at=NOW - 1,
        qualified=True,
        complete=True,
        contributors_complete=True,
        reviews_complete=True,
        threads_complete=True,
        checks_complete=True,
        links_complete=True,
        stable=True,
        fresh_worktree=True,
        fresh_session=True,
        isolated_context=True,
        independent_source=True,
        transcript_access=False,
        shared_writable_worktree=False,
        reviewer_edited=False,
        unresolved_findings=False,
        security_blockers=False,
        pr_open=True,
        pr_draft=True,
        final_statuses_successful=True,
    )
    return h, o


def assess(h, o, now=NOW):
    before = asdict(h), asdict(o)
    result = handoff.assess(h, o, now=now)
    assert (asdict(h), asdict(o)) == before
    for field in fields(result):
        if field.name.endswith("_authorized") or field.name == "launch_allowed":
            assert getattr(result, field.name) is False
    assert result.status in {
        "ELIGIBLE_OFFLINE_FIXTURE",
        "INSUFFICIENT_EVIDENCE",
        "BLOCKED",
    }
    return result


def rebind(h, o, **changes):
    h = replace(h, **changes)
    return h, replace(
        o,
        handoff_sha256=handoff.digest(h),
        contributors=h.contributors,
        contributor_count=len(h.contributors),
    )


@pytest.mark.parametrize("reverse", [False, True])
def test_rotating_roles_on_separate_candidates(reverse):
    h, o = fixture(reverse)
    result = assess(h, o)
    assert result.status == "ELIGIBLE_OFFLINE_FIXTURE"
    assert result == assess(h, o)
    assert result.head_sha == h.policy.head_sha
    assert result.base_sha == BASE and result.merge_sha == MERGE
    assert result.handoff_sha256 == handoff.digest(h)
    with pytest.raises(FrozenInstanceError):
        result.comment_authorized = True
    for value in (h, o, h.reviewer, h.contributors[0], o.checks[0]):
        assert not hasattr(value, "__dict__")


@pytest.mark.parametrize(
    "field", ["worker_id", "agent_id", "session_id", "context_id", "worktree_id"]
)
def test_shared_contributor_identity_blocks(field):
    h, o = fixture()
    reviewer = replace(h.reviewer, **{field: getattr(h.implementer, field)})
    h, o = rebind(h, o, reviewer=reviewer)
    o = replace(o, reviewer=reviewer)
    assert assess(h, o).status == "BLOCKED"


def test_self_review_and_both_workers_contributed():
    h, o = fixture()
    h, o = rebind(h, o, reviewer=h.implementer)
    assert assess(h, replace(o, reviewer=h.reviewer)).status == "BLOCKED"
    h, o = fixture()
    historical = handoff.Contributor(
        "3" * 64, "d" * 40, h.reviewer, o.reviewer_app, o.reviewer_installation
    )
    h, o = rebind(h, o, contributors=h.contributors + (historical,))
    assert assess(h, o).status == "BLOCKED"


@pytest.mark.parametrize(
    "collision", ["worker", "agent", "app", "bot_id", "login", "installation"]
)
def test_historical_contributor_and_app_rotation(collision):
    h, o = fixture()
    old_app = app(3)
    old_worker = worker(3)
    if collision == "worker":
        old_worker = replace(old_worker, worker_id=h.reviewer.worker_id)
    elif collision == "agent":
        old_worker = replace(old_worker, agent_id=h.reviewer.agent_id)
    elif collision == "app":
        old_app = replace(old_app, app_id=o.reviewer_app.app_id)
    elif collision == "bot_id":
        old_app = replace(
            old_app, bot=replace(old_app.bot, identifier=o.reviewer_app.bot.identifier)
        )
    elif collision == "login":
        old_app = replace(
            old_app,
            slug=o.reviewer_app.slug.upper(),
            bot=replace(old_app.bot, login=o.reviewer_app.slug.upper() + "[bot]"),
        )
    else:
        old_app = replace(old_app, installation_id=o.reviewer_app.installation_id)
    old_install = replace(o.author_installation, identifier=old_app.installation_id)
    old = handoff.Contributor("9" * 64, "e" * 40, old_worker, old_app, old_install)
    h, o = rebind(h, o, contributors=h.contributors + (old,))
    assert assess(h, o).status == "BLOCKED"


@pytest.mark.parametrize("field", ["author_app", "reviewer_app"])
@pytest.mark.parametrize("change", ["app_id", "bot", "owner", "installation_id"])
def test_observed_app_and_actual_author_mismatch(field, change):
    h, o = fixture()
    original = getattr(o, field)
    value = {
        "app_id": 999,
        "bot": replace(original.bot, identifier=999),
        "owner": evidence.Principal(99, "other"),
        "installation_id": 999,
    }[change]
    o = replace(o, **{field: replace(original, **{change: value})})
    assert assess(h, o).status == "BLOCKED"


@pytest.mark.parametrize("field", ["author_installation", "reviewer_installation"])
@pytest.mark.parametrize("change", ["identifier", "account", "account_type"])
def test_installation_account_mismatch(field, change):
    h, o = fixture()
    value = {
        "identifier": 999,
        "account": evidence.Principal(99, "other"),
        "account_type": "User",
    }[change]
    o = replace(o, **{field: replace(getattr(o, field), **{change: value})})
    assert assess(h, o).status == "BLOCKED"


@pytest.mark.parametrize(
    "field,value",
    [
        ("head_sha", "d" * 40),
        ("base_sha", "d" * 40),
        ("merge_sha", "d" * 40),
        ("merge_parents", (HEAD, BASE)),
        ("merge_parents", (BASE,)),
        ("head_repo_id", 99),
        ("base_repo_id", 99),
        ("base_branch", "other"),
        ("repo_id", 99),
        ("repository", "foreign/project"),
        ("pull_request", 99),
        ("pull_request_id", 99),
        ("project_sha256", "9" * 64),
        ("source_sha256", "9" * 64),
        ("ci_sha256", "9" * 64),
        ("handoff_sha256", "9" * 64),
        ("contributor_count", 2),
        ("check_count", 5),
        ("review_count", 1),
        ("thread_count", 1),
        ("linked_issue_count", 2),
        ("checks", ()),
        ("contributors", ()),
        ("observed_at", NOW - 301),
        ("source_observed_at", NOW - 301),
        ("ci_observed_at", NOW - 301),
        ("observed_at", NOW + 1),
        ("source_observed_at", NOW + 1),
        ("ci_observed_at", NOW + 1),
    ],
)
def test_stale_conflicting_missing_and_partial_facts(field, value):
    h, o = fixture()
    assert assess(h, replace(o, **{field: value})).status == "BLOCKED"


@pytest.mark.parametrize(
    "field",
    [
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
        "pr_open",
        "pr_draft",
        "final_statuses_successful",
    ],
)
def test_incomplete_pagination_and_missing_isolation(field):
    h, o = fixture()
    assert assess(h, replace(o, **{field: False})).status == "BLOCKED"


@pytest.mark.parametrize(
    "field",
    [
        "transcript_access",
        "shared_writable_worktree",
        "reviewer_edited",
        "unresolved_findings",
        "security_blockers",
    ],
)
def test_prohibited_access_edits_and_blockers(field):
    h, o = fixture()
    assert assess(h, replace(o, **{field: True})).status == "BLOCKED"


@pytest.mark.parametrize(
    "change",
    [
        {"status": "pending"},
        {"status": "in_progress"},
        {"conclusion": "failure"},
        {"conclusion": "skipped"},
        {"checkout_sha": None},
        {"checkout_sha": BASE},
        {"commit_sha": BASE},
        {"completed_at": NOW - 301},
        {"completed_at": NOW + 1},
        {"check": evidence.Check(99, "github-actions", "checks")},
        {"check": evidence.Check(33, "impostor", "checks")},
    ],
)
@pytest.mark.parametrize("index", [0, 2])
def test_ci_requires_actual_checkout_success_app_and_freshness(change, index):
    h, o = fixture()
    runs = list(o.checks)
    runs[index] = replace(runs[index], **change)
    assert assess(h, replace(o, checks=tuple(runs))).status == "BLOCKED"


@pytest.mark.parametrize(
    "links",
    [
        (),
        (handoff.LinkedIssue(99, 192, 92, "open"),),
        (handoff.LinkedIssue(12, 192, 92, "closed"),),
        (handoff.LinkedIssue(12, 193, 93, "open"),),
        (
            handoff.LinkedIssue(12, 192, 92, "open"),
            handoff.LinkedIssue(12, 193, 93, "open"),
        ),
    ],
)
def test_single_same_repository_linked_open_issue(links):
    h, o = fixture()
    assert (
        assess(h, replace(o, linked_issues=links, linked_issue_count=len(links))).status
        == "BLOCKED"
    )


def test_review_and_thread_inventory():
    h, o = fixture()
    record = handoff.ReviewRecord(1, evidence.Principal(44, "observer"), HEAD, False)
    o = replace(
        o,
        reviews=(record,),
        review_count=1,
        threads=(handoff.Thread(2, True),),
        thread_count=1,
    )
    assert assess(h, o).status == "ELIGIBLE_OFFLINE_FIXTURE"
    assert (
        assess(h, replace(o, reviews=(replace(record, blocking=True),))).status
        == "BLOCKED"
    )
    assert (
        assess(h, replace(o, threads=(handoff.Thread(2, False),))).status == "BLOCKED"
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", 2),
        ("schema_version", True),
        ("complete", 1),
        ("observed_at", True),
        ("observed_at", float("nan")),
        ("observed_at", float("inf")),
        ("observed_at", 2**63),
        ("repo_id", True),
        ("thread_count", True),
        ("thread_count", 129),
        ("checks", []),
        ("repository", "x" * 100000),
    ],
)
def test_exact_types_bounds_and_unknown_version(field, value):
    h, o = fixture()
    assert assess(h, replace(o, **{field: value})).status == "BLOCKED"


def test_unknown_fields_candidate_claims_and_unsupported_live_source():
    h, o = fixture()
    with pytest.raises(TypeError):
        handoff.Observations(**asdict(o), extra="model authority")
    assert handoff.assess(asdict(h), asdict(o), now=NOW).status == "BLOCKED"
    assert assess(h, replace(o, qualified=False)).status == "INSUFFICIENT_EVIDENCE"
    assert (
        assess(h, replace(o, provenance="live_github")).status
        == "INSUFFICIENT_EVIDENCE"
    )
    assert handoff.assess(h, now=NOW).status == "INSUFFICIENT_EVIDENCE"
    h = replace(h, policy=replace(h.policy, project=None))
    assert assess(h, o).reason == "project_context_unsupported"


def test_duplicates_and_record_overflow():
    h, o = fixture()
    assert assess(h, replace(o, checks=o.checks + (o.checks[0],))).status == "BLOCKED"
    conflicting = replace(o.checks[0], checkout_sha=BASE)
    assert assess(h, replace(o, checks=o.checks + (conflicting,))).status == "BLOCKED"
    for count in (128, 129):
        threads = tuple(handoff.Thread(i + 1, True) for i in range(count))
        assert (
            assess(h, replace(o, threads=threads, thread_count=count)).status
            == "BLOCKED"
        )
    h, o = rebind(h, o, contributors=h.contributors * 2)
    assert assess(h, o).status == "BLOCKED"


def test_descriptor_bound_and_expiry():
    h, o = fixture()
    assert len(publisher.encoded(asdict(h))) <= handoff.MAX_DESCRIPTOR
    old = h.contributors[0]
    contributors = tuple(replace(old, job_id=f"{i:064x}") for i in range(20))
    h, o = rebind(h, o, contributors=contributors)
    assert len(publisher.encoded(asdict(h))) > handoff.MAX_DESCRIPTOR
    assert assess(h, o).status == "BLOCKED"
    h, o = fixture()
    for changes in (
        {"expires_at": NOW + 301},
        {"issued_at": NOW + 1},
        {"schema_version": True},
        {"schema_version": 2},
        {"pull_request_id": True},
    ):
        other, facts = rebind(h, o, **changes)
        assert assess(other, facts).status == "BLOCKED"
    assert assess(h, o, NOW + 290).status == "BLOCKED"
    assert assess(h, o, True).status == "BLOCKED"


def test_all_paths_without_io_or_model_calls(monkeypatch):
    h, o = fixture()
    cases = (o, replace(o, qualified=False), replace(o, reviewer_edited=True), None)

    def forbidden(*args, **kwargs):
        pytest.fail("side effect attempted")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(evidence, "collect", forbidden)
    monkeypatch.setattr(review, "publish", forbidden)
    monkeypatch.setattr(assignment, "advise", forbidden)
    for facts in cases:
        result = handoff.assess(h, facts, now=NOW)
        assert result.status in {
            "ELIGIBLE_OFFLINE_FIXTURE",
            "BLOCKED",
            "INSUFFICIENT_EVIDENCE",
        }
        assert not result.review_authorized and not result.comment_authorized
        assert "worker" not in repr(result)


def test_exact_record_and_freshness_boundaries():
    h, o = fixture()
    threads = tuple(handoff.Thread(i + 1, True) for i in range(122))
    o = replace(o, threads=threads, thread_count=122)
    assert assess(h, o).status == "ELIGIBLE_OFFLINE_FIXTURE"
    o = replace(o, threads=threads + (handoff.Thread(123, True),), thread_count=123)
    assert assess(h, o).status == "BLOCKED"
    h, o = fixture()
    o = replace(
        o,
        observed_at=NOW - 300,
        source_observed_at=NOW - 300,
        ci_observed_at=NOW - 300,
        checks=tuple(replace(r, completed_at=NOW - 300) for r in o.checks),
    )
    assert assess(h, o).status == "ELIGIBLE_OFFLINE_FIXTURE"


def test_policy_changes_cannot_reuse_observations():
    h, o = fixture()
    for policy in (
        replace(h.policy, head_sha="d" * 40, project=None),
        replace(
            h.policy, project=replace(h.policy.project, authorization_sha256="8" * 64)
        ),
    ):
        other = replace(h, policy=policy)
        assert assess(other, o).status != "ELIGIBLE_OFFLINE_FIXTURE"
    h, o = rebind(h, o, source_sha256="8" * 64)
    assert assess(h, o).status == "BLOCKED"


def test_contributor_history_cannot_drop_current_implementation():
    h, o = fixture()
    other = replace(h.contributors[0], revision="d" * 40)
    h, o = rebind(h, o, contributors=(other,))
    assert assess(h, o).status == "BLOCKED"


def test_redaction_and_invalid_nested_values():
    h, o = fixture()
    dangerous = "untrusted private transcript credential text"
    result = assess(h, replace(o, provenance=dangerous))
    assert dangerous not in repr(result)
    assert result.handoff_sha256 is None
    for run in (
        replace(o.checks[0], identifier=True),
        replace(o.checks[0], completed_at=True),
    ):
        assert assess(h, replace(o, checks=(run,) + o.checks[1:])).status == "BLOCKED"
    assert handoff.assess(h, {"secret": dangerous}, now=NOW).status == "BLOCKED"
