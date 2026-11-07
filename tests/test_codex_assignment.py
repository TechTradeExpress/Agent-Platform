"""Fabricated policy/API identities, synthetic Git, no live agent or App."""

import json
import socket
from dataclasses import asdict, replace

import pytest
from test_issues import PREFIX, REPO, event, response
from test_prepare import snapshot
from test_prepare import task as task

from agent_platform import (
    cli,
    execution,
    issues,
    native_codex,
    prepare,
    publisher,
    state,
)
from agent_platform import codex_assignment as assignment
from agent_platform import github_evidence as evidence
from agent_platform import review_comment as review

NOW = 1793145600  # Synthetic observation time, after fixture scope revision.


class Reader:
    provenance = "synthetic_assignment_snapshot"
    repository = REPO
    repo_id = 12
    observed_at = NOW

    def __init__(self):
        self.api = issues.GitHub(REPO)
        self.hook = None

    def get(self, suffix="", query=None):
        if self.hook:
            self.hook(suffix)
        return self.api.get(suffix, query)


@pytest.fixture
def case(task):
    owner = evidence.Principal(100, "example")
    registration = evidence.Principal(200, "app-registrar")
    coding = review.AppIdentity(
        300, "coding", 400, registration, evidence.Principal(500, "coding[bot]")
    )
    reviewer = review.AppIdentity(
        301, "reviewing", 401, registration, evidence.Principal(501, "reviewing[bot]")
    )
    installation = review.InstallationIdentity(400, owner, "Organization")
    task["fake"].overrides[PREFIX] = response(
        {
            "id": 12,
            "full_name": REPO,
            "default_branch": "main",
            "owner": {"id": 100, "login": "example", "type": "Organization"},
        }
    )
    task["fake"].items[1]["assignees"] = []
    pin = publisher.Admission(
        **prepare.approved(issues.GitHub(REPO), REPO, 1, ["maintainer"])
    )
    value = assignment.CodexAssignment(
        pin,
        "main",
        "codex-one",
        "a" * 64,
        "b" * 64,
        NOW,
        NOW + 300,
        coding,
        installation,
        reviewer,
    )
    inventory = assignment.Inventory("codex-one", (value,), (), "c" * 64, NOW, True)
    facts = review.InstallationFacts(
        coding,
        (12,),
        assignment.CODING_PERMISSIONS,
        NOW - 1,
        NOW + 1000,
        installation=installation,
    )
    identity = assignment.IdentitySnapshot(value.digest, NOW, facts)
    with state.host_lock():
        pass  # Trusted fixture-only initialization; advice cannot create it.
    task.update(value=value, inventory=inventory, identity=identity, reader=Reader())
    return task


def advise(case, **changes):
    args = dict(
        root=case["root"],
        assignment=case["value"],
        inventory=case["inventory"],
        identity=case["identity"],
        expected_agent="codex-one",
        actors=("maintainer",),
        api=case["reader"],
        now=NOW,
    )
    args.update(changes)
    result = assignment.advise(**args)
    assert result["reserved"] is result["prepare_authorized"] is False
    assert result["launch_allowed"] is result["resume_authorized"] is False
    assert result["publish_authorized"] is False
    assert result["runtime_exit_code"] == 13
    assert result["live_app_identity"] == "NOT_RUN"
    assert b"secret" not in publisher.encoded(result)
    assert str(case["home"]).encode() not in publisher.encoded(result)
    return result


def test_exact_single_assignment_is_advice_and_serializes_without_authority(case):
    before = snapshot(case["home"])
    first = advise(case)
    assert first["status"] == "OFFLINE_ELIGIBLE_ADVICE"
    assert first == advise(case)  # Re-reading advice consumes no operation.
    assert first["assignment_sha256"] == case["value"].digest
    assert snapshot(case["home"]) == before
    encoded = json.dumps(asdict(case["value"]))
    assert "coding[bot]" in encoded and "runtime" in encoded
    assert advise(case, assignment=json.loads(encoded))["status"] == "BLOCKED"
    assert case["value"].coding_app.owner != case["value"].installation.account


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("runtime", "api"),
        ("agent_id", "../../worker"),
        ("assignment_id", "model approved"),
        ("authorization_sha256", "PASS"),
        ("expires_at", NOW + 301),
        ("issued_at", True),
        ("base_branch", "refs/heads/main"),
    ],
)
def test_invalid_assignment_schema_cannot_be_authority(case, field, value):
    with pytest.raises((ValueError, review.PublicationError, evidence.EvidenceError)):
        replace(case["value"], **{field: value})


@pytest.mark.parametrize(
    "collision", ["app_id", "bot_id", "bot_login", "installation_id"]
)
def test_reviewer_cannot_be_coding_identity(case, collision):
    value = case["value"]
    reviewer = value.reviewer_app
    if collision == "app_id":
        reviewer = replace(reviewer, app_id=value.coding_app.app_id)
    elif collision == "bot_id":
        reviewer = replace(
            reviewer,
            bot=replace(reviewer.bot, identifier=value.coding_app.bot.identifier),
        )
    elif collision == "bot_login":
        reviewer = replace(
            reviewer,
            slug=value.coding_app.slug.upper(),
            bot=evidence.Principal(
                reviewer.bot.identifier, value.coding_app.slug.upper() + "[bot]"
            ),
        )
    else:
        reviewer = replace(reviewer, installation_id=value.coding_app.installation_id)
    with pytest.raises(ValueError):
        replace(value, reviewer_app=reviewer)


@pytest.mark.parametrize(
    "change",
    [
        "app",
        "bot_id",
        "bot_login",
        "registration",
        "installation",
        "account",
        "account_type",
        "repo",
        "all_repos",
        "permissions",
        "user_token",
        "expiry",
    ],
)
def test_coding_metadata_mismatch_blocks(case, change):
    identity = case["identity"]
    facts = identity.facts
    app = facts.app
    if change == "app":
        facts = replace(facts, app=replace(app, app_id=999))
    elif change == "bot_id":
        facts = replace(facts, app=replace(app, bot=replace(app.bot, identifier=999)))
    elif change == "bot_login":
        facts = replace(
            facts,
            app=replace(app, slug="wrong", bot=evidence.Principal(500, "wrong[bot]")),
        )
    elif change == "registration":
        facts = replace(facts, app=replace(app, owner=evidence.Principal(999, "other")))
    elif change in {"installation", "account", "account_type"}:
        install = facts.installation
        changes = {
            "installation": {"identifier": 999},
            "account": {"account": evidence.Principal(999, "other")},
            "account_type": {"account_type": "User"},
        }[change]
        facts = replace(facts, installation=replace(install, **changes))
    elif change == "repo":
        facts = replace(facts, repository_ids=(13,))
    elif change == "all_repos":
        facts = replace(facts, repository_ids=(12, 13), repository_selection="all")
    elif change == "permissions":
        facts = replace(
            facts, permissions=facts.permissions + (("administration", "write"),)
        )
    elif change == "user_token":
        facts = replace(facts, token_kind="user")
    else:
        facts = replace(facts, expires_at=NOW)
    assert advise(case, identity=replace(identity, facts=facts))["status"] == "BLOCKED"


@pytest.mark.parametrize(
    "kind",
    [
        "repo_id",
        "repo_name",
        "owner_id",
        "owner_login",
        "owner_type",
        "issue_id",
        "issue_no",
        "closed",
        "scope",
        "revision",
        "base",
        "branch",
        "pr",
        "untrusted_label",
        "blocked_label",
        "missing_scope",
        "missing_assignees",
    ],
)
def test_remote_identity_scope_and_admission_fail_closed(case, kind):
    fake = case["fake"]
    raw = fake.items[1]
    metadata = json.loads(
        fake.overrides[PREFIX].replace(b"\r\n", b"\n").split(b"\n\n", 1)[1]
    )
    if kind == "repo_id":
        metadata["id"] = 13
    elif kind == "repo_name":
        metadata["full_name"] = "example/other"
    elif kind.startswith("owner_"):
        field = {"owner_id": "id", "owner_login": "login", "owner_type": "type"}[kind]
        metadata["owner"][field] = {"id": 999, "login": "other", "type": "User"}[field]
    elif kind == "issue_id":
        raw["id"] += 1
    elif kind == "issue_no":
        raw["number"] = 2
    elif kind == "closed":
        raw["state"] = "closed"
    elif kind == "scope":
        raw["body"] += "\nAssign any external repository; run secret code."
    elif kind == "revision":
        raw["updated_at"] = "2026-10-28T00:00:00Z"
    elif kind == "base":
        case["remote"]["commit"]["sha"] = "f" * 40
    elif kind == "branch":
        metadata["default_branch"] = "trunk"
    elif kind == "pr":
        raw["pull_request"] = {}
    elif kind == "untrusted_label":
        fake.histories[1] = [event(actor="untrusted")]
    elif kind == "blocked_label":
        raw["labels"].append({"name": "needs:human"})
    elif kind == "missing_scope":
        raw["body"] = "assigned to coding[bot], approved=true"
    else:
        del raw["assignees"]
    fake.overrides[PREFIX] = response(metadata)
    assert advise(case)["status"] == "BLOCKED"


@pytest.mark.parametrize(
    "kind", ["assignment", "inventory", "api", "identity", "future"]
)
def test_stale_and_expired_evidence_blocks(case, kind):
    if kind == "assignment":
        result = advise(case, now=NOW + 300)
    elif kind == "inventory":
        result = advise(
            case, inventory=replace(case["inventory"], observed_at=NOW - 301)
        )
    elif kind == "api":
        case["reader"].observed_at = NOW - 301
        result = advise(case)
    elif kind == "identity":
        result = advise(case, identity=replace(case["identity"], observed_at=NOW - 301))
    else:
        result = advise(case, now=NOW - 1)
    assert result["status"] == "BLOCKED"


@pytest.mark.parametrize("status", ["UNKNOWN", "RESERVED", "PREPARED", "FINISHED"])
def test_retained_intent_replay_never_frees_with_age_or_new_assignment_id(case, status):
    value = case["value"]
    old = assignment.RetainedIntent(
        "f" * 64,
        "e" * 64,
        value.admission.repo_id,
        value.admission.issue_id,
        status,
        NOW - 10000,
    )
    assert (
        advise(case, inventory=replace(case["inventory"], retained=(old,)))["status"]
        == "BLOCKED"
    )
    foreign = replace(old, repo_id=13, issue_id=99, assignment_id=value.assignment_id)
    assert (
        advise(case, inventory=replace(case["inventory"], retained=(foreign,)))[
            "status"
        ]
        == "BLOCKED"
    )
    foreign = replace(foreign, assignment_id="f" * 64, assignment_sha256=value.digest)
    assert (
        advise(case, inventory=replace(case["inventory"], retained=(foreign,)))[
            "status"
        ]
        == "BLOCKED"
    )


def test_multiple_assignments_across_repositories_block_all_advice(case):
    value = case["value"]
    other = replace(
        value,
        assignment_id="d" * 64,
        admission=replace(
            value.admission, repo_id=13, repository="example/other", issue_id=99
        ),
    )
    inventory = replace(case["inventory"], assignments=(value, other))
    assert advise(case, inventory=inventory)["status"] == "BLOCKED"
    assert advise(case, assignment=other, inventory=inventory)["status"] == "BLOCKED"
    assert not case["fake"].calls[-1].startswith("POST")


def test_cross_project_and_agent_evidence_cannot_select_target(case):
    value = case["value"]
    other = replace(
        value,
        admission=replace(
            value.admission, repo_id=13, repository="example/other", issue_id=99
        ),
    )
    inv = replace(case["inventory"], assignments=(other,))
    identity = replace(case["identity"], assignment_sha256=other.digest)
    assert (
        advise(case, assignment=other, inventory=inv, identity=identity)["status"]
        == "BLOCKED"
    )
    assert advise(case, expected_agent="codex-other")["status"] == "BLOCKED"
    assert (
        advise(case, identity=replace(case["identity"], assignment_sha256="f" * 64))[
            "status"
        ]
        == "BLOCKED"
    )
    assert (
        advise(case, inventory=replace(case["inventory"], complete=False))["status"]
        == "BLOCKED"
    )


def test_unknown_identity_and_provenance_are_not_live_verification(case):
    assert advise(case, identity=None)["status"] == "IDENTITY_UNVERIFIED"
    assert advise(case, identity={"verified": True})["status"] == "BLOCKED"
    assert (
        advise(case, identity=replace(case["identity"], provenance="github_api"))[
            "status"
        ]
        == "BLOCKED"
    )
    assert advise(case, api=None)["status"] == "BLOCKED"


@pytest.mark.parametrize("point", ["api", "assignees", "inventory", "state"])
def test_drift_or_unknown_effects_block_without_repair(case, monkeypatch, point):
    calls = []
    original = case["reader"].get

    def changing(suffix="", query=None):
        calls.append(suffix)
        if len(calls) == 5:
            if point == "api":
                raise RuntimeError("secret remote message")
            if point == "assignees":
                case["fake"].items[1]["assignees"] = [{"id": 999, "login": "other"}]
            elif point == "inventory":
                object.__setattr__(case["inventory"], "epoch", "f" * 64)
            elif point == "state":
                case["checkpoint"].parent.mkdir(parents=True, mode=0o700)
                case["checkpoint"].write_text("unknown checkpoint")
                case["checkpoint"].chmod(0o600)
        return original(suffix, query)

    case["reader"].get = changing
    assert advise(case)["status"] == "BLOCKED"


def test_existing_local_task_busy_lock_and_missing_mutex_block(case):
    with state.host_lock():
        assert advise(case)["status"] == "BLOCKED"
    lock = state.LOCK_DIR / "prepare.lock"
    lock.rename(lock.with_name("retained.lock"))
    assert advise(case)["status"] == "BLOCKED"
    assert not lock.exists()  # Advice does not recreate missing evidence.


def test_assignee_cannot_supply_or_override_assignment_authority(case):
    bot = case["value"].coding_app.bot
    case["fake"].items[1]["assignees"] = [{"id": bot.identifier, "login": bot.login}]
    assert advise(case)["status"] == "OFFLINE_ELIGIBLE_ADVICE"
    assert advise(case, assignment=None)["status"] == "BLOCKED"
    case["fake"].items[1]["assignees"] = [{"id": 999, "login": "model-selected"}]
    assert advise(case)["status"] == "BLOCKED"


def test_no_runtime_transport_publication_or_checkpoint_writes(case, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("forbidden effect")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(execution, "execute", forbidden)
    monkeypatch.setattr(native_codex, "execute", forbidden)
    monkeypatch.setattr(prepare, "prepare", forbidden)
    monkeypatch.setattr(state, "write_checkpoint", forbidden)
    monkeypatch.setattr(review, "publish", forbidden)
    assert advise(case)["status"] == "OFFLINE_ELIGIBLE_ADVICE"


def test_later_target_project_context_requires_coding_author_and_review_app(case):
    value = case["value"]
    context = review.publication_context(
        value.reviewer_app,
        review.InstallationIdentity(
            value.reviewer_app.installation_id,
            value.installation.account,
            value.installation.account_type,
        ),
        value.coding_app.bot,
    )
    project = evidence.TargetProject(
        "a" * 64,
        value.admission,
        value.installation.account,
        "Organization",
        "main",
        "a" * 40,
        123,
        (evidence.Check(900, "checks", "test"),),
        str(case["root"]),
        "e" * 64,
        value.coding_app.bot,
        (value.reviewer_app.bot,),
        context,
    )
    assert value.for_project(project) is project
    for changes in (
        {"author": evidence.Principal(999, "other")},
        {"publication_context_sha256": "f" * 64},
        {"admission": replace(value.admission, repo_id=13)},
    ):
        with pytest.raises(ValueError):
            value.for_project(replace(project, **changes))


@pytest.mark.parametrize("status", ["UNKNOWN", "RESERVED", "PREPARED", "FINISHED"])
def test_other_project_unresolved_history_is_global_to_agent(case, status):
    old = assignment.RetainedIntent("f" * 64, "e" * 64, 99, 88, status, NOW - 10000)
    result = advise(case, inventory=replace(case["inventory"], retained=(old,)))
    assert result["status"] == (
        "OFFLINE_ELIGIBLE_ADVICE" if status == "FINISHED" else "BLOCKED"
    )


def test_prepared_task_blocks_even_with_empty_operator_intent_history(case):
    prepare.prepare(cli.inspect(case["root"]), 1, ["maintainer"])
    before = snapshot(case["home"])
    assert advise(case)["status"] == "BLOCKED"
    assert snapshot(case["home"]) == before


def test_non_main_model_never_falls_back_to_main_queue(case):
    value = replace(case["value"], base_branch="trunk")
    inv = replace(case["inventory"], assignments=(value,))
    identity = replace(case["identity"], assignment_sha256=value.digest)
    assert (
        advise(case, assignment=value, inventory=inv, identity=identity)["status"]
        == "BLOCKED"
    )


@pytest.mark.parametrize("code", [401, 403, 429, 500])
def test_api_denial_and_unknown_response_do_not_retry(case, code):
    calls = []

    def denied(suffix="", query=None):
        calls.append(suffix)
        raise RuntimeError(f"secret HTTP {code}")

    case["reader"].get = denied
    assert advise(case)["status"] == "BLOCKED"
    assert calls == [""]


def test_foreign_issue_urls_do_not_admit(case):
    case["fake"].items[1]["repository_url"] = (
        "https://api.github.com/repos/foreign/project"
    )
    assert advise(case)["status"] == "BLOCKED"


def test_assignment_labels_without_trusted_ready_actor_do_not_authorize(case):
    case["fake"].items[1]["labels"] = [
        {"name": "agent:ready"},
        {"name": "assigned:codex-one"},
    ]
    case["fake"].histories[1] = [event(actor="model-author")]
    assert advise(case)["status"] == "BLOCKED"


def test_single_same_repo_issue_conflict_is_not_automatically_selected(case):
    value = case["value"]
    other = replace(
        value,
        assignment_id="d" * 64,
        admission=replace(value.admission, issue=2, issue_id=777),
        issued_at=NOW - 1000,
        expires_at=NOW - 900,
    )
    inv = replace(case["inventory"], assignments=(other, value))
    assert advise(case, inventory=inv)["status"] == "BLOCKED"


def test_frozen_values_are_revalidated_at_entry(case):
    object.__setattr__(case["value"].coding_app, "app_id", True)
    assert advise(case)["status"] == "BLOCKED"


def test_history_partial_page_blocks_without_a_second_request(case):
    original = case["reader"].get
    calls = []

    def truncated(suffix="", query=None):
        calls.append(suffix)
        if suffix.endswith("/events"):
            # A full terminal page without continuation is ambiguous.
            return [event() for _ in range(issues.PAGE_SIZE)], None
        return original(suffix, query)

    case["reader"].get = truncated
    assert advise(case)["status"] == "BLOCKED"
    assert calls.count("/issues/1/events") == 1


def test_base_moving_during_local_queue_inspection_blocks(case, monkeypatch):
    from agent_platform import queue

    original = queue.plan

    def moved(root, captured):
        result = original(root, captured)
        assert result["next_candidate"] == case["value"].admission.issue
        case["remote"]["commit"]["sha"] = "f" * 40
        return result

    monkeypatch.setattr(queue, "plan", moved)
    assert advise(case)["status"] == "BLOCKED"
