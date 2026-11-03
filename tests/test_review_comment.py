"""Gate A scripted snapshots/COMMENTs only; no real account, network or journal."""

import copy
import socket
import subprocess
from dataclasses import replace

import pytest
from test_github_evidence import HEAD, MERGE, NOW, STAMP
from test_github_evidence import (
    fabricated_auth_environment as fabricated_auth_environment,
)
from test_github_evidence import setup as setup
from test_issues import REPO, event
from test_prepare import snapshot
from test_prepare import task as task

from agent_platform import github_evidence as evidence
from agent_platform import issues, native_codex, publisher, state, subscription
from agent_platform import review_comment as comment


class Journal:
    provenance = "synthetic_journal"

    def __init__(self):
        self.cells, self.hook = {}, None
        self.facts = comment.JournalFacts("e" * 64, True)

    def identity(self):
        return self.facts

    def read(self, key, *, epoch=None):
        assert epoch is None or (epoch == self.facts.epoch and self.facts.complete)
        return self.cells.get(key)

    def compare_and_swap(self, key, old, new, *, epoch):
        assert epoch == self.facts.epoch and self.facts.complete
        if self.cells.get(key) != old:
            return False
        self.cells[key] = new
        if self.hook:
            self.hook(new)
        return True


class Reader:
    provenance = "synthetic_snapshot"

    def __init__(self, data, policy):
        self.data, self.policy, self.hook = data, policy, None
        self.calls = []

    def get(self, suffix="", query=None):
        self.calls.append(suffix)
        if self.hook:
            self.hook(suffix)
        pin = self.policy.admission
        if suffix == "":
            value = {
                "id": pin.repo_id,
                "full_name": pin.repository,
                "default_branch": "main",
            }
        elif suffix == "/branches/main":
            value = self.data["remote"]
        elif suffix == "/issues/1":
            value = self.data["fake"].items[1]
        elif suffix == "/issues/1/events":
            value = self.data["fake"].histories.get(1, [event()])
        else:
            value = self.data["values"][suffix]
        return copy.deepcopy(value), None

    def graph(self, connection, after=None):
        if self.hook:
            self.hook(connection)
        pr = self.data["values"]["/pulls/101"]
        nodes = copy.deepcopy(self.data[connection])
        return {
            "repository": {
                "databaseId": 12,
                "nameWithOwner": REPO,
                "pullRequest": {
                    "databaseId": 201,
                    "number": 101,
                    "headRefOid": pr["head"]["sha"],
                    "baseRefOid": pr["base"]["sha"],
                    "closingIssuesReferences"
                    if connection == "links"
                    else "reviewThreads": {
                        "totalCount": len(nodes),
                        "nodes": nodes,
                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                    },
                },
            }
        }


class Writer:
    provenance = "synthetic_review_transport"

    def __init__(self, s, env, journal):
        self.data, self.env, self.journal = s, env, journal
        self.calls, self.error, self.after, self.response_hook = [], None, None, None
        self.facts = comment.InstallationFacts(
            env.app, (12,), comment.PERMISSIONS, NOW - 1, NOW + 3000
        )

    def identity(self, **limits):
        assert limits == {"timeout": 5, "limit": 4096}
        return self.facts

    def review(self):
        return {
            "id": 501,
            "user": {
                "id": self.env.app.bot.identifier,
                "login": self.env.app.bot.login,
                "type": "Bot",
            },
            "body": self.env.body,
            "commit_id": HEAD,
            "state": "COMMENTED",
            "submitted_at": STAMP,
            "pull_request_url": f"https://api.github.com/repos/{REPO}/pulls/101",
        }

    def comment(self, request, **limits):
        assert type(request) is comment.CommentRequest
        assert request.method == "POST" and request.event == "COMMENT"
        assert request.endpoint == f"/repos/{REPO}/pulls/101/reviews"
        assert request.commit_id == HEAD and request.body == self.env.body
        assert 0 < limits["timeout"] <= 5 and limits["limit"] == 65536
        assert self.journal.read(self.env.key).state == "UNKNOWN"
        self.calls.append(request)
        if self.error:
            raise self.error
        response = self.review()
        self.data["values"]["/pulls/101/reviews"].append(copy.deepcopy(response))
        if self.after:
            self.after()
        if self.response_hook:
            self.response_hook(response)
        return response


@pytest.fixture
def case(setup):
    s = setup
    bot = evidence.Principal(22, "reviewer[bot]")
    owner = evidence.Principal(99, "example")
    policy = replace(s["policy"], reviewers=(bot,))
    app = comment.AppIdentity(88, "reviewer", 77, owner, bot)
    env = comment.Envelope(
        policy,
        evidence.Principal(21, "implementer"),
        app,
        comment.Decision.PASS,
        "Independent analysis checked the exact diff and CI.",
    )
    grant = comment.ManualAuthorization(
        env.digest,
        "c" * 64,
        "d" * 64,
        evidence.Principal(23, "operator"),
        NOW,
        NOW + 300,
        "e" * 64,
    )
    s["values"]["/pulls/101"]["base"]["repo"]["owner"] = {
        "id": 99,
        "login": "example",
        "type": "Organization",
    }
    s["values"]["/pulls/101/reviews"] = []
    journal = Journal()
    s.update(env=env, grant=grant, journal=journal, reader=Reader(s, policy))
    s["writer"] = Writer(s, env, journal)
    return s


def publish(s, **changes):
    args = dict(
        envelope=s["env"],
        authorization=s["grant"],
        reader=s["reader"],
        writer=s["writer"],
        journal=s["journal"],
        now=NOW,
    )
    args.update(changes)
    result = comment.publish(**args)
    raw = publisher.encoded(result)
    assert len(raw) < 1024 and b"SECRET_SENTINEL" not in raw
    assert result["live_app_identity"] == result["live_publication"] == "NOT_RUN"
    assert (
        result["launch_allowed"]
        is result["resume_authorized"]
        is result["publish_authorized"]
        is False
    )
    assert result["runtime_exit_code"] == 13
    return result


def test_success_has_exact_marker_post_verification_and_idempotent_rerun(case):
    s = case
    before = snapshot(s["home"]), snapshot(s["root"] / ".git")
    result = publish(s)
    assert result["status"] == "PUBLISHED_SYNTHETIC" and result["review_id"] == 501
    assert len(s["writer"].calls) == 1
    assert s["journal"].read(s["env"].key).state == "VERIFIED"
    assert publish(s)["status"] == "ALREADY_VERIFIED_SYNTHETIC"
    assert len(s["writer"].calls) == 1
    assert (snapshot(s["home"]), snapshot(s["root"] / ".git")) == before
    # Existing #49 acceptance still needs a real observed exact marker, not the
    # prepublication branch. Bot identity is now accepted without dropping pins.
    assert evidence._read(s["reader"], s["env"].policy, NOW)[1]


def test_collector_still_rejects_absent_review_before_publication(case):
    with pytest.raises(evidence.EvidenceError):
        evidence._read(case["reader"], case["env"].policy, NOW)
    assert publish(case)["status"] == "PUBLISHED_SYNTHETIC"


@pytest.mark.parametrize("login", ["reviewer[bot]", "ordinary-user"])
def test_collector_accepts_only_canonical_bot_or_user_login(login):
    assert evidence.Principal(1, login).login == login


@pytest.mark.parametrize(
    "login", ["x[bot]junk", "[bot]", "x[BOT]", "x/y[bot]", "x[bot][bot]"]
)
def test_noncanonical_bot_login_blocked(login):
    with pytest.raises(evidence.EvidenceError):
        evidence.Principal(1, login)


@pytest.mark.parametrize("bad", [None, {}, True])
def test_no_manual_authority_means_no_io(case, bad):
    assert publish(case, authorization=bad)["status"] == "BLOCKED"
    assert not case["reader"].calls and not case["writer"].calls


@pytest.mark.parametrize(
    "field,value",
    [
        ("envelope_sha256", "f" * 64),
        ("expires_at", NOW),
        ("approved_at", NOW + 1),
    ],
)
def test_stale_or_different_human_decision_blocks(case, field, value):
    # Bypass constructors only to exercise defensive boundary with an immutable
    # impossible/stale trusted object. Production has no JSON loader.
    grant = copy.copy(case["grant"])
    object.__setattr__(grant, field, value)
    assert publish(case, authorization=grant)["status"] == "BLOCKED"
    assert not case["writer"].calls


@pytest.mark.parametrize(
    "text",
    [
        "",
        "x" * 4097,
        "Agent-Platform review v1: PASS " + HEAD,
        "agent-platform REVIEW duplicate",
        "Bearer SECRET_SENTINEL",
        "ghp_abc",
        "github_pat_abc",
        "-----BEGIN PRIVATE KEY-----",
        "line\rhidden",
        "\x1b[31m",
        "token value",
        "a" * 1025,
    ],
)
def test_unbounded_duplicate_marker_control_and_sensitive_text_rejected(case, text):
    with pytest.raises(comment.PublicationError):
        replace(case["env"], summary=text)


@pytest.mark.parametrize("kind", ["id", "login"])
def test_same_or_forged_author_identity_blocks_before_post(case, kind):
    user = case["values"]["/pulls/101"]["user"]
    if kind == "id":
        user["id"] = case["env"].app.bot.identifier
    else:
        user["login"] = case["env"].app.bot.login.replace("reviewer", "REVIEWER")
    assert publish(case)["status"] == "BLOCKED"
    assert not case["writer"].calls


@pytest.mark.parametrize(
    "kind",
    [
        "repo",
        "base",
        "head",
        "draft",
        "issue",
        "link",
        "threads",
        "merge",
        "checks",
        "check_app",
        "review",
        "owner",
    ],
)
def test_remote_pr_ci_link_thread_and_actor_conditions_fail_closed(case, kind):
    s = case
    pr = s["values"]["/pulls/101"]
    if kind == "repo":
        pr["head"]["repo"]["id"] = 900
    elif kind == "base":
        pr["base"]["sha"] = "f" * 40
    elif kind == "head":
        pr["head"]["sha"] = "f" * 40
    elif kind == "draft":
        pr["draft"] = False
    elif kind == "issue":
        s["fake"].items[1]["state"] = "closed"
    elif kind == "link":
        s["links"] *= 2
    elif kind == "threads":
        s["threads"] = [{"id": "T1", "isResolved": False}]
    elif kind == "merge":
        s["values"][f"/commits/{MERGE}"]["parents"].reverse()
    elif kind == "checks":
        s["values"][f"/commits/{HEAD}/check-runs"]["check_runs"][0]["status"] = (
            "in_progress"
        )
    elif kind == "check_app":
        s["values"][f"/commits/{MERGE}/check-runs"]["check_runs"][0]["app"]["id"] = 999
    elif kind == "owner":
        pr["base"]["repo"]["owner"]["id"] = 999
    else:
        s["values"]["/pulls/101/reviews"] = [
            {**s["writer"].review(), "state": "CHANGES_REQUESTED"}
        ]
    assert publish(s)["status"] == "BLOCKED"
    assert not s["writer"].calls and not s["journal"].cells


@pytest.mark.parametrize(
    "changes",
    [
        {"token_kind": "user"},
        {"repository_ids": (12, 13)},
        {"permissions": (("contents", "write"),)},
        {"expires_at": NOW},
        {"issued_at": NOW + 1},
        {"expires_at": NOW + 3601},
        {"owner_type": "User"},
        {"repository_selection": "all"},
    ],
)
def test_installation_scope_lifetime_and_permissions_block(case, changes):
    case["writer"].facts = replace(case["writer"].facts, **changes)
    assert publish(case)["status"] == "BLOCKED"
    assert not case["writer"].calls


@pytest.mark.parametrize("where", ["reader", "writer", "journal"])
def test_live_or_unavailable_adapters_are_disabled(case, where):
    instance = case[where]
    instance.provenance = "github_api_snapshot"
    assert publish(case)["status"] == "BLOCKED"
    assert not case["writer"].calls
    assert publish(case, **{where: None})["status"] == "BLOCKED"


@pytest.mark.parametrize("code", [401, 403, 429, 500, 503])
@pytest.mark.parametrize("phase", ["preflight", "post"])
def test_api_errors_never_retry_or_leak(case, code, phase):
    def denied(*args):
        raise RuntimeError(f"HTTP {code} SECRET_SENTINEL")

    if phase == "preflight":
        case["reader"].hook = denied
    else:
        case["writer"].error = RuntimeError(f"HTTP {code} SECRET_SENTINEL")
    assert publish(case)["status"] == (
        "BLOCKED" if phase == "preflight" else "NEEDS_HUMAN"
    )
    assert len(case["writer"].calls) == (0 if phase == "preflight" else 1)
    if phase == "post":
        assert publish(case)["reason"] == "reconciliation_required"
        assert len(case["writer"].calls) == 1


def test_timeout_after_remote_write_reconciles_without_second_post_even_after_expiry(
    case,
):
    s = case

    def lost():
        raise TimeoutError("SECRET_SENTINEL unknown response")

    s["writer"].after = lost
    assert publish(s)["status"] == "NEEDS_HUMAN"
    assert s["journal"].read(s["env"].key).state == "UNKNOWN"
    assert publish(s)["reason"] == "reconciliation_required"
    assert (
        publish(s, reconcile_only=True, now=NOW + 301)["status"]
        == "RECONCILED_SYNTHETIC"
    )
    assert len(s["writer"].calls) == 1


def test_timeout_before_remote_write_stays_unknown_not_permission_to_retry(case):
    s = case
    s["writer"].error = TimeoutError("SECRET_SENTINEL")
    assert publish(s)["status"] == "NEEDS_HUMAN"
    assert publish(s, reconcile_only=True)["reason"] == "remote_outcome_unconfirmed"
    assert publish(s)["reason"] == "reconciliation_required"
    assert len(s["writer"].calls) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("state", "APPROVED"),
        ("commit_id", "f" * 40),
        ("body", "Agent-Platform review v1: PASS " + HEAD),
        ("id", True),
        ("pull_request_url", "https://example.invalid/SECRET_SENTINEL"),
    ],
)
def test_invalid_post_receipt_is_unknown_not_success(case, field, value):
    case["writer"].response_hook = lambda r: r.update({field: value})
    assert publish(case)["status"] == "NEEDS_HUMAN"
    assert case["journal"].read(case["env"].key).state == "UNKNOWN"


@pytest.mark.parametrize(
    "kind", ["bot_id", "bot_login", "bot_type", "duplicate", "wrong_body"]
)
def test_untrusted_or_duplicate_existing_review_cannot_authorize_publication(
    case, kind
):
    r = case["writer"].review()
    if kind == "bot_id":
        r["user"]["id"] = 999
    elif kind == "bot_login":
        r["user"]["login"] = "forged[bot]"
    elif kind == "bot_type":
        r["user"]["type"] = "User"
    elif kind == "wrong_body":
        r["body"] += "\nOther analysis"
    case["values"]["/pulls/101/reviews"] = (
        [r, copy.deepcopy(r)] if kind == "duplicate" else [r]
    )
    assert publish(case)["status"] == "BLOCKED"
    assert not case["writer"].calls


def test_existing_exact_comment_is_reverified_without_post(case):
    case["values"]["/pulls/101/reviews"] = [case["writer"].review()]
    assert publish(case)["status"] == "RECONCILED_SYNTHETIC"
    assert not case["writer"].calls


def test_head_drift_after_post_retains_unknown_and_no_replay(case):
    case["writer"].after = lambda: case["values"]["/pulls/101"]["head"].update(
        sha="f" * 40
    )
    assert publish(case)["status"] == "NEEDS_HUMAN"
    assert publish(case, reconcile_only=True)["status"] == "NEEDS_HUMAN"
    assert len(case["writer"].calls) == 1


def test_journal_cas_and_uncertain_confirmation_never_repost(case):
    def fail_verified(record):
        if record.state == "VERIFIED":
            raise OSError("SECRET_SENTINEL uncertain persistence")

    case["journal"].hook = fail_verified
    assert publish(case)["status"] == "NEEDS_HUMAN"
    assert publish(case)["status"] == "ALREADY_VERIFIED_SYNTHETIC"
    assert len(case["writer"].calls) == 1


def test_new_body_authorization_or_head_cannot_escape_unknown_record(case):
    case["writer"].error = TimeoutError()
    publish(case)
    grant = replace(case["grant"], decision_id="e" * 64)
    assert publish(case, authorization=grant)["status"] == "BLOCKED"
    assert len(case["writer"].calls) == 1


def test_comment_request_has_no_event_or_endpoint_override(case):
    with pytest.raises(TypeError):
        comment.CommentRequest(REPO, 101, HEAD, "body", event="APPROVE")
    with pytest.raises(TypeError):
        comment.CommentRequest(REPO, 101, HEAD, "body", endpoint="/merge")


def test_no_host_write_network_runtime_or_checkpoint(case, monkeypatch):
    def forbidden(*a, **kw):
        pytest.fail("forbidden external effect")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(state, "write_checkpoint", forbidden)
    monkeypatch.setattr(issues, "read_command", forbidden)
    assert publish(case)["status"] == "PUBLISHED_SYNTHETIC"
    assert subscription.readiness()["launch_allowed"] is False
    with pytest.raises(state.PrepareError) as exc:
        native_codex.execute({}, 1, ["maintainer"])
    assert exc.value.code == 13


@pytest.mark.parametrize(
    "field,value",
    [
        ("app_id", 999),
        ("installation_id", 999),
        ("bot", evidence.Principal(999, "reviewer[bot]")),
        ("owner", evidence.Principal(999, "example")),
    ],
)
def test_actual_installation_facts_must_match_all_expected_app_pins(case, field, value):
    app = replace(case["env"].app, **{field: value})
    case["writer"].facts = replace(case["writer"].facts, app=app)
    assert publish(case)["status"] == "BLOCKED"
    assert not case["writer"].calls


@pytest.mark.parametrize("kind", ["id", "login", "type"])
def test_wrong_post_actor_is_unknown_not_verified(case, kind):
    def forged(response):
        response["user"][{"id": "id", "login": "login", "type": "type"}[kind]] = {
            "id": 999,
            "login": "forged[bot]",
            "type": "User",
        }[kind]

    case["writer"].response_hook = forged
    assert publish(case)["status"] == "NEEDS_HUMAN"
    assert case["journal"].read(case["env"].key).state == "UNKNOWN"


def test_fail_is_comment_only_and_cannot_satisfy_pass_collector(case):
    env = replace(case["env"], decision=comment.Decision.FAIL)
    grant = replace(case["grant"], envelope_sha256=env.digest)
    case.update(env=env, grant=grant)
    case["writer"].env = env
    assert publish(case)["status"] == "PUBLISHED_SYNTHETIC"
    assert case["writer"].calls[0].event == "COMMENT"
    with pytest.raises(evidence.EvidenceError):
        evidence._read(case["reader"], env.policy, NOW)


def test_grant_expiring_during_preflight_stops_before_intent_and_post(
    case, monkeypatch
):
    clock = [0.0]
    monkeypatch.setattr(comment.time, "monotonic", lambda: clock[0])
    grant = replace(case["grant"], expires_at=NOW + 1)
    case["reader"].hook = lambda *a: clock.__setitem__(0, 2.0)
    assert publish(case, authorization=grant)["status"] == "BLOCKED"
    assert not case["writer"].calls and not case["journal"].cells


def test_concurrent_unknown_intent_is_never_a_second_post(case):
    others = []

    def contender(record):
        if record.state == "UNKNOWN":
            others.append(publish(case))

    case["journal"].hook = contender
    assert publish(case)["status"] == "PUBLISHED_SYNTHETIC"
    assert others[0]["reason"] == "reconciliation_required"
    assert len(case["writer"].calls) == 1


def test_frozen_payload_is_revalidated_before_callbacks(case):
    env = copy.copy(case["env"])
    object.__setattr__(env, "summary", "Bearer SECRET_SENTINEL")
    grant = replace(case["grant"], envelope_sha256=env.digest)
    assert publish(case, envelope=env, authorization=grant)["status"] == "BLOCKED"
    assert not case["reader"].calls and not case["writer"].calls


def test_corrupt_lost_or_failing_journal_never_initializes_or_sends(case):
    case["journal"].cells[case["env"].key] = {"secret": "untrusted fake receipt"}
    assert publish(case)["status"] == "BLOCKED"
    assert not case["writer"].calls
    assert publish(case, reconcile_only=True)["status"] == "BLOCKED"


def test_public_collector_cannot_be_changed_into_prepublication_acceptance(case):
    with pytest.raises(evidence.EvidenceError):
        evidence.collect(case["root"], case["env"].policy, api=case["reader"])
    with pytest.raises(TypeError):
        evidence.collect(
            case["root"], case["env"].policy, api=case["reader"], _before_comment=True
        )


def test_changed_app_installation_cannot_escape_retained_pr_intent(case):
    env = replace(case["env"], app=replace(case["env"].app, installation_id=999))
    assert env.key == case["env"].key
    assert env.digest != case["env"].digest


def test_existing_distinct_bot_comment_is_not_human_authorization(case):
    case["values"]["/pulls/101/reviews"] = [case["writer"].review()]
    assert publish(case, authorization=None)["status"] == "BLOCKED"
    assert not case["writer"].calls and not case["journal"].cells


@pytest.mark.parametrize(
    "facts",
    [None, comment.JournalFacts("e" * 64, False), comment.JournalFacts("f" * 64, True)],
)
def test_lost_or_replaced_journal_is_not_an_empty_authorized_store(case, facts):
    case["journal"].facts = facts
    assert publish(case)["status"] == "BLOCKED"
    assert not case["writer"].calls


def test_same_head_different_base_bound_context_is_not_the_same_review(case):
    env = replace(case["env"], policy=replace(case["env"].policy, merge_sha="c" * 40))
    assert env.body.splitlines()[0] == case["env"].body.splitlines()[0]
    assert env.body != case["env"].body
    assert env.digest != case["env"].digest
    assert publish(case, envelope=env)["status"] == "BLOCKED"
    assert not case["writer"].calls


def test_installation_expiring_during_intent_persistence_never_sends(case, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(comment.time, "monotonic", lambda: clock[0])
    case["writer"].facts = replace(case["writer"].facts, expires_at=NOW + 1)

    def delayed_intent(record):
        if record.state == "UNKNOWN":
            clock[0] = 2.0

    case["journal"].hook = delayed_intent
    assert publish(case)["status"] == "NEEDS_HUMAN"
    assert not case["writer"].calls
    assert case["journal"].read(case["env"].key).state == "UNKNOWN"


def test_uncertain_intent_persistence_never_calls_comment(case):
    def interrupted(record):
        if record.state == "UNKNOWN":
            raise OSError("SECRET_SENTINEL uncertain intent")

    case["journal"].hook = interrupted
    assert publish(case)["status"] == "NEEDS_HUMAN"
    assert not case["writer"].calls
    assert publish(case)["reason"] == "reconciliation_required"
