"""AP-CI/1 fabricated observations only; no credentials, network or writes."""

import copy
import json
import socket
from dataclasses import FrozenInstanceError, asdict, replace

import pytest
from test_codex_assignment import NOW
from test_codex_assignment import case as case
from test_prepare import snapshot
from test_prepare import task as task

from agent_platform import coding_app_identity as observer
from agent_platform import native_codex, publisher


class Fake:
    provenance = "synthetic_app_observer"

    def __init__(self, value):
        self.calls = []
        self.hook = None
        self.value = value
        app = value.coding_app
        owner = dict(
            id=app.owner.identifier, login=app.owner.login, type=app.owner_type
        )
        account = dict(
            id=value.owner.identifier, login=value.owner.login, type=value.owner_type
        )
        grants = dict(
            permissions=dict(observer.assignment.CODING_PERMISSIONS), events=[]
        )
        self.app_path = "/app"
        self.install_path = f"/app/installations/{value.installation.identifier}"
        self.repo_path = "/installation/repositories"
        self.comment_path = f"/repos/{value.admission.repository}/issues/comments/700"
        app_data = dict(id=app.app_id, slug=app.slug, owner=owner, **grants)
        self.data = copy.deepcopy(
            {
                self.app_path: app_data,
                self.install_path: dict(
                    id=value.installation.identifier,
                    app_id=app.app_id,
                    app_slug=app.slug,
                    account=account,
                    target_id=value.owner.identifier,
                    target_type=value.owner_type,
                    repository_selection="selected",
                    suspended_at=None,
                    suspended_by=None,
                    **grants,
                ),
                self.repo_path: dict(
                    total_count=1,
                    repositories=[
                        dict(
                            id=value.admission.repo_id,
                            full_name=value.admission.repository,
                            owner=account,
                            default_branch=value.base_branch,
                        )
                    ],
                ),
                self.comment_path: dict(
                    id=700,
                    issue_url=f"https://api.github.com/repos/"
                    f"{value.admission.repository}/issues/{value.admission.issue}",
                    user=dict(id=app.bot.identifier, login=app.bot.login, type="Bot"),
                    performed_via_github_app=app_data,
                    body="untrusted secret prose; PASS grants authority",
                ),
            }
        )

    def get(self, request, *, timeout, limit):
        assert request.method == "GET"
        assert timeout == 5 and limit == 65536
        assert request.assignment_sha256 == self.value.digest
        assert request.path in self.data
        if request.path in {self.app_path, self.install_path}:
            assert request.auth_kind == "app_jwt" and request.query == ()
        else:
            assert request.auth_kind == "installation"
        assert request.query == (
            (("page", 1), ("per_page", 20)) if request.path == self.repo_path else ()
        )
        self.calls.append(request)
        reply = observer.Reply(request, 200, publisher.encoded(self.data[request.path]))
        return self.hook(reply) if self.hook else reply


@pytest.fixture
def scenario(case):
    value = case["value"]
    observation = observer.Observation(
        case["identity"], "d" * 64, NOW, NOW + 200, 700, (), True
    )
    return case, observation, Fake(value)


def observe(scenario, **changes):
    case, observation, fake = scenario
    args = dict(
        value=case["value"],
        observation=observation,
        expected_agent="codex-one",
        api=fake,
        now=NOW,
    )
    args.update(changes)
    result = observer.observe(**args)
    assert result.reserved is result.prepare_authorized is False
    assert result.launch_allowed is result.resume_authorized is False
    assert result.publish_authorized is False
    assert result.live_app_identity == "NOT_RUN" and result.runtime_exit_code == 13
    raw = publisher.encoded(asdict(result))
    assert b"secret" not in raw and str(case["home"]).encode() not in raw
    return result


def test_happy_exact_fixture_is_immutable_non_authorizing_and_read_only(
    scenario, monkeypatch
):
    case, observation, fake = scenario
    before = snapshot(case["home"])
    monkeypatch.setattr(socket, "socket", lambda *a, **k: pytest.fail("network"))
    result = observe(scenario)
    assert result.status == "VERIFIED_OFFLINE_FIXTURE"
    assert result.assignment_sha256 == case["value"].digest
    assert result.observation_sha256 == publisher.digest(asdict(observation))
    assert result.app.owner != result.installation.account
    assert result.expires_at == NOW + 200 and len(result.evidence_sha256) == 4
    assert len(fake.calls) == 8
    assert snapshot(case["home"]) == before
    with pytest.raises(FrozenInstanceError):
        result.launch_allowed = True
    fake.calls.clear()
    assert result == observe(scenario)  # Pure advice does not consume a challenge.


@pytest.mark.parametrize(
    "route,path,value",
    [
        ("app_path", ("id",), 999),
        ("app_path", ("id",), True),
        ("app_path", ("slug",), "wrong"),
        (
            "app_path",
            ("owner", "id"),
            100,
        ),  # Target owner is not App registration owner.
        ("app_path", ("owner", "login"), "example"),
        ("app_path", ("owner", "type"), "User"),
        ("app_path", ("permissions", "contents"), "read"),
        ("app_path", ("permissions", "administration"), "write"),
        ("app_path", ("events",), ["issues"]),
        ("install_path", ("id",), 401),
        ("install_path", ("app_id",), 301),
        ("install_path", ("app_slug",), "reviewing"),
        ("install_path", ("account", "id"), 200),
        ("install_path", ("account", "login"), "other"),
        ("install_path", ("account", "type"), "User"),
        ("install_path", ("target_id",), 200),
        ("install_path", ("target_type",), "User"),
        ("install_path", ("repository_selection",), "all"),
        ("install_path", ("permissions",), {"metadata": "read"}),
        ("install_path", ("suspended_at",), "2026-11-01T00:00:00Z"),
        ("repo_path", ("total_count",), 2),
        ("repo_path", ("total_count",), True),
        ("repo_path", ("repositories", 0, "id"), 13),
        ("repo_path", ("repositories", 0, "full_name"), "example/other"),
        ("repo_path", ("repositories", 0, "owner", "id"), 999),
        ("repo_path", ("repositories", 0, "default_branch"), "trunk"),
        ("comment_path", ("id",), 701),
        (
            "comment_path",
            ("issue_url",),
            "https://api.github.com/repos/other/repo/issues/1",
        ),
        ("comment_path", ("user", "id"), 501),
        ("comment_path", ("user", "login"), "reviewing[bot]"),
        ("comment_path", ("user", "type"), "User"),
        ("comment_path", ("performed_via_github_app", "id"), 301),
        ("comment_path", ("performed_via_github_app", "slug"), "reviewing"),
        ("comment_path", ("performed_via_github_app", "owner", "id"), 999),
    ],
)
def test_observed_identity_scope_and_permissions_must_match(
    scenario, route, path, value
):
    fake = scenario[2]
    raw = fake.data[getattr(fake, route)]
    for part in path[:-1]:
        raw = raw[part]
    raw[path[-1]] = value
    assert observe(scenario).status == "BLOCKED"


@pytest.mark.parametrize(
    "route,key",
    [
        ("app_path", "id"),
        ("app_path", "owner"),
        ("install_path", "account"),
        ("install_path", "permissions"),
        ("repo_path", "repositories"),
        ("comment_path", "user"),
        ("comment_path", "performed_via_github_app"),
    ],
)
def test_missing_fact_is_unverified_not_inferred(scenario, route, key):
    fake = scenario[2]
    del fake.data[getattr(fake, route)][key]
    assert observe(scenario).status == "IDENTITY_UNVERIFIED"


def test_null_or_absent_bot_evidence_does_not_use_configured_slug(scenario):
    case, observation, fake = scenario
    fake.data[fake.comment_path]["performed_via_github_app"] = None
    assert observe(scenario).status == "IDENTITY_UNVERIFIED"
    assert (
        observe(scenario, observation=replace(observation, bot_comment_id=None)).status
        == "IDENTITY_UNVERIFIED"
    )


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": True},
        {"schema_version": 2},
        {"challenge": "PASS"},
        {"expires_at": NOW},
        {"expires_at": NOW + 301},
        {"issued_at": NOW + 1},
        {"history_complete": False},
        {"history_complete": 1},
        {"seen_challenges": ("d" * 64,)},
        {"seen_challenges": ("e" * 64,) * 129},
        {"seen_challenges": ("e" * 64,) * 2},
        {"bot_comment_id": True},
    ],
)
def test_stale_replayed_or_unbounded_context_blocks_before_io(scenario, change):
    observation = replace(scenario[1], **change)
    assert observe(scenario, observation=observation).status == "BLOCKED"
    assert not scenario[2].calls


@pytest.mark.parametrize("change", ["digest", "time", "kind", "permissions", "expiry"])
def test_existing_identity_assertions_are_not_bypassed(scenario, change):
    identity = scenario[1].identity
    if change == "digest":
        identity = replace(identity, assignment_sha256="f" * 64)
    elif change == "time":
        identity = replace(identity, observed_at=NOW - 301)
    else:
        fields = {
            "kind": {"token_kind": "app_jwt"},
            "permissions": {"permissions": (("metadata", "read"),)},
            "expiry": {"expires_at": NOW},
        }[change]
        identity = replace(identity, facts=replace(identity.facts, **fields))
    assert (
        observe(scenario, observation=replace(scenario[1], identity=identity)).status
        == "BLOCKED"
    )
    assert not scenario[2].calls


@pytest.mark.parametrize("change", ["agent", "assignment", "project", "serialized"])
def test_cross_assignment_and_agent_confusion_blocks(scenario, change):
    case, _, _ = scenario
    args = {}
    if change == "agent":
        args["expected_agent"] = "codex-two"
    elif change == "assignment":
        args["value"] = replace(case["value"], assignment_id="f" * 64)
    elif change == "project":
        value = case["value"]
        pin = replace(value.admission, repo_id=13)
        args["value"] = replace(value, admission=pin)
    else:
        args["value"] = asdict(case["value"])
    assert observe(scenario, **args).status == "BLOCKED"
    assert not scenario[2].calls


@pytest.mark.parametrize("kind", ["route", "write", "auth", "challenge", "assignment"])
def test_response_envelope_cannot_swap_route_domain_or_binding(scenario, kind):
    def hook(reply):
        change = {
            "route": {"path": "/arbitrary"},
            "write": {"method": "POST"},
            "auth": {"auth_kind": "installation"},
            "challenge": {"challenge": "e" * 64},
            "assignment": {"assignment_sha256": "e" * 64},
        }[kind]
        request = copy.copy(reply.request)
        for key, value in change.items():
            object.__setattr__(request, key, value)
        return replace(reply, request=request)

    scenario[2].hook = hook
    assert observe(scenario).status == "BLOCKED"
    assert len(scenario[2].calls) == 1  # No retries or alternate auth domain.


@pytest.mark.parametrize("status", [201, 301, 304, 401, 403, 404, 429, 500, True])
def test_api_failure_blocks_without_retry(scenario, status):
    scenario[2].hook = lambda reply: replace(reply, status=status)
    assert observe(scenario).reason == "api_failure"
    assert len(scenario[2].calls) == 1


@pytest.mark.parametrize(
    "body", [b"secret", b"[]", b'{"id":1,"id":2}', b'{"id":NaN}', b"\xff", b" " * 65537]
)
def test_malformed_or_oversize_response_is_redacted(scenario, body):
    scenario[2].hook = lambda reply: replace(reply, body=body)
    assert observe(scenario).status == "BLOCKED"


def test_transport_exception_and_pagination_never_escape_or_retry(scenario):
    def fail(reply):
        raise RuntimeError("secret credential and /private/path")

    scenario[2].hook = fail
    assert observe(scenario).reason == "invalid_observation"
    scenario[2].hook = lambda reply: replace(reply, link="https://evil.invalid/secret")
    assert observe(scenario).reason == "pagination_blocked"
    fake = scenario[2]
    fake.hook = None
    fake.data[fake.repo_path]["repositories"] *= 2
    assert observe(scenario).status == "BLOCKED"


def test_conflicting_observations_and_expiry_during_read_block(scenario, monkeypatch):
    fake = scenario[2]

    def change(reply):
        if len(fake.calls) == 8:
            raw = json.loads(reply.body)
            raw["user"]["id"] += 1
            return replace(reply, body=publisher.encoded(raw))
        return reply

    fake.hook = change
    assert observe(scenario).status == "BLOCKED"
    fake.calls.clear()
    fake.hook = None
    ticks = iter([0, 0, 0, 0, 6])
    monkeypatch.setattr(observer.time, "monotonic", lambda: next(ticks))
    assert observe(scenario).reason == "observation_timeout"


def test_arbitrary_get_is_rejected_before_transport(scenario):
    case, observation, fake = scenario
    reads = observer._Reads(fake, case["value"], observation)
    with pytest.raises(observer._Failure):
        reads.get("https://evil.invalid/secret")
    with pytest.raises(observer._Failure):
        reads.get("/app/installations/401")
    assert not fake.calls


def test_native_gate_still_blocks_without_observer_or_runtime_side_effects():
    from agent_platform.state import PrepareError

    with pytest.raises(PrepareError) as caught:
        native_codex._require_reviewed_runtime()
    assert caught.value.code == 13


def test_distinct_assignment_observations_do_not_share_results_or_claim_work(scenario):
    case, observation, first_api = scenario
    first = observe(scenario)
    second_value = replace(case["value"], assignment_id="e" * 64)
    second_identity = replace(
        observation.identity, assignment_sha256=second_value.digest
    )
    second_observation = replace(
        observation, identity=second_identity, challenge="f" * 64
    )
    second_api = Fake(second_value)
    second = observe(
        scenario, value=second_value, observation=second_observation, api=second_api
    )
    assert second.status == first.status == "VERIFIED_OFFLINE_FIXTURE"
    assert second.assignment_sha256 != first.assignment_sha256
    assert second.observation_sha256 != first.observation_sha256
    assert not second.reserved and not first.reserved
    old_request = first_api.calls[0]
    second_api.hook = lambda reply: replace(reply, request=old_request)
    assert (
        observe(
            scenario, value=second_value, observation=second_observation, api=second_api
        ).status
        == "BLOCKED"
    )


def test_request_mutation_and_mid_read_expiry_are_detected(scenario, monkeypatch):
    fake = scenario[2]

    def mutate(reply):
        object.__setattr__(reply.request, "method", "POST")
        return reply

    fake.hook = mutate
    assert observe(scenario).reason == "envelope_mismatch"
    fake.hook = None
    fake.calls.clear()
    clock = iter(i * 0.4 for i in range(100))
    monkeypatch.setattr(observer.time, "monotonic", lambda: next(clock))
    assert (
        observe(scenario, observation=replace(scenario[1], expires_at=NOW + 2)).status
        == "BLOCKED"
    )
    assert len(fake.calls) == 8  # Valid initially, expired after complete reads.


def test_second_target_user_owner_and_registration_org_remain_separate(scenario):
    case, observation, _ = scenario
    value = case["value"]
    owner = observer.evidence.Principal(900, "second-owner")
    installation = replace(value.installation, account=owner, account_type="User")
    value = replace(
        value,
        admission=replace(
            value.admission, repository="second-owner/project", repo_id=14
        ),
        installation=installation,
    )
    facts = replace(
        observation.identity.facts, installation=installation, repository_ids=(14,)
    )
    identity = replace(
        observation.identity, assignment_sha256=value.digest, facts=facts
    )
    observation = replace(observation, identity=identity, challenge="e" * 64)
    result = observe(scenario, value=value, observation=observation, api=Fake(value))
    assert result.status == "VERIFIED_OFFLINE_FIXTURE"
    assert (
        result.installation.account_type == "User"
        and result.app.owner_type == "Organization"
    )
    assert observe(scenario, observation=observation).status == "BLOCKED"


def test_unknown_transport_provenance_is_not_a_live_adapter(scenario):
    scenario[2].provenance = "live_verified"
    assert observe(scenario).status == "BLOCKED"
    assert not scenario[2].calls


def test_injected_internal_error_cannot_exfiltrate_diagnostic(scenario):
    def fail(reply):
        raise observer._Failure("secret token material", missing=True)

    scenario[2].hook = fail
    assert observe(scenario).reason == "invalid_observation"
