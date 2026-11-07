"""Real-shaped nonsecret metadata fixtures; all HTTP and issuance mocked."""

import copy
import socket
from dataclasses import FrozenInstanceError, asdict, replace

import pytest

from agent_platform import app_metadata as metadata
from agent_platform import native_codex, publisher
from agent_platform.github_evidence import Principal
from agent_platform.review_comment import AppIdentity, InstallationIdentity
from agent_platform.state import PrepareError

NOW = 1794088800


class Clock:
    wall_offset = 0
    elapsed = 0

    def wall(self):
        return NOW + self.elapsed + self.wall_offset

    def monotonic(self):
        return 100 + self.elapsed


class Custody:
    def __init__(self, clock, observation):
        self.clock, self.observation = clock, observation
        self.issued, self.revoked = [], []
        self.hook = None
        self.revoke_hook = None

    def acquire(self, pins, binding_sha256, *, timeout):
        assert 0 < timeout <= 5
        lease = metadata.Lease(
            str(len(self.issued) + 1) * 64,
            binding_sha256,
            self.observation.source_id,
            pins.app.app_id,
            pins.installation.identifier,
            NOW - 1,
            NOW + 200,
            NOW - 1,
            NOW + 3600 - 1,
        )
        self.issued.append(lease)
        return self.hook(lease) if self.hook else lease

    def revoke(self, lease, *, timeout):
        assert timeout == 5
        self.revoked.append(lease)
        return self.revoke_hook(lease) if self.revoke_hook else True


class HTTP:
    def __init__(self, pins):
        self.calls = []
        self.hook = None
        registration = dict(
            id=pins.app.owner.identifier,
            login=pins.app.owner.login,
            type="Organization",
        )
        account = dict(
            id=pins.installation.account.identifier,
            login=pins.installation.account.login,
            type=pins.installation.account_type,
        )
        grants = dict(permissions={"metadata": "read"}, events=[])
        self.install = f"/app/installations/{pins.installation.identifier}"
        self.bot = "/users/" + metadata.quote(pins.app.bot.login, safe="")
        self.data = {
            "/app": dict(
                id=pins.app.app_id, slug=pins.app.slug, owner=registration, **grants
            ),
            self.install: dict(
                id=pins.installation.identifier,
                app_id=pins.app.app_id,
                app_slug=pins.app.slug,
                account=account,
                target_id=pins.installation.account.identifier,
                target_type=pins.installation.account_type,
                repository_selection="selected",
                suspended_at=None,
                suspended_by=None,
                **grants,
            ),
            "/installation/repositories": dict(
                total_count=1,
                repositories=[
                    dict(
                        id=pins.repo_id,
                        full_name=pins.repository,
                        default_branch="main",
                        owner=account,
                    )
                ],
            ),
            self.bot: dict(
                id=pins.app.bot.identifier, login=pins.app.bot.login, type="Bot"
            ),
        }
        self.data = copy.deepcopy(self.data)

    def get(self, request, *, timeout, limit):
        assert request.path in self.data and request.method == "GET"
        assert request.origin == "https://api.github.com"
        assert (
            request.verify_tls and not request.allow_redirects and not request.trust_env
        )
        assert limit == 65536 and 0 < timeout <= 5
        expected_kind = (
            "app_jwt"
            if request.path in {"/app", self.install}
            else "public"
            if request.path == self.bot
            else "installation"
        )
        assert request.auth_kind == expected_kind
        assert request.query == (
            (("per_page", 100),) if request.path == "/installation/repositories" else ()
        )
        self.calls.append(request)
        response = metadata.Response(
            request,
            200,
            publisher.encoded(self.data[request.path]),
            metadata.ORIGIN,
            True,
            False,
            False,
        )
        return self.hook(response) if self.hook else response


@pytest.fixture
def case(monkeypatch):
    # Issue #74's explicit nonsecret App/repo/Bot pins, NOT an implicit allowlist.
    # Numeric org ID 900 is fabricated: the Issue records its login, not numeric ID.
    org = Principal(900, "TechTradeExpress")
    app = AppIdentity(
        5660901,
        "techtradeexpress-agent",
        179693483,
        org,
        Principal(353883253, "techtradeexpress-agent[bot]"),
    )
    pins = metadata.Pins(
        app,
        InstallationIdentity(179693483, org, "Organization"),
        1436076348,
        "TechTradeExpress/Agent-Platform",
        "main",
    )
    observation = metadata.Observation(
        "a" * 64,
        "b" * 64,
        metadata.Source.OFFLINE_HTTP_FIXTURE,
        NOW,
        NOW + 150,
        (),
        True,
        "c" * 64,
    )
    clock = Clock()
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: pytest.fail("network"))
    return dict(
        pins=pins,
        observation=observation,
        expected_reference="c" * 64,
        custody=Custody(clock, observation),
        transport=HTTP(pins),
        clock=clock,
    )


def observe(case, **changes):
    result = metadata.observe(**(case | changes))
    assert not any(
        (
            result.reserved,
            result.prepare_authorized,
            result.launch_allowed,
            result.resume_authorized,
            result.publish_authorized,
        )
    )
    assert (
        result.runtime_exit_code == 13
        and result.app_attributed_bot_action == "NOT_OBSERVED"
    )
    assert "secret" not in publisher.encoded(asdict(result)).decode()
    return result


def test_metadata_read_happy_case_does_not_claim_association_or_authority(case):
    result = observe(case)
    assert result.status == "METADATA_ONLY_BOT_ATTRIBUTION_UNVERIFIED"
    assert result.cleanup == "CONFIRMED"
    assert result.facts.public_bot_profile == case["pins"].app.bot
    assert result.facts.permissions == (("metadata", "read"),)
    assert result.evidence_sha256[0] == result.evidence_sha256[1]
    assert result.custody_sha256[0] != result.custody_sha256[1]
    assert result.expires_at == NOW + 150
    assert len(case["transport"].calls) == 8
    assert len(case["custody"].issued) == len(case["custody"].revoked) == 2
    assert result.observation.source == metadata.Source.OFFLINE_HTTP_FIXTURE
    assert result.evidence_classes == (
        "authenticated_application_and_installation_metadata",
        "authenticated_installation_repository_scope",
        "observed_public_bot_profile",
    )
    with pytest.raises(FrozenInstanceError):
        result.publish_authorized = True


@pytest.mark.parametrize(
    "route,path,value",
    [
        ("/app", ("id",), 2),
        ("/app", ("id",), True),
        ("/app", ("slug",), "TechTradeExpress-agent"),
        ("/app", ("owner", "id"), 2),
        ("/app", ("owner", "login"), "techtradeexpress"),
        ("/app", ("owner", "type"), "User"),
        ("install", ("id",), 2),
        ("install", ("app_id",), 2),
        ("install", ("app_slug",), "different"),
        ("install", ("account", "id"), 2),
        ("install", ("account", "login"), "techtradeexpress"),
        ("install", ("account", "type"), "User"),
        ("install", ("target_id",), 2),
        ("install", ("target_type",), "User"),
        ("install", ("repository_selection",), "all"),
        ("install", ("suspended_at",), "2026-11-07T00:00:00Z"),
        ("install", ("suspended_by",), {"id": 2}),
        ("/app", ("permissions", "contents"), "write"),
        ("install", ("permissions", "pull_requests"), "write"),
        ("install", ("permissions", "metadata"), "write"),
        ("install", ("permissions",), {}),
        ("/app", ("events",), ["push"]),
        ("/installation/repositories", ("total_count",), None),
        ("/installation/repositories", ("total_count",), 2),
        ("/installation/repositories", ("total_count",), True),
        ("/installation/repositories", ("repositories", 0, "id"), 2),
        (
            "/installation/repositories",
            ("repositories", 0, "full_name"),
            "other/project",
        ),
        ("/installation/repositories", ("repositories", 0, "default_branch"), "trunk"),
        ("/installation/repositories", ("repositories", 0, "owner", "id"), 2),
        ("bot", ("id",), 2),
        ("bot", ("login",), "Techtradeexpress-agent[bot]"),
        ("bot", ("type",), "User"),
    ],
)
def test_mismatches_revoke_and_block(case, route, path, value):
    http = case["transport"]
    route = getattr(http, route) if route in {"install", "bot"} else route
    target = http.data[route]
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    assert observe(case).status == "BLOCKED"
    assert len(case["custody"].issued) == len(case["custody"].revoked) == 1


@pytest.mark.parametrize(
    "route,key",
    [
        ("/app", "owner"),
        ("install", "account"),
        ("install", "suspended_at"),
        ("/installation/repositories", "total_count"),
    ],
)
def test_absent_binding_blocks(case, route, key):
    http = case["transport"]
    del http.data[getattr(http, route) if route == "install" else route][key]
    assert observe(case).status == "BLOCKED"


@pytest.mark.parametrize("change", ["null_bot", "duplicate", "extra", "unknown_count"])
def test_incomplete_profile_and_membership_fail_closed(case, change):
    http = case["transport"]
    repo = http.data["/installation/repositories"]
    if change == "null_bot":
        http.data[http.bot] = None
    elif change == "unknown_count":
        del repo["total_count"]
    else:
        repo["repositories"].append(copy.deepcopy(repo["repositories"][0]))
        if change == "extra":
            repo["repositories"][1]["id"] = 2
    assert observe(case).status == "BLOCKED"


@pytest.mark.parametrize(
    "field,value",
    [
        ("token_kind", "app_jwt"),
        ("token_kind", None),
        ("repository_restriction", "single_repository"),
        ("permission_restriction", "metadata_subset"),
        ("source_id", "d" * 64),
        ("binding_sha256", "d" * 64),
        ("app_id", 3),
        ("installation_id", 3),
        ("issued_at", NOW + 1),
        ("expires_at", NOW),
        ("jwt_expires_at", NOW),
        ("jwt_issued_at", True),
    ],
)
def test_wrong_or_narrowed_credential_domain_blocks_before_http(case, field, value):
    case["custody"].hook = lambda lease: replace(lease, **{field: value})
    assert observe(case).status == "BLOCKED"
    assert not case["transport"].calls and len(case["custody"].revoked) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("history_complete", False),
        ("history_complete", 1),
        ("seen_challenges", ("a" * 64,)),
        ("seen_challenges", ("d" * 64,) * 129),
        ("seen_challenges", ("d" * 64,) * 2),
        ("challenge", "PASS"),
        ("issued_at", NOW + 1),
        ("expires_at", NOW),
        ("expires_at", NOW + 301),
        ("schema_version", True),
        ("assignment_reference", "d" * 64),
        ("source", "synthetic_app_observer"),
    ],
)
def test_untrusted_stale_replayed_or_cross_assignment_context_blocks(
    case, field, value
):
    observation = replace(case["observation"], **{field: value})
    assert observe(case, observation=observation).status == "BLOCKED"
    assert not case["custody"].issued


@pytest.mark.parametrize(
    "field,value",
    [
        ("origin", "http://api.github.com"),
        ("origin", "https://evil.invalid/secret"),
        ("tls_verified", False),
        ("tls_verified", 1),
        ("redirected", True),
        ("proxy_used", True),
        ("link", "https://api.github.com/installation/repositories?page=2"),
        ("status", 301),
        ("status", 401),
        ("status", 403),
        ("status", 429),
        ("status", 500),
        ("status", True),
        ("body", b'{"id":1,"id":2}'),
        ("body", b'{"id":NaN}'),
        ("body", b"secret"),
        ("body", b"\xff"),
        ("body", b"x" * 65537),
    ],
)
def test_bad_http_never_retries_or_leaks(case, field, value):
    case["transport"].hook = lambda response: replace(response, **{field: value})
    assert observe(case).status == "BLOCKED"
    assert len(case["transport"].calls) == len(case["custody"].revoked) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("path", "/arbitrary"),
        ("method", "POST"),
        ("auth_kind", None),
        ("auth_kind", "installation"),
        ("lease_id", "f" * 64),
        ("source_id", "f" * 64),
        ("binding_sha256", "f" * 64),
        ("origin", "https://evil.invalid"),
        ("trust_env", True),
    ],
)
def test_request_or_auth_swap_blocks(case, field, value):
    def swap(response):
        request = copy.copy(response.request)
        object.__setattr__(request, field, value)
        return replace(response, request=request)

    case["transport"].hook = swap
    assert observe(case).status == "BLOCKED"


def test_changed_second_read_and_reused_lease_block(case):
    http = case["transport"]

    def drift(response):
        if len(http.calls) == 5:
            raw = copy.deepcopy(http.data["/app"])
            raw["slug"] = "changed"
            return replace(response, body=publisher.encoded(raw))
        return response

    http.hook = drift
    assert observe(case).status == "BLOCKED"
    assert len(case["custody"].revoked) == 2


def test_same_lease_cannot_back_two_observations(case):
    case["custody"].hook = lambda lease: replace(lease, lease_id="e" * 64)
    assert observe(case).status == "BLOCKED"
    assert len(case["transport"].calls) == 4
    assert len(case["custody"].revoked) == 2


@pytest.mark.parametrize("stage", ["acquire", "http", "revoke", "uncertain_revoke"])
def test_failure_and_finally_semantics(case, stage):
    def fail(*args):
        raise RuntimeError("secret PEM token /private/secret")

    custody = case["custody"]
    if stage == "acquire":
        custody.hook = fail
    elif stage == "http":
        case["transport"].hook = fail
    elif stage == "revoke":
        custody.revoke_hook = fail
    else:
        custody.revoke_hook = lambda lease: False
    result = observe(case)
    assert result.status == "BLOCKED" and result.facts is None
    assert result.cleanup == ("CONFIRMED" if stage == "http" else "UNKNOWN")
    assert len(custody.issued) == 1
    assert len(custody.revoked) == (0 if stage == "acquire" else 1)


@pytest.mark.parametrize(
    "change",
    ["timeout", "expired", "wall_forward", "wall_back", "total", "cleanup_timeout"],
)
def test_clock_and_budget_failures_still_attempt_revocation(case, change):
    clock = case["clock"]

    def advance(response):
        if change == "timeout":
            clock.elapsed += 5
        elif change == "expired":
            clock.elapsed += 1
        elif change == "wall_forward":
            clock.wall_offset += 10
        elif change == "wall_back":
            clock.wall_offset -= 1
        elif change == "total":
            clock.elapsed += 4
        return response

    case["transport"].hook = advance
    observation = case["observation"]
    if change == "expired":
        observation = replace(observation, expires_at=NOW + 2)
    if change == "cleanup_timeout":

        def slow(lease):
            clock.elapsed += 5
            return True

        case["custody"].revoke_hook = slow
    assert observe(case, observation=observation).status == "BLOCKED"
    assert case["custody"].revoked


def test_public_profile_or_forged_association_never_promotes_metadata(case):
    http = case["transport"]
    http.data[http.bot]["performed_via_github_app"] = {"id": case["pins"].app.app_id}
    http.data[http.bot]["secret"] = "secret"
    result = observe(case)
    assert result.status == "METADATA_ONLY_BOT_ATTRIBUTION_UNVERIFIED"
    # No action endpoint exists; profile-only/absent association remains explicit.
    case["custody"].issued.clear()
    observation = replace(case["observation"], include_public_bot=False)
    http.calls.clear()
    assert observe(case, observation=observation).facts.public_bot_profile is None
    assert len(http.calls) == 6


def test_other_operator_pins_registration_owner_distinct_from_target(case):
    pins = case["pins"]
    registration = Principal(910, "other-registration")
    target = Principal(920, "other-target")
    app = AppIdentity(
        111, "other-agent", 222, registration, Principal(333, "other-agent[bot]")
    )
    pins = metadata.Pins(
        app,
        InstallationIdentity(222, target, "Organization"),
        444,
        "other-target/project",
        "main",
    )
    result = observe(case, pins=pins, transport=HTTP(pins))
    assert result.status == "METADATA_ONLY_BOT_ATTRIBUTION_UNVERIFIED"
    assert result.facts.registration_owner != result.facts.installation.account
    assert observe(case, pins=pins).status == "BLOCKED"


def test_pins_are_not_serialized_assignment_authority_and_native_stays_blocked(case):
    assert observe(case, pins=asdict(case["pins"])).status == "BLOCKED"
    with pytest.raises(metadata.Blocked):
        replace(case["pins"], permissions=(("contents", "write"),))
    with pytest.raises(PrepareError) as error:
        native_codex._require_reviewed_runtime()
    assert error.value.code == 13


@pytest.mark.parametrize("failure", ["late", "clock_drift"])
def test_lease_returned_before_post_acquire_failure_is_still_revoked(case, failure):
    def late(lease):
        if failure == "late":
            case["clock"].elapsed += 6
        else:
            case["clock"].wall_offset += 10
        return lease

    case["custody"].hook = late
    result = observe(case)
    assert result.status == "BLOCKED" and result.cleanup == "CONFIRMED"
    assert len(case["custody"].revoked) == 1
    assert not case["transport"].calls


def test_first_lease_evidence_expiring_during_second_pass_blocks(case):
    def first_short(lease):
        if len(case["custody"].issued) == 1:
            return replace(lease, jwt_expires_at=NOW + 3)
        return lease

    def advance(response):
        case["clock"].elapsed += 0.5
        return response

    case["custody"].hook = first_short
    case["transport"].hook = advance
    result = observe(case)
    assert result.status == "BLOCKED" and result.facts is None
    assert len(case["custody"].revoked) == 2


def test_untrusted_response_fields_are_neither_hashed_nor_returned(case):
    result = observe(case)
    for raw in case["transport"].data.values():
        raw["secret"] = "secret"
    case["custody"].issued.clear()
    again = observe(case)
    assert again.evidence_sha256 == result.evidence_sha256


def test_no_arbitrary_route_reaches_transport(case):
    pins, observation, custody = case["pins"], case["observation"], case["custody"]
    binding = "d" * 64
    lease = custody.acquire(pins, binding, timeout=5)
    budget = metadata._Budget(case["clock"])
    reads = metadata._Reads(
        case["transport"], pins, observation, lease, binding, budget
    )
    for path in (
        "https://evil.invalid",
        "/app/installations/2",
        "/installation/token",
        "/app/installations/179693483/access_tokens",
    ):
        with pytest.raises(metadata.Blocked):
            reads.get(path)
    assert not case["transport"].calls
    custody.revoke(lease, timeout=5)


def test_optional_reference_and_explicit_profile_type_are_non_authorizing(case):
    result = observe(
        case,
        observation=replace(case["observation"], assignment_reference=None),
        expected_reference=None,
    )
    assert result.status == "METADATA_ONLY_BOT_ATTRIBUTION_UNVERIFIED"
    assert result.pins.bot_profile_type == result.facts.public_bot_type == "Bot"
    assert result.observation_times == (NOW, NOW)


def test_explicit_external_source_label_never_grants_live_verification(case):
    # A classification enum is not cryptographic authentication or authority.
    result = observe(
        case,
        observation=replace(
            case["observation"], source=metadata.Source.EXTERNAL_TRUSTED_TRANSPORT
        ),
    )
    assert result.status == "METADATA_ONLY_BOT_ATTRIBUTION_UNVERIFIED"
    assert result.app_attributed_bot_action == "NOT_OBSERVED"


def test_replayed_response_from_another_pass_is_blocked(case):
    captured = []

    def replay(response):
        if len(case["transport"].calls) == 1:
            captured.append(response)
        if len(case["transport"].calls) == 5:
            return captured[0]
        return response

    case["transport"].hook = replay
    assert observe(case).status == "BLOCKED"
    assert len(case["custody"].revoked) == 2
