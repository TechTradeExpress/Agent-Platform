"""AP-CI/1: bounded synthetic GET observations; no credentials or live adapter."""

import json
import math
import time
from dataclasses import asdict, dataclass, field, replace
from enum import StrEnum

from . import codex_assignment as assignment
from . import github_evidence as evidence
from . import issues, publisher
from . import review_comment as review

MAX_BODY = 64 * 1024
MAX_REQUESTS = 8
MAX_HISTORY = 128
TOTAL_SECONDS = 30
REQUEST_SECONDS = 5
_FIXED_REASONS = frozenset(
    {
        "invalid_observation",
        "missing_identity_fact",
        "missing_bot_association",
        "replayed_observation",
        "route_blocked",
        "observation_timeout",
        "envelope_mismatch",
        "api_failure",
        "pagination_blocked",
        "conflicting_observations",
    }
)


class Status(StrEnum):
    VERIFIED_OFFLINE_FIXTURE = "VERIFIED_OFFLINE_FIXTURE"
    IDENTITY_UNVERIFIED = "IDENTITY_UNVERIFIED"
    BLOCKED = "BLOCKED"


class _Failure(Exception):
    def __init__(self, reason="invalid_observation", missing=False):
        self.reason = reason
        self.missing = missing


def _need(value, reason="invalid_observation"):
    if not value:
        raise _Failure(reason)


def _required(raw, key):
    if type(raw) is not dict or key not in raw or raw[key] is None:
        raise _Failure("missing_identity_fact", missing=True)
    return raw[key]


@dataclass(frozen=True, slots=True)
class Observation:
    """Trusted observer metadata, not an authorization or durable claim.

    Snapshot contains existing synthetic custody assertions. History must come
    from the independent observer, never a model-selected subset. No persistence
    or consumption is implemented; repeated pure reads remain non-authorizing.
    """

    identity: assignment.IdentitySnapshot
    challenge: str
    issued_at: int
    expires_at: int
    bot_comment_id: int | None
    seen_challenges: tuple[str, ...]
    history_complete: bool
    schema_version: int = 1


@dataclass(frozen=True, slots=True)
class Request:
    path: str
    auth_kind: str
    query: tuple[tuple[str, int], ...]
    assignment_sha256: str
    challenge: str
    method: str = field(default="GET", init=False)


@dataclass(frozen=True, slots=True)
class Reply:
    """Synthetic observer envelope. Auth/challenge are NOT GitHub API fields."""

    request: Request
    status: int
    body: bytes
    link: str | None = None


@dataclass(frozen=True, slots=True)
class Result:
    status: Status
    reason: str
    assignment_sha256: str | None = None
    observation_sha256: str | None = None
    app: review.AppIdentity | None = None
    installation: review.InstallationIdentity | None = None
    repository: str | None = None
    repo_id: int | None = None
    agent_id: str | None = None
    expires_at: int | None = None
    evidence_sha256: tuple[str, ...] = ()
    identity: assignment.IdentitySnapshot | None = None
    schema_version: int = field(default=1, init=False)
    reserved: bool = field(default=False, init=False)
    prepare_authorized: bool = field(default=False, init=False)
    launch_allowed: bool = field(default=False, init=False)
    resume_authorized: bool = field(default=False, init=False)
    publish_authorized: bool = field(default=False, init=False)
    live_app_identity: str = field(default="NOT_RUN", init=False)
    runtime_exit_code: int = field(default=13, init=False)


def _context(value, observation, expected_agent, now):
    _need(type(value) is assignment.CodexAssignment)
    replace(value)
    _need(type(now) is int and value.issued_at <= now < value.expires_at)
    _need(type(expected_agent) is str and value.agent_id == expected_agent)
    _need(type(observation) is Observation)
    o = observation
    _need(type(o.schema_version) is int and o.schema_version == 1)
    assignment._identity(value, o.identity, now)
    _need(publisher.hex_digest(o.challenge))
    _need(type(o.issued_at) is type(o.expires_at) is int)
    _need(0 <= o.issued_at <= now < o.expires_at <= o.issued_at + assignment.MAX_AGE)
    _need(value.issued_at <= o.issued_at)
    _need(value.issued_at <= o.identity.observed_at <= o.issued_at)
    _need(o.identity.facts.issued_at <= o.issued_at)
    _need(type(o.history_complete) is bool and o.history_complete)
    _need(type(o.seen_challenges) is tuple and len(o.seen_challenges) <= MAX_HISTORY)
    _need(all(publisher.hex_digest(c) for c in o.seen_challenges))
    _need(len(set(o.seen_challenges)) == len(o.seen_challenges))
    _need(o.challenge not in o.seen_challenges, "replayed_observation")
    _need(o.bot_comment_id is None or issues.positive_int(o.bot_comment_id))


class _Reads:
    def __init__(self, api, value, observation):
        _need(api is not None and api.provenance == "synthetic_app_observer")
        self.api = api
        self.value = value
        self.observation = observation
        self.deadline = time.monotonic() + TOTAL_SECONDS
        self.count = 0
        self.routes = {
            "/app": ("app_jwt", ()),
            f"/app/installations/{value.installation.identifier}": ("app_jwt", ()),
            "/installation/repositories": (
                "installation",
                (("page", 1), ("per_page", 20)),
            ),
        }
        if observation.bot_comment_id is not None:
            self.routes[self.comment_path] = ("installation", ())

    @property
    def comment_path(self):
        return (
            f"/repos/{self.value.admission.repository}/issues/comments/"
            f"{self.observation.bot_comment_id}"
        )

    def get(self, path):
        _need(type(path) is str and path in self.routes, "route_blocked")
        _need(self.count < MAX_REQUESTS and time.monotonic() < self.deadline)
        kind, query = self.routes[path]
        request = Request(
            path, kind, query, self.value.digest, self.observation.challenge
        )
        request_pin = publisher.digest(asdict(request))
        self.count += 1
        started = time.monotonic()
        reply = self.api.get(request, timeout=REQUEST_SECONDS, limit=MAX_BODY)
        _need(time.monotonic() - started < REQUEST_SECONDS, "observation_timeout")
        _need(time.monotonic() < self.deadline, "observation_timeout")
        _need(
            publisher.digest(asdict(request)) == request_pin
            and type(reply) is Reply
            and type(reply.request) is Request
            and publisher.digest(asdict(reply.request)) == request_pin,
            "envelope_mismatch",
        )
        _need(type(reply.status) is int and reply.status == 200, "api_failure")
        _need(reply.link is None, "pagination_blocked")
        _need(type(reply.body) is bytes and 0 < len(reply.body) <= MAX_BODY)
        raw = json.loads(
            reply.body.decode("utf-8"),
            object_pairs_hook=issues.unique_object,
            parse_constant=issues.invalid_constant,
        )
        _need(type(raw) is dict)
        return raw


def _principal(raw, pin, kind):
    _need(type(raw) is dict)
    identifier = _required(raw, "id")
    login = _required(raw, "login")
    account_type = _required(raw, "type")
    _need(issues.positive_int(identifier))
    _need(evidence.Principal(identifier, login) == pin)
    _need(account_type == kind)
    return {"id": identifier, "login": login, "type": account_type}


def _app(raw, value, grants=True):
    app = value.coding_app
    identifier = _required(raw, "id")
    _need(issues.positive_int(identifier) and identifier == app.app_id)
    _need(_required(raw, "slug") == app.slug)
    owner = _principal(_required(raw, "owner"), app.owner, app.owner_type)
    result = {"id": identifier, "slug": app.slug, "owner": owner}
    if grants:
        result.update(_grants(raw))
    return result


def _grants(raw):
    permissions = _required(raw, "permissions")
    _need(type(permissions) is dict)
    _need(permissions == dict(assignment.CODING_PERMISSIONS))
    _need(_required(raw, "events") == [])
    return {"permissions": permissions, "events": []}


def _snapshot(reads, value, observation):
    app = _app(reads.get("/app"), value)
    raw = reads.get(f"/app/installations/{value.installation.identifier}")
    identifier = _required(raw, "id")
    _need(
        issues.positive_int(identifier) and identifier == value.installation.identifier
    )
    _need(type(_required(raw, "app_id")) is int and raw["app_id"] == app["id"])
    _need(_required(raw, "app_slug") == app["slug"])
    _need(_required(raw, "repository_selection") == "selected")
    account = _principal(_required(raw, "account"), value.owner, value.owner_type)
    _need(
        type(_required(raw, "target_id")) is int and raw["target_id"] == account["id"]
    )
    _need(_required(raw, "target_type") == value.owner_type)
    _need("suspended_at" in raw and "suspended_by" in raw)
    _need(raw["suspended_at"] is raw["suspended_by"] is None)
    installation = {
        "id": identifier,
        "app_id": app["id"],
        "app_slug": app["slug"],
        "account": account,
        "repository_selection": "selected",
        "target_id": account["id"],
        "target_type": value.owner_type,
        "suspended_at": None,
        "suspended_by": None,
        **_grants(raw),
    }
    raw = reads.get("/installation/repositories")
    _need(type(_required(raw, "total_count")) is int and raw["total_count"] == 1)
    repositories = _required(raw, "repositories")
    _need(type(repositories) is list and len(repositories) == 1)
    repo = repositories[0]
    identifier = _required(repo, "id")
    _need(issues.positive_int(identifier) and identifier == value.admission.repo_id)
    _need(_required(repo, "full_name") == value.admission.repository)
    _need(_required(repo, "default_branch") == value.base_branch)
    repository = {
        "id": identifier,
        "full_name": value.admission.repository,
        "default_branch": value.base_branch,
        "owner": _principal(_required(repo, "owner"), value.owner, value.owner_type),
    }
    if observation.bot_comment_id is None:
        raise _Failure("missing_bot_association", missing=True)
    raw = reads.get(reads.comment_path)
    _need(type(_required(raw, "id")) is int and raw["id"] == observation.bot_comment_id)
    issue_url = (
        f"https://api.github.com/repos/{value.admission.repository}"
        f"/issues/{value.admission.issue}"
    )
    _need(_required(raw, "issue_url") == issue_url)
    bot = _principal(_required(raw, "user"), value.coding_app.bot, "Bot")
    association = _app(_required(raw, "performed_via_github_app"), value, grants=False)
    return (
        app,
        installation,
        repository,
        {
            "id": observation.bot_comment_id,
            "issue_url": issue_url,
            "user": bot,
            "performed_via_github_app": association,
        },
    )


def observe(*, value, observation, expected_agent, api, now):
    """Pure, non-authorizing fixture observation. All failures have fixed output.

    Injected observer must honor the request deadline/output limit; no arbitrary
    untrusted callable can be isolated by this in-process contract. No production
    observer/client is present and no supplied provenance string proves trust.
    """
    try:
        _context(value, observation, expected_agent, now)
        pin = value.digest
        context = publisher.digest(asdict(observation))
        started = time.monotonic()
        reads = _Reads(api, value, observation)
        first = _snapshot(reads, value, observation)
        second = _snapshot(reads, value, observation)
        _need(first == second, "conflicting_observations")
        elapsed = math.ceil(time.monotonic() - started)
        _context(value, observation, expected_agent, now + elapsed)
        _need(value.digest == pin and publisher.digest(asdict(observation)) == context)
        return Result(
            Status.VERIFIED_OFFLINE_FIXTURE,
            "synthetic_only",
            pin,
            context,
            value.coding_app,
            value.installation,
            value.admission.repository,
            value.admission.repo_id,
            value.agent_id,
            min(
                value.expires_at,
                observation.expires_at,
                observation.identity.facts.expires_at,
                observation.identity.observed_at + assignment.MAX_AGE,
            ),
            tuple(publisher.digest(item) for item in first),
            observation.identity,
        )
    except _Failure as exc:
        # An injected transport may throw this exception too: never echo its text.
        if type(exc.reason) is not str or exc.reason not in _FIXED_REASONS:
            return Result(Status.BLOCKED, "invalid_observation")
        status = Status.IDENTITY_UNVERIFIED if exc.missing is True else Status.BLOCKED
        return Result(status, exc.reason)
    except Exception:
        # Never expose transport exceptions, raw API text or partial untrusted pins.
        return Result(Status.BLOCKED, "invalid_observation")
