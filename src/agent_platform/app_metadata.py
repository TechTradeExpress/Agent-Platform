"""AP-AM/1 metadata boundary. No HTTP implementation, signing or live entrypoint."""

import json
import math
import re
import time
from dataclasses import asdict, dataclass, field, replace
from enum import StrEnum
from typing import Protocol
from urllib.parse import quote

from . import cli, issues, publisher
from .github_evidence import Principal
from .review_comment import AppIdentity, InstallationIdentity

ORIGIN = "https://api.github.com"
PERMISSIONS = (("metadata", "read"),)
MAX_BODY = 65536
MAX_AGE = 300
MAX_HISTORY = 128


class Blocked(Exception):
    """No remote or transport text is used as a diagnostic."""


def need(value):
    if not value:
        raise Blocked()


class Source(StrEnum):
    OFFLINE_HTTP_FIXTURE = "OFFLINE_HTTP_FIXTURE"
    EXTERNAL_TRUSTED_TRANSPORT = "EXTERNAL_TRUSTED_TRANSPORT"


class Status(StrEnum):
    METADATA_ONLY_BOT_ATTRIBUTION_UNVERIFIED = (
        "METADATA_ONLY_BOT_ATTRIBUTION_UNVERIFIED"
    )
    BLOCKED = "BLOCKED"


@dataclass(frozen=True, slots=True)
class Pins:
    """Independent operator input, not assignment/admission or an App allowlist.

    AppIdentity.bot is an expected profile pin only, NOT observed attribution.
    This metadata-read profile cannot satisfy AP-CA/1's coding writer contract.
    """

    app: AppIdentity
    installation: InstallationIdentity
    repo_id: int
    repository: str
    default_branch: str
    permissions: tuple[tuple[str, str], ...] = PERMISSIONS
    schema_version: int = 1
    bot_profile_type: str = field(default="Bot", init=False)

    def __post_init__(self):
        need(type(self.schema_version) is int and self.schema_version == 1)
        need(type(self.app) is AppIdentity)
        need(type(self.installation) is InstallationIdentity)
        replace(self.app)
        replace(self.installation)
        need(self.app.owner_type == "Organization")
        need(self.installation.identifier == self.app.installation_id)
        need(issues.positive_int(self.repo_id))
        need(type(self.repository) is str)
        need(
            cli.parse_origin("https://github.com/" + self.repository) == self.repository
        )
        need(self.repository.split("/")[0] == self.installation.account.login)
        need(type(self.default_branch) is str)
        need(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", self.default_branch))
        need(type(self.permissions) is tuple and self.permissions == PERMISSIONS)


@dataclass(frozen=True, slots=True)
class Observation:
    challenge: str
    source_id: str
    source: Source
    issued_at: int
    expires_at: int
    seen_challenges: tuple[str, ...]
    history_complete: bool
    assignment_reference: str | None = None
    include_public_bot: bool = True
    schema_version: int = 1


@dataclass(frozen=True, slots=True)
class Lease:
    """Custody assertions only. NEVER a bearer token or PEM/JWT material.

    Installation-wide issuance is mandatory: no repository/permission subset may
    conceal a wider installed scope. Custody owns and authenticates this claim.
    """

    lease_id: str
    binding_sha256: str
    source_id: str
    app_id: int
    installation_id: int
    jwt_issued_at: int
    jwt_expires_at: int
    issued_at: int
    expires_at: int
    token_kind: str = "installation"
    repository_restriction: str = "installation_wide"
    permission_restriction: str = "installation_grants"


class Custody(Protocol):
    """Future external issuer/revoker, never implemented here.

    acquire is single-use for one observation pass. A later implementation owns
    POST access_tokens and DELETE installation/token, key/JWT custody and cleanup
    of partial issuance even if acquire raises. No automatic retry on uncertainty.
    revoke must confirm revocation or report failure; no token enters this API.
    """

    def acquire(self, pins: Pins, binding_sha256: str, *, timeout: float) -> Lease: ...
    def revoke(self, lease: Lease, *, timeout: float) -> bool: ...


@dataclass(frozen=True, slots=True)
class Request:
    path: str
    auth_kind: str
    query: tuple[tuple[str, int], ...]
    binding_sha256: str
    lease_id: str
    source_id: str
    origin: str = field(default=ORIGIN, init=False)
    method: str = field(default="GET", init=False)
    verify_tls: bool = field(default=True, init=False)
    allow_redirects: bool = field(default=False, init=False)
    trust_env: bool = field(default=False, init=False)


@dataclass(frozen=True, slots=True)
class Response:
    """Adapter attestation is separate from the raw GitHub-shaped JSON body."""

    request: Request
    status: int
    body: bytes
    origin: str
    tls_verified: bool
    redirected: bool
    proxy_used: bool
    link: str | None = None


class Transport(Protocol):
    """No implementation/default client. Independent trusted code, not a sandbox.

    A future implementation must enforce verified HTTPS to ORIGIN, no proxies,
    redirects or arbitrary routes, bounded streaming and hard socket deadlines.
    Request flags and response booleans alone cannot establish that assurance.
    """

    def get(self, request: Request, *, timeout: float, limit: int) -> Response: ...


@dataclass(frozen=True, slots=True)
class Facts:
    app_id: int
    app_slug: str
    registration_owner: Principal
    installation: InstallationIdentity
    repo_id: int
    repository: str
    default_branch: str
    permissions: tuple[tuple[str, str], ...]
    public_bot_profile: Principal | None
    public_bot_type: str | None
    registration_owner_type: str = field(default="Organization", init=False)
    repository_selection: str = field(default="selected", init=False)
    suspended: bool = field(default=False, init=False)


@dataclass(frozen=True, slots=True)
class Result:
    status: Status
    reason: str
    cleanup: str
    pins: Pins | None = None
    observation: Observation | None = None
    observed_at: int | None = None
    expires_at: int | None = None
    facts: Facts | None = None
    evidence_sha256: tuple[str, ...] = ()
    custody_sha256: tuple[str, ...] = ()
    evidence_classes: tuple[str, ...] = ()
    observation_times: tuple[int, ...] = ()
    schema_version: int = field(default=1, init=False)
    app_attributed_bot_action: str = field(default="NOT_OBSERVED", init=False)
    reserved: bool = field(default=False, init=False)
    prepare_authorized: bool = field(default=False, init=False)
    launch_allowed: bool = field(default=False, init=False)
    resume_authorized: bool = field(default=False, init=False)
    publish_authorized: bool = field(default=False, init=False)
    runtime_exit_code: int = field(default=13, init=False)


class Clock:
    def wall(self):
        return time.time()

    def monotonic(self):
        return time.monotonic()


class _Budget:
    def __init__(self, clock):
        self.clock = clock
        self.start_wall = self.wall = self._number(clock.wall())
        self.start_mono = self.mono = self._number(clock.monotonic())

    @staticmethod
    def _number(value):
        need(
            type(value) in {float, int} and math.isfinite(value) and 0 <= value < 2**53
        )
        return value

    def tick(self):
        wall = self._number(self.clock.wall())
        mono = self._number(self.clock.monotonic())
        need(wall >= self.wall and mono >= self.mono)
        need(abs((wall - self.start_wall) - (mono - self.start_mono)) <= 2)
        need(mono - self.start_mono < 30)
        self.wall, self.mono = wall, mono
        return wall

    def begin(self):
        self.tick()
        return self.mono, min(5, 30 - (self.mono - self.start_mono))

    def finish(self, started, timeout):
        self.tick()
        need(self.mono - started < timeout)

    def call(self, callback, *args, **kwargs):
        started, timeout = self.begin()
        result = callback(*args, timeout=timeout, **kwargs)
        self.finish(started, timeout)
        return result


def _context(pins, observation, expected_reference, now):
    need(type(pins) is Pins)
    replace(pins)
    need(type(observation) is Observation)
    o = observation
    need(type(o.schema_version) is int and o.schema_version == 1)
    need(type(o.source) is Source)
    need(publisher.hex_digest(o.challenge) and publisher.hex_digest(o.source_id))
    need(o.assignment_reference is None or publisher.hex_digest(o.assignment_reference))
    need(o.assignment_reference == expected_reference)
    need(type(o.include_public_bot) is bool)
    need(type(o.issued_at) is type(o.expires_at) is int)
    need(0 <= o.issued_at <= now < o.expires_at <= o.issued_at + MAX_AGE)
    need(type(o.history_complete) is bool and o.history_complete)
    need(type(o.seen_challenges) is tuple and len(o.seen_challenges) <= MAX_HISTORY)
    need(all(publisher.hex_digest(x) for x in o.seen_challenges))
    need(len(set(o.seen_challenges)) == len(o.seen_challenges))
    need(o.challenge not in o.seen_challenges)


def _lease(lease, pins, observation, binding, now):
    need(type(lease) is Lease)
    need(publisher.hex_digest(lease.lease_id))
    need(lease.binding_sha256 == binding and lease.source_id == observation.source_id)
    need(type(lease.app_id) is int and lease.app_id == pins.app.app_id)
    need(type(lease.installation_id) is int)
    need(lease.installation_id == pins.installation.identifier)
    need(lease.token_kind == "installation")
    need(lease.repository_restriction == "installation_wide")
    need(lease.permission_restriction == "installation_grants")
    for issued, expires, maximum in (
        (lease.jwt_issued_at, lease.jwt_expires_at, 600),
        (lease.issued_at, lease.expires_at, 3600),
    ):
        need(type(issued) is type(expires) is int)
        need(0 <= issued <= now < expires <= issued + maximum)


def _principal(raw, pin, kind):
    need(type(raw) is dict and type(raw.get("id")) is int)
    need(Principal(raw["id"], raw["login"]) == pin and raw["type"] == kind)


def _grants(raw, pins):
    need(type(raw.get("permissions")) is dict)
    need(raw["permissions"] == dict(pins.permissions))
    need(raw.get("events") == [])


class _Reads:
    def __init__(self, transport, pins, observation, lease, binding, budget):
        self.transport, self.pins, self.observation = transport, pins, observation
        self.lease, self.binding, self.budget = lease, binding, budget
        self.routes = {
            "/app": ("app_jwt", ()),
            f"/app/installations/{pins.installation.identifier}": ("app_jwt", ()),
            "/installation/repositories": ("installation", (("per_page", 100),)),
        }
        self.bot_path = "/users/" + quote(pins.app.bot.login, safe="")
        if observation.include_public_bot:
            self.routes[self.bot_path] = ("public", ())
        self.count = 0

    def get(self, path):
        need(path in self.routes and self.count < 4)
        self.count += 1
        _lease(
            self.lease, self.pins, self.observation, self.binding, self.budget.tick()
        )
        kind, query = self.routes[path]
        request = Request(
            path,
            kind,
            query,
            self.binding,
            self.lease.lease_id,
            self.observation.source_id,
        )
        digest = publisher.digest(asdict(request))
        response = self.budget.call(self.transport.get, request, limit=MAX_BODY)
        need(publisher.digest(asdict(request)) == digest)
        need(type(response) is Response and type(response.request) is Request)
        need(publisher.digest(asdict(response.request)) == digest)
        need(response.origin == ORIGIN and response.tls_verified is True)
        need(response.redirected is False and response.proxy_used is False)
        need(type(response.status) is int and response.status == 200)
        need(response.link is None)
        need(type(response.body) is bytes and 0 < len(response.body) <= MAX_BODY)
        _lease(
            self.lease, self.pins, self.observation, self.binding, self.budget.tick()
        )
        raw = json.loads(
            response.body.decode("utf-8"),
            object_pairs_hook=issues.unique_object,
            parse_constant=issues.invalid_constant,
        )
        need(type(raw) is dict)
        return raw


def _facts(reads, pins, observation):
    raw = reads.get("/app")
    need(type(raw["id"]) is int and raw["id"] == pins.app.app_id)
    need(raw["slug"] == pins.app.slug)
    _principal(raw["owner"], pins.app.owner, pins.app.owner_type)
    _grants(raw, pins)
    raw = reads.get(f"/app/installations/{pins.installation.identifier}")
    need(type(raw["id"]) is int and raw["id"] == pins.installation.identifier)
    need(type(raw["app_id"]) is int and raw["app_id"] == pins.app.app_id)
    need(raw["app_slug"] == pins.app.slug)
    _principal(
        raw["account"], pins.installation.account, pins.installation.account_type
    )
    need(type(raw["target_id"]) is int)
    need(raw["target_id"] == pins.installation.account.identifier)
    need(raw["target_type"] == pins.installation.account_type)
    need(raw["repository_selection"] == "selected")
    need(raw["suspended_at"] is raw["suspended_by"] is None)
    _grants(raw, pins)
    raw = reads.get("/installation/repositories")
    need(type(raw["total_count"]) is int and raw["total_count"] == 1)
    need(type(raw["repositories"]) is list and len(raw["repositories"]) == 1)
    repo = raw["repositories"][0]
    need(type(repo["id"]) is int and repo["id"] == pins.repo_id)
    need(repo["full_name"] == pins.repository)
    need(repo["default_branch"] == pins.default_branch)
    _principal(repo["owner"], pins.installation.account, pins.installation.account_type)
    bot = None
    if observation.include_public_bot:
        _principal(reads.get(reads.bot_path), pins.app.bot, "Bot")
        bot = pins.app.bot
    return Facts(
        pins.app.app_id,
        pins.app.slug,
        pins.app.owner,
        pins.installation,
        pins.repo_id,
        pins.repository,
        pins.default_branch,
        pins.permissions,
        bot,
        "Bot" if bot is not None else None,
    )


def observe(
    *,
    pins,
    observation,
    expected_reference,
    custody: Custody,
    transport: Transport,
    clock=None,
):
    """Non-authorizing metadata artifact; only mocked adapters exercised here.

    Two distinct single-use leases, each finally-revoked, bracket two independent
    reads. Any uncertain cleanup suppresses the artifact. External adapters own
    hard I/O bounds and partial-issuance reconciliation, not this in-process code.
    """
    cleanup = "NOT_STARTED"
    try:
        budget = _Budget(Clock() if clock is None else clock)
        _context(pins, observation, expected_reference, budget.tick())
        binding = publisher.digest(
            {"pins": asdict(pins), "observation": asdict(observation)}
        )
        facts, custody_digests, lease_ids, expiries = [], [], set(), []
        observation_times = []
        for pass_number in (1, 2):
            pass_binding = publisher.digest(
                {"observation": binding, "pass": pass_number}
            )
            lease = None
            cleanup = "UNKNOWN"
            try:
                started, timeout = budget.begin()
                # Retain the returned lease BEFORE any post-call clock checks so
                # a late/invalid response still enters finally-revocation.
                lease = custody.acquire(pins, pass_binding, timeout=timeout)
                budget.finish(started, timeout)
                _lease(lease, pins, observation, pass_binding, budget.tick())
                need(lease.lease_id not in lease_ids)
                lease_ids.add(lease.lease_id)
                lease_pin = publisher.digest(asdict(lease))
                reads = _Reads(
                    transport, pins, observation, lease, pass_binding, budget
                )
                facts.append(_facts(reads, pins, observation))
                need(publisher.digest(asdict(lease)) == lease_pin)
                custody_digests.append(lease_pin)
                expiries.extend((lease.jwt_expires_at, lease.expires_at))
            finally:
                # Revoke even after validation/HTTP/clock failures. A fresh bounded
                # cleanup call must not be suppressed by an expired read budget.
                if lease is not None:
                    try:
                        cleanup_start = budget._number(budget.clock.monotonic())
                    except Exception:
                        cleanup_start = None
                    confirmed = custody.revoke(lease, timeout=5)
                    cleanup_end = budget._number(budget.clock.monotonic())
                    need(confirmed is True and cleanup_start is not None)
                    need(0 <= cleanup_end - cleanup_start < 5)
                    cleanup = "CONFIRMED"
            _context(pins, observation, expected_reference, budget.tick())
            observation_times.append(int(budget.wall))
        need(budget.tick() < min(expiries))
        need(facts[0] == facts[1])
        need(
            binding
            == publisher.digest(
                {"pins": asdict(pins), "observation": asdict(observation)}
            )
        )
        return Result(
            Status.METADATA_ONLY_BOT_ATTRIBUTION_UNVERIFIED,
            "metadata_is_not_bot_attribution",
            cleanup,
            pins,
            observation,
            int(budget.start_wall),
            min(observation.expires_at, *expiries),
            facts[0],
            tuple(publisher.digest(asdict(f)) for f in facts),
            tuple(custody_digests),
            (
                "authenticated_application_and_installation_metadata",
                "authenticated_installation_repository_scope",
            )
            + (
                ("observed_public_bot_profile",)
                if observation.include_public_bot
                else ()
            ),
            tuple(observation_times),
        )
    except Exception:
        return Result(Status.BLOCKED, "metadata_observation_blocked", cleanup)
