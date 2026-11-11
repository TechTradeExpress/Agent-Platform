"""CP-05: synthetic-only first publication transaction; no network implementation.

Injected ports belong to a trusted control-plane process, never to candidate code.
No serializer, credential provider or runtime entrypoint is supplied.
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from time import monotonic
from typing import Protocol

from agent_platform import publisher_candidate as pc

VERSION = "AP-DP/1"
PERMISSIONS = (("contents", "write"), ("metadata", "read"), ("pull_requests", "write"))


@dataclass(frozen=True, slots=True)
class Policy:
    candidate: pc.Policy
    app_id: int
    installation_id: int
    owner_id: int
    bot_id: int
    bot_login: str
    authorization: str  # opaque trusted admission reference, never emitted
    expires: int
    app_owner_id: int
    version: str = VERSION


@dataclass(frozen=True, slots=True)
class Request:
    """Exact immutable payload approved by the separate admission port."""

    policy: Policy
    candidate_digest: str
    commit: str
    tree: str
    title: str
    body: str
    version: str = VERSION


@dataclass(frozen=True, slots=True)
class Observation:
    """Complete independent bounded snapshot; no arbitrary API response dictionaries."""

    repository: str
    repo_id: int
    owner_id: int
    issue: int
    issue_id: int
    scope: str
    issue_open: bool
    app_id: int
    installation_id: int
    bot_id: int
    bot_login: str
    permissions: tuple[tuple[str, str], ...]
    repositories: tuple[int, ...]
    base_branch: str
    base_sha: str
    feature_ref: str
    feature_sha: str | None
    prs: tuple[int, ...]  # ALL open AND closed PRs for this Issue OR feature ref
    complete: bool
    app_attribution_verified: bool
    governance_verified: bool
    app_owner_id: int
    installation_account_id: int
    repository_selection: str
    installation_active: bool
    events: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PullRequest:
    number: int
    repo_id: int
    head_repo_id: int
    base_repo_id: int
    head_ref: str
    head_sha: str
    base_ref: str
    base_sha: str
    author_id: int
    author_login: str
    app_id: int
    draft: bool
    open: bool
    title: str
    body: str
    linked_issue_ids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class Intent:
    request_digest: str
    sequence: int
    operation: str
    payload_digest: str
    version: str = VERSION


@dataclass(frozen=True, slots=True)
class State:
    """Ephemeral immutable machine snapshot; durable authority belongs to Journal."""

    phase: str = "VALIDATED"
    completed_writes: int = 0
    pending: Intent | None = None
    version: str = field(default=VERSION, init=False)

    def claiming(self):
        _require(self.phase == "VALIDATED")
        return State("CLAIMING")

    def admitted(self):
        _require(self.phase == "CLAIMING")
        return State("ACTIVE")

    def begin(self, intent):
        _require(self.phase == "ACTIVE" and self.pending is None)
        _require(intent.sequence == self.completed_writes + 1)
        _require(intent.operation in {"create_object", "create_ref", "create_draft"})
        return State("UNKNOWN", self.completed_writes, intent)

    def confirmed(self, intent):
        _require(self.phase == "UNKNOWN" and self.pending == intent)
        return State("ACTIVE", self.completed_writes + 1)

    def complete(self):
        _require(self.phase == "ACTIVE" and self.completed_writes >= 3)
        return State("COMPLETE", self.completed_writes)

    @property
    def uncertain(self):
        # Claim intent/history is itself irreversible, even without GitHub writes.
        return self.phase != "VALIDATED"


@dataclass(frozen=True, slots=True)
class Result:
    status: str
    code: str
    completed_writes: int = 0
    pr_number: int | None = None
    version: str = field(default=VERSION, init=False)
    live_authorized: bool = field(default=False, init=False)


class Admission(Protocol):
    def validate(self, request: Request) -> bool:
        """Fresh authenticated exact-payload authority, expiry/fence/#73 checks."""
        ...


class Journal(Protocol):
    """Externally owned exclusive session with independent continuity anchor.

    claim atomically reserves BOTH repository/Issue AND repository/ref across policy/App
    rotation. False means retained history/conflict. It never resets history.
    Every True below means durable independently confirmed exact readback.
    Session must remain exclusive through the entire publish() call, including
    observation and crash; release never erases claim/UNKNOWN/replay history.
    """

    def claim(self, repository: int, issue: int, ref: str, digest: str) -> bool: ...
    def unknown(self, intent: Intent) -> bool: ...
    def confirmed(self, intent: Intent, result_digest: str) -> bool: ...


class API(Protocol):
    """Fixed synthetic GitHub domain port, NOT an HTTP/proxy client.

    Trusted adapter must enforce <=64KiB ordinary responses, complete enumeration
    <=3 pages of 20, <=5s calls and no redirects/retries. Object reads are bounded
    canonical artifact reads (<=256KiB/object, <=1MiB per inventory), not ordinary
    JSON responses. No live adapter is supplied or admitted by this module.
    """

    def observe(self, request: Request) -> Observation: ...
    def create_object(self, request: Request, obj: pc.GitObject) -> str: ...
    def read_object(self, request: Request, oid: str) -> pc.GitObject: ...
    def create_ref(self, request: Request) -> str:
        """Atomic create-if-absent ONLY; existing ref is a conflict, never update."""
        ...

    def create_draft(self, request: Request) -> int: ...
    def read_pr(self, request: Request, number: int) -> PullRequest: ...


class _Stop(Exception):
    pass


def _require(ok):
    if not ok:
        raise _Stop


def _same(actual, expected):
    """Strict recursive equality: bool never substitutes for numeric identity."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, tuple):
        return len(actual) == len(expected) and all(
            _same(a, e) for a, e in zip(actual, expected, strict=True)
        )
    if hasattr(expected, "__dataclass_fields__"):
        return all(
            _same(getattr(actual, k), getattr(expected, k))
            for k in expected.__dataclass_fields__
        )
    return actual == expected


def _digest(value):
    return hashlib.sha256(value).hexdigest()


def _request_digest(r):
    # Explicit immutable scalar/tuple schema, no candidate-supplied authority.
    from dataclasses import asdict

    return _digest(
        json.dumps(asdict(r), sort_keys=True, separators=(",", ":")).encode()
    )


def validate(candidate: pc.Candidate, policy: Policy, now: int) -> Request | None:
    """Pure structural validation, separate from authenticated admission."""
    try:
        _require(type(policy) is Policy and policy.version == VERSION)
        p = policy.candidate
        _require(pc.verify(candidate, p).status == "VERIFIED_OFFLINE_FIXTURE")
        _require(p.operation == "create" and p.expected_old == "ABSENT")
        _require(type(now) is int and type(policy.expires) is int)
        _require(0 <= now < policy.expires <= now + 300)
        _require(
            all(
                type(n) is int and 0 < n < 2**63
                for n in (
                    policy.app_id,
                    policy.installation_id,
                    policy.owner_id,
                    policy.bot_id,
                    policy.app_owner_id,
                    p.repo_id,
                    p.issue,
                    p.issue_id,
                )
            )
        )
        _require(type(policy.bot_login) is str and 0 < len(policy.bot_login) <= 100)
        _require(
            all(c.isascii() and (c.isalnum() or c in "-[]") for c in policy.bot_login)
        )
        _require(
            type(policy.authorization) is str
            and re.fullmatch(r"[a-f0-9]{64}", policy.authorization)
        )
        d = json.loads(candidate.descriptor)
        digest = hashlib.sha256(candidate.descriptor)
        for obj in sorted(candidate.objects, key=lambda o: o.oid):
            digest.update(bytes.fromhex(obj.oid))
            digest.update(len(obj.canonical).to_bytes(8, "big"))
            digest.update(obj.canonical)
        return Request(
            policy,
            digest.hexdigest(),
            d["commit"],
            d["tree"],
            f"Issue #{p.issue}: proposed changes",
            f"Closes #{p.issue}\n",
        )
    except Exception:
        return None


class RouteOperation(Enum):
    REPOSITORY = "repository"
    ISSUE = "issue"
    INSTALLATION = "installation"
    BASE = "base"
    FEATURE = "feature"
    LIST_PRS = "list_prs"
    READ_OBJECT = "read_object"
    CREATE_BLOB = "create_blob"
    CREATE_TREE = "create_tree"
    CREATE_COMMIT = "create_commit"
    CREATE_REF = "create_ref"
    CREATE_DRAFT = "create_draft"
    READ_PR = "read_pr"


@dataclass(frozen=True, slots=True)
class Route:
    """Synthetic route metadata only; NOT an HTTP request or payload adapter."""

    operation: RouteOperation
    method: str
    path: str
    origin: str = "https://api.github.com"
    query: tuple[tuple[str, str], ...] = ()
    ref: str | None = None
    sha: str | None = None
    draft: bool | None = None
    force: bool | None = None  # always forbidden, even False
    version: str = field(default=VERSION, init=False)
    semantics_verified: bool = field(default=False, init=False)


def allowed_routes(
    candidate: pc.Candidate, policy: Policy, *, now: int, pr_number: int | None = None
) -> tuple[Route, ...]:
    """Closed synthetic method/path profile, without I/O or publication authority.

    PR number is a separately observed exact pin, never an arbitrary URL. Unknown
    payloads cannot be expressed here. Object wire encoding, native Issue linkage,
    atomic create semantics and complete observation transport remain UNVERIFIED.
    """
    request = validate(candidate, policy, now)
    if request is None:
        return ()
    if pr_number is not None and not (type(pr_number) is int and 0 < pr_number < 2**63):
        return ()
    p = policy.candidate
    # Conservative path-segment grammar; even caller pins cannot insert traversal.
    if len(p.repository) > 201 or not re.fullmatch(
        r"[A-Za-z0-9_-]+/[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*", p.repository
    ):
        return ()
    root = f"/repos/{p.repository}"
    op = RouteOperation
    routes = [
        Route(op.REPOSITORY, "GET", root),
        Route(op.ISSUE, "GET", f"{root}/issues/{p.issue}"),
        Route(op.INSTALLATION, "GET", f"/app/installations/{policy.installation_id}"),
        Route(op.BASE, "GET", f"{root}/git/ref/heads/main"),
        Route(op.FEATURE, "GET", f"{root}/git/ref/{p.feature_ref[5:]}"),
        Route(op.CREATE_BLOB, "POST", f"{root}/git/blobs"),
        Route(op.CREATE_TREE, "POST", f"{root}/git/trees"),
        Route(op.CREATE_COMMIT, "POST", f"{root}/git/commits"),
        Route(
            op.CREATE_REF,
            "POST",
            f"{root}/git/refs",
            ref=p.feature_ref,
            sha=request.commit,
        ),
        Route(
            op.CREATE_DRAFT,
            "POST",
            f"{root}/pulls",
            ref=p.feature_ref,
            sha=request.commit,
            draft=True,
        ),
    ]
    for page in range(1, 4):
        routes.append(
            Route(
                op.LIST_PRS,
                "GET",
                f"{root}/pulls",
                query=(
                    ("state", "all"),
                    ("per_page", "20"),
                    ("page", str(page)),
                ),
            )
        )
    for obj in candidate.objects:
        kind = obj.canonical.split(b" ", 1)[0].decode()
        routes.append(Route(op.READ_OBJECT, "GET", f"{root}/git/{kind}s/{obj.oid}"))
    if pr_number is not None:
        routes.append(Route(op.READ_PR, "GET", f"{root}/pulls/{pr_number}"))
    return tuple(routes)


def route_allowed(
    candidate: pc.Candidate,
    policy: Policy,
    route: Route,
    *,
    now: int,
    pr_number: int | None = None,
) -> bool:
    """Deny unknown methods, origins, paths, query fields and metadata by default."""
    if type(route) is not Route:
        return False
    return any(
        _same(route, expected)
        for expected in allowed_routes(candidate, policy, now=now, pr_number=pr_number)
    )


def publish(
    candidate: pc.Candidate,
    policy: Policy,
    *,
    now: int,
    admission: Admission,
    journal: Journal,
    api: API,
) -> Result:
    """One bounded initial attempt. Any retained claim requires human reconciliation.

    Ordinary exceptions are redacted. Process death/BaseException propagates with
    the already durable UNKNOWN retained; a subsequent invocation cannot replay.
    No journal/authority implementation or live capability is provided.
    """
    request = validate(candidate, policy, now)
    if request is None:
        return Result("BLOCKED", "invalid_candidate_or_policy")
    started = monotonic()
    state = State()
    digest = _request_digest(request)
    p = policy.candidate

    def call(fn, *args):
        before = monotonic()
        _require(before - started < min(60, policy.expires - now))
        result = fn(*args)
        after = monotonic()
        _require(
            after - before <= 5 and after - started < min(60, policy.expires - now)
        )
        return result

    def observe(ref, prs=()):
        _require(call(admission.validate, request) is True)
        expected = Observation(
            p.repository,
            p.repo_id,
            policy.owner_id,
            p.issue,
            p.issue_id,
            p.scope,
            True,
            policy.app_id,
            policy.installation_id,
            policy.bot_id,
            policy.bot_login,
            PERMISSIONS,
            (p.repo_id,),
            "main",
            p.base_sha,
            p.feature_ref,
            ref,
            prs,
            True,
            True,
            True,
            policy.app_owner_id,
            policy.owner_id,
            "selected",
            True,
            (),
        )
        actual = call(api.observe, request)
        _require(_same(actual, expected))

    def write(operation, payload, fn, *args):
        nonlocal state
        intent = Intent(digest, state.completed_writes + 1, operation, _digest(payload))
        state = state.begin(intent)  # a failed journal write can have durable effects
        _require(call(journal.unknown, intent) is True)
        result = call(fn, request, *args)
        return intent, result

    def confirm(intent, value):
        nonlocal state
        _require(call(journal.confirmed, intent, _digest(value)) is True)
        state = state.confirmed(intent)

    try:
        _require(call(admission.validate, request) is True)
        state = state.claiming()
        _require(call(journal.claim, p.repo_id, p.issue, p.feature_ref, digest) is True)
        state = state.admitted()
        observe(None)
        # Upload dependencies first, ignoring worker-supplied object order.
        objects = sorted(
            candidate.objects,
            key=lambda o: (
                {b"blob": 0, b"tree": 1, b"commit": 2}[o.canonical.split(b" ", 1)[0]],
                o.oid,
            ),
        )
        for obj in objects:
            observe(None)
            intent, oid = write("create_object", obj.canonical, api.create_object, obj)
            _require(type(oid) is str and oid == obj.oid)
            observed = call(api.read_object, request, obj.oid)
            _require(type(observed) is pc.GitObject and observed == obj)
            confirm(intent, bytes.fromhex(oid))
        observe(None)
        intent, tip = write(
            "create_ref",
            p.feature_ref.encode() + bytes.fromhex(request.commit),
            api.create_ref,
        )
        _require(type(tip) is str and tip == request.commit)
        observe(request.commit)
        # Reread canonical objects, including exact tree and parent bytes.
        for obj in objects:
            observed = call(api.read_object, request, obj.oid)
            _require(type(observed) is pc.GitObject and observed == obj)
        confirm(intent, bytes.fromhex(tip))
        observe(request.commit)
        intent, number = write(
            "create_draft",
            (request.title + "\n" + request.body).encode(),
            api.create_draft,
        )
        _require(type(number) is int and 0 < number < 2**63)
        expected = PullRequest(
            number,
            p.repo_id,
            p.repo_id,
            p.repo_id,
            p.feature_ref.removeprefix("refs/heads/"),
            request.commit,
            "main",
            p.base_sha,
            policy.bot_id,
            policy.bot_login,
            policy.app_id,
            True,
            True,
            request.title,
            request.body,
            (p.issue_id,),
        )
        # Two independent reads, not a trusted create-response echo.
        for _ in range(2):
            actual = call(api.read_pr, request, number)
            _require(_same(actual, expected))
            observe(request.commit, (number,))
        confirm(intent, str(number).encode())
        state = state.complete()
        return Result(
            "PUBLISHED_OFFLINE_FIXTURE",
            "verified_draft",
            state.completed_writes,
            number,
        )
    except Exception:
        return Result(
            "UNKNOWN_NEEDS_HUMAN" if state.uncertain else "BLOCKED",
            "reconciliation_required" if state.uncertain else "precondition_failed",
            state.completed_writes,
        )
