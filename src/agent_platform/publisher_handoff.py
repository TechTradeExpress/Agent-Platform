"""PUB-01: byte-only intake and synthetic exact-tip Draft update, never live I/O.

No filesystem, Git, credential, HTTP, service or executable adapter is supplied.
Ports must be trusted offline fixtures. Python objects/digests are not authority.
"""

import base64
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from time import monotonic
from typing import Protocol

from agent_platform import draft_publisher as dp
from agent_platform import publisher_candidate as pc

VERSION = "AP-PH/1"
MAX_ARTIFACT = pc.MAX_DATA  # wire bytes, in addition to all unchanged CP-03 limits
MAX_ANCESTORS = 32


@dataclass(frozen=True, slots=True, repr=False)
class Policy:
    publication: dp.Policy
    pr_number: int
    artifact_sha256: str
    title: str
    body: str
    version: str = VERSION

    def __repr__(self):
        return "<offline handoff policy; redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class Request:
    policy: Policy
    candidate: pc.Candidate
    commit: str
    tree: str
    parent: str
    version: str = field(default=VERSION, init=False)

    def __repr__(self):
        return "<offline handoff request; redacted>"

    @property
    def digest(self):
        # The byte digest binds the entire validated candidate including identities.
        return _hash(
            _json(
                {
                    "policy": asdict(self.policy),
                    "commit": self.commit,
                    "tree": self.tree,
                    "parent": self.parent,
                }
            )
        )


@dataclass(frozen=True, slots=True)
class Snapshot:
    remote: dp.Observation
    pr: dp.PullRequest
    ancestors: tuple[pc.GitObject, ...]
    publisher_isolation_verified: bool
    app_merge_denied: bool
    atomic_compare_verified: bool


@dataclass(frozen=True, slots=True)
class Intent:
    request_digest: str
    sequence: int
    operation: str
    payload_digest: str
    version: str = field(default=VERSION, init=False)


@dataclass(frozen=True, slots=True)
class Result:
    status: str
    code: str
    completed_writes: int = 0
    version: str = field(default=VERSION, init=False)
    live: str = field(default="LIVE_NO_GO", init=False)
    host: str = field(default="HOST_NOT_RUN", init=False)
    gate_73: str = field(default="BLOCKED", init=False)
    live_authorized: bool = field(default=False, init=False)

    def encode(self):
        allowed = {
            ("BLOCKED", "invalid_artifact_or_policy"),
            ("BLOCKED", "precondition_failed"),
            ("BLOCKED", "live_requirements_unverified"),
            ("UNKNOWN_NEEDS_HUMAN", "reconciliation_required"),
            ("UPDATED_OFFLINE_FIXTURE", "verified_draft_update"),
        }
        _need((self.status, self.code) in allowed)
        _need(type(self.completed_writes) is int and 0 <= self.completed_writes <= 131)
        _need(self.version == VERSION and self.live == "LIVE_NO_GO")
        _need(self.host == "HOST_NOT_RUN" and self.gate_73 == "BLOCKED")
        _need(self.live_authorized is False)
        if self.status == "BLOCKED":
            _need(self.completed_writes == 0)
        if self.status == "UPDATED_OFFLINE_FIXTURE":
            _need(self.completed_writes >= 4)
        return _json(asdict(self))


class Admission(Protocol):
    def validate(self, request: Request) -> bool:
        """Fresh exact immutable effect, prior history, expiry/revocation/fence."""
        ...


class Journal(Protocol):
    """Exclusive externally anchored session for entire update, including reads.

    claim binds prior publication history and reserves stable repo+Issue, repo+ref
    and repo+PR guards across App/installation/namespace rotation. A retained
    attempt (even zero writes) cannot be claimed again. True means durable exact
    readback, never an in-memory assertion or proof of independent continuity.
    No implementation, reset, release or repair operation is provided here.
    """

    def claim(self, request: Request) -> bool: ...
    def unknown(self, intent: Intent) -> bool: ...
    def confirmed(self, intent: Intent, result_digest: str) -> bool: ...


class FixtureAPI(Protocol):
    """Synthetic domain interface only, no URL/method/token/command parameter.

    <=5s per call, <=60s total, <=64KiB ordinary responses, <=3x20 inventory.
    Canonical object reads have CP-03 limits. Ports enforce their own hard bounds;
    cooperative elapsed checks cannot interrupt blocked injected Python code.
    compare_exchange must atomically compare expected_old AND deny non-FF. A
    GET followed by unconditional PATCH is never a conforming implementation.
    """

    def observe(self, request: Request) -> Snapshot: ...
    def create_object(self, request: Request, obj: pc.GitObject) -> str: ...
    def read_object(self, request: Request, oid: str) -> pc.GitObject: ...
    def compare_exchange(self, request: Request) -> str: ...


def live_readiness() -> Result:
    # No policy, fixture PASS, flag or model assertion can activate production.
    return Result("BLOCKED", "live_requirements_unverified")


class _Stop(Exception):
    pass


def _need(ok):
    if not ok:
        raise _Stop("handoff_blocked")


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result)
        result[key] = value
    return result


def _bytes(value, limit):
    _need(type(value) is str and len(value) <= 4 * ((limit + 2) // 3))
    raw = base64.b64decode(value, validate=True)
    _need(len(raw) <= limit and base64.b64encode(raw).decode() == value)
    return raw


def intake(data: bytes, policy: Policy, *, now: int) -> Request | None:
    """Accept bounded bytes only; paths, bundles, links and archive extraction absent.

    Envelope: version, pr_number, parent, descriptor(base64), objects[{oid,data}].
    Descriptor retains CP-03 repo/Issue/scope/ref/expected-old/HEAD/tree/inventory.
    No supplied field may name a command, source directory or authority provider.
    """
    try:
        _need(type(data) is bytes and 0 < len(data) <= MAX_ARTIFACT)
        _need(type(policy) is Policy and policy.version == VERSION)
        _need(type(policy.artifact_sha256) is str)
        _need(re.fullmatch(r"[0-9a-f]{64}", policy.artifact_sha256))
        _need(_hash(data) == policy.artifact_sha256)
        _need(type(policy.publication) is dp.Policy)
        pub, p = policy.publication, policy.publication.candidate
        _need(pub.version == dp.VERSION and type(p) is pc.Policy)
        _need(p.operation == "update" and pc.SHA.fullmatch(p.expected_old))
        _need(p.expected_old != "0" * 40 and p.base_sha != "0" * 40)
        _need(type(now) is int and type(pub.expires) is int)
        _need(0 <= now < pub.expires <= now + 300)
        _need(
            all(
                type(n) is int and 0 < n < 2**63
                for n in (
                    policy.pr_number,
                    pub.app_id,
                    pub.installation_id,
                    pub.owner_id,
                    pub.bot_id,
                    pub.app_owner_id,
                    p.repo_id,
                    p.issue,
                    p.issue_id,
                )
            )
        )
        _need(
            type(pub.bot_login) is str
            and re.fullmatch(r"[A-Za-z0-9\[\]-]{1,100}", pub.bot_login)
        )
        _need(
            type(pub.authorization) is str
            and re.fullmatch(r"[0-9a-f]{64}", pub.authorization)
        )
        _need(
            type(policy.title) is str
            and re.fullmatch(r"[\x20-\x7e]{1,200}", policy.title)
        )
        _need(type(policy.body) is str and policy.body == f"Closes #{p.issue}\n")
        raw = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs)
        _need(
            type(raw) is dict
            and set(raw) == {"version", "pr_number", "parent", "descriptor", "objects"}
        )
        _need(raw["version"] == VERSION and type(raw["pr_number"]) is int)
        _need(raw["pr_number"] == policy.pr_number and raw["parent"] == p.expected_old)
        _need(type(raw["objects"]) is list and 0 < len(raw["objects"]) <= 130)
        objects = []
        for item in raw["objects"]:
            _need(type(item) is dict and set(item) == {"oid", "data"})
            objects.append(
                pc.GitObject(item["oid"], _bytes(item["data"], pc.MAX_OBJECT))
            )
        candidate = pc.Candidate(
            _bytes(raw["descriptor"], pc.MAX_DESCRIPTOR), tuple(objects)
        )
        checked = pc.verify(candidate, p)
        # CP-03 performs ALL content/lineage checks before this final refusal.
        # Preserve that refusal; this is not CP-03 approval of a remote update.
        _need(
            checked.status == "BLOCKED" and checked.code == "remote_update_unverified"
        )
        descriptor = json.loads(candidate.descriptor)
        _need(descriptor["commit"] != "0" * 40 and descriptor["tree"] != "0" * 40)
        return Request(
            policy, candidate, descriptor["commit"], descriptor["tree"], p.expected_old
        )
    except Exception:
        return None


def _lineage(snapshot, request):
    p = request.policy.publication.candidate
    chain = snapshot.ancestors
    _need(type(chain) is tuple and len(chain) <= MAX_ANCESTORS)
    _need(all(type(o) is pc.GitObject and type(o.canonical) is bytes for o in chain))
    _need(all(len(o.canonical) <= pc.MAX_OBJECT for o in chain))
    _need(sum(len(o.canonical) for o in chain) <= pc.MAX_DATA)
    tip = request.parent
    for obj in chain:
        _need(type(obj.oid) is str and obj.oid == tip and tip != p.base_sha)
        _need(hashlib.sha1(obj.canonical).hexdigest() == tip)
        header, sep, payload = obj.canonical.partition(b"\0")
        _need(sep and header == b"commit " + str(len(payload)).encode())
        # Bounded single-parent ASCII history only; no merges/extra headers.
        match = re.fullmatch(
            rb"tree [0-9a-f]{40}\nparent ([0-9a-f]{40})\n"
            rb"author [\x20-\x7e]{1,200}\ncommitter [\x20-\x7e]{1,200}\n"
            rb"\n[\x20-\x7e]{1,200}\n",
            payload,
        )
        _need(match is not None)
        tip = match[1].decode()
    _need(tip == p.base_sha)


def _check_snapshot(actual, request, tip):
    _need(type(actual) is Snapshot)
    _need(actual.publisher_isolation_verified is True)
    _need(actual.app_merge_denied is True and actual.atomic_compare_verified is True)
    policy, pub = request.policy, request.policy.publication
    p = pub.candidate
    expected = dp.Observation(
        p.repository,
        p.repo_id,
        pub.owner_id,
        p.issue,
        p.issue_id,
        p.scope,
        True,
        pub.app_id,
        pub.installation_id,
        pub.bot_id,
        pub.bot_login,
        dp.PERMISSIONS,
        (p.repo_id,),
        "main",
        p.base_sha,
        p.feature_ref,
        tip,
        (policy.pr_number,),
        True,
        True,
        True,
        pub.app_owner_id,
        pub.owner_id,
        "selected",
        True,
        (),
    )
    pr = dp.PullRequest(
        policy.pr_number,
        p.repo_id,
        p.repo_id,
        p.repo_id,
        p.feature_ref.removeprefix("refs/heads/"),
        tip,
        "main",
        p.base_sha,
        pub.bot_id,
        pub.bot_login,
        pub.app_id,
        True,
        True,
        policy.title,
        policy.body,
        (p.issue_id,),
    )
    _need(dp._same(actual.remote, expected) and dp._same(actual.pr, pr))
    _lineage(actual, request)


def update_fixture(
    data: bytes,
    policy: Policy,
    *,
    now: int,
    admission: Admission,
    journal: Journal,
    api: FixtureAPI,
) -> Result:
    """One offline attempt, at most 130 object writes and one atomic ref update.

    No PR mutation: updating its existing head ref is the only final effect.
    Any claim uncertainty or later failure stops, preserving UNKNOWN/history.
    Ordinary errors are fixed/redacted; BaseException propagates, never retries.
    """
    request = intake(data, policy, now=now)
    if request is None:
        return Result("BLOCKED", "invalid_artifact_or_policy")
    started, claimed, completed = monotonic(), False, 0
    pub = policy.publication

    def call(fn, *args):
        before = monotonic()
        _need(0 <= before - started < min(60, pub.expires - now))
        value = fn(*args)
        after = monotonic()
        _need(
            0 <= after - before <= 5
            and 0 <= after - started < min(60, pub.expires - now)
        )
        return value

    def observe(tip):
        _need(call(admission.validate, request) is True)
        _check_snapshot(call(api.observe, request), request, tip)

    def begin(operation, payload):
        intent = Intent(request.digest, completed + 1, operation, _hash(payload))
        _need(call(journal.unknown, intent) is True)
        return intent

    def confirm(intent, value):
        nonlocal completed
        _need(call(journal.confirmed, intent, _hash(value)) is True)
        completed += 1

    try:
        _need(call(admission.validate, request) is True)
        claimed = True  # A failing claim may have already persisted its intent.
        _need(call(journal.claim, request) is True)
        observe(request.parent)
        objects = sorted(
            request.candidate.objects,
            key=lambda o: (
                {b"blob": 0, b"tree": 1, b"commit": 2}[o.canonical.split(b" ", 1)[0]],
                o.oid,
            ),
        )
        for obj in objects:
            observe(request.parent)
            intent = begin("create_object", obj.canonical)
            observe(request.parent)
            oid = call(api.create_object, request, obj)
            _need(type(oid) is str and oid == obj.oid)
            _need(dp._same(call(api.read_object, request, oid), obj))
            confirm(intent, bytes.fromhex(oid))
        # Revalidate full object closure before the only ref effect.
        for obj in objects:
            _need(dp._same(call(api.read_object, request, obj.oid), obj))
        observe(request.parent)
        intent = begin(
            "compare_exchange",
            _json(
                {
                    "repo_id": pub.candidate.repo_id,
                    "ref": pub.candidate.feature_ref,
                    "before": request.parent,
                    "after": request.commit,
                    "pr": policy.pr_number,
                }
            ),
        )
        observe(request.parent)
        tip = call(api.compare_exchange, request)
        _need(type(tip) is str and tip == request.commit)
        # Independent complete reads, not the CAS response or a PR-number echo.
        for _ in range(2):
            observe(request.commit)
        for obj in objects:
            _need(dp._same(call(api.read_object, request, obj.oid), obj))
        confirm(intent, bytes.fromhex(tip))
        return Result("UPDATED_OFFLINE_FIXTURE", "verified_draft_update", completed)
    except Exception:
        return Result(
            "UNKNOWN_NEEDS_HUMAN" if claimed else "BLOCKED",
            "reconciliation_required" if claimed else "precondition_failed",
            completed,
        )
