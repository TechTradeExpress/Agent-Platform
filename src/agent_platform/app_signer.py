"""AP-AS/1 fixed RS256 signer session. No key loader or admission producer."""

import threading
from dataclasses import asdict, dataclass, replace
from typing import Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from . import app_api_adapter as adapter
from . import app_metadata as metadata
from . import issues, publisher


class SignerError(Exception):
    def __init__(self):
        super().__init__("signer_blocked")


def need(value):
    if not value:
        raise SignerError()


@dataclass(frozen=True, slots=True)
class Peer:
    pid: int
    uid: int
    gid: int

    def __post_init__(self):
        need(type(self.pid) is int and 0 < self.pid < 2**31)
        need(all(type(x) is int and 0 <= x < 2**32 for x in (self.uid, self.gid)))


@dataclass(frozen=True, slots=True)
class Policy:
    app_id: int
    target_sha256: str
    key_sha256: str
    custody_peer: Peer
    signer_peer: Peer
    purpose: str = "github_app_metadata"
    schema_version: int = 1

    def __post_init__(self):
        need(type(self.schema_version) is int and self.schema_version == 1)
        need(issues.positive_int(self.app_id))
        need(self.purpose == "github_app_metadata")
        need(
            publisher.hex_digest(self.target_sha256)
            and publisher.hex_digest(self.key_sha256)
        )
        for peer in (self.custody_peer, self.signer_peer):
            need(type(peer) is Peer)
            replace(peer)

    @property
    def digest(self):
        return publisher.digest(asdict(self))


@dataclass(frozen=True, slots=True)
class Pass:
    request_id: str
    binding_sha256: str

    def __post_init__(self):
        need(
            publisher.hex_digest(self.request_id)
            and publisher.hex_digest(self.binding_sha256)
        )


@dataclass(frozen=True, slots=True)
class Admission:
    """Independent authority record, never decoded from signer IPC/model JSON."""

    run_id: str
    nonce: str
    policy_sha256: str
    issued_at: int
    expires_at: int
    passes: tuple[Pass, Pass]

    def __post_init__(self):
        need(
            all(
                publisher.hex_digest(x)
                for x in (self.run_id, self.nonce, self.policy_sha256)
            )
        )
        need(type(self.issued_at) is type(self.expires_at) is int)
        need(0 <= self.issued_at < self.expires_at <= self.issued_at + 300)
        need(type(self.passes) is tuple and len(self.passes) == 2)
        for item in self.passes:
            need(type(item) is Pass)
            replace(item)
        need(len({p.request_id for p in self.passes}) == 2)
        need(len({p.binding_sha256 for p in self.passes}) == 2)

    @property
    def digest(self):
        return publisher.digest(asdict(self))


@dataclass(frozen=True, slots=True)
class Request:
    run_id: str
    nonce: str
    request_id: str
    pass_binding: str
    policy_sha256: str
    claims: adapter.Claims

    def __post_init__(self):
        need(
            all(
                publisher.hex_digest(x)
                for x in (
                    self.run_id,
                    self.nonce,
                    self.request_id,
                    self.pass_binding,
                    self.policy_sha256,
                )
            )
        )
        need(type(self.claims) is adapter.Claims)
        replace(self.claims)

    @property
    def digest(self):
        return publisher.digest(asdict(self))


class Authority(Protocol):
    """External authenticated approval + durable global consume boundary.

    lookup must return only independently approved records, or fail on missing /
    lost / uncertain history. consume atomically retains UNKNOWN before crypto,
    never grants the same request/pass twice across sessions/restarts and enforces
    the exact two-pass order/quota globally. No implementation/default is supplied.
    """

    def lookup(self, run_id: str) -> Admission: ...
    def consume(self, admission: Admission, request: Request, peer: Peer) -> None: ...
    def finish(self, admission: Admission, request: Request, outcome: str) -> None: ...


class CredentialProvider(Protocol):
    """Trusted signer-side in-memory key only; no PEM/path/env/FD loader here."""

    def private_key(self, app_id: int, key_sha256: str) -> rsa.RSAPrivateKey: ...


def public_fingerprint(public_key):
    need(isinstance(public_key, rsa.RSAPublicKey))
    need(2048 <= public_key.key_size <= 4096)
    need(public_key.public_numbers().e == 65537)
    import hashlib

    return hashlib.sha256(
        public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).hexdigest()


class _SignedJWT:
    __slots__ = ("_value",)

    def __init__(self, value):
        need(type(value) is str and 0 < len(value.encode("ascii")) <= 8192)
        self._value = value

    def __repr__(self):
        return "<redacted signer response>"

    def __reduce_ex__(self, protocol):
        raise SignerError()

    def take_for_custody(self):
        need(self._value is not None)
        value, self._value = self._value, None
        return value


class SignerSession:
    """One independently admitted run, max two signs; no automatic session renewal.

    Only the IPC handler calls _issue after kernel peer verification. Python
    privacy is not an OS boundary. Reconstructing this object cannot reset the
    mandatory authority's global durable replay/quota state.
    """

    def __init__(
        self,
        *,
        policy,
        approved_run_id,
        authority: Authority,
        credentials: CredentialProvider,
        clock=None,
    ):
        self._closed = True
        failed = False
        try:
            need(type(policy) is Policy)
            replace(policy)
            need(publisher.hex_digest(approved_run_id))
            need(authority is not None and credentials is not None)
            admission = authority.lookup(approved_run_id)
            need(type(admission) is Admission)
            replace(admission)
            need(
                admission.run_id == approved_run_id
                and admission.policy_sha256 == policy.digest
            )
            self._clock = metadata.Clock() if clock is None else clock
            now = metadata._Budget._number(self._clock.wall())
            need(admission.issued_at <= now < admission.expires_at)
            key = credentials.private_key(policy.app_id, policy.key_sha256)
            need(isinstance(key, rsa.RSAPrivateKey))
            need(public_fingerprint(key.public_key()) == policy.key_sha256)
            self._key, self._policy, self._admission = key, policy, admission
            self._policy_pin, self._admission_pin = policy.digest, admission.digest
            self._authority, self._next, self._closed = authority, 0, False
            self._lock = threading.Lock()
        except BaseException:
            failed = True
        if failed:
            raise SignerError()

    def __repr__(self):
        return "<admitted signer session; key redacted>"

    def __reduce_ex__(self, protocol):
        raise SignerError()

    def sign(self, claims, *, timeout):
        # Current AP-AL/1 Signer API lacks independent request/pass context.
        # Do not infer it from a call count, model data or syntactically valid JWT.
        raise SignerError()

    def _issue(self, request, peer, deadline):
        need(not self._closed and type(request) is Request)
        replace(request)
        need(type(peer) is Peer and peer == self._policy.custody_peer)
        need(
            self._policy.digest == self._policy_pin
            and self._admission.digest == self._admission_pin
        )
        record = self._authority.lookup(self._admission.run_id)
        need(type(record) is Admission and record == self._admission)
        now = metadata._Budget._number(self._clock.wall())
        deadline.remaining()
        need(self._admission.issued_at <= now < self._admission.expires_at)
        need(
            request.run_id == self._admission.run_id
            and request.nonce == self._admission.nonce
        )
        need(request.policy_sha256 == self._policy_pin)
        need(self._next < 2)
        slot = self._admission.passes[self._next]
        need(
            request.request_id == slot.request_id
            and request.pass_binding == slot.binding_sha256
        )
        claims = request.claims
        need(claims.app_id == self._policy.app_id)
        need(claims.issued_at <= now < claims.expires_at <= now + 300)
        need(
            now - claims.issued_at <= 60
            and claims.expires_at <= self._admission.expires_at
        )
        self._authority.consume(
            self._admission, request, peer
        )  # Durable UNKNOWN before sign.
        deadline.remaining()
        self._next += 1  # Consumed even if crypto, finish or send fails; never retry.
        header = adapter._b64(publisher.encoded({"alg": "RS256", "typ": "JWT"}))
        payload = adapter._b64(publisher.encoded(claims.payload))
        message = (header + "." + payload).encode("ascii")
        signature = self._key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        deadline.remaining()
        result = _SignedJWT(message.decode("ascii") + "." + adapter._b64(signature))
        self._authority.finish(self._admission, request, "SIGNED")
        deadline.remaining()
        return result

    def close(self):
        self._closed = True
        self._key = None
