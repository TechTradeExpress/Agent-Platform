"""AP-AL/1 fixed-purpose custody/metadata adapter, no enabled live entrypoint."""

import base64
import json
import re
import uuid
from dataclasses import asdict, dataclass, replace
from typing import Protocol

from . import app_metadata as metadata
from . import issues, publisher
from .app_api_wire import (
    AdapterError,
    Operation,
    _Deadline,
    _Reply,
    _Secret,
    need,
    route,
)

MAX_EVENTS = 128


def _json(raw):
    need(type(raw) is bytes and 0 < len(raw) <= metadata.MAX_BODY)
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=issues.unique_object,
        parse_constant=issues.invalid_constant,
    )
    need(type(value) is dict)
    return value


def _b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@dataclass(frozen=True, slots=True)
class Claims:
    app_id: int
    issued_at: int
    expires_at: int

    def __post_init__(self):
        need(issues.positive_int(self.app_id))
        need(type(self.issued_at) is type(self.expires_at) is int)
        need(0 <= self.issued_at < self.expires_at <= self.issued_at + 600)

    @property
    def payload(self):
        return {"iss": str(self.app_id), "iat": self.issued_at, "exp": self.expires_at}


class Signer(Protocol):
    """External fixed-purpose RS256 signer. No implementation, key path or fallback.

    Must independently validate App/time policy, only sign this fixed JWT format,
    and return a JWT in memory. Cannot accept arbitrary payloads/algorithms.
    """

    def sign(self, claims: Claims, *, timeout: float) -> str: ...


def _jwt(raw, claims, now):
    need(type(raw) is str and len(raw) <= 8192)
    parts = raw.split(".")
    need(len(parts) == 3)
    decoded = []
    for part in parts:
        need(re.fullmatch(r"[A-Za-z0-9_-]+", part))
        data = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
        need(_b64(data) == part)
        decoded.append(data)
    need(_json(decoded[0]) == {"alg": "RS256", "typ": "JWT"})
    payload = _json(decoded[1])
    need(type(payload.get("iat")) is type(payload.get("exp")) is int)
    need(payload == claims.payload and decoded[2])
    need(claims.issued_at <= now < claims.expires_at and now - claims.issued_at <= 60)
    # Shape/claim checks do not verify RSA; the separately trusted signer owns it.
    return _Secret(raw, "app_jwt")


@dataclass(frozen=True, slots=True)
class Event:
    lease_id: str
    binding_sha256: str
    source_id: str
    repo_id: int
    app_id: int
    installation_id: int
    state: str
    observed_at: int
    schema_version: int = 1

    def __post_init__(self):
        need(type(self.schema_version) is int and self.schema_version == 1)
        need(
            all(
                publisher.hex_digest(x)
                for x in (self.lease_id, self.binding_sha256, self.source_id)
            )
        )
        need(
            all(
                issues.positive_int(x)
                for x in (self.repo_id, self.app_id, self.installation_id)
            )
        )
        need(self.state in {"UNKNOWN", "ISSUED", "REVOKE_UNKNOWN", "REVOKED"})
        need(type(self.observed_at) is int and self.observed_at >= 0)


class Journal(Protocol):
    """External, exclusive, durable, complete nonsecret custody history.

    append must fsync/confirm before returning. Missing/uncertain state must not
    become an empty snapshot. No default memory/disk sink, cleanup or reset API.
    Future trusted host supplies independently reviewed durable storage/locking.
    """

    complete: bool

    def snapshot(self) -> tuple[Event, ...]: ...
    def append(self, event: Event) -> None: ...


def _history(journal):
    need(journal.complete is True)
    events = journal.snapshot()
    need(type(events) is tuple and len(events) <= MAX_EVENTS)
    latest, bindings = {}, set()
    transitions = {
        "UNKNOWN": {"ISSUED", "REVOKE_UNKNOWN"},
        "ISSUED": {"REVOKE_UNKNOWN"},
        "REVOKE_UNKNOWN": {"REVOKED"},
        "REVOKED": set(),
    }
    last_time = 0
    for event in events:
        need(type(event) is Event)
        replace(event)
        need(event.observed_at >= last_time)
        last_time = event.observed_at
        previous = latest.get(event.lease_id)
        if previous is None:
            need(event.state == "UNKNOWN" and event.binding_sha256 not in bindings)
            bindings.add(event.binding_sha256)
        else:
            need(event.state in transitions[previous.state])
            need(
                replace(previous, state=event.state, observed_at=event.observed_at)
                == event
            )
        latest[event.lease_id] = event
    return events, latest, bindings


class _Entry:
    def __init__(self, lease_id, binding, jwt, claims):
        self.lease_id, self.binding = lease_id, binding
        self.jwt, self.claims, self.token, self.lease = jwt, claims, None, None
        self.used = set()
        self.revoke_attempted = False

    def __repr__(self):
        return "<redacted custody entry>"

    def __reduce_ex__(self, protocol):
        raise AdapterError()


class Adapter:
    """Explicitly supplied pins/signer/wire/journal only. Constructor does no I/O
    except trusted journal reads. No host config, credentials, default provider,
    execution, CLI or repository publication integration is supplied.
    """

    def __init__(
        self, *, pins, source_id, signer: Signer, wire, journal: Journal, clock=None
    ):
        failed = False
        try:
            self._initialize(pins, source_id, signer, wire, journal, clock)
        except Exception:
            failed = True
        if failed:
            raise AdapterError()

    def _initialize(self, pins, source_id, signer, wire, journal, clock):
        need(type(pins) is metadata.Pins)
        replace(pins)
        need(publisher.hex_digest(source_id))
        need(signer is not None and wire is not None)
        self._pins, self._pin = pins, publisher.digest(asdict(pins))
        self._source, self._signer, self._wire, self._journal = (
            source_id,
            signer,
            wire,
            journal,
        )
        self._clock = metadata.Clock() if clock is None else clock
        self._events, latest, _ = _history(journal)
        need(all(e.state == "REVOKED" for e in latest.values()))
        self._active = None
        self._poisoned = False

    def __repr__(self):
        return "<App metadata adapter; credentials redacted>"

    def __reduce_ex__(self, protocol):
        raise AdapterError()

    def _check(self):
        need(not self._poisoned)
        need(type(self._pins) is metadata.Pins)
        replace(self._pins)
        need(publisher.digest(asdict(self._pins)) == self._pin)
        events, latest, bindings = _history(self._journal)
        need(events == self._events)
        now = metadata._Budget._number(self._clock.wall())
        need(not events or now >= events[-1].observed_at)
        return latest, bindings

    def _event(self, entry, state):
        now = int(metadata._Budget._number(self._clock.wall()))
        event = Event(
            entry.lease_id,
            entry.binding,
            self._source,
            self._pins.repo_id,
            self._pins.app.app_id,
            self._pins.installation.identifier,
            state,
            now,
        )
        need(not self._events or now >= self._events[-1].observed_at)
        need(len(self._events) < MAX_EVENTS)
        need(self._journal.complete is True)
        need(self._journal.snapshot() == self._events)
        self._journal.append(event)  # Durable UNKNOWN before POST; no write on failure.
        expected = (*self._events, event)
        need(self._journal.snapshot() == expected)
        self._events = expected

    def _preflight(self, jwt, deadline):
        # Reuse AP-AM normalization checks before requesting an unrestricted token.
        pins = self._pins
        raw = _json(
            self._wire.exchange(
                Operation.APP, pins, jwt, timeout=deadline.remaining()
            ).body
        )
        need(type(raw["id"]) is int and raw["id"] == pins.app.app_id)
        need(raw["slug"] == pins.app.slug)
        metadata._principal(raw["owner"], pins.app.owner, pins.app.owner_type)
        metadata._grants(raw, pins)
        raw = _json(
            self._wire.exchange(
                Operation.INSTALLATION, pins, jwt, timeout=deadline.remaining()
            ).body
        )
        need(type(raw["id"]) is int and raw["id"] == pins.installation.identifier)
        need(type(raw["app_id"]) is int and raw["app_id"] == pins.app.app_id)
        need(
            raw["app_slug"] == pins.app.slug
            and raw["repository_selection"] == "selected"
        )
        metadata._principal(
            raw["account"], pins.installation.account, pins.installation.account_type
        )
        need(type(raw["target_id"]) is int)
        need(raw["target_id"] == pins.installation.account.identifier)
        need(raw["target_type"] == pins.installation.account_type)
        need(raw["suspended_at"] is raw["suspended_by"] is None)
        metadata._grants(raw, pins)
        deadline.remaining()

    def acquire(self, pins, binding_sha256, *, timeout):
        entry = None
        failed = False
        try:
            self._check()
            need(type(pins) is metadata.Pins and pins == self._pins)
            need(publisher.hex_digest(binding_sha256) and self._active is None)
            _, latest, bindings = _history(self._journal)
            need(all(e.state == "REVOKED" for e in latest.values()))
            need(binding_sha256 not in bindings and len(self._events) <= MAX_EVENTS - 4)
            deadline = _Deadline(self._clock, timeout)
            now = int(metadata._Budget._number(self._clock.wall()))
            claims = Claims(pins.app.app_id, now - 30, now + 300)
            signed = self._signer.sign(claims, timeout=deadline.remaining())
            deadline.remaining()
            jwt = _jwt(signed, claims, self._clock.wall())
            self._preflight(jwt, deadline)
            entry = _Entry(
                publisher.digest({"nonce": uuid.uuid4().hex}),
                binding_sha256,
                jwt,
                claims,
            )
            self._event(entry, "UNKNOWN")
            self._active = entry
            reply = self._wire.exchange(
                Operation.ISSUE_TOKEN, pins, jwt, timeout=deadline.remaining()
            )
            need(type(reply) is _Reply)
            raw = _json(reply.body)
            # Retain a usable returned token BEFORE any other validation/clock
            # check so malformed grants/expiry or a late response still revoke.
            entry.token = _Secret(raw["token"], "installation")
            deadline.remaining()
            need(raw["permissions"] == dict(metadata.PERMISSIONS))
            need(raw["repository_selection"] == "selected")
            expires = int(issues.timestamp(raw["expires_at"]).timestamp())
            issued = int(metadata._Budget._number(self._clock.wall()))
            need(issued + 30 < expires <= issued + 3600)
            lease = metadata.Lease(
                entry.lease_id,
                binding_sha256,
                self._source,
                pins.app.app_id,
                pins.installation.identifier,
                claims.issued_at,
                claims.expires_at,
                issued,
                expires,
            )
            entry.lease = lease
            self._event(entry, "ISSUED")
            deadline.remaining()
            return lease
        except BaseException:
            failed = True
        if failed:
            # No retry. If a token is known, make exactly one cleanup attempt;
            # unknown/partial issuance stays durably UNKNOWN for reconciliation.
            if entry is not None and entry.token is not None:
                self._revoke_entry(entry, timeout=5)
            self._poisoned = True
            self._active = None
            raise AdapterError()

    def _revoke_entry(self, entry, *, timeout):
        if entry.revoke_attempted:
            return False
        entry.revoke_attempted = True
        confirmed = False
        try:
            # An UNKNOWN/ISSUED record already guards uncertainty even if this
            # extra intent append fails. Cleanup must still attempt once.
            try:
                self._event(entry, "REVOKE_UNKNOWN")
            except Exception:
                self._poisoned = True
            deadline = _Deadline(self._clock, timeout)
            reply = self._wire.exchange(
                Operation.REVOKE_TOKEN,
                self._pins,
                entry.token,
                timeout=deadline.remaining(),
            )
            deadline.remaining()
            need(type(reply) is _Reply and reply.body == b"")
            self._event(entry, "REVOKED")
            confirmed = not self._poisoned
        except BaseException:
            self._poisoned = True
        finally:
            entry.token = entry.jwt = None
        return confirmed

    def revoke(self, lease, *, timeout):
        entry = self._active
        if type(lease) is not metadata.Lease or entry is None or lease != entry.lease:
            return False
        result = self._revoke_entry(entry, timeout=timeout)
        self._active = None
        if not result:
            self._poisoned = True
        return result

    def close(self):
        """Explicit cancel/finally cleanup, never network I/O from a destructor."""
        entry = self._active
        if entry is not None and entry.token is not None:
            self._revoke_entry(entry, timeout=5)
        self._active = None
        self._poisoned = True

    def get(self, request, *, timeout, limit):
        failed = False
        result = None
        try:
            self._check()
            entry = self._active
            need(type(request) is metadata.Request and entry is not None)
            need(entry.lease is not None)
            need(request.origin == metadata.ORIGIN and request.method == "GET")
            need(request.verify_tls is True and request.allow_redirects is False)
            need(request.trust_env is False and limit == metadata.MAX_BODY)
            need(request.lease_id == entry.lease.lease_id)
            need(
                request.binding_sha256 == entry.binding
                and request.source_id == self._source
            )
            now = self._clock.wall()
            metadata._lease(
                entry.lease, self._pins, _Source(self._source), entry.binding, now
            )
            operations = (
                Operation.APP,
                Operation.INSTALLATION,
                Operation.REPOSITORIES,
                Operation.BOT,
            )
            match = [
                op
                for op in operations
                if route(op, self._pins)[1].split("?")[0] == request.path
            ]
            need(len(match) == 1)
            op = match[0]
            _, _, kind, _ = route(op, self._pins)
            query = (("per_page", 100),) if op is Operation.REPOSITORIES else ()
            need(request.query == query and request.auth_kind == kind)
            need(op not in entry.used and len(entry.used) < 4)
            entry.used.add(op)
            bearer = (
                None
                if kind == "public"
                else entry.jwt
                if kind == "app_jwt"
                else entry.token
            )
            reply = self._wire.exchange(op, self._pins, bearer, timeout=timeout)
            need(type(reply) is _Reply)
            need(len(reply.body) <= limit)
            result = metadata.Response(
                request, 200, reply.body, metadata.ORIGIN, True, False, False
            )
        except BaseException:
            failed = True
        if failed:
            raise AdapterError()
        return result


@dataclass(frozen=True, slots=True)
class _Source:
    source_id: str
