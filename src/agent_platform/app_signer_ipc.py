"""AP-AS/1 one-request Unix socket handlers. No bind/listen/connect/daemon API."""

import array
import base64
import json
import os
import socket
import struct
import sys
import threading
from dataclasses import replace

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from . import app_api_adapter as adapter
from . import app_metadata as metadata
from . import issues, publisher
from .app_api_wire import _Deadline
from .app_signer import (
    Peer,
    Policy,
    Request,
    SignerError,
    SignerSession,
    _SignedJWT,
    need,
    public_fingerprint,
)

_SERVER_SLOT = threading.BoundedSemaphore(1)
MAX_REQUEST = 2048
MAX_REPLY = 8192
ERROR = {"v": 1, "status": "BLOCKED", "code": "signer_blocked"}


def _peer(sock):
    need(sys.platform == "linux" and isinstance(sock, socket.socket))
    need(sock.family == socket.AF_UNIX and sock.type == socket.SOCK_STREAM)
    # Only already-connected injected handles. No path is opened/selected here;
    # identity is checked from kernel credentials, never inferred from a pathname.
    for address in (sock.getsockname(), sock.getpeername()):
        if address in ("", b""):
            continue
        need(type(address) is str and address.startswith("/"))
        need("\x00" not in address and len(os.fsencode(address)) < 108)
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    need(len(raw) == struct.calcsize("3i"))
    return Peer(*struct.unpack("3i", raw))


def _recv(sock, count, deadline):
    sock.settimeout(deadline.remaining())
    data, ancillary, flags, _ = sock.recvmsg(
        count,
        socket.CMSG_SPACE(16 * array.array("i").itemsize),
        socket.MSG_CMSG_CLOEXEC,
    )
    # Close any descriptors actually received before rejecting the whole message.
    close_failed = False
    for level, kind, payload in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            values = array.array("i")
            values.frombytes(payload[: len(payload) - len(payload) % values.itemsize])
            for fd in values:
                try:
                    os.close(fd)
                except OSError:
                    close_failed = True
    need(not close_failed)
    need(not ancillary and not flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC))
    deadline.remaining()
    return data


def _exact(sock, count, deadline):
    out = bytearray()
    while len(out) < count:
        chunk = _recv(sock, min(4096, count - len(out)), deadline)
        need(chunk)
        out.extend(chunk)
    return bytes(out)


def _read(sock, maximum, deadline):
    size = struct.unpack("!I", _exact(sock, 4, deadline))[0]
    need(0 < size <= maximum - 4)
    raw = _exact(sock, size, deadline)
    need(
        _recv(sock, 1, deadline) == b""
    )  # Required half-close; no pipelining/trailing bytes.
    obj = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=issues.unique_object,
        parse_constant=issues.invalid_constant,
    )
    need(type(obj) is dict and publisher.encoded(obj) == raw)
    return obj


def _write(sock, obj, maximum, deadline):
    raw = publisher.encoded(obj)
    need(0 < len(raw) <= maximum - 4)
    sock.settimeout(deadline.remaining())
    sock.sendall(struct.pack("!I", len(raw)) + raw)
    deadline.remaining()
    sock.shutdown(socket.SHUT_WR)


def _request(obj):
    need(
        set(obj)
        == {
            "v",
            "op",
            "run_id",
            "nonce",
            "request_id",
            "pass_binding",
            "policy_sha256",
            "app_id",
            "iat",
            "exp",
        }
    )
    need(type(obj["v"]) is int and obj["v"] == 1 and obj["op"] == "SignAppJwtV1")
    claims = adapter.Claims(obj["app_id"], obj["iat"], obj["exp"])
    return Request(
        obj["run_id"],
        obj["nonce"],
        obj["request_id"],
        obj["pass_binding"],
        obj["policy_sha256"],
        claims,
    )


def _object(request):
    return {
        "v": 1,
        "op": "SignAppJwtV1",
        "run_id": request.run_id,
        "nonce": request.nonce,
        "request_id": request.request_id,
        "pass_binding": request.pass_binding,
        "policy_sha256": request.policy_sha256,
        "app_id": request.claims.app_id,
        "iat": request.claims.issued_at,
        "exp": request.claims.expires_at,
    }


def _close(sock):
    try:
        sock.close()
    except BaseException:
        pass


def serve_one(sock, session, *, timeout=5):
    """One explicit injected socket; at most one active handler, no queued work.

    A signing/send failure closes this admitted session. The mandatory external
    authority retains consumed UNKNOWN/SIGNED state across restart/lost replies.
    """
    locked = False
    global_slot = False
    failed = False
    deadline = None
    try:
        need(type(session) is SignerSession)
        locked = session._lock.acquire(blocking=False)
        need(locked and not session._closed)
        global_slot = _SERVER_SLOT.acquire(blocking=False)
        need(global_slot)
        deadline = _Deadline(session._clock, timeout)
        need(_peer(sock) == session._policy.custody_peer)
        request = _request(_read(sock, MAX_REQUEST, deadline))
        token = session._issue(request, _peer(sock), deadline)
        value = token.take_for_custody()
        _write(
            sock,
            {"v": 1, "status": "OK", "request_sha256": request.digest, "jwt": value},
            MAX_REPLY,
            deadline,
        )
    except BaseException:
        failed = True
        if locked:
            session.close()
        if deadline is not None:
            try:
                _write(sock, ERROR, MAX_REPLY, deadline)
            except BaseException:
                pass
    finally:
        _close(sock)
        if global_slot:
            _SERVER_SLOT.release()
        if locked:
            session._lock.release()
    if failed:
        raise SignerError()


class SignerClient:
    def __init__(self, *, policy, public_key, clock=None):
        failed = False
        try:
            need(type(policy) is Policy)
            replace(policy)
            need(public_fingerprint(public_key) == policy.key_sha256)
            self._policy, self._public_key = policy, public_key
            self._policy_pin = policy.digest
            self._clock = metadata.Clock() if clock is None else clock
            self._lock = threading.Lock()
            self._poisoned = False
        except BaseException:
            failed = True
        if failed:
            raise SignerError()

    def __repr__(self):
        return "<signer custody client; responses redacted>"

    def __reduce_ex__(self, protocol):
        raise SignerError()

    def sign(self, claims, *, timeout):
        # AP-AL/1 lacks approved request/pass context: integration BLOCKED.
        raise SignerError()

    def exchange(self, sock, request, *, timeout=5):
        failed = False
        locked = False
        result = None
        try:
            locked = self._lock.acquire(blocking=False)
            need(locked and not self._poisoned)
            deadline = _Deadline(self._clock, timeout)
            need(self._policy.digest == self._policy_pin)
            need(type(request) is Request)
            replace(request)
            need(request.policy_sha256 == self._policy.digest)
            need(request.claims.app_id == self._policy.app_id)
            now = metadata._Budget._number(self._clock.wall())
            need(
                request.claims.issued_at <= now < request.claims.expires_at <= now + 300
            )
            need(now - request.claims.issued_at <= 60)
            need(_peer(sock) == self._policy.signer_peer)
            _write(sock, _object(request), MAX_REQUEST, deadline)
            obj = _read(sock, MAX_REPLY, deadline)
            need(set(obj) == {"v", "status", "request_sha256", "jwt"})
            need(type(obj["v"]) is int and obj["v"] == 1 and obj["status"] == "OK")
            need(obj["request_sha256"] == request.digest)
            jwt = obj["jwt"]
            adapter._jwt(jwt, request.claims, self._clock.wall())
            parts = jwt.split(".")
            signature = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
            self._public_key.verify(
                signature,
                (parts[0] + "." + parts[1]).encode("ascii"),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            deadline.remaining()
            result = _SignedJWT(jwt)
        except BaseException:
            failed = True
            self._poisoned = True
        finally:
            _close(sock)
            if locked:
                self._lock.release()
        if failed:
            raise SignerError()
        return result
