"""Real RSA signatures with fresh throwaway keys; no PEM/files/live App/daemon."""

import base64
import json
import os
import pickle
import socket
import struct
import threading
from dataclasses import replace

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from agent_platform import app_api_adapter as adapter
from agent_platform import app_signer as signer
from agent_platform import app_signer_ipc as ipc
from agent_platform import publisher

NOW = 1794139200


class Clock:
    elapsed = 0
    wall_offset = 0

    def wall(self):
        return NOW + self.elapsed + self.wall_offset

    def monotonic(self):
        return 100 + self.elapsed


class Credentials:
    def __init__(self, key):
        self._key, self.calls = key, 0

    def private_key(self, app_id, key_sha256):
        self.calls += 1
        return self._key


class Authority:
    """Fabricated independently installed approval/replay map, NOT a live producer."""

    complete = True

    def __init__(self, admission, peer):
        self.record, self.peer = admission, peer
        self.used = {}
        self.hook = None
        self._lock = threading.Lock()

    def lookup(self, run_id):
        if not self.complete or run_id != self.record.run_id:
            raise signer.SignerError()
        return self.record

    def consume(self, admission, request, peer):
        with self._lock:
            assert admission == self.lookup(request.run_id) and peer == self.peer
            if len(self.used) >= 2:
                raise signer.SignerError()
            slot = self.record.passes[len(self.used)]
            if (
                request.request_id in self.used
                or request.request_id != slot.request_id
                or request.pass_binding != slot.binding_sha256
            ):
                raise signer.SignerError()
            self.used[request.request_id] = "UNKNOWN"
            if self.hook:
                self.hook("consume")

    def finish(self, admission, request, outcome):
        assert outcome == "SIGNED" and self.used[request.request_id] == "UNKNOWN"
        if self.hook:
            self.hook("finish")
        self.used[request.request_id] = outcome


@pytest.fixture(scope="module")
def keys():
    return (
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
    )


@pytest.fixture
def case(keys, monkeypatch):
    # No socket creation except explicitly injected local Unix test fixtures.
    original = socket.socket

    class LocalSocket(original):
        def __init__(self, family=socket.AF_INET, *args, **kwargs):
            if family != socket.AF_UNIX:
                pytest.fail("external socket forbidden")
            super().__init__(family, *args, **kwargs)

    monkeypatch.setattr(socket, "socket", LocalSocket)
    monkeypatch.setattr(
        socket, "create_connection", lambda *a, **kw: pytest.fail("network")
    )
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: pytest.fail("DNS"))
    peer = signer.Peer(os.getpid(), os.getuid(), os.getgid())
    policy = signer.Policy(
        12345, "a" * 64, signer.public_fingerprint(keys[0].public_key()), peer, peer
    )
    approval = signer.Admission(
        "b" * 64,
        "c" * 64,
        policy.digest,
        NOW,
        NOW + 300,
        (signer.Pass("d" * 64, "e" * 64), signer.Pass("f" * 64, "1" * 64)),
    )
    authority = Authority(approval, peer)
    credentials, clock = Credentials(keys[0]), Clock()
    session = signer.SignerSession(
        policy=policy,
        approved_run_id=approval.run_id,
        authority=authority,
        credentials=credentials,
        clock=clock,
    )
    client = ipc.SignerClient(
        policy=policy, public_key=keys[0].public_key(), clock=clock
    )
    return dict(
        policy=policy,
        approval=approval,
        authority=authority,
        credentials=credentials,
        clock=clock,
        session=session,
        client=client,
        public=keys[0].public_key(),
    )


def request(case, number=0, **changes):
    slot = case["approval"].passes[number]
    value = signer.Request(
        case["approval"].run_id,
        case["approval"].nonce,
        slot.request_id,
        slot.binding_sha256,
        case["policy"].digest,
        adapter.Claims(case["policy"].app_id, NOW - 30, NOW + 250),
    )
    return replace(value, **changes)


def exchange(case, value=None, timeout=1):
    server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    outcomes = []

    def handle():
        try:
            ipc.serve_one(server, case["session"], timeout=timeout)
            outcomes.append("OK")
        except signer.SignerError as error:
            outcomes.append(str(error))

    thread = threading.Thread(target=handle)
    thread.start()
    try:
        return case["client"].exchange(
            client, request(case) if value is None else value, timeout=timeout
        )
    finally:
        client.close()
        thread.join(2)
        assert not thread.is_alive()
        assert outcomes in (["OK"], ["signer_blocked"])


def verify(public, jwt):
    parts = jwt.split(".")
    decoded = [base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)) for x in parts]
    public.verify(
        decoded[2],
        (parts[0] + "." + parts[1]).encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return json.loads(decoded[0]), json.loads(decoded[1])


def test_real_pkcs1v15_sha256_canonical_jwt_and_exact_two_pass_admission(case):
    for number in (0, 1):
        value = request(case, number)
        token = exchange(case, value)
        assert "eyJ" not in repr(token)
        with pytest.raises(signer.SignerError):
            pickle.dumps(token)
        jwt = token.take_for_custody()
        header, payload = verify(case["public"], jwt)
        assert header == {"alg": "RS256", "typ": "JWT"}
        assert payload == value.claims.payload
        assert jwt.split(".")[:2] == [
            adapter._b64(publisher.encoded(header)),
            adapter._b64(publisher.encoded(payload)),
        ]
        with pytest.raises(signer.SignerError):
            token.take_for_custody()
        signature = base64.urlsafe_b64decode(
            jwt.split(".")[2] + "=" * (-len(jwt.split(".")[2]) % 4)
        )
        with pytest.raises(InvalidSignature):
            case["public"].verify(
                signature,
                ".".join(jwt.split(".")[:2]).encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
    assert list(case["authority"].used.values()) == ["SIGNED", "SIGNED"]
    with pytest.raises(signer.SignerError):
        exchange(case)


@pytest.mark.parametrize(
    "field,value",
    [
        ("run_id", "2" * 64),
        ("nonce", "2" * 64),
        ("request_id", "2" * 64),
        ("pass_binding", "2" * 64),
        ("policy_sha256", "2" * 64),
    ],
)
def test_wrong_approved_context_never_signs(case, field, value):
    with pytest.raises(signer.SignerError) as caught:
        exchange(case, request(case, **{field: value}))
    assert str(caught.value) == "signer_blocked" and caught.value.__context__ is None
    assert not case["authority"].used


@pytest.mark.parametrize(
    "claims",
    [
        adapter.Claims(999, NOW - 30, NOW + 250),
        adapter.Claims(12345, NOW + 1, NOW + 250),
        adapter.Claims(12345, NOW - 61, NOW + 250),
        adapter.Claims(12345, NOW - 30, NOW),
        adapter.Claims(12345, NOW - 30, NOW + 301),
    ],
)
def test_independent_clock_and_app_bounds(case, claims):
    with pytest.raises(signer.SignerError):
        exchange(case, request(case, claims=claims))
    assert not case["authority"].used


@pytest.mark.parametrize("failure", ["missing", "lost", "wrong_policy", "expired"])
def test_no_admission_no_key_access(case, failure):
    authority = case["authority"]
    run_id = case["approval"].run_id
    if failure == "missing":
        run_id = "9" * 64
    elif failure == "lost":
        authority.complete = False
    elif failure == "wrong_policy":
        authority.record = replace(authority.record, policy_sha256="9" * 64)
    else:
        authority.record = replace(
            authority.record, issued_at=NOW - 300, expires_at=NOW
        )
    calls = case["credentials"].calls
    with pytest.raises(signer.SignerError):
        signer.SignerSession(
            policy=case["policy"],
            approved_run_id=run_id,
            authority=authority,
            credentials=case["credentials"],
            clock=case["clock"],
        )
    assert case["credentials"].calls == calls


def test_key_type_strength_and_fingerprint_mismatch_block(case, keys):
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    for key in (
        None,
        b"not-a-key",
        weak,
        ec.generate_private_key(ec.SECP256R1()),
        keys[1],
    ):
        with pytest.raises(signer.SignerError) as caught:
            signer.SignerSession(
                policy=case["policy"],
                approved_run_id=case["approval"].run_id,
                authority=case["authority"],
                credentials=Credentials(key),
                clock=case["clock"],
            )
        assert caught.value.__context__ is None


@pytest.mark.parametrize("stage", ["consume", "finish"])
def test_unknown_on_authority_failure_never_replayed_after_new_session(case, stage):
    def fail(step):
        if step == stage:
            raise OSError("secret independent continuity failure")

    case["authority"].hook = fail
    with pytest.raises(signer.SignerError):
        exchange(case)
    assert case["authority"].used == {request(case).request_id: "UNKNOWN"}
    case["authority"].hook = None
    case["session"] = signer.SignerSession(
        policy=case["policy"],
        approved_run_id=case["approval"].run_id,
        authority=case["authority"],
        credentials=case["credentials"],
        clock=case["clock"],
    )
    with pytest.raises(signer.SignerError):
        exchange(case)
    assert list(case["authority"].used.values()) == ["UNKNOWN"]


def test_pass_order_and_duplicate_context_not_inferred_from_call_count(case):
    with pytest.raises(signer.SignerError):
        exchange(case, request(case, 1))
    assert not case["authority"].used


def test_adapter_compatible_sign_is_explicitly_blocked(case):
    for obj in (case["session"], case["client"]):
        with pytest.raises(signer.SignerError):
            obj.sign(request(case).claims, timeout=1)
        assert "eyJ" not in repr(obj)
        with pytest.raises(signer.SignerError):
            pickle.dumps(obj)
    assert not case["authority"].used


def raw_exchange(case, raw, *, rights=None, timeout=0.2):
    server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    result = []

    def run():
        try:
            ipc.serve_one(server, case["session"], timeout=timeout)
            result.append("OK")
        except signer.SignerError:
            result.append("BLOCKED")

    thread = threading.Thread(target=run)
    thread.start()
    try:
        if rights:
            client.sendmsg([raw], rights)
        else:
            client.sendall(raw)
        client.shutdown(socket.SHUT_WR)
        client.settimeout(1)
        data = bytearray()
        while True:
            chunk = client.recv(8192)
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data), result
    except (BrokenPipeError, ConnectionResetError):
        return b"", result
    finally:
        client.close()
        thread.join(2)
        assert not thread.is_alive()


@pytest.mark.parametrize(
    "payload", [b"secret", b"[]", b'{"v":1,"v":1}', b"\xff", b'{"v":NaN}']
)
def test_malformed_json_and_utf8_do_not_leak_or_sign(case, payload):
    raw, result = raw_exchange(case, struct.pack("!I", len(payload)) + payload)
    assert result == ["BLOCKED"]
    assert b"secret" not in raw and not case["authority"].used


@pytest.mark.parametrize(
    "change", ["extra", "version_bool", "extra_claim", "key_path", "method"]
)
def test_exact_schema_not_generic_signer(case, change):
    obj = ipc._object(request(case))
    if change == "version_bool":
        obj["v"] = True
    elif change == "method":
        obj["op"] = "arbitrary-sign"
    else:
        obj[
            {"extra": "extra", "extra_claim": "kid", "key_path": "pem_path"}[change]
        ] = "secret"
    raw = publisher.encoded(obj)
    response, result = raw_exchange(case, struct.pack("!I", len(raw)) + raw)
    assert result == ["BLOCKED"] and b"secret" not in response
    assert not case["authority"].used


@pytest.mark.parametrize(
    "frame",
    [
        b"",
        b"\x00",
        struct.pack("!I", 2045),
        struct.pack("!I", 0),
        struct.pack("!I", 2**32 - 1),
        struct.pack("!I", 10) + b"{}",
    ],
)
def test_partial_eof_and_oversize_checked_before_decode(case, frame):
    _, result = raw_exchange(case, frame)
    assert result == ["BLOCKED"] and not case["authority"].used


def test_extra_frame_and_noncanonical_whitespace_block(case):
    raw = publisher.encoded(ipc._object(request(case))) + b" "
    _, outcome = raw_exchange(case, struct.pack("!I", len(raw)) + raw)
    assert outcome == ["BLOCKED"] and not case["authority"].used


def test_received_fds_are_closed_and_never_accepted(case):
    import array

    read, write = os.pipe()
    raw = publisher.encoded(ipc._object(request(case)))
    before = len(os.listdir("/proc/self/fd"))
    try:
        _, result = raw_exchange(
            case,
            struct.pack("!I", len(raw)) + raw,
            rights=[(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [read]))],
        )
        assert result == ["BLOCKED"] and not case["authority"].used
        assert len(os.listdir("/proc/self/fd")) == before
    finally:
        os.close(read)
        os.close(write)


@pytest.mark.parametrize("side", ["server", "client"])
def test_kernel_peer_credentials_not_payload_claims(case, side):
    wrong = replace(
        case["policy"].custody_peer, uid=case["policy"].custody_peer.uid + 1
    )
    if side == "server":
        policy = replace(case["policy"], custody_peer=wrong)
        approval = replace(case["approval"], policy_sha256=policy.digest)
        case["session"] = signer.SignerSession(
            policy=policy,
            approved_run_id=approval.run_id,
            authority=Authority(approval, wrong),
            credentials=case["credentials"],
            clock=case["clock"],
        )
    else:
        policy = replace(case["policy"], signer_peer=wrong)
        case["client"] = ipc.SignerClient(
            policy=policy, public_key=case["public"], clock=case["clock"]
        )
    with pytest.raises(signer.SignerError):
        exchange(case)
    assert not case["authority"].used


@pytest.mark.parametrize(
    "kind", ["signature", "payload", "echo", "oversize", "extra_reply"]
)
def test_poisoned_or_replayed_reply_is_rejected_and_client_cannot_retry(
    case, monkeypatch, kind
):
    original = ipc._write

    def corrupt(sock, obj, maximum, deadline):
        if obj.get("status") == "OK":
            obj = dict(obj)
            if kind == "signature":
                parts = obj["jwt"].split(".")
                parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
                obj["jwt"] = ".".join(parts)
            elif kind == "payload":
                parts = obj["jwt"].split(".")
                parts[1] = adapter._b64(
                    publisher.encoded({"iss": "999", "iat": NOW - 30, "exp": NOW + 250})
                )
                obj["jwt"] = ".".join(parts)
            elif kind == "echo":
                obj["request_sha256"] = "a" * 64
            elif kind == "extra_reply":
                obj["extra"] = "secret"
            else:
                sock.sendall(struct.pack("!I", 8192))
                sock.shutdown(socket.SHUT_WR)
                return
        original(sock, obj, maximum, deadline)

    monkeypatch.setattr(ipc, "_write", corrupt)
    with pytest.raises(signer.SignerError):
        exchange(case)
    assert case["client"]._poisoned
    used = dict(case["authority"].used)
    with pytest.raises(signer.SignerError):
        exchange(case, request(case, 1))
    assert case["authority"].used == used


@pytest.mark.parametrize("field", ["uid", "gid", "pid"])
def test_each_kernel_peer_component_is_required(case, field):
    wrong = replace(
        case["policy"].signer_peer,
        **{field: getattr(case["policy"].signer_peer, field) + 1},
    )
    case["client"] = ipc.SignerClient(
        policy=replace(case["policy"], signer_peer=wrong),
        public_key=case["public"],
        clock=case["clock"],
    )
    with pytest.raises(signer.SignerError):
        exchange(case)
    assert not case["authority"].used


def test_no_concurrent_or_queued_crypto_handlers(case):
    assert ipc._SERVER_SLOT.acquire(blocking=False)
    server, client = socket.socketpair()
    try:
        with pytest.raises(signer.SignerError):
            ipc.serve_one(server, case["session"], timeout=0.2)
        assert not case["authority"].used and case["session"]._closed
    finally:
        ipc._SERVER_SLOT.release()
        server.close()
        client.close()


def test_partial_or_trickled_frames_have_total_deadline(case, monkeypatch):
    original = socket.socketpair

    def pair(*args, **kwargs):
        server, client = original(*args, **kwargs)
        receive = server.recvmsg

        def trickle(count, *a):
            result = receive(min(count, 1), *a)
            case["clock"].elapsed += 0.1
            return result

        server.recvmsg = trickle
        return server, client

    monkeypatch.setattr(socket, "socketpair", pair)
    raw = publisher.encoded(ipc._object(request(case)))
    _, result = raw_exchange(case, struct.pack("!I", len(raw)) + raw, timeout=0.3)
    assert result == ["BLOCKED"] and not case["authority"].used


def test_late_crypto_discards_signature_and_retains_consumed_unknown(case):
    actual = case["session"]._key

    class Slow:
        def sign(self, *args):
            result = actual.sign(*args)
            case["clock"].elapsed += 6
            return result

    case["session"]._key = Slow()
    with pytest.raises(signer.SignerError):
        exchange(case)
    assert list(case["authority"].used.values()) == ["UNKNOWN"]


def test_extra_frame_and_boolean_claims_are_rejected(case):
    obj = ipc._object(request(case))
    obj["iat"] = True
    raw = publisher.encoded(obj)
    _, result = raw_exchange(case, struct.pack("!I", len(raw)) + raw)
    assert result == ["BLOCKED"] and not case["authority"].used


def test_helper_process_shutdown_and_signature_use_no_key_serialization(case):
    import multiprocessing

    context = multiprocessing.get_context("fork")
    server, client = socket.socketpair()

    def worker():
        os.environ.clear()  # No controller environment is needed by the offline helper.
        client.close()
        try:
            ipc.serve_one(server, case["session"], timeout=2)
        except signer.SignerError:
            os._exit(9)
        finally:
            case["session"].close()
        os._exit(0)

    process = context.Process(target=worker)
    process.start()
    server.close()
    try:
        token = case["client"].exchange(client, request(case), timeout=2)
        verify(case["public"], token.take_for_custody())
    finally:
        client.close()
        process.join(3)
        if process.is_alive():
            process.kill()
            process.join(2)
    assert process.exitcode == 0
    # SO_PEERCRED on this pre-fork pair identifies its creator, not child executable.


def test_missing_peer_verification_and_expired_admission_block(case, monkeypatch):
    monkeypatch.setattr(
        ipc,
        "_peer",
        lambda s: (_ for _ in ()).throw(OSError("secret peer unavailable")),
    )
    with pytest.raises(signer.SignerError) as error:
        exchange(case)
    assert error.value.__context__ is None and not case["authority"].used


def test_explicit_test_only_named_unix_connection_uses_peer_not_path(case, tmp_path):
    # Fixture only: libraries never bind/listen/connect/select/unlink a pathname.
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    path = tmp_path / "fixture.sock"
    listener.bind(str(path))
    path.chmod(0o600)
    listener.listen(1)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(str(path))
    server, _ = listener.accept()
    listener.close()
    errors = []

    def handler():
        try:
            ipc.serve_one(server, case["session"], timeout=1)
        except signer.SignerError:
            errors.append("BLOCKED")

    thread = threading.Thread(target=handler)
    thread.start()
    try:
        verify(
            case["public"],
            case["client"]
            .exchange(client, request(case), timeout=1)
            .take_for_custody(),
        )
    finally:
        client.close()
        thread.join(2)
    assert not thread.is_alive() and not errors


@pytest.mark.parametrize("field,value", [("pid", True), ("uid", -1), ("gid", 2**32)])
def test_peer_types_are_not_boolean_or_out_of_range(field, value):
    values = dict(pid=1, uid=1, gid=1)
    values[field] = value
    with pytest.raises(signer.SignerError):
        signer.Peer(**values)


def test_missing_authority_object_cannot_load_credentials(case):
    calls = case["credentials"].calls
    with pytest.raises(signer.SignerError):
        signer.SignerSession(
            policy=case["policy"],
            approved_run_id=case["approval"].run_id,
            authority=None,
            credentials=case["credentials"],
            clock=case["clock"],
        )
    assert calls == case["credentials"].calls


def test_cancelled_signing_preserves_unknown_and_fixed_diagnostics(case, capsys):
    class Cancelled:
        def sign(self, *args):
            raise KeyboardInterrupt("synthetic-secret-cancellation")

    case["session"]._key = Cancelled()
    with pytest.raises(signer.SignerError) as error:
        exchange(case)
    assert str(error.value) == "signer_blocked"
    assert error.value.__context__ is None
    assert list(case["authority"].used.values()) == ["UNKNOWN"]
    assert capsys.readouterr() == ("", "")
