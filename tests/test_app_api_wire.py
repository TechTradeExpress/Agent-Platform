"""Exercise the concrete HTTP parser with fake sockets/TLS, never a network."""

import socket
import ssl

import pytest
from test_app_metadata import Clock
from test_app_metadata import case as case

from agent_platform import app_api_wire as wire


class Socket:
    def __init__(self, raw):
        self.raw = raw
        self.sent = []
        self.closed = False
        self.timeouts = []
        self.hook = None
        self.handshake_error = False

    def connect(self, address):
        assert address == ("140.82.112.6", 443)  # Fixture IP only, no DNS/real connect.

    def settimeout(self, timeout):
        assert 0 < timeout <= 5
        self.timeouts.append(timeout)

    def do_handshake(self):
        if self.handshake_error:
            raise ssl.SSLCertVerificationError("secret hostile certificate")

    def sendall(self, value):
        self.sent.append(value)

    def recv(self, count):
        if self.hook:
            self.hook()
        value, self.raw = self.raw[:count], self.raw[count:]
        return value

    def close(self):
        self.closed = True


class Context:
    def __init__(self, protocol, sock):
        assert protocol == ssl.PROTOCOL_TLS_CLIENT
        self.sock = sock

    def load_verify_locations(self, *, cafile):
        assert cafile == "/etc/ssl/certs/ca-certificates.crt"

    def wrap_socket(self, sock, *, server_hostname, do_handshake_on_connect):
        assert sock is self.sock and server_hostname == "api.github.com"
        assert do_handshake_on_connect is False
        assert self.check_hostname is True and self.verify_mode == ssl.CERT_REQUIRED
        assert self.minimum_version == ssl.TLSVersion.TLSv1_2
        return sock


@pytest.fixture
def configured(case, monkeypatch):
    clock = Clock()
    sock = Socket(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
    monkeypatch.setattr(socket, "socket", lambda *a, **k: sock)
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **k: pytest.fail("DNS forbidden")
    )
    monkeypatch.setattr(ssl, "SSLContext", lambda protocol: Context(protocol, sock))
    value = wire.Wire(address="140.82.112.6", clock=clock)
    return case["pins"], value, sock, clock


def exchange(configured, op=wire.Operation.APP, bearer=None, **kwargs):
    pins, value, _, _ = configured
    if bearer is None and op is not wire.Operation.BOT:
        kind = (
            "installation"
            if op in {wire.Operation.REPOSITORIES, wire.Operation.REVOKE_TOKEN}
            else "app_jwt"
        )
        bearer = wire._Secret("offline-not-valid-secret", kind)
    return value.exchange(op, pins, bearer, timeout=kwargs.get("timeout", 5))


@pytest.mark.parametrize("op", list(wire.Operation))
def test_fixed_method_route_and_auth_domains(configured, op, monkeypatch):
    status = (
        201
        if op is wire.Operation.ISSUE_TOKEN
        else 204
        if op is wire.Operation.REVOKE_TOKEN
        else 200
    )
    body = b"" if status == 204 else b"{}"
    configured[2].raw = (
        f"HTTP/1.1 {status} OK\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body
    )
    monkeypatch.setenv("HTTPS_PROXY", "https://evil.invalid/secret")
    monkeypatch.setenv("HTTP_PROXY", "https://evil.invalid/secret")
    monkeypatch.setenv("SSL_CERT_FILE", "/evil/untrusted")
    assert exchange(configured, op).body == body
    sent = configured[2].sent[0]
    method, path, _, _ = wire.route(op, configured[0])
    assert sent.startswith(f"{method} {path} HTTP/1.1\r\n".encode())
    assert b"Host: api.github.com\r\n" in sent
    assert (b"Authorization:" in sent) == (op is not wire.Operation.BOT)
    if op is wire.Operation.ISSUE_TOKEN:
        assert sent.endswith(b"\r\n\r\n{}")
        assert b"repository_ids" not in sent and b'"permissions"' not in sent
    assert configured[2].closed


@pytest.mark.parametrize(
    "raw",
    [
        b"HTTP/1.1 301 Redirect\r\nLocation: https://evil.invalid/secret\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nLink: secret\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Length: 65537\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Length: -2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n",
        b"HTTP/1.1 200 OK\r\nX-Large: " + b"x" * 17000 + b"\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 65537,
        b"secret malformed status line\r\n\r\n",
    ],
)
def test_bounds_framing_truncation_pagination_and_redirects(configured, raw):
    configured[2].raw = raw
    with pytest.raises(wire.AdapterError) as caught:
        exchange(configured)
    assert str(caught.value) == "app_api_adapter_blocked"
    assert caught.value.__context__ is None
    assert configured[2].closed and len(configured[2].sent) == 1


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
def test_http_failures_never_retry_or_return_hostile_body(configured, status):
    configured[
        2
    ].raw = f"HTTP/1.1 {status} FAIL\r\n\r\nsecret Authorization: Bearer".encode()
    with pytest.raises(wire.AdapterError):
        exchange(configured)
    assert len(configured[2].sent) == 1


def test_chunked_and_close_framing_are_bounded(configured):
    configured[
        2
    ].raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n"
    assert exchange(configured).body == b"{}"


@pytest.mark.parametrize(
    "kind", ["invalid_tls", "timeout", "partial_read", "clock_skew"]
)
def test_tls_timeout_and_partial_errors_close_without_leak(configured, kind):
    sock, clock = configured[2:]
    if kind == "invalid_tls":
        sock.handshake_error = True
    else:

        def fail():
            if kind == "timeout":
                clock.elapsed += 6
            elif kind == "clock_skew":
                clock.wall_offset += 20
            else:
                raise ConnectionError("secret headers token PEM")

        sock.hook = fail
    with pytest.raises(wire.AdapterError) as caught:
        exchange(configured)
    assert "secret" not in str(caught.value) and caught.value.__context__ is None
    assert sock.closed


@pytest.mark.parametrize(
    "op,bearer",
    [
        ("GET /arbitrary", None),
        (wire.Operation.BOT, wire._Secret("fake", "app_jwt")),
        (wire.Operation.APP, wire._Secret("fake", "installation")),
    ],
)
def test_no_arbitrary_route_or_wrong_credential_domain(configured, op, bearer):
    with pytest.raises(wire.AdapterError):
        exchange(configured, op, bearer)
    assert not configured[2].sent


@pytest.mark.parametrize(
    "address",
    [
        "http://api.github.com",
        "api.github.com",
        "127.0.0.1",
        "169.254.169.254",
        "::1",
        "224.0.0.1",
    ],
)
def test_no_default_dns_private_or_metadata_endpoint(address):
    with pytest.raises((wire.AdapterError, ValueError)):
        wire.Wire(address=address)


@pytest.mark.parametrize("value", ["fake\r\nsecret: x", "fake token", "", "é"])
def test_header_injection_cannot_become_bearer(value):
    with pytest.raises(wire.AdapterError):
        wire._Secret(value, "installation")


def test_trickled_headers_do_not_reset_total_deadline(configured):
    sock, clock = configured[2:]
    original = sock.recv

    def trickle(count):
        clock.elapsed += 0.2
        return original(1)

    sock.recv = trickle
    with pytest.raises(wire.AdapterError):
        exchange(configured)
    assert sock.closed and len(sock.sent) == 1


@pytest.mark.parametrize("timeout", [0, -1, 6, float("nan"), True])
def test_invalid_timeout_never_connects(configured, timeout):
    with pytest.raises(wire.AdapterError):
        exchange(configured, timeout=timeout)
    assert not configured[2].sent
