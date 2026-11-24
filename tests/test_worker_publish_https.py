"""Offline transport regressions using the standard-library HTTP parser."""

import errno
import io
from types import SimpleNamespace

import pytest

from agent_platform import worker_publish_io as transport


@pytest.fixture
def wire(monkeypatch):
    class Peer(io.BytesIO):
        def read1(self, size):
            if state.slow:
                # A drip-fed body crosses the overall deadline without any
                # individual read taking five seconds.
                state.now += 2
                if state.now >= 5:
                    state.interrupt()
                    return b""
            state.reads += 1
            return super().read(min(size, 4))

    class Watchdog:
        def shutdown(self, how):
            assert how == transport.socket.SHUT_RDWR
            state.interrupted = True

        def close(self):
            state.watchdog_closed = True

    class Channel:
        def connect(self, address):
            assert address == state.peer

        def getpeername(self):
            return state.peername

        def settimeout(self, seconds):
            if state.detached:
                raise OSError(errno.EBADF, "simulated closed descriptor")
            assert 0 < seconds <= 5

        def dup(self):
            return Watchdog()

        def sendall(self, request):
            state.requests += 1

        def makefile(self, mode):
            assert mode == "rb"
            return Peer(state.response)

        def close(self):
            state.detached = True

    class Context:
        def load_default_certs(self):
            state.ca_loaded = True

        def wrap_socket(self, raw, *, server_hostname):
            assert server_hostname == "api.github.com" and state.ca_loaded
            return raw

    class Timer:
        def __init__(self, interval, callback):
            assert interval == 5
            state.interrupt = callback

        def start(self):
            pass

        def cancel(self):
            state.timer_cancelled = True

        def join(self, timeout):
            assert timeout == 1

    def socket_factory(family, kind, protocol):
        assert (family, kind, protocol) == (
            transport.socket.AF_INET,
            transport.socket.SOCK_STREAM,
            transport.socket.IPPROTO_TCP,
        )
        return Channel()

    state = SimpleNamespace(
        now=0,
        peer=("140.82.112.6", 443),
        peername=("140.82.112.6", 443),
        slow=False,
        interrupted=False,
        detached=False,
        reads=0,
        requests=0,
        timer_cancelled=False,
        watchdog_closed=False,
        ca_loaded=False,
    )
    monkeypatch.setattr(transport.ssl, "SSLContext", lambda protocol: Context())
    monkeypatch.setattr(transport.socket, "socket", socket_factory)
    monkeypatch.setattr(transport.threading, "Timer", Timer)
    monkeypatch.setattr(transport.time, "monotonic", lambda: state.now)
    return state


def exchange(limit=1024):
    return transport.HTTPS.homelab("140.82.112.6").exchange(
        "GET",
        "/app",
        None,
        None,
        limit=limit,
    )


@pytest.mark.parametrize("connection", [b"close", b"keep-alive"])
@pytest.mark.parametrize("chunked", [False, True])
def test_http_response_lifetime(wire, connection, chunked):
    body = b'{"publisher":"worker01"}'
    framing = b"Content-Length: 24 \t"
    if chunked:
        framing = b"Transfer-Encoding: chunked"
        body = b'e\r\n{"publisher":"\r\na\r\nworker01"}\r\n0\r\n\r\n'
    wire.response = (
        b"HTTP/1.1 200 OK\r\nConnection: "
        + connection
        + (b"\r\n" + framing + b"\r\n\r\n" + body)
    )
    assert exchange() == (200, {"publisher": "worker01"})
    assert wire.reads > 1 and wire.requests == 1
    assert wire.detached and wire.timer_cancelled and wire.watchdog_closed


def test_close_delimited_body(wire):
    wire.response = b'HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{"ok":true}'
    assert exchange() == (200, {"ok": True})


def test_watchdog_interrupts_drip_feed_after_the_total_deadline(wire):
    wire.response = b'HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{"slow":true}'
    wire.slow = True
    with pytest.raises(transport.ExchangeFailure, match="^publisher_blocked$") as exc:
        exchange()
    assert exc.value.reason == transport.FailureReason.TIMEOUT
    assert wire.reads == 2 and wire.interrupted
    assert wire.timer_cancelled and wire.watchdog_closed and wire.requests == 1


@pytest.mark.parametrize(
    "response,limit",
    [
        (b"200 OK\r\nContent-Length: 100\r\n\r\n{}", 128),
        (b"200 OK\r\nContent-Length: 2, 2\r\n\r\n{}", 128),
        (
            b"200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"2\r\n{}\r\n0\r\n\r\n",
            128,
        ),
        (b"200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n", 128),
        (b"200 OK\r\nContent-Length: 2\r\n\r\n{}", 1),
        (b"200 OK\r\n\r\n{}", 1),
        (b"200 OK\r\nLocation: https://invalid.test\r\n\r\n{}", 128),
        (b"200 OK\r\nLink: <https://invalid.test>\r\n\r\n{}", 128),
        (b"200 OK\r\nX-Large: " + b"x" * 32768 + b"\r\n\r\n{}", 128),
        (b'200 OK\r\n\r\n{"x":1,"x":2}', 128),
        (b'200 OK\r\n\r\n{"x":', 128),
        (b"302 Found\r\n\r\n{}", 128),
    ],
)
def test_invalid_responses_fail_closed(wire, response, limit):
    wire.response = b"HTTP/1.1 " + response
    with pytest.raises(transport.ExchangeFailure, match="^publisher_blocked$") as exc:
        exchange(limit)
    assert exc.value.reason == (
        transport.FailureReason.STATUS
        if response.startswith(b"302")
        else transport.FailureReason.RESPONSE
    )
    assert wire.timer_cancelled and wire.watchdog_closed and wire.requests == 1


def test_wrong_connected_peer_is_rejected_before_tls_or_http(wire):
    wire.peername = ("140.82.112.7", 443)
    with pytest.raises(transport.Blocked):
        exchange()
    assert not wire.requests


def test_request_guard_runs_after_tls_and_before_sending(wire):
    def expired():
        assert wire.ca_loaded
        raise transport.Blocked()

    client = transport.HTTPS.homelab("140.82.112.6", before_request=expired)
    with pytest.raises(transport.Blocked):
        client.exchange("POST", "/test", {"test": True}, None)
    assert not wire.requests
