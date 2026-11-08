"""AP-AL/1 fixed-origin wire; inert until explicitly constructed and invoked.

No DNS, proxy, redirect, default address, credential provider or CLI. All tests
replace sockets/TLS; no live App traffic is authorized by this implementation.
"""

import http.client
import io
import ipaddress
import socket
import ssl
from dataclasses import replace
from enum import StrEnum
from urllib.parse import quote

from . import app_metadata as metadata

MAX_HEADER = 16384
MAX_WIRE = metadata.MAX_BODY + 2 * MAX_HEADER


class AdapterError(Exception):
    def __init__(self):
        super().__init__("app_api_adapter_blocked")


def need(value):
    if not value:
        raise AdapterError()


class Operation(StrEnum):
    APP = "app"
    INSTALLATION = "installation"
    REPOSITORIES = "repositories"
    BOT = "public_bot"
    ISSUE_TOKEN = "issue_token"
    REVOKE_TOKEN = "revoke_token"


def route(operation, pins):
    need(type(operation) is Operation and type(pins) is metadata.Pins)
    replace(pins)
    installation = pins.installation.identifier
    return {
        Operation.APP: ("GET", "/app", "app_jwt", 200),
        Operation.INSTALLATION: (
            "GET",
            f"/app/installations/{installation}",
            "app_jwt",
            200,
        ),
        Operation.REPOSITORIES: (
            "GET",
            "/installation/repositories?per_page=100",
            "installation",
            200,
        ),
        Operation.BOT: (
            "GET",
            "/users/" + quote(pins.app.bot.login, safe=""),
            "public",
            200,
        ),
        Operation.ISSUE_TOKEN: (
            "POST",
            f"/app/installations/{installation}/access_tokens",
            "app_jwt",
            201,
        ),
        Operation.REVOKE_TOKEN: ("DELETE", "/installation/token", "installation", 204),
    }[operation]


class _Secret:
    __slots__ = ("value", "kind")

    def __init__(self, value, kind):
        need(type(value) is str and value and value.isascii())
        need(
            all(33 <= ord(c) <= 126 for c in value)
        )  # Header injection, not token format.
        need(len(value.encode()) <= metadata.MAX_BODY)
        need(kind in {"app_jwt", "installation"})
        self.value, self.kind = value, kind

    def __repr__(self):
        return "<redacted credential>"

    def __reduce_ex__(self, protocol):
        raise AdapterError()


class _Reply:
    __slots__ = ("body",)

    def __init__(self, body):
        need(type(body) is bytes and len(body) <= metadata.MAX_BODY)
        self.body = body

    def __repr__(self):
        return "<redacted HTTP reply>"

    def __reduce_ex__(self, protocol):
        raise AdapterError()


class _Deadline:
    def __init__(self, clock, timeout):
        need(type(timeout) in {int, float} and 0 < timeout <= 5)
        self.clock = clock
        self.wall = metadata._Budget._number(clock.wall())
        self.start = self.last = metadata._Budget._number(clock.monotonic())
        self.end = self.start + timeout

    def remaining(self):
        now = metadata._Budget._number(self.clock.monotonic())
        wall = metadata._Budget._number(self.clock.wall())
        need(now >= self.last and now < self.end)
        need(abs((wall - self.wall) - (now - self.start)) <= 2)
        self.last = now
        return self.end - now


class _Reader(io.RawIOBase):
    def __init__(self, sock, deadline):
        super().__init__()
        self.sock, self.deadline, self.received = sock, deadline, 0

    def readable(self):
        return True

    def readinto(self, target):
        self.sock.settimeout(self.deadline.remaining())
        chunk = self.sock.recv(min(len(target), 4096))
        self.deadline.remaining()
        self.received += len(chunk)
        need(self.received <= MAX_WIRE)
        target[: len(chunk)] = chunk
        return len(chunk)


class _SocketView:
    def __init__(self, sock, deadline):
        self.reader = _Reader(sock, deadline)

    def makefile(self, mode):
        need(mode == "rb")
        return io.BufferedReader(self.reader, buffer_size=4096)


class Wire:
    """Concrete bounded TLS/HTTP. Explicit numeric address avoids unbounded DNS.

    Address must be independently resolved/approved by a future trusted operator.
    It does not change the fixed HTTPS origin: SNI, cert hostname and Host remain
    api.github.com. No default address and no supplied TLS context/CA path.
    """

    def __init__(self, *, address, clock=None):
        ip = None
        if type(address) is str:
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                pass
        need(ip is not None)
        need(ip.is_global and not ip.is_multicast)
        if isinstance(ip, ipaddress.IPv6Address):
            need(ip.scope_id is None)
        self.address = str(ip)
        self.family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        self.clock = metadata.Clock() if clock is None else clock

    def exchange(self, operation, pins, bearer, *, timeout):
        sock = tls = response = None
        failed = False
        result = None
        try:
            method, path, kind, status = route(operation, pins)
            need(
                (bearer is None)
                if kind == "public"
                else (type(bearer) is _Secret and bearer.kind == kind)
            )
            deadline = _Deadline(self.clock, timeout)
            # Fixed system CA bundle; SSL_CERT_FILE/DIR and proxies are not consulted.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_verify_locations(cafile="/etc/ssl/certs/ca-certificates.crt")
            sock = socket.socket(self.family, socket.SOCK_STREAM)
            sock.settimeout(deadline.remaining())
            sock.connect((self.address, 443))
            deadline.remaining()
            tls = context.wrap_socket(
                sock, server_hostname="api.github.com", do_handshake_on_connect=False
            )
            tls.settimeout(deadline.remaining())
            tls.do_handshake()
            deadline.remaining()
            headers = [
                f"{method} {path} HTTP/1.1",
                "Host: api.github.com",
                "Accept: application/vnd.github+json",
                "Accept-Encoding: identity",
                "X-GitHub-Api-Version: 2022-11-28",
                "User-Agent: agent-platform-ap-al-1",
                "Connection: close",
            ]
            if bearer is not None:
                headers.append("Authorization: Bearer " + bearer.value)
            body = b"{}" if operation is Operation.ISSUE_TOKEN else b""
            if body:
                headers += ["Content-Type: application/json", "Content-Length: 2"]
            payload = "\r\n".join(headers).encode("ascii") + b"\r\n\r\n" + body
            tls.settimeout(deadline.remaining())
            tls.sendall(payload)
            deadline.remaining()
            response = http.client.HTTPResponse(_SocketView(tls, deadline))
            response.begin()
            deadline.remaining()
            need(response.status == status)
            need(len(response.headers.as_bytes()) <= MAX_HEADER)
            need(response.getheader("Link") is None)
            need(response.getheader("Content-Encoding") in {None, "identity"})
            lengths = response.headers.get_all("Content-Length", [])
            transfers = response.headers.get_all("Transfer-Encoding", [])
            need(len(lengths) <= 1 and len(transfers) <= 1)
            need(not (lengths and transfers))
            need(not transfers or transfers == ["chunked"])
            length = None
            if lengths:
                need(lengths[0].isascii() and lengths[0].isdigit())
                length = int(lengths[0])
                need(length <= metadata.MAX_BODY)
            raw = response.read(metadata.MAX_BODY + 1)
            deadline.remaining()
            need(len(raw) <= metadata.MAX_BODY)
            need(length is None or len(raw) == length)
            need(status != 204 or not raw)
            result = _Reply(raw)
        except BaseException:
            failed = True
        finally:
            for resource in (response, tls, sock):
                if resource is not None:
                    try:
                        resource.close()
                    except BaseException:
                        failed = True
        if failed:
            # Outside the handler: do not retain a hostile HTTP exception context.
            raise AdapterError()
        return result
