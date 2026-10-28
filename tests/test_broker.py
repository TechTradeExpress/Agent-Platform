"""Offline AF_UNIX integration; fake inference only, no credentials or TLS calls."""

import asyncio
import contextlib
import dataclasses
import http.client
import json
import os
import socket
import ssl
import threading
from socketserver import UnixStreamServer

import pytest
from test_isolation import profile as profile

from agent_platform import _sandbox, broker, isolation
from agent_platform.broker_policy import ENDPOINT, Policy, Rejected

TOKEN = "fabricated_sentinel_secret_123456789"


def configuration():
    return {
        "version": 1,
        "endpoint": ENDPOINT,
        "broker_id": "b" * 64,
        "peers": [[os.getuid(), os.getgid()]],
        "models": ["fixture-model"],
    }


def policy(**limits):
    value = configuration()
    value["limits"] = limits
    return Policy.parse(value)


def request(**updates):
    value = {
        "model": "fixture-model",
        "input": "nonsecret fixture",
        "stream": True,
        "store": False,
        "background": False,
    }
    value.update(updates)
    return json.dumps(value).encode()


def event(kind, **extra):
    return (
        "event: " + kind + "\ndata: " + json.dumps({"type": kind, **extra}) + "\n\n"
    ).encode()


CREATED = event(
    "response.created", response={"id": "resp_fixture", "status": "in_progress"}
)
COMPLETED = event(
    "response.completed", response={"id": "resp_fixture", "status": "completed"}
)


class FakeUpstream:
    _token = TOKEN

    def __init__(self, chunks=None, delay=0):
        self.chunks = chunks if chunks is not None else [CREATED, COMPLETED]
        self.delay = delay
        self.calls = []
        self.closed = False
        self.entered = asyncio.Event()

    async def stream(self, body):
        self.calls.append(json.loads(body))
        self.entered.set()
        try:
            for chunk in self.chunks:
                if self.delay:
                    await asyncio.sleep(self.delay)
                if isinstance(chunk, Exception):
                    raise chunk
                yield chunk
        finally:
            self.closed = True


async def exchange(path, body=None, *, method=None, route=None, extra=b"", raw=None):
    reader, writer = await asyncio.open_unix_connection(path)
    if raw is None:
        method = method or ("POST" if body is not None else "GET")
        route = route or (
            "/v1/responses" if body is not None else "/agent-platform/health"
        )
        payload = body or b""
        raw = (
            (
                f"{method} {route} HTTP/1.1\r\nHost: localhost\r\n"
                f"Content-Length: {len(payload)}\r\n"
                "Content-Type: application/json\r\nAccept: text/event-stream\r\n"
            ).encode()
            + extra
            + b"\r\n"
            + payload
        )
    writer.write(raw)
    await writer.drain()
    try:

        async def collect():
            chunks = []
            try:
                while chunk := await reader.read(4096):
                    chunks.append(chunk)
            except ConnectionResetError:
                pass  # Early denial closes without draining untrusted client data.
            return b"".join(chunks)

        return await asyncio.wait_for(collect(), 2)
    finally:
        writer.close()
        with contextlib.suppress(ConnectionResetError):
            await writer.wait_closed()


async def fixture(tmp_path, upstream=None, config=None):
    path = tmp_path / "inference.sock"
    server = broker.Broker(config or policy(), upstream or FakeUpstream())
    await server.start(path)
    return server, path


def run(coroutine):
    return asyncio.run(coroutine)


def test_health_preflight_and_sse(tmp_path, monkeypatch):
    async def scenario():
        upstream = FakeUpstream()
        server, path = await fixture(tmp_path, upstream)
        monkeypatch.setattr(isolation, "BROKER", path)
        monkeypatch.setattr(isolation, "OWNER_UID", os.getuid())
        try:
            code, raw = await asyncio.to_thread(
                isolation.broker_request, "GET", "/agent-platform/health"
            )
            assert code == 200 and json.loads(raw) == {
                "protocol": 1,
                "broker_id": "b" * 64,
                "inference_only": True,
                "credentials_exposed": False,
                "network_tools": False,
            }
            for method, endpoint in [
                ("GET", "/auth"),
                ("POST", "/v1/admin"),
                ("GET", "/v1/models"),
            ]:
                assert (
                    await asyncio.to_thread(isolation.broker_request, method, endpoint)
                )[0] == 403
            response = await exchange(path, request())
            assert response.startswith(b"HTTP/1.1 200")
            assert b"response.completed" in response and TOKEN.encode() not in response
            assert upstream.calls[0]["store"] is False
            assert upstream.calls[0]["max_output_tokens"] == 4096
            assert upstream.closed
        finally:
            await server.close()
        assert path.exists()  # Never automatically unlink recovery/restart artifacts.

    run(scenario())


def test_existing_relay_compatibility(tmp_path, monkeypatch):
    async def scenario():
        server, path = await fixture(tmp_path)
        relay_path = tmp_path / "relay.sock"
        original = socket.socket

        class Redirected(original):
            def connect(self, address):
                return super().connect(
                    str(path) if address == "/inference.sock" else address
                )

        monkeypatch.setattr(_sandbox.socket, "socket", Redirected)
        relay = UnixStreamServer(str(relay_path), _sandbox.Relay)
        thread = threading.Thread(target=relay.handle_request)
        thread.start()

        def call():
            sock = original(socket.AF_UNIX)
            sock.settimeout(2)
            sock.connect(str(relay_path))
            connection = http.client.HTTPConnection("localhost", timeout=2)
            connection.sock = sock
            try:
                connection.request(
                    "POST",
                    "/v1/responses",
                    request(),
                    {"Content-Type": "application/json"},
                )
                response = connection.getresponse()
                return response.status, response.read()
            finally:
                connection.close()

        try:
            status, body = await asyncio.to_thread(call)
            assert status == 200 and b"response.completed" in body
        finally:
            await server.close()
            await asyncio.to_thread(thread.join, 2)
            relay.server_close()

    run(scenario())


def test_unauthorized_peer_before_any_input(tmp_path):
    async def scenario():
        config = dataclasses.replace(policy(), peers=((os.getuid() + 1, os.getgid()),))
        server, path = await fixture(tmp_path, config=config)
        try:
            reader, writer = await asyncio.open_unix_connection(path)
            # Send nothing at all: peer rejection must not await body or headers.
            raw = await asyncio.wait_for(reader.read(), 0.5)
            assert raw.startswith(b"HTTP/1.1 403") and not server.upstream.calls
            writer.close()
            await writer.wait_closed()
        finally:
            await server.close()

    run(scenario())


@pytest.mark.parametrize(
    "extra",
    [
        b"Content-Length: 1\r\n",
        b"Transfer-Encoding: chunked\r\n",
        b"Content-Encoding: gzip\r\n",
        b"Authorization: Bearer attacker\r\n",
        b"Upgrade: websocket\r\n",
        b"Proxy-Authorization: secret\r\n",
        b"X-Forwarded-For: root\r\n",
        b"Bad : value\r\n",
        b" folded: value\r\n",
        b"X-Test: bad\x00value\r\n",
    ],
)
def test_smuggling_and_headers_denied(tmp_path, extra):
    async def scenario():
        server, path = await fixture(tmp_path)
        try:
            response = await exchange(path, request(), extra=extra)
            assert response.startswith(b"HTTP/1.1 403") and not server.upstream.calls
        finally:
            await server.close()

    run(scenario())


@pytest.mark.parametrize(
    "method,route",
    [
        ("CONNECT", "example:443"),
        ("GET", "/v1/responses"),
        ("POST", "/v1/responses?url=evil"),
        ("PUT", "/agent-platform/health"),
        ("POST", "https://evil.example/v1/responses"),
        ("GET", "/auth"),
    ],
)
def test_routes_denied(tmp_path, method, route):
    async def scenario():
        server, path = await fixture(tmp_path)
        try:
            assert (await exchange(path, method=method, route=route)).startswith(
                b"HTTP/1.1 403"
            )
            assert not server.upstream.calls
        finally:
            await server.close()

    run(scenario())


@pytest.mark.parametrize(
    "raw",
    [
        b"POST /v1/responses HTTP/1.1\r\nContent-Length: 9999999\r\n\r\n",
        b"POST /v1/responses HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
        b"GET /agent-platform/health HTTP/1.1\r\nX: " + b"x" * 9000 + b"\r\n\r\n",
        b"GET /agent-platform/health HTTP/1.0\r\n\r\n",
    ],
)
def test_oversize_or_invalid_framing(tmp_path, raw):
    async def scenario():
        server, path = await fixture(tmp_path)
        try:
            response = await exchange(path, raw=raw)
            assert response.startswith(b"HTTP/1.1 403") and not server.upstream.calls
        finally:
            await server.close()

    run(scenario())


@pytest.mark.parametrize(
    "body",
    [
        b"{}",
        b"not-json",
        b"\xff",
        b'{"model":1,"model":2}',
        request(model="other-model"),
        request(stream=False),
        request(background=True),
        request(store=True),
        request(previous_response_id="resp_elsewhere"),
        request(conversation="conversation"),
        request(metadata={"x": "y"}),
        request(tools=[{"type": "web_search"}]),
        request(tools=[{"type": "mcp", "server_url": "https://evil"}]),
        request(input=[{"type": "input_image", "image_url": "https://evil"}]),
        request(max_output_tokens=99999),
        request(max_output_tokens=True),
        request(tool_choice={"type": "web_search"}),
        request(
            input=[
                {"role": "user", "content": [{"type": "input_file", "file_id": "f"}]}
            ]
        ),
        request(input=[{"type": "item_reference", "id": "secret"}]),
        request(text={"format": {"type": "json_schema"}}),
        request(tools=[{"type": "function", "name": [], "parameters": {}}]),
    ],
)
def test_request_policy_denied(tmp_path, body):
    async def scenario():
        server, path = await fixture(tmp_path)
        try:
            response = await exchange(path, body)
            assert response.startswith(b"HTTP/1.1 403")
            assert not server.upstream.calls and TOKEN.encode() not in response
        finally:
            await server.close()

    run(scenario())


def test_function_custom_and_stateless_history_subset():
    tools = [
        {
            "type": "function",
            "name": "shell",
            "parameters": {"type": "object"},
            "strict": True,
        },
        {
            "type": "custom",
            "name": "apply_patch",
            "format": {"type": "grammar", "syntax": "lark", "definition": 'start: "x"'},
        },
    ]
    body = request(
        tools=tools,
        input=[
            {"role": "developer", "content": [{"type": "input_text", "text": "task"}]},
            {
                "type": "function_call",
                "name": "shell",
                "call_id": "c1",
                "arguments": "{}",
            },
            {"type": "function_call_output", "call_id": "c1", "output": "safe output"},
            {
                "type": "custom_tool_call",
                "name": "apply_patch",
                "call_id": "c2",
                "input": "patch",
            },
            {"type": "custom_tool_call_output", "call_id": "c2", "output": "done"},
            {"type": "reasoning", "summary": [], "encrypted_content": "opaque"},
        ],
        include=["reasoning.encrypted_content"],
        reasoning={"effort": "high", "summary": "auto"},
        text={"format": {"type": "text"}, "verbosity": "low"},
    )
    accepted = json.loads(policy().request(body))
    assert accepted["tools"] == tools and accepted["store"] is False


@pytest.mark.parametrize(
    "chunks",
    [
        [b"not sse\n\n"],
        [b"x" * 65537],
        [CREATED],
        [event("error", message=TOKEN)],
        [event("response.failed", error={"message": TOKEN})],
        [event("response.created", response={"error": {"message": TOKEN}})],
        [event("response.created", response={"id": TOKEN})],
        [CREATED, event("response.output_text.delta", delta=TOKEN)],
        [CREATED, COMPLETED, b"bad trailing data"],
        [CREATED, RuntimeError(TOKEN)],
        [
            b"event: response.created\n"
            b'data: {"type":"response.created","type":"error"}\n\n'
        ],
        [b"event: response.created\ndata: \xff\n\n"],
    ],
)
def test_invalid_stream_and_errors_never_leak_or_complete(tmp_path, chunks, capsys):
    async def scenario():
        upstream = FakeUpstream(chunks)
        server, path = await fixture(tmp_path, upstream)
        try:
            response = await exchange(path, request())
            assert (
                TOKEN.encode() not in response and b"response.completed" not in response
            )
            assert upstream.closed
        finally:
            await server.close()

    run(scenario())
    assert TOKEN not in repr(capsys.readouterr())


def test_stream_size_event_and_lifetime_limits(tmp_path):
    async def scenario():
        upstream = FakeUpstream(
            [CREATED, event("response.output_text.delta", delta="x" * 400)]
        )
        server, path = await fixture(tmp_path, upstream, policy(event_bytes=256))
        try:
            assert b"response.completed" not in await exchange(path, request())
            server.started -= server.policy.lifetime_seconds
            assert (await exchange(path, request())).startswith(b"HTTP/1.1 429")
        finally:
            await server.close()

    run(scenario())


def test_slow_upstream_and_client_disconnect_close_transport(tmp_path):
    async def scenario():
        upstream = FakeUpstream(delay=10)
        config = dataclasses.replace(policy(), idle_seconds=0.05)
        server, path = await fixture(tmp_path, upstream, config)
        try:
            response = await exchange(path, request())
            assert response.startswith(b"HTTP/1.1 502") and upstream.closed
            upstream.closed = False
            upstream.entered.clear()
            reader, writer = await asyncio.open_unix_connection(path)
            body = request()
            writer.write(
                (
                    "POST /v1/responses HTTP/1.1\r\nHost: localhost\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n"
                ).encode()
                + body
            )
            await writer.drain()
            await asyncio.wait_for(upstream.entered.wait(), 0.5)
            writer.close()
            await writer.wait_closed()
            for _ in range(50):
                if upstream.closed:
                    break
                await asyncio.sleep(0.01)
            assert upstream.closed
        finally:
            await server.close()

    run(scenario())


def test_concurrency_and_nonrefundable_peer_budget(tmp_path):
    async def scenario():
        upstream = FakeUpstream(delay=10)
        server, path = await fixture(
            tmp_path, upstream, policy(concurrency=1, requests_per_peer=1)
        )
        try:
            call = asyncio.create_task(exchange(path, request()))
            await asyncio.wait_for(upstream.entered.wait(), 0.5)
            assert (await exchange(path, request())).startswith(b"HTTP/1.1 429")
            call.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await call
            for _ in range(50):
                if server.active == 0:
                    break
                await asyncio.sleep(0.01)
            assert (await exchange(path, request())).startswith(b"HTTP/1.1 429")
            assert len(upstream.calls) == 1
        finally:
            await server.close()

    run(scenario())


@pytest.mark.parametrize("kind", ["file", "symlink", "socket"])
def test_path_collision_never_overwritten(tmp_path, kind):
    path = tmp_path / "inference.sock"
    other = None
    if kind == "file":
        path.write_text("preserve")
    elif kind == "symlink":
        path.symlink_to(tmp_path / "absent")
    else:
        other = socket.socket(socket.AF_UNIX)
        other.bind(str(path))
    before = path.lstat()

    async def scenario():
        with pytest.raises(Rejected):
            await fixture(tmp_path)

    try:
        run(scenario())
        assert path.lstat().st_ino == before.st_ino
    finally:
        if other:
            other.close()


@pytest.mark.parametrize(
    "change", ["origin", "model", "id", "peer", "limit", "unknown", "version"]
)
def test_configuration_fail_closed(change):
    data = configuration()
    if change == "origin":
        data["endpoint"] = "http://evil.example/v1/responses"
    elif change == "model":
        data["models"] = ["https://evil.example"]
    elif change == "id":
        data["broker_id"] = "short"
    elif change == "peer":
        data["peers"] = [[True, 0]]
    elif change == "limit":
        data["limits"] = {"concurrency": 99999}
    elif change == "unknown":
        data["credentials"] = TOKEN
    else:
        data["version"] = True
    with pytest.raises(Rejected):
        Policy.parse(data)


def test_credential_and_config_private_files(tmp_path):
    path = tmp_path / "secret"
    path.write_text(TOKEN)
    path.chmod(0o600)
    assert broker.credential(os.open(path, os.O_RDONLY)) == TOKEN
    path.chmod(0o644)
    with pytest.raises(Rejected):
        broker.credential(os.open(path, os.O_RDONLY))
    with pytest.raises(Rejected):
        broker.private_read(path, 1024)


class FakeWriter:
    def __init__(self):
        self.raw = b""
        self.closed = False

    def write(self, raw):
        self.raw += raw

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


@pytest.mark.parametrize(
    "response",
    [
        b"HTTP/1.1 302 Found\r\nLocation: https://evil.example\r\n"
        b"Content-Length: 0\r\n\r\n",
        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 20\r\n\r\n" + TOKEN.encode(),
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
        b"Content-Encoding: gzip\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
        b"Transfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n",
    ],
)
def test_tls_fixed_origin_rejects_redirect_errors_and_encoding(monkeypatch, response):
    async def scenario():
        writer = FakeWriter()
        calls = []

        async def connect(host, port, **kwargs):
            calls.append((host, port))
            assert kwargs["server_hostname"] == "api.openai.com"
            assert kwargs["ssl"].verify_mode == ssl.CERT_REQUIRED
            assert kwargs["ssl"].check_hostname
            reader = asyncio.StreamReader(limit=8192)
            reader.feed_data(response)
            reader.feed_eof()
            return reader, writer

        monkeypatch.setattr(asyncio, "open_connection", connect)
        monkeypatch.setenv("HTTPS_PROXY", "https://evil.example")
        upstream = broker.HTTPSUpstream(TOKEN, policy())
        with pytest.raises(Rejected):
            async for _ in upstream.stream(request()):
                pass
        assert calls == [("api.openai.com", 443)] and writer.closed
        assert b"POST /v1/responses HTTP/1.1" in writer.raw
        assert TOKEN not in repr(upstream)

    run(scenario())


def test_tls_chunked_stream_and_header_isolation(monkeypatch, tmp_path):
    async def scenario():
        writer = FakeWriter()
        body = CREATED + COMPLETED
        encoded = hex(len(body))[2:].encode() + b"\r\n" + body + b"\r\n0\r\n\r\n"

        async def connect(*args, **kwargs):
            reader = asyncio.StreamReader(limit=8192)
            reader.feed_data(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                b"Transfer-Encoding: chunked\r\nX-Secret: "
                + TOKEN.encode()
                + b"\r\n\r\n"
                + encoded
            )
            reader.feed_eof()
            return reader, writer

        monkeypatch.setattr(asyncio, "open_connection", connect)
        server, path = await fixture(tmp_path, broker.HTTPSUpstream(TOKEN, policy()))
        try:
            result = await exchange(path, request())
            assert (
                result.startswith(b"HTTP/1.1 200") and b"response.completed" in result
            )
            assert TOKEN.encode() not in result and b"X-Secret" not in result
            assert writer.closed
        finally:
            await server.close()

    run(scenario())


@pytest.mark.parametrize("limit", ["response_bytes", "events", "total_response_bytes"])
def test_stream_budgets_reject_before_completion(tmp_path, limit):
    async def scenario():
        limits = {limit: 1 if limit == "events" else len(CREATED)}
        server, path = await fixture(tmp_path, config=policy(**limits))
        try:
            result = await exchange(path, request())
            assert b"response.completed" not in result
            assert server.upstream.closed
        finally:
            await server.close()

    run(scenario())


def test_global_request_budget_and_malformed_attempts_not_refunded(tmp_path):
    async def scenario():
        server, path = await fixture(tmp_path, config=policy(total_requests=1))
        try:
            assert (await exchange(path, b"{}")).startswith(b"HTTP/1.1 403")
            assert (await exchange(path, request())).startswith(b"HTTP/1.1 429")
            assert not server.upstream.calls
        finally:
            await server.close()

    run(scenario())


def test_backpressure_stops_reading_and_cancels_upstream():
    async def scenario():
        upstream = FakeUpstream([CREATED] * 1000)
        server = broker.Broker(
            dataclasses.replace(policy(), idle_seconds=0.02), upstream
        )

        class StalledWriter(FakeWriter):
            async def drain(self):
                await asyncio.Event().wait()

        writer = StalledWriter()
        await asyncio.wait_for(server.forward(writer, request()), 0.5)
        assert upstream.closed
        assert len(writer.raw) < 1024

    run(scenario())


def test_header_and_body_deadlines(tmp_path):
    async def scenario():
        config = dataclasses.replace(policy(), idle_seconds=0.02)
        server, path = await fixture(tmp_path, config=config)
        try:
            for raw in [
                b"GET ",
                b"POST /v1/responses HTTP/1.1\r\nHost: localhost\r\n"
                b"Content-Type: application/json\r\nContent-Length: 200\r\n\r\n{}",
            ]:
                assert (await exchange(path, raw=raw)).startswith(b"HTTP/1.1 403")
            assert not server.upstream.calls
        finally:
            await server.close()

    run(scenario())


def test_lease_expiry_cancels_active_turn_and_preserves_socket(tmp_path):
    async def scenario():
        config = dataclasses.replace(policy(), lifetime_seconds=0.05)
        upstream = FakeUpstream(delay=10)
        server, path = await fixture(tmp_path, upstream, config)
        serving = asyncio.create_task(server.serve())
        turn = asyncio.create_task(exchange(path, request()))
        await asyncio.wait_for(upstream.entered.wait(), 0.5)
        await asyncio.wait_for(serving, 0.5)
        await asyncio.wait_for(turn, 0.5)
        assert upstream.closed and path.exists() and not server.tasks

    run(scenario())


@pytest.mark.parametrize(
    "fault", ["gid", "platform", "symlink_parent", "writable_parent"]
)
def test_peer_gid_and_socket_environment_fail_closed(tmp_path, monkeypatch, fault):
    async def scenario():
        if fault == "gid":
            server, path = await fixture(
                tmp_path,
                config=dataclasses.replace(
                    policy(), peers=((os.getuid(), os.getgid() + 1),)
                ),
            )
            try:
                assert (await exchange(path)).startswith(b"HTTP/1.1 403")
            finally:
                await server.close()
            return
        directory = tmp_path / "directory"
        directory.mkdir()
        if fault == "platform":
            monkeypatch.setattr(broker.sys, "platform", "unsupported")
        elif fault == "symlink_parent":
            alias = tmp_path / "alias"
            alias.symlink_to(directory, target_is_directory=True)
            directory = alias
        else:
            directory.chmod(0o777)
        with pytest.raises(Rejected):
            await broker.Broker(policy(), FakeUpstream()).start(directory / "socket")
        assert not (directory / "socket").exists()

    run(scenario())


def test_credential_rejects_pipe_newline_and_hardlink(tmp_path):
    read_fd, write_fd = os.pipe()
    try:
        with pytest.raises(Rejected):
            broker.credential(read_fd)  # Must not block waiting for pipe bytes.
    finally:
        os.close(write_fd)
    secret = tmp_path / "sentinel"
    secret.write_text(TOKEN + "\n")
    secret.chmod(0o600)
    with pytest.raises(Rejected):
        broker.credential(os.open(secret, os.O_RDONLY))
    secret.write_text(TOKEN)
    os.link(secret, tmp_path / "hardlink")
    with pytest.raises(Rejected):
        broker.credential(os.open(secret, os.O_RDONLY))


def test_external_schema_refs_rejected():
    body = request(
        tools=[
            {
                "type": "function",
                "name": "shell",
                "parameters": {"$ref": "https://evil.example/schema"},
            }
        ]
    )
    with pytest.raises(Rejected):
        policy().request(body)


def test_cli_generic_error_and_closed_secret_fd(tmp_path, monkeypatch, capsys):
    config = tmp_path / "config"
    config.write_text(json.dumps(configuration()))
    config.chmod(0o600)
    secret = tmp_path / "secret"
    secret.write_text(TOKEN)
    secret.chmod(0o600)
    fd = os.open(secret, os.O_RDONLY)

    async def fail(*args):
        raise RuntimeError(TOKEN)

    monkeypatch.setattr(broker, "run", fail)
    monkeypatch.setattr(
        broker.sys,
        "argv",
        [
            "agent-platform-broker",
            "--config",
            str(config),
            "--socket",
            str(tmp_path / "sock"),
            "--credential-fd",
            str(fd),
        ],
    )
    assert broker.main() == 1
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == "agent-platform-broker: unavailable\n"
    with pytest.raises(OSError):
        os.fstat(fd)


REAL_BROKER_REQUEST = isolation.broker_request


@pytest.mark.parametrize("identity_matches", [True, False])
def test_actual_broker_with_shared_profile_preflight(
    tmp_path, monkeypatch, profile, identity_matches
):
    async def scenario():
        data = configuration()
        if not identity_matches:
            data["broker_id"] = "a" * 64
        server, path = await fixture(tmp_path, config=Policy.parse(data))
        current, _, reads = profile
        monkeypatch.setattr(isolation, "BROKER", path)
        monkeypatch.setattr(isolation, "broker_request", REAL_BROKER_REQUEST)
        try:
            if identity_matches:
                await asyncio.to_thread(current.preflight)
                assert len(reads) == 3 and current.digest is not None
            else:
                with pytest.raises(isolation.IsolationError):
                    await asyncio.to_thread(current.preflight)
                assert not reads and current.digest is None
        finally:
            await server.close()

    run(scenario())


@pytest.mark.parametrize(
    "chunks",
    [
        [event("response.created", response=None)],
        [event("response.created", response={"id": "resp_f", "status": "failed"})],
        [
            event(
                "response.created",
                response={
                    "id": "resp_f",
                    "status": "in_progress",
                    "model": "unapproved",
                },
            )
        ],
        [CREATED, CREATED, COMPLETED],
        [
            CREATED,
            event("response.output_item.added", item={"type": "web_search_call"}),
        ],
        [
            CREATED,
            event("response.completed", response={"id": "resp_f", "status": "failed"}),
        ],
        [CREATED, event("response.output_text.delta", delta={"bad": "shape"})],
    ],
)
def test_semantic_sse_validation(tmp_path, chunks):
    async def scenario():
        server, path = await fixture(tmp_path, FakeUpstream(chunks))
        try:
            raw = await exchange(path, request())
            assert b"response.completed" not in raw
        finally:
            await server.close()

    run(scenario())


@pytest.mark.parametrize(
    "framing",
    ["truncated_length", "bad_chunk", "chunk_extension", "trailer", "duplicate_length"],
)
def test_upstream_transport_framing_aborts_without_success(
    tmp_path, monkeypatch, framing
):
    async def scenario():
        writer = FakeWriter()
        base = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
        body = CREATED + COMPLETED
        if framing == "truncated_length":
            raw = base + f"Content-Length: {len(body) + 20}\r\n\r\n".encode() + body
        elif framing == "duplicate_length":
            raw = base + b"Content-Length: 1\r\nContent-Length: 2\r\n\r\nx"
        else:
            payload = {
                "bad_chunk": b"not-hex\r\n",
                "chunk_extension": b"10;foo=bar\r\n",
                "trailer": b"0\r\nX-Secret: " + TOKEN.encode() + b"\r\n\r\n",
            }[framing]
            raw = base + b"Transfer-Encoding: chunked\r\n\r\n" + payload

        async def connect(*args, **kwargs):
            reader = asyncio.StreamReader(limit=8192)
            reader.feed_data(raw)
            reader.feed_eof()
            return reader, writer

        monkeypatch.setattr(asyncio, "open_connection", connect)
        server, path = await fixture(tmp_path, broker.HTTPSUpstream(TOKEN, policy()))
        try:
            response = await exchange(path, request())
            assert (
                b"response.completed" not in response and TOKEN.encode() not in response
            )
            assert writer.closed
        finally:
            await server.close()

    run(scenario())


def test_disconnect_closes_mock_tls_transport(tmp_path, monkeypatch):
    async def scenario():
        upstream_writer = FakeWriter()

        async def connect(*args, **kwargs):
            reader = asyncio.StreamReader(limit=8192)
            reader.feed_data(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n" + CREATED
            )
            return (
                reader,
                upstream_writer,
            )  # Never EOF: simulate stalled live transport.

        monkeypatch.setattr(asyncio, "open_connection", connect)
        server, path = await fixture(tmp_path, broker.HTTPSUpstream(TOKEN, policy()))
        try:
            reader, writer = await asyncio.open_unix_connection(path)
            body = request()
            writer.write(
                (
                    "POST /v1/responses HTTP/1.1\r\nHost: localhost\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n"
                ).encode()
                + body
            )
            await writer.drain()
            assert (
                await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 0.5)
            ).startswith(b"HTTP/1.1 200")
            writer.close()
            await writer.wait_closed()
            for _ in range(50):
                if upstream_writer.closed:
                    break
                await asyncio.sleep(0.01)
            assert upstream_writer.closed
        finally:
            await server.close()

    run(scenario())
