"""Foreground reference broker. Deployment and independent audit are external."""

import argparse
import asyncio
import contextlib
import os
import re
import socket
import ssl
import stat
import struct
import sys
from pathlib import Path

from agent_platform.broker_policy import Policy, Rejected, decode, require

HEADER_BYTES = 8192
CHUNK_BYTES = 4096


def trusted_parent(path):
    require(path.is_absolute() and ".." not in path.parts)
    for parent in [*reversed(path.parents), path]:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid()))
        sticky = (
            parent in (Path("/tmp"), Path("/var/tmp")) and info.st_mode & stat.S_ISVTX
        )
        require(not info.st_mode & 0o022 or sticky)


def private_read(path, limit):
    trusted_parent(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid in (0, os.getuid())
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_nlink == 1
        )
        raw = os.read(fd, limit + 1)
        require(len(raw) <= limit)
        return raw
    finally:
        os.close(fd)


def credential(fd):
    require(fd >= 3)
    try:
        info = os.fstat(fd)
        # A pre-opened private regular secret file avoids an unbounded pipe read.
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid in (0, os.getuid())
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_nlink == 1
        )
        raw = os.read(fd, 513)
        require(re.fullmatch(rb"[A-Za-z0-9_-]{16,512}", raw) is not None)
        return raw.decode("ascii")
    finally:
        os.close(fd)


async def headers(reader):
    raw = await reader.readuntil(b"\r\n\r\n")
    require(len(raw) <= HEADER_BYTES)
    lines = raw[:-4].split(b"\r\n")
    require(len(lines) <= 33 and all(len(line) <= 2048 for line in lines))
    first = lines.pop(0).decode("ascii")
    result = {}
    for line in lines:
        require(b":" in line)
        name, value = line.split(b":", 1)
        require(re.fullmatch(rb"[A-Za-z0-9-]+", name) is not None)
        key = name.decode("ascii").lower()
        require(key not in result)
        value = value.strip(b" ")
        require(all(32 <= char < 127 for char in value))
        result[key] = value.decode("ascii")
    return first, result


class HTTPSUpstream:
    """No URL input, proxy environment, redirects, alternate transports or retries."""

    def __init__(self, token, policy):
        require(
            isinstance(token, str)
            and re.fullmatch(r"[A-Za-z0-9_-]{16,512}", token) is not None
        )
        self._token = token
        self.policy = policy

    def __repr__(self):
        return "HTTPSUpstream(<redacted>)"

    async def stream(self, body):
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    "api.openai.com",
                    443,
                    ssl=context,
                    server_hostname="api.openai.com",
                    ssl_handshake_timeout=self.policy.idle_seconds,
                    limit=HEADER_BYTES,
                ),
                self.policy.idle_seconds,
            )
            writer.write(
                (
                    "POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\n"
                    "Content-Type: application/json\r\nAccept: text/event-stream\r\n"
                    "Accept-Encoding: identity\r\nConnection: close\r\n"
                    f"Authorization: Bearer {self._token}\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n"
                ).encode("ascii")
                + body
            )
            await asyncio.wait_for(writer.drain(), self.policy.idle_seconds)
            first, response = await asyncio.wait_for(
                headers(reader), self.policy.idle_seconds
            )
            require(re.fullmatch(r"HTTP/1\.[01] 200(?: [ -~]*)?", first) is not None)
            require(
                response.get("content-type", "").lower()
                in ("text/event-stream", "text/event-stream; charset=utf-8")
            )
            require("content-encoding" not in response)
            transfer = response.get("transfer-encoding")
            length = response.get("content-length")
            require(not (transfer and length))
            require(transfer in (None, "chunked"))
            remaining = None
            if length is not None:
                require(re.fullmatch("[0-9]{1,10}", length) is not None)
                remaining = int(length)
                require(0 < remaining <= self.policy.response_bytes)
            total = chunks = 0
            while True:
                if transfer == "chunked":
                    line = await asyncio.wait_for(
                        reader.readuntil(b"\r\n"), self.policy.idle_seconds
                    )
                    require(
                        len(line) <= 12 and re.fullmatch(rb"[0-9a-fA-F]{1,8}\r\n", line)
                    )
                    size = int(line[:-2], 16)
                    require(size <= 65536)
                    if size == 0:
                        require(
                            await asyncio.wait_for(
                                reader.readexactly(2), self.policy.idle_seconds
                            )
                            == b"\r\n"
                        )  # No trailers.
                        break
                    while size:
                        chunk = await asyncio.wait_for(
                            reader.readexactly(min(size, CHUNK_BYTES)),
                            self.policy.idle_seconds,
                        )
                        size -= len(chunk)
                        total += len(chunk)
                        chunks += 1
                        require(total <= self.policy.response_bytes and chunks <= 32768)
                        yield chunk
                    require(
                        await asyncio.wait_for(
                            reader.readexactly(2), self.policy.idle_seconds
                        )
                        == b"\r\n"
                    )
                    continue
                chunk = await asyncio.wait_for(
                    reader.read(
                        min(CHUNK_BYTES, remaining)
                        if remaining is not None
                        else CHUNK_BYTES
                    ),
                    self.policy.idle_seconds,
                )
                if not chunk:
                    require(remaining in (None, 0))
                    break
                total += len(chunk)
                chunks += 1
                require(total <= self.policy.response_bytes and chunks <= 32768)
                yield chunk
                if remaining is not None:
                    remaining -= len(chunk)
                    if remaining == 0:
                        break
        finally:
            if writer is not None:
                writer.close()
                # Closing the socket cancels transport; do not wait on peer shutdown.
                with contextlib.suppress(OSError, TimeoutError):
                    await asyncio.wait_for(writer.wait_closed(), 0.2)


KINDS = {
    "response.created",
    "response.in_progress",
    "response.completed",
    "response.output_item.added",
    "response.output_item.done",
    "response.content_part.added",
    "response.content_part.done",
    "response.output_text.delta",
    "response.output_text.done",
    "response.refusal.delta",
    "response.refusal.done",
    "response.function_call_arguments.delta",
    "response.function_call_arguments.done",
    "response.custom_tool_call_input.delta",
    "response.custom_tool_call_input.done",
    "response.reasoning_summary_text.delta",
    "response.reasoning_summary_text.done",
    "response.reasoning_summary_part.added",
    "response.reasoning_summary_part.done",
    "response.reasoning_text.delta",
    "response.reasoning_text.done",
}


def safe_event(raw, token, models):
    """Forward only parsed successful inference events, never upstream errors."""
    lines = raw.replace(b"\r\n", b"\n").split(b"\n")
    require(
        len(lines) == 2
        and lines[0].startswith(b"event: ")
        and lines[1].startswith(b"data: ")
    )
    kind = lines[0][7:].decode("ascii")
    require(kind in KINDS)
    data = decode(lines[1][6:])
    require(isinstance(data, dict) and data.get("type") == kind)

    if "sequence_number" in data:
        require(type(data["sequence_number"]) is int and data["sequence_number"] >= 0)
    if kind in ("response.created", "response.in_progress", "response.completed"):
        response = data.get("response")
        require(isinstance(response, dict))
        require(isinstance(response.get("id"), str) and 0 < len(response["id"]) <= 256)
        expected = "completed" if kind == "response.completed" else "in_progress"
        require(response.get("status") == expected)
        if "model" in response:
            require(response["model"] in models)
    elif kind.endswith(".delta"):
        require(isinstance(data.get("delta"), str))
    elif kind.endswith(".done") and kind not in (
        "response.output_item.done",
        "response.content_part.done",
        "response.reasoning_summary_part.done",
    ):
        key = (
            "arguments"
            if "function_call_arguments" in kind
            else "input"
            if "custom_tool_call_input" in kind
            else "refusal"
            if "refusal" in kind
            else "text"
        )
        require(isinstance(data.get(key), str))
    for key in ("item", "part"):
        if key in data:
            require(isinstance(data[key], dict))
    if kind.startswith("response.output_item."):
        require(
            isinstance(data.get("item"), dict)
            and data["item"].get("type")
            in ("message", "reasoning", "function_call", "custom_tool_call")
        )

    # Do not forward upstream diagnostics embedded in otherwise valid envelopes.
    def clean(value, depth=0):
        require(depth <= 64)
        if isinstance(value, dict):
            require(
                value.get("type")
                not in (
                    "web_search_call",
                    "file_search_call",
                    "computer_call",
                    "mcp_call",
                    "code_interpreter_call",
                    "image_generation_call",
                    "local_shell_call",
                )
            )
            require(
                not any(
                    k in value and value[k] is not None
                    for k in ("error", "incomplete_details")
                )
            )
            require(
                not any(k in value for k in ("authorization", "headers", "api_key"))
            )
            for key, child in value.items():
                require(token not in key)
                clean(child, depth + 1)
        elif isinstance(value, list):
            for child in value:
                clean(child, depth + 1)
        elif isinstance(value, str):
            require(token not in value)

    clean(data)
    # Canonicalize JSON and SSE framing: arbitrary upstream headers are discarded.
    import json

    return kind, b"event: " + kind.encode() + b"\ndata: " + json.dumps(
        data, separators=(",", ":"), ensure_ascii=True
    ).encode() + b"\n\n"


class Broker:
    def __init__(self, policy, upstream):
        self.policy, self.upstream = policy, upstream
        self.active = self.requests = self.response_bytes = 0
        self.counts = {}
        self.tasks = set()
        self.server = None
        self.started = None

    async def start(self, path):
        require(sys.platform == "linux" and hasattr(socket, "SO_PEERCRED"))
        path = Path(path)
        require(path.name not in ("", ".", ".."))
        trusted_parent(path.parent)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            try:
                os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise Rejected()
            # Pin the directory inode; no unlink, chmod/chown or path adoption.
            old = os.umask(0o177)
            try:
                listener.bind(f"/proc/self/fd/{directory}/{path.name}")
            finally:
                os.umask(old)
            info = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            require(
                stat.S_ISSOCK(info.st_mode)
                and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o600
            )
            current, pinned = os.stat(path.parent), os.fstat(directory)
            require((current.st_dev, current.st_ino) == (pinned.st_dev, pinned.st_ino))
            listener.listen(self.policy.concurrency)
            listener.setblocking(False)
            self.started = asyncio.get_running_loop().time()
            self.server = await asyncio.start_unix_server(
                self.accept,
                sock=listener,
                limit=HEADER_BYTES,
                backlog=self.policy.concurrency,
            )
        except BaseException:
            listener.close()
            raise
        finally:
            os.close(directory)
        return self

    async def close(self):
        if self.server:
            self.server.close()
        # Python 3.12 waits for active transports in Server.wait_closed().
        # Cancel/reap their handlers first, or a stalled upstream can block exit.
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if self.server:
            await self.server.wait_closed()
        # Leave the socket path for explicit operator reconciliation/restart.

    async def serve(self):
        try:
            # start_unix_server already accepts connections. serve_forever's
            # cancellation waits for clients before our cleanup can cancel them.
            remaining = (
                self.started
                + self.policy.lifetime_seconds
                - asyncio.get_running_loop().time()
            )
            await asyncio.sleep(max(0, remaining))
        finally:
            await self.close()

    async def reply(
        self,
        writer,
        code,
        body=b'{"error":"request_denied"}',
        content="application/json",
    ):
        writer.write(
            (
                f"HTTP/1.1 {code} Result\r\nContent-Type: {content}\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode()
            + body
        )
        await asyncio.wait_for(writer.drain(), self.policy.idle_seconds)

    async def accept(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        admitted = False
        try:
            raw = writer.get_extra_info("socket").getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, 12
            )
            _, uid, gid = struct.unpack("iII", raw)
            peer = (uid, gid)
            require(peer in self.policy.peers)  # Before reading headers OR body.
            if (
                self.active >= self.policy.concurrency
                or self.started is None
                or asyncio.get_running_loop().time() - self.started
                >= self.policy.lifetime_seconds
            ):
                await self.reply(writer, 429)
                return
            self.active += 1
            admitted = True
            async with asyncio.timeout(self.policy.request_seconds):
                await self.handle(reader, writer, peer)
        except Exception:
            with contextlib.suppress(OSError, TimeoutError):
                await self.reply(writer, 403)
        finally:
            if admitted:
                self.active -= 1
            writer.close()
            self.tasks.discard(task)

    async def handle(self, reader, writer, peer):
        first, request = await asyncio.wait_for(
            headers(reader), self.policy.idle_seconds
        )
        parts = first.split(" ")
        require(len(parts) == 3 and parts[2] == "HTTP/1.1")
        method, route, _ = parts
        if (method, route) not in (
            ("GET", "/agent-platform/health"),
            ("POST", "/v1/responses"),
        ):
            await self.reply(writer, 403)
            return
        require(
            request.keys()
            <= {
                "host",
                "content-length",
                "content-type",
                "accept",
                "accept-encoding",
                "connection",
                "user-agent",
            }
        )
        require(request.get("host") == "localhost")
        require(request.get("accept-encoding", "identity") == "identity")
        require(request.get("connection", "close").lower() in ("close", "keep-alive"))
        length = request.get("content-length", "0")
        require(re.fullmatch("[0-9]{1,10}", length) is not None)
        size = int(length)
        if method == "GET":
            require(size == 0)
            import json

            body = json.dumps(
                {
                    "protocol": 1,
                    "broker_id": self.policy.broker_id,
                    "inference_only": True,
                    "credentials_exposed": False,
                    "network_tools": False,
                },
                separators=(",", ":"),
            ).encode()
            await self.reply(writer, 200, body)
            return
        require(request.get("content-type") == "application/json")
        require(request.get("accept", "text/event-stream") == "text/event-stream")
        require(0 < size <= self.policy.request_bytes)
        if (
            self.requests >= self.policy.total_requests
            or self.counts.get(peer, 0) >= self.policy.requests_per_peer
        ):
            await self.reply(writer, 429)
            return
        # Reserve budget before body parsing, across connections; never refund.
        self.requests += 1
        self.counts[peer] = self.counts.get(peer, 0) + 1
        body = await asyncio.wait_for(
            reader.readexactly(size), self.policy.idle_seconds
        )
        body = self.policy.request(body)
        # Reject pipelining and cancel upstream on FIN or extra client data.
        monitor = asyncio.create_task(reader.read(1))
        forward = asyncio.create_task(self.forward(writer, body))
        try:
            done, _ = await asyncio.wait(
                (monitor, forward), return_when=asyncio.FIRST_COMPLETED
            )
            if monitor in done:
                forward.cancel()
            else:
                await forward
        finally:
            monitor.cancel()
            forward.cancel()
            await asyncio.gather(monitor, forward, return_exceptions=True)

    async def forward(self, writer, body):
        started = terminal = False
        total = events = chunks = wire_bytes = 0
        pending = b""
        stream = self.upstream.stream(body)
        try:
            async for chunk in timed_chunks(stream, self.policy.idle_seconds):
                require(isinstance(chunk, bytes) and 0 < len(chunk) <= 65536)
                chunks += 1
                total += len(chunk)
                require(chunks <= 32768 and total <= self.policy.response_bytes)
                pending += chunk
                while True:
                    # Accept LF or CRLF SSE frames, with no comments/id/retry fields.
                    match = re.search(rb"\r?\n\r?\n", pending)
                    if match is None:
                        break
                    raw, pending = pending[: match.start()], pending[match.end() :]
                    require(len(raw) <= self.policy.event_bytes and not terminal)
                    kind, safe = safe_event(
                        raw, self.upstream._token, self.policy.models
                    )
                    if started:
                        require(kind != "response.created")
                    wire_bytes += len(safe)
                    self.response_bytes += len(safe)
                    require(self.response_bytes <= self.policy.total_response_bytes)
                    require(
                        len(safe) <= self.policy.event_bytes
                        and wire_bytes <= self.policy.response_bytes
                    )
                    events += 1
                    require(events <= self.policy.events)
                    if not started:
                        require(kind == "response.created")
                        writer.write(
                            b"HTTP/1.1 200 OK\r\n"
                            b"Content-Type: text/event-stream\r\n"
                            b"Connection: close\r\n\r\n"
                        )
                        started = True
                    terminal = kind == "response.completed"
                    # Hold completed until the stream ends cleanly: no false success
                    # on excess/invalid trailing data or truncated transport.
                    if terminal:
                        completed = safe
                    else:
                        writer.write(safe)
                        await asyncio.wait_for(writer.drain(), self.policy.idle_seconds)
                require(len(pending) <= self.policy.event_bytes)
            require(terminal and not pending)
            writer.write(completed)
            await asyncio.wait_for(writer.drain(), self.policy.idle_seconds)
        except Exception:
            if not started:
                await self.reply(writer, 502, b'{"error":"inference_unavailable"}')
            # After SSE starts, close without a completed event; never echo errors.
        finally:
            await stream.aclose()


async def timed_chunks(stream, seconds):
    while True:
        try:
            chunk = await asyncio.wait_for(anext(stream), seconds)
        except StopAsyncIteration:
            return
        yield chunk


async def run(config, token, path):
    broker = Broker(config, HTTPSUpstream(token, config))
    await broker.start(path)
    await broker.serve()  # Finite lease expires; budgets never auto-reset.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--socket", required=True, type=Path)
    parser.add_argument("--credential-fd", required=True, type=int)
    args = parser.parse_args()
    try:
        policy = Policy.parse(decode(private_read(args.config, 16384)))
        token = credential(args.credential_fd)
        asyncio.run(run(policy, token, args.socket))
        return 0
    except (Exception, KeyboardInterrupt):
        print("agent-platform-broker: unavailable", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
