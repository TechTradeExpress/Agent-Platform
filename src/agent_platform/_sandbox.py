"""Read-only namespace helper. Runs isolated (-I), without Agent Platform imports."""

import http.client
import json
import os
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def probe():
    # -I ignores environment optimization flags; also reject an optimized
    # interpreter/wrapper explicitly so security assertions cannot disappear.
    if not __debug__:
        raise RuntimeError("optimized_probe")
    policy = json.loads(sys.argv[2])
    for name, host in policy["namespaces"].items():
        assert os.readlink("/proc/self/ns/" + name) != host
    assert "CapEff:\t0000000000000000" in Path("/proc/self/status").read_text()
    assert not any(
        key in os.environ
        for key in (
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "OPENAI_API_KEY",
            "SSH_AUTH_SOCK",
            "AWS_ACCESS_KEY_ID",
        )
    )
    for value in [*policy["private"], "/root/.ssh", "/etc/shadow", "/etc/ssh", "/home"]:
        # An empty /home directory may exist in the curated image; private roots
        # must never be visible or readable, even via same-UID permissions.
        if value == "/home" and Path(value).exists():
            assert not list(Path(value).iterdir())
            continue
        assert not Path(value).exists()
    for directory in Path("/proc").iterdir():
        if not directory.name.isdigit():
            continue
        try:
            for fd in (directory / "fd").iterdir():
                try:
                    info = fd.stat()
                    assert [info.st_dev, info.st_ino] != policy["lock_inode"]
                except (FileNotFoundError, PermissionError):
                    pass
        except (FileNotFoundError, PermissionError):
            pass
    network = socket.socket()
    network.settimeout(0.2)
    assert network.connect_ex(("1.1.1.1", 443)) != 0
    network.close()
    if sys.argv[-1] == "native":
        forbidden = Path("/codex-home/native-write-probe")
        try:
            fd = os.open(forbidden, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except PermissionError:
            pass
        else:
            os.close(fd)
            raise AssertionError("runtime writable by a tool")
        with open("/workspace/native-write-probe", "xb") as stream:
            stream.write(b"probe")
    print("isolated")


class Relay(BaseHTTPRequestHandler):
    """Only inference; root-owned external broker is a required trusted component."""

    def log_message(self, *args):
        pass

    def do_POST(self):
        try:
            size = int(self.headers.get("Content-Length", "-1"))
            if self.path != "/v1/responses" or not 0 < size <= 512 * 1024:
                self.send_error(403)
                return
            if self.headers.get("Transfer-Encoding") is not None:
                self.send_error(403)
                return
            body = self.rfile.read(size)
            data = json.loads(body)
            if (
                not isinstance(data, dict)
                or data.get("background")
                or data.get("store")
            ):
                self.send_error(403)
                return
            tools = data.get("tools", [])
            if not isinstance(tools, list) or any(
                not isinstance(tool, dict)
                or tool.get("type") not in ("function", "custom")
                for tool in tools
            ):
                self.send_error(403)
                return
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(30)
            with sock:
                sock.connect("/inference.sock")
                connection = http.client.HTTPConnection("localhost", timeout=30)
                connection.sock = sock
                connection.request(
                    "POST",
                    "/v1/responses",
                    body,
                    {"Content-Type": "application/json", "Accept": "text/event-stream"},
                )
                response = connection.getresponse()
                self.send_response(response.status)
                self.send_header(
                    "Content-Type",
                    response.getheader("Content-Type", "text/event-stream"),
                )
                self.send_header("Connection", "close")
                self.end_headers()
                total = 0
                while chunk := response.read1(4096):
                    total += len(chunk)
                    if total > 8 * 1024 * 1024:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
        except (OSError, ValueError, RecursionError):
            self.close_connection = True


def relay():
    server = HTTPServer(("127.0.0.1", 31847), Relay)
    server.timeout = 0.2
    stopped = threading.Event()

    def serve():
        for _ in range(2048):
            if stopped.is_set():
                return
            server.handle_request()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        # Fixed argv from the trusted parent, no shell and no daemon child.
        result = subprocess.run(
            sys.argv[2:], shell=False, timeout=310, check=False, close_fds=True
        )
        return result.returncode
    finally:
        stopped.set()
        server.server_close()


if __name__ == "__main__":
    try:
        if sys.argv[1] == "probe":
            probe()
        elif sys.argv[1] == "relay":
            sys.exit(relay())
        else:
            sys.exit(1)
    except Exception:
        # Never disclose host paths, environment or raw runtime errors.
        sys.exit(1)
