"""Explicit developer-only, single-use Cargo evidence job; never product runtime."""

import argparse
import hashlib
import ipaddress
import json
import os
import select
import signal
import socket
import socketserver
import stat
import subprocess
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PIN_SHA256 = "341fa35f8de13b71614a4822c1ae50971f27ed60def9d2a6162b2eaaa16f2950"


def read_pin():
    data = (ROOT / "resolution-job-inputs.json").read_bytes()
    if hashlib.sha256(data).hexdigest() != PIN_SHA256:
        raise ValueError("job_input_pin_changed")
    return json.loads(data)


def capacity(path, limits):
    st = os.statvfs(path)
    result = {
        "total_bytes": st.f_blocks * st.f_frsize,
        "free_bytes": st.f_bavail * st.f_frsize,
    }
    if (
        result["free_bytes"] < limits["minimum_free_bytes"]
        or result["total_bytes"] < limits["minimum_total_bytes"]
    ):
        raise ValueError("larger_filesystem_unavailable")
    return result


def verify_inputs(source, tools, tree_path, pin):
    raw = tree_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != pin["tree_json_sha256"]:
        raise ValueError("source_tree_pin_changed")
    tree = json.loads(raw)
    if tree.get("truncated") is not False:
        raise ValueError("incomplete_source_tree")
    expected = {item["path"] for item in tree["tree"] if item["type"] == "blob"}
    if file_inventory(source) != expected:
        raise ValueError("source_inventory_changed")
    if file_inventory(tools) != {item["path"] for item in pin["toolchain_files"]}:
        raise ValueError("toolchain_inventory_changed")
    for item in tree["tree"]:
        if item["type"] != "blob":
            continue
        path = source / item["path"]
        if item["mode"] == "120000":
            if (
                item["path"] != "codex-rs/vendor/bubblewrap/LICENSE"
                or os.readlink(path) != "COPYING"
            ):
                raise ValueError("source_symlink_changed")
            data = b"COPYING"
        else:
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError("source_type_changed")
            data = path.read_bytes()
        if (
            hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            != item["sha"]
        ):
            raise ValueError("source_blob_changed")
    for item in pin["toolchain_files"]:
        path = tools / item["path"]
        if "symlink" in item:
            if os.readlink(path) != item["symlink"]:
                raise ValueError("toolchain_link_changed")
        else:
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError("toolchain_type_changed")
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            if path.stat().st_size != item["size"] or digest != item["sha256"]:
                raise ValueError("toolchain_changed")


def file_inventory(root):
    found = set()
    for directory, directories, files in os.walk(root, followlinks=False):
        if any((Path(directory) / name).is_symlink() for name in directories):
            raise ValueError("unexpected_directory_alias")
        found.update(str((Path(directory) / name).relative_to(root)) for name in files)
    return found


def connect_host(header, hosts):
    """Strict CONNECT only; no HTTP forwarding, auth, chosen IPs or alternate port."""
    if len(header) > 4096 or b"proxy-authorization:" in header.lower():
        raise ValueError("proxy_request_refused")
    lines = header.decode("ascii").split("\r\n")
    fields = lines[0].split(" ")
    if len(fields) != 3 or fields[0] != "CONNECT" or fields[2] != "HTTP/1.1":
        raise ValueError("proxy_request_refused")
    host, separator, port = fields[1].rpartition(":")
    if separator != ":" or port != "443" or host not in hosts:
        raise ValueError("proxy_destination_refused")
    return host


class TransferBudget:
    def __init__(self, maximum_bytes, maximum_connections):
        self.maximum_bytes = maximum_bytes
        self.maximum_connections = maximum_connections
        self.bytes = 0
        self.connections = 0
        self.reason = None
        self.lock = threading.Lock()

    def admit(self, size=0, connection=False):
        with self.lock:
            if self.reason:
                return False
            if (
                self.bytes + size > self.maximum_bytes
                or self.connections + int(connection) > self.maximum_connections
            ):
                self.reason = "NETWORK_BUDGET"
                return False
            self.bytes += size
            self.connections += int(connection)
            return True


class Proxy(socketserver.ThreadingTCPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, hosts, budget):
        self.hosts, self.budget = hosts, budget
        super().__init__(("127.0.0.1", 0), Tunnel)


class Tunnel(socketserver.BaseRequestHandler):
    def handle(self):
        peer = None
        try:
            if not self.server.budget.admit(connection=True):
                return
            self.request.settimeout(5)
            header = b""
            while not header.endswith(b"\r\n\r\n"):
                part = self.request.recv(1)
                if not part or len(header) >= 4096:
                    return
                header += part
            host = connect_host(header, self.server.hosts)
            addresses = socket.getaddrinfo(
                host, 443, socket.AF_INET, socket.SOCK_STREAM
            )
            if not addresses or any(
                not ipaddress.ip_address(a[4][0]).is_global for a in addresses
            ):
                return
            peer = socket.create_connection(addresses[0][4], timeout=10)
            self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            pair = [self.request, peer]
            last = time.monotonic()
            while not self.server.budget.reason and time.monotonic() - last < 60:
                readable, _, _ = select.select(pair, [], [], 1)
                for source in readable:
                    data = source.recv(64 * 1024)
                    if not data or not self.server.budget.admit(len(data)):
                        return
                    (peer if source is self.request else self.request).sendall(data)
                    last = time.monotonic()
        except (OSError, ValueError, UnicodeError):
            return  # No raw request, DNS result, URL, exception or credentials in logs.
        finally:
            if peer is not None:
                peer.close()


def usage(path):
    return sum(
        os.lstat(os.path.join(root, name)).st_size
        for root, _, names in os.walk(path)
        for name in names
    )


def owned_rss(pid):
    """Read only statistics for the supervised process tree; never signal by PID."""
    total, pending, seen = 0, [pid], set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        try:
            base = Path("/proc") / str(current)
            words = (base / "statm").read_text().split()
            total += int(words[1]) * os.sysconf("SC_PAGE_SIZE")
            children = base / "task" / str(current) / "children"
            pending.extend(int(n) for n in children.read_text().split())
        except (OSError, ValueError, IndexError):
            pass  # A child exiting can disappear between these read-only observations.
    return total


def argv_for(source, tools, fixture, proxy, limits, command):
    args = [
        "/usr/bin/bwrap",
        "--unshare-all",
        "--share-net",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/sbin",
        "/sbin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/etc",
        "--dir",
        "/etc/ssl",
        "--dir",
        "/etc/ssl/certs",
        "--ro-bind",
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/certs/ca-certificates.crt",
        "--ro-bind",
        str(source),
        "/source",
        "--ro-bind",
        str(tools),
        "/tools",
        "--bind",
        str(fixture / "cargo"),
        "/cargo",
        "--bind",
        str(fixture / "home"),
        "/home",
    ]
    env = {
        "HOME": "/home",
        "CARGO_HOME": "/cargo",
        "PATH": "/tools/bin:/usr/bin:/bin",
        "RUSTC": "/tools/bin/rustc",
        "LC_ALL": "C",
        "CARGO_NET_RETRY": "0",
        "CARGO_HTTP_TIMEOUT": "20",
        "CARGO_HTTP_PROXY": proxy,
        "CARGO_HTTP_SSL_CAINFO": "/etc/ssl/certs/ca-certificates.crt",
        "CARGO_NET_GIT_FETCH_WITH_CLI": "true",
        "https_proxy": proxy,
        "HTTPS_PROXY": proxy,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ALLOW_PROTOCOL": "https",
        "GIT_CONFIG_COUNT": "3",
        "GIT_CONFIG_KEY_0": "http.proxy",
        "GIT_CONFIG_VALUE_0": proxy,
        "GIT_CONFIG_KEY_1": "credential.helper",
        "GIT_CONFIG_VALUE_1": "",
        "GIT_CONFIG_KEY_2": "protocol.file.allow",
        "GIT_CONFIG_VALUE_2": "never",
    }
    for name, value in env.items():
        args.extend(["--setenv", name, value])
    return args + [
        "--chdir",
        "/source/codex-rs",
        "/usr/bin/prlimit",
        "--as=" + str(limits["address_space_bytes_per_process"]),
        "--fsize=" + str(limits["file_bytes_per_process"]),
        "--nofile=1024",
        "--cpu=" + str(limits["cpu_seconds_per_process"]),
        "/tools/bin/cargo",
        *command,
    ]


def run(source, tools, tree, fixture):
    pin = read_pin()
    limits = pin["limits"]
    before = capacity(fixture, limits)  # Refuse small FS before Cargo/network.
    meta = fixture.lstat()
    if (
        fixture.resolve() != fixture.absolute()
        or not stat.S_ISDIR(meta.st_mode)
        or meta.st_uid != os.getuid()
        or stat.S_IMODE(meta.st_mode) != 0o700
    ):
        raise ValueError("unsafe_fixture")
    probe = os.pidfd_open(os.getpid())  # Missing support blocks before child/network.
    os.close(probe)
    verify_inputs(source, tools, tree, pin)
    if any(
        (fixture / name).is_symlink() or list((fixture / name).iterdir())
        for name in ("home", "cargo", "output")
    ):
        raise ValueError("fixture_not_fresh")
    budget = TransferBudget(
        limits["maximum_network_bytes"], limits["maximum_connections"]
    )
    result = {
        "status": "BLOCKED",
        "capacity_before": before,
        "commands": [],
        "runtime_authorized": False,
        "redistribution_allowed": False,
    }
    started = time.monotonic()
    with Proxy(pin["hosts"], budget) as proxy:
        thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        thread.start()
        address = "http://127.0.0.1:" + str(proxy.server_address[1])
        commands = [
            (
                "metadata",
                [
                    "metadata",
                    "--locked",
                    "--format-version",
                    "1",
                    "--filter-platform",
                    "x86_64-unknown-linux-musl",
                ],
            ),
            (
                "cli-tree",
                [
                    "tree",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "codex-cli",
                    "-e",
                    "normal,features",
                ],
            ),
        ]
        try:
            for name, command in commands:
                output = fixture / "output"
                reason = None
                telemetry = []
                with (
                    (output / (name + ".stdout")).open("xb") as stdout,
                    (output / (name + ".stderr")).open("xb") as stderr,
                ):
                    child = subprocess.Popen(
                        argv_for(source, tools, fixture, address, limits, command),
                        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                        stdout=stdout,
                        stderr=stderr,
                        close_fds=True,
                    )
                    fd = os.pidfd_open(child.pid)
                    try:
                        while child.poll() is None:
                            time.sleep(2)
                            st = os.statvfs(fixture)
                            sample = {
                                "seconds": int(time.monotonic() - started),
                                "free_bytes": st.f_bavail * st.f_frsize,
                                "cache_bytes": usage(fixture / "cargo"),
                                "network_bytes": budget.bytes,
                                "rss_bytes": owned_rss(child.pid),
                            }
                            telemetry.append(sample)
                            if budget.reason:
                                reason = budget.reason
                            elif sample["free_bytes"] < limits["reserve_free_bytes"]:
                                reason = "FREE_SPACE_RESERVE"
                            elif sample["cache_bytes"] > limits["maximum_cache_bytes"]:
                                reason = "CACHE_BUDGET"
                            elif (
                                sample["rss_bytes"] > limits["aggregate_rss_stop_bytes"]
                            ):
                                reason = "MEMORY_BUDGET"
                            elif sample["seconds"] > limits["maximum_seconds"]:
                                reason = "TIME_BUDGET"
                            elif (
                                stdout.tell() + stderr.tell()
                                > limits["maximum_log_bytes"]
                            ):
                                reason = "OUTPUT_BUDGET"
                            if reason:
                                signal.pidfd_send_signal(fd, signal.SIGKILL)
                                child.wait(timeout=15)
                                break
                    except BaseException:
                        if child.poll() is None:
                            signal.pidfd_send_signal(fd, signal.SIGKILL)
                            child.wait(timeout=15)
                        raise
                    finally:
                        os.close(fd)
                result["commands"].append(
                    {
                        "name": name,
                        "argv": command,
                        "exit": child.returncode,
                        "stop": reason,
                        "telemetry": telemetry,
                    }
                )
                (output / "job-result.json").write_text(
                    json.dumps(result, sort_keys=True)
                )
                if child.returncode != 0 or reason:
                    break
        finally:
            proxy.shutdown()
            thread.join(timeout=5)
    result["network_bytes"] = budget.bytes
    result["connections"] = budget.connections
    result["source_unchanged_after"] = False
    verify_inputs(source, tools, tree, pin)
    result["source_unchanged_after"] = True
    # Resolution success is not license/official-binary validation or runtime GO.
    result["resolution_completed"] = len(result["commands"]) == 2 and all(
        c["exit"] == 0 for c in result["commands"]
    )
    (fixture / "output/job-result.json").write_text(
        json.dumps(result, sort_keys=True, indent=2)
    )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--tools", type=Path, required=True)
    parser.add_argument("--tree", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if not args.execute:
        print('{"status":"NOT_RUN","runtime_authorized":false}')
        return 13
    try:
        result = run(args.source, args.tools, args.tree, args.fixture)
    except (OSError, ValueError, subprocess.SubprocessError):
        print('{"status":"BLOCKED","code":"resolution_job_refused"}')
        return 13
    print(
        json.dumps(
            {
                "status": "BLOCKED",
                "resolution_completed": result["resolution_completed"],
                "runtime_authorized": False,
            }
        )
    )
    return 0 if result["resolution_completed"] else 13


if __name__ == "__main__":
    raise SystemExit(main())
