"""One fail-closed Linux profile; never provision a runtime or credentials."""

import hashlib
import http.client
import json
import os
import socket
import stat
import struct
from pathlib import Path

from agent_platform import codex, issues, process, state

PROFILE = Path("/opt/agent-platform/codex-0.164.0")
BROKER = Path("/run/agent-platform/inference.sock")
BWRAP = Path("/usr/bin/bwrap")
OWNER_UID = 0
HELPER = Path(__file__).with_name("_sandbox.py")
ENV = {"PATH": os.defpath, "LC_ALL": "C"}


class IsolationError(Exception):
    def __init__(self):
        super().__init__("isolation_unavailable")


def require(condition):
    if not condition:
        raise IsolationError()


def trusted(path, directory=False):
    state.no_symlinks(path)
    for parent in path.parents:
        info = parent.stat()
        require(info.st_uid in (OWNER_UID, os.stat("/").st_uid))
        sticky_temp = (
            parent in (Path("/tmp"), Path("/var/tmp")) and info.st_mode & stat.S_ISVTX
        )
        require(not info.st_mode & 0o022 or bool(sticky_temp))
    info = path.lstat()
    require(info.st_uid == OWNER_UID and not info.st_mode & 0o022)
    require(not info.st_mode & (stat.S_ISUID | stat.S_ISGID))
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))


def broker_request(method, path):
    """Local root-owned inference service; never read or forward a host token."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect(str(BROKER))
        _, uid, _ = struct.unpack(
            "3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        require(uid == OWNER_UID)
        connection = http.client.HTTPConnection("localhost", timeout=2)
        connection.sock = sock
        connection.request(method, path, body=b"" if method == "POST" else None)
        response = connection.getresponse()
        body = response.read(4097)
        require(len(body) <= 4096)
        return response.status, body
    finally:
        sock.close()


def check_worktree(path):
    """Prevent pre-existing sockets, nested mounts and external hardlink aliases."""
    root_device = path.stat().st_dev
    counts, links = {}, {}
    entries = 0
    for directory, dirs, files in os.walk(path, followlinks=False):
        for name in [*dirs, *files]:
            entries += 1
            require(entries <= 50000)
            info = (Path(directory) / name).lstat()
            require(info.st_dev == root_device)
            require(
                stat.S_ISREG(info.st_mode)
                or stat.S_ISDIR(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
            )
            if stat.S_ISREG(info.st_mode):
                key = (info.st_dev, info.st_ino)
                counts[key] = counts.get(key, 0) + 1
                links[key] = info.st_nlink
    require(all(counts[key] == links[key] for key in counts))
    # /proc mountinfo uses octal escapes. Reject nested bind mounts too.
    import re

    for row in Path("/proc/self/mountinfo").read_text().splitlines():
        value = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), row.split()[4])
        mount = Path(value)
        require(mount == path or not mount.is_relative_to(path))


class Profile:
    def __init__(self, record, lock_fd):
        self.record = record
        self.lock_fd = lock_fd
        self.digest = None

    def command(self, command, *, probe=False):
        tree = Path(self.record["worktree"])
        args = [
            str(BWRAP),
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-cgroup",
            "--uid",
            "0",
            "--gid",
            "0",
            "--cap-drop",
            "ALL",
            "--sync-fd",
            str(self.lock_fd),
            "--ro-bind",
            str(PROFILE / "rootfs"),
            "/",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "LC_ALL",
            "C",
            "--setenv",
            "HOME",
            "/codex-home",
            "--setenv",
            "CODEX_HOME",
            "/codex-home",
            "--setenv",
            "GIT_CONFIG_NOSYSTEM",
            "1",
            "--setenv",
            "GIT_CONFIG_GLOBAL",
            "/dev/null",
            "--ro-bind",
            str(HELPER),
            "/agent-platform-sandbox.py",
        ]
        if probe:
            args += ["--tmpfs", "/workspace", "--tmpfs", "/codex-home"]
        else:
            args += [
                "--bind",
                str(tree),
                "/workspace",
                "--ro-bind",
                str(tree / ".git"),
                "/workspace/.git",
                "--bind",
                self.record["codex_home"],
                "/codex-home",
                "--bind",
                str(BROKER),
                "/inference.sock",
            ]
        return [*args, "--chdir", "/workspace", "--", *command]

    def preflight(self):
        try:
            require(os.name == "posix" and Path("/proc/self/ns/user").exists())
            require(int(Path("/proc/sys/kernel/yama/ptrace_scope").read_text()) >= 1)
            trusted(BWRAP)
            trusted(PROFILE, True)
            trusted(PROFILE / "profile.json")
            require((PROFILE / "profile.json").stat().st_size <= 4096)
            metadata = json.loads(
                (PROFILE / "profile.json").read_bytes(),
                object_pairs_hook=issues.unique_object,
                parse_constant=issues.invalid_constant,
            )
            require(
                isinstance(metadata, dict)
                and type(metadata.get("version")) is int
                and metadata.get("version") == 1
                and metadata.get("codex_version") == codex.VERSION
            )
            require(
                metadata.keys()
                == {"version", "codex_version", "codex_sha256", "broker_id"}
            )
            installation = Path(__file__).resolve().parent
            require(not installation.is_relative_to(Path(self.record["worktree"])))
            root = PROFILE / "rootfs"
            trusted(root, True)
            check_worktree(root)
            total = 0
            for directory, dirs, files in os.walk(root, followlinks=False):
                for name in [*dirs, *files]:
                    total += 1
                    require(total <= 50000)
                    path = Path(directory) / name
                    trusted(path, path.is_dir())
            for relative in ("usr/bin/codex", "usr/bin/python3", "bin/sh"):
                trusted(root / relative)
            binary = root / "usr/bin/codex"
            require(binary.stat().st_size <= 256 * 1024 * 1024)
            with binary.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            require(metadata.get("codex_sha256") == digest)
            trusted(BROKER.parent, True)
            info = BROKER.lstat()
            require(
                stat.S_ISSOCK(info.st_mode)
                and info.st_uid == OWNER_UID
                and not info.st_mode & 7
            )
            status, body = broker_request("GET", "/agent-platform/health")
            require(status == 200)
            health = json.loads(
                body,
                object_pairs_hook=issues.unique_object,
                parse_constant=issues.invalid_constant,
            )
            require(isinstance(health, dict) and type(health.get("protocol")) is int)
            require(
                all(
                    type(health.get(key)) is bool
                    for key in (
                        "inference_only",
                        "credentials_exposed",
                        "network_tools",
                    )
                )
            )
            require(
                health
                == {
                    "protocol": 1,
                    "broker_id": metadata.get("broker_id"),
                    "inference_only": True,
                    "credentials_exposed": False,
                    "network_tools": False,
                }
            )
            require(
                isinstance(health["broker_id"], str) and len(health["broker_id"]) == 64
            )
            for method, endpoint in (
                ("GET", "/auth"),
                ("POST", "/v1/admin"),
                ("GET", "/v1/models"),
            ):
                require(broker_request(method, endpoint)[0] == 403)
            check_worktree(Path(self.record["worktree"]))
            lock = os.fstat(self.lock_fd)
            names = ("user", "mnt", "pid", "net", "ipc", "uts", "cgroup")
            data = {
                "namespaces": {n: os.readlink("/proc/self/ns/" + n) for n in names},
                "private": [
                    self.record["source_root"],
                    self.record["common_dir"],
                    str(state.LOCK_DIR),
                    str(Path(__file__).resolve().parent),
                    str(Path(self.record["checkpoint"]).parent),
                    str(Path.home() / ".ssh"),
                    str(Path.home() / ".aws"),
                ],
                "lock_inode": [lock.st_dev, lock.st_ino],
            }
            probe = [
                "/usr/bin/python3",
                "-I",
                "/agent-platform-sandbox.py",
                "probe",
                json.dumps(data),
            ]
            for command in (
                probe,
                [
                    "/usr/bin/codex",
                    "--no-daemon",
                    "-c",
                    'sandbox_mode="workspace-write"',
                    "sandbox",
                    "linux",
                    "--",
                    *probe,
                    "native",
                ],
            ):
                output = process.read_command(
                    self.command(command, probe=True),
                    Path("/"),
                    ENV,
                    timeout=10,
                    limit=4096,
                    pass_fds=(self.lock_fd,),
                )
                require(output == b"isolated\n")
            version = process.read_command(
                self.command(["/usr/bin/codex", "--version"], probe=True),
                Path("/"),
                ENV,
                timeout=5,
                limit=4096,
                pass_fds=(self.lock_fd,),
            )
            require(version.strip() == ("codex-cli " + codex.VERSION).encode())
            self.digest = hashlib.sha256(
                json.dumps(metadata, sort_keys=True).encode() + HELPER.read_bytes()
            ).hexdigest()
            return self
        except (
            OSError,
            ValueError,
            AttributeError,
            process.CommandError,
            state.PrepareError,
            issues.AdmissionError,
        ):
            raise IsolationError() from None

    def launch(self, args):
        require(self.digest is not None)
        return self.command(
            ["/usr/bin/python3", "-I", "/agent-platform-sandbox.py", "relay", *args]
        )
