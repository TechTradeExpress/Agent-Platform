"""Fixed fabricated-only probes, run with -I; no Codex or Agent Platform imports."""

import errno
import json
import os
import signal
import socket
import sys
import time
from pathlib import Path

NAMES = ("user", "mnt", "pid", "net", "ipc", "uts", "cgroup")
KEYS = (
    "namespaces",
    "caps",
    "files",
    "worktree",
    "proc",
    "fds",
    "network",
    "ipc",
    "descendants",
    "home_readable",
)
DENIED = {
    errno.ENOENT,
    errno.EACCES,
    errno.EPERM,
    errno.EROFS,
    errno.EXDEV,
    errno.ELOOP,
}


def denied(action):
    try:
        action()
    except OSError as exc:
        return exc.errno in DENIED
    return False


def open_only(path, flags=os.O_RDONLY):
    fd = os.open(path, flags | os.O_NONBLOCK, 0o600)
    os.close(fd)  # Never read process memory or a non-fabricated credential.


def namespaces(policy):
    return set(policy) == set(NAMES) and all(
        os.readlink("/proc/self/ns/" + name) != policy[name] for name in NAMES
    )


def capabilities():
    rows = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
    )
    return (
        all(
            int(rows[k].strip(), 16) == 0
            for k in ("CapEff", "CapPrm", "CapInh", "CapAmb")
        )
        and rows["NoNewPrivs"].strip() == "1"
    )


def files(policy):
    host = Path(policy["host"])
    paths = [host / n for n in ("ssh", "github", "control")]
    paths += [host / "codex-home" / n for n in ("auth.json", "session")]
    paths += [
        Path("/workspace/escape/codex-home/auth.json"),
        Path("/workspace/../host/auth.json"),
    ]
    return all(denied(lambda p=p: open_only(p)) for p in paths) and all(
        (
            denied(
                lambda: open_only(
                    "/codex-home/forbidden-write", os.O_WRONLY | os.O_CREAT | os.O_EXCL
                )
            ),
            denied(
                lambda: open_only(
                    host / "outside-write", os.O_WRONLY | os.O_CREAT | os.O_EXCL
                )
            ),
            denied(
                lambda: open_only(
                    "/dev/outside-write", os.O_WRONLY | os.O_CREAT | os.O_EXCL
                )
            ),
            denied(
                lambda: open_only(
                    "/canary-outside-write", os.O_WRONLY | os.O_CREAT | os.O_EXCL
                )
            ),
            denied(
                lambda: os.link("/codex-home/auth.json", "/workspace/hardlink-escape")
            ),
        )
    )


def permitted(mode):
    path = Path("/workspace/permitted-" + mode + ".txt")
    with path.open("xb") as stream:
        stream.write(b"permitted synthetic edit")
    return path.read_bytes() == b"permitted synthetic edit"


def parent_hidden(policy):
    parent = Path("/proc") / str(policy["pid"])
    return all(
        (
            denied(lambda: os.listdir(parent / "fd")),
            denied(lambda: open_only(parent / "fd/200")),
            denied(lambda: open_only(parent / "mem")),
        )
    )


def descriptors(policy):
    # Metadata only; even an erroneously inherited descriptor is never read.
    for name in os.listdir("/proc/self/fd"):
        try:
            info = os.fstat(int(name))
        except OSError as exc:
            if exc.errno == errno.EBADF:  # The fd used by listdir itself is closed.
                continue
            raise
        if [info.st_dev, info.st_ino] == policy["fd_inode"]:
            return False
    return True


def network(policy):
    with socket.socket() as sock:
        sock.settimeout(0.2)
        status = sock.connect_ex(("127.0.0.1", policy["port"]))
    return status in {
        errno.ECONNREFUSED,
        errno.ENETUNREACH,
        errno.EHOSTUNREACH,
        errno.EACCES,
        errno.EPERM,
        errno.ETIMEDOUT,
    }


def ipc(policy):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(0.2)
        return denied(lambda: sock.connect(str(Path(policy["host"]) / "ipc.sock")))


def descendants():
    pid = os.fork()
    if pid == 0:
        signal.alarm(1)
        time.sleep(1)
        os._exit(1)
    try:
        os.kill(pid, signal.SIGTERM)
    finally:
        _, status = os.waitpid(pid, 0)
    return os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGTERM


def home_readable():
    # Opening is sufficient evidence of exposure; never read/echo file contents.
    readable = False
    for name in ("auth.json", "session"):
        try:
            open_only(Path("/codex-home", name))
            readable = True
        except OSError as exc:
            if exc.errno not in DENIED:
                raise
    return readable


def probe(mode):
    result = dict.fromkeys(KEYS, False)
    signal.alarm(2)
    policy = json.loads(Path("/canary-policy.json").read_bytes())
    result["namespaces"] = namespaces(policy["namespaces"])
    result["caps"] = capabilities()
    if not result["namespaces"] or not result["caps"]:
        return result  # Never attempt probes without actual namespace/cap checks.
    for name, action in (
        ("files", lambda: files(policy)),
        ("worktree", lambda: permitted(mode)),
        ("proc", lambda: parent_hidden(policy)),
        ("fds", lambda: descriptors(policy)),
        ("network", lambda: network(policy)),
        ("ipc", lambda: ipc(policy)),
        ("descendants", descendants),
        ("home_readable", home_readable),
    ):
        result[name] = action()
    return result


def sentinel():
    # Trusted temporary fixture only. No inherited account env or host-home reads.
    signal.alarm(12)
    with open("host/fd-canary", "rb") as stream:
        os.dup2(stream.fileno(), 200, inheritable=False)
        with socket.socket() as tcp, socket.socket(socket.AF_UNIX) as unix:
            tcp.bind(("127.0.0.1", 0))
            tcp.listen(4)
            unix.bind("host/ipc.sock")
            unix.listen(1)
            print(
                json.dumps({"pid": os.getpid(), "port": tcp.getsockname()[1]}),
                flush=True,
            )
            sys.stdin.buffer.read(1)
        os.close(200)


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["sentinel"]:
            sentinel()
        elif sys.argv[1:] in (["worker"], ["same-domain"]):
            print(json.dumps(probe(sys.argv[1]), sort_keys=True))
        else:
            sys.exit(1)
    except Exception:
        sys.exit(1)  # Never echo paths, content, env, commands or diagnostics.
