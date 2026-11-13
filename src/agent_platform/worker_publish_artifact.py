"""PUB-02 content-addressed full-tree transfer. No credentials or network."""

import base64
import errno
import hashlib
import json
import os
import re
import resource
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
from datetime import UTC, datetime

VERSION = "AP-WP/1"
MAX_WIRE = 32 * 1024 * 1024
MAX_DATA = 16 * 1024 * 1024
MAX_OBJECT = 4 * 1024 * 1024
MAX_OBJECTS = 4096
SHA = re.compile(r"[0-9a-f]{40}")


class Blocked(Exception):
    def __init__(self):
        super().__init__("publisher_blocked")


def need(value):
    if not value:
        raise Blocked()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def pairs(items):
    result = {}
    for k, v in items:
        need(k not in result)
        result[k] = v
    return result


def decode(data):
    need(type(data) is bytes and len(data) <= MAX_WIRE)
    return json.loads(
        data.decode("utf-8"),
        object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(Blocked()),
    )


def sha(value):
    return type(value) is str and SHA.fullmatch(value) and value != "0" * 40


def canonical(kind, data):
    return kind.encode() + b" " + str(len(data)).encode() + b"\0" + data


def oid(kind, data):
    return hashlib.sha1(canonical(kind, data)).hexdigest()


def identity(line):
    # REST normalizes dates; accept only exact UTC commits, never rewrite offsets.
    m = re.fullmatch(
        rb"([^<>\x00-\x1f]{1,200}) <([^<>\x00-\x20]{1,200})> ([0-9]{1,12}) \+0000", line
    )
    need(m is not None)
    return {
        "name": m[1].decode("utf-8"),
        "email": m[2].decode("utf-8"),
        "date": datetime.fromtimestamp(int(m[3]), UTC)
        .isoformat()
        .replace("+00:00", "Z"),
    }


def commit(data):
    headers, sep, message = data.partition(b"\n\n")
    lines = headers.split(b"\n")
    need(sep and len(lines) == 4 and message.endswith(b"\n"))
    need(lines[0].startswith(b"tree ") and lines[1].startswith(b"parent "))
    tree, parent = lines[0][5:].decode(), lines[1][7:].decode()
    need(sha(tree) and sha(parent))
    need(lines[2].startswith(b"author ") and lines[3].startswith(b"committer "))
    need(b"\0" not in message and len(message) <= 65536)
    return {
        "tree": tree,
        "parents": [parent],
        "author": identity(lines[2][7:]),
        "committer": identity(lines[3][10:]),
        "message": message.decode("utf-8"),
    }


def tree(data):
    entries, seen, previous = [], set(), None
    while data:
        mode, sep, tail = data.partition(b" ")
        name, nul, rest = tail.partition(b"\0")
        need(
            sep and nul and len(rest) >= 20 and mode in (b"40000", b"100644", b"100755")
        )
        need(0 < len(name) <= 255)
        text = name.decode("ascii")
        lower = text.casefold()
        need(re.fullmatch(r"[A-Za-z0-9_.-]+", text) and text not in (".", ".."))
        need(not text.endswith(".") and lower not in (".git", ".hg", ".svn"))
        need(lower not in seen)
        seen.add(lower)
        order = name + (b"/" if mode == b"40000" else b"")
        need(previous is None or previous < order)
        previous = order
        entry = {
            "path": text,
            "mode": "040000" if mode == b"40000" else mode.decode(),
            "type": "tree" if mode == b"40000" else "blob",
            "sha": rest[:20].hex(),
        }
        need(sha(entry["sha"]))
        need(len(entries) < MAX_OBJECTS)
        entries.append(entry)
        data = rest[20:]
    return entries


def validate(data, head, expected_tree, parent):
    need(all(sha(s) for s in (head, expected_tree, parent)))
    raw = decode(data)
    need(type(raw) is dict and set(raw) == {"version", "head", "objects"})
    need(raw["version"] == VERSION and raw["head"] == head)
    need(type(raw["objects"]) is list and 0 < len(raw["objects"]) <= MAX_OBJECTS)
    objects, total = {}, 0
    for value in raw["objects"]:
        need(type(value) is dict and set(value) == {"oid", "kind", "data"})
        k, s, b = value["kind"], value["oid"], value["data"]
        need(k in ("blob", "tree", "commit") and sha(s) and s not in objects)
        need(type(b) is str and len(b) <= 4 * ((MAX_OBJECT + 2) // 3))
        payload = base64.b64decode(b, validate=True)
        need(base64.b64encode(payload).decode() == b and len(payload) <= MAX_OBJECT)
        total += len(payload)
        need(total <= MAX_DATA and oid(k, payload) == s)
        objects[s] = (k, payload)
    need(head in objects and objects[head][0] == "commit")
    c = commit(objects[head][1])
    need(c["tree"] == expected_tree and c["parents"] == [parent])
    visited, ordered, files = {head}, [], []
    visits = 0

    def walk(s, prefix, depth, ancestors):
        nonlocal visits
        visits += 1
        need(visits <= MAX_OBJECTS)
        need(depth <= 32 and s not in ancestors and s in objects)
        kind, payload = objects[s]
        need(kind == "tree")
        visited.add(s)
        for entry in tree(payload):
            path = prefix + entry["path"]
            need(len(path) <= 1024)
            target = entry["sha"]
            need(target in objects and objects[target][0] == entry["type"])
            if entry["type"] == "tree":
                walk(target, path + "/", depth + 1, ancestors | {s})
            else:
                visited.add(target)
                files.append((path, entry["mode"], target))
                need(len(files) <= MAX_OBJECTS)
                ordered.append(target)
        ordered.append(s)

    walk(expected_tree, "", 0, set())
    need(visited == set(objects))  # no tags, parent objects, packs or unreachable data
    ordered.append(head)
    return objects, tuple(dict.fromkeys(ordered)), tuple(sorted(files)), c


class _Unreaped(Blocked):
    pass


def _bound_git():
    # Fixed trusted hook, only after refusing threaded/nondefault-reaper callers.
    # No target callable and no privilege change. Alarm survives exec of Git.
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.alarm(6)
    for which, cap in (
        (resource.RLIMIT_CORE, 0),
        (resource.RLIMIT_CPU, 5),
        (resource.RLIMIT_NOFILE, 64),
        (resource.RLIMIT_FSIZE, 1024 * 1024),
        (resource.RLIMIT_AS, 256 * 1024 * 1024),
    ):
        soft, hard = resource.getrlimit(which)
        limit = min([cap] + [n for n in (soft, hard) if n != resource.RLIM_INFINITY])
        resource.setrlimit(which, (limit, limit))


def _git(repo, args, limit, *, git_dir=None, objects=None):
    argv = [
        "/usr/bin/git",
        "--no-replace-objects",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        *args,
    ]
    if git_dir is not None:
        argv.insert(1, "--git-dir=" + git_dir)
    env = {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_LAZY_FETCH": "1",
    }
    if objects is not None:
        env["GIT_OBJECT_DIRECTORY"] = objects
    need(signal.getsignal(signal.SIGCHLD) is signal.SIG_DFL)
    need(
        threading.current_thread() is threading.main_thread()
        and threading.active_count() == 1
    )
    own = os.pidfd_open(os.getpid(), 0)
    os.close(own)
    child = subprocess.Popen(
        argv,
        cwd=repo,
        shell=False,
        close_fds=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=env,
        preexec_fn=_bound_git,
    )
    output, started = bytearray(), time.monotonic()
    pin = None
    try:
        flags = os.WEXITED | os.WNOHANG | os.WNOWAIT
        os.waitid(os.P_PID, child.pid, flags)
        candidate = os.pidfd_open(child.pid, 0)
        try:
            os.waitid(os.P_PID, child.pid, flags)
        except BaseException:
            os.close(candidate)
            raise
        pin = candidate
        os.set_blocking(child.stdout.fileno(), False)
        with selectors.DefaultSelector() as poll:
            poll.register(child.stdout, selectors.EVENT_READ)
            while poll.get_map():
                need(time.monotonic() - started < 5)
                for key, _ in poll.select(0.05):
                    part = os.read(key.fd, min(65536, limit + 1 - len(output)))
                    if not part:
                        poll.unregister(key.fd)
                    output.extend(part)
                    need(len(output) <= limit)
        need(child.wait(timeout=1) == 0)
        return bytes(output)
    finally:
        try:
            if child.poll() is None and pin is not None:
                try:
                    signal.pidfd_send_signal(pin, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                child.wait(timeout=7)
            except subprocess.TimeoutExpired:
                raise _Unreaped() from None
        finally:
            child.stdout.close()
            if pin is not None:
                os.close(pin)


def _export(repo, head, scratch, object_dir):
    """Worker-side credential-free exporter; publisher never calls Git or sees repo."""
    need(sha(head))
    need(_git(repo, ["rev-parse", "--show-object-format"], 32) == b"sha1\n")
    objects, total = {}, 0
    started = time.monotonic()

    def read(s, expected):
        nonlocal total
        need(time.monotonic() - started < 60)
        if s in objects:
            need(objects[s][0] == expected)
            return objects[s][1]
        need(time.monotonic() - started < 60 and len(objects) < MAX_OBJECTS)
        need(sha(s))
        size = _git(
            repo, ["cat-file", "-s", s], 32, git_dir=scratch, objects=object_dir
        ).strip()
        need(size.isdigit() and int(size) <= MAX_OBJECT)
        payload = _git(
            repo,
            ["cat-file", expected, s],
            MAX_OBJECT,
            git_dir=scratch,
            objects=object_dir,
        )
        need(len(payload) == int(size) and oid(expected, payload) == s)
        total += len(payload)
        need(total <= MAX_DATA)
        objects[s] = (expected, payload)
        return payload

    c = commit(read(head, "commit"))

    visits = 0

    def walk(s, depth):
        nonlocal visits
        visits += 1
        need(visits <= MAX_OBJECTS and time.monotonic() - started < 60)
        need(depth <= 32)
        for entry in tree(read(s, "tree")):
            if entry["type"] == "tree":
                walk(entry["sha"], depth + 1)
            else:
                read(entry["sha"], "blob")

    walk(c["tree"], 0)
    data = encoded(
        {
            "version": VERSION,
            "head": head,
            "objects": [
                {"oid": s, "kind": k, "data": base64.b64encode(b).decode()}
                for s, (k, b) in sorted(objects.items())
            ],
        }
    )
    need(len(data) <= MAX_WIRE)
    validate(data, head, c["tree"], c["parents"][0])
    return data, c


def export(repo, head):
    """Read through a disposable trusted bare config, never source remote config.

    Source rev-parse is read-only and never resolves objects/lazy fetches. All
    object reads use a fresh config with no remotes or credential helpers.
    """
    need(
        os.getuid() != 0 and os.getuid() == os.geteuid() and os.getgid() == os.getegid()
    )
    need(len(set(os.getresuid())) == len(set(os.getresgid())) == 1)
    with open("/proc/self/status", "rb") as own:
        metadata = own.read(8193)
    need(len(metadata) <= 8192)
    fields = dict(line.split(b":", 1) for line in metadata.splitlines() if b":" in line)
    need(
        all(
            int(fields[k].strip(), 16) == 0
            for k in (b"CapInh", b"CapPrm", b"CapEff", b"CapAmb")
        )
    )
    st = os.stat("/usr/bin/git", follow_symlinks=False)
    need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o6022)
    try:
        caps = os.getxattr("/usr/bin/git", "security.capability", follow_symlinks=False)
        need(not caps)
    except OSError as exc:
        need(exc.errno == errno.ENODATA)
    need(sha(head))
    object_dir = (
        _git(
            repo, ["rev-parse", "--path-format=absolute", "--git-path", "objects"], 4096
        )
        .decode()
        .strip()
    )
    need(os.path.isabs(object_dir) and os.path.realpath(object_dir) == object_dir)
    scratch = tempfile.mkdtemp(prefix="ap-export-")
    retained = False
    try:
        _git(scratch, ["init", "--bare", "."], 4096)
        return _export(repo, head, scratch, object_dir)
    except _Unreaped:
        retained = True
        raise
    finally:
        if not retained:
            shutil.rmtree(scratch)  # only this newly created, quiescent bare config
