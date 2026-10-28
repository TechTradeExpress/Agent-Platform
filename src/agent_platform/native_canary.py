"""Opt-in synthetic confinement experiment; never launches Codex or authenticates."""

import argparse
import errno
import fcntl
import hashlib
import json
import os
import selectors
import signal
import socket
import stat
import subprocess
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path

from agent_platform import isolation, issues, process, state

RUNTIME = Path("/opt/agent-platform/native-canary-v1")
BWRAP = Path("/usr/bin/bwrap")
TEMP = Path("/tmp")
PROBE = Path(__file__).with_name("_native_canary_probe.py")
ENV = {"PATH": os.defpath, "LC_ALL": "C"}
NAMESPACES = ("user", "mnt", "pid", "net", "ipc", "uts", "cgroup")
REASONS = {
    "unsafe_fixture",
    "unprivileged_linux_required",
    "trusted_bwrap_unavailable",
    "reviewed_runtime_unavailable",
    "bwrap_hash_mismatch",
    "privileged_executable",
    "timer_in_use",
    "interrupted",
    "deadline",
    "invalid_probe_report",
    "sentinel_unavailable",
    "invalid_json",
}
CHECKS = {
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
}


class Blocked(Exception):
    pass


def require(value, reason="unsafe_fixture"):
    if not value:
        raise Blocked(reason)


def _json(raw):
    try:
        return json.loads(
            raw,
            object_pairs_hook=issues.unique_object,
            parse_constant=issues.invalid_constant,
        )
    except (ValueError, RecursionError, issues.AdmissionError):
        raise Blocked("invalid_json") from None


def _hash(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _trusted(path, directory=False):
    isolation.trusted(path, directory)
    if not directory:
        require(path.stat().st_nlink == 1)
        try:
            os.getxattr(path, "security.capability")
        except OSError as exc:
            require(exc.errno in (errno.ENODATA, errno.ENOTSUP))
        else:
            raise Blocked("privileged_executable")


def _runtime():
    require(
        sys.platform == "linux" and os.geteuid() != 0, "unprivileged_linux_required"
    )
    with Path("/proc/self/status").open() as stream:
        status = stream.read(4097)
    require(len(status) <= 4096)
    rows = dict(line.split(":", 1) for line in status.splitlines())
    require(
        all(
            int(rows[n].strip(), 16) == 0
            for n in ("CapEff", "CapPrm", "CapInh", "CapAmb")
        ),
        "unprivileged_linux_required",
    )
    try:
        _trusted(BWRAP)
    except (OSError, isolation.IsolationError, state.PrepareError):
        raise Blocked("trusted_bwrap_unavailable") from None
    require(BWRAP.stat().st_size <= 2 * 1024 * 1024)
    try:
        _trusted(RUNTIME, True)
        manifest = RUNTIME / "manifest.json"
        _trusted(manifest)
    except (OSError, isolation.IsolationError, state.PrepareError):
        raise Blocked("reviewed_runtime_unavailable") from None
    require(manifest.stat().st_size <= 65536)
    raw = manifest.read_bytes()
    data = _json(raw)
    require(type(data) is dict and set(data) == {"version", "bwrap_sha256", "files"})
    require(type(data["version"]) is int and data["version"] == 1)
    require(data["bwrap_sha256"] == _hash(BWRAP), "bwrap_hash_mismatch")
    files = data["files"]
    require(type(files) is dict and 0 < len(files) <= 512)
    require("usr/bin/python3" in files)
    root = RUNTIME / "rootfs"
    _trusted(root, True)
    observed = set()
    total = count = 0

    def walk_error(error):
        raise Blocked("unsafe_fixture") from None

    for parent, dirs, names in os.walk(root, followlinks=False, onerror=walk_error):
        for name in [*dirs, *names]:
            path = Path(parent) / name
            count += 1
            require(count <= 2048)
            relative_parts = path.relative_to(root).parts
            require(
                relative_parts[0]
                in {
                    "usr",
                    "lib",
                    "lib64",
                    "bin",
                    "proc",
                    "dev",
                    "workspace",
                    "codex-home",
                    "canary-probe.py",
                    "canary-policy.json",
                }
            )
            require(
                not any(
                    p.startswith(".")
                    or p
                    in {"auth.json", "credentials", "id_rsa", "id_ed25519", "codex"}
                    for p in relative_parts
                )
            )
            require(
                relative_parts[0] not in {"proc", "dev", "workspace", "codex-home"}
                or len(relative_parts) == 1
            )
            info = path.lstat()
            require(not stat.S_ISLNK(info.st_mode))
            directory = stat.S_ISDIR(info.st_mode)
            _trusted(path, directory)
            if not directory:
                relative = path.relative_to(root).as_posix()
                total += info.st_size
                require(total <= 64 * 1024 * 1024)
                require(relative in files and files[relative] == _hash(path))
                observed.add(relative)
    require(observed == set(files))
    for name in ("proc", "dev", "workspace", "codex-home"):
        require((root / name).is_dir())
    for name in ("canary-probe.py", "canary-policy.json"):
        require(name in files and (root / name).stat().st_size == 0)
    require((root / "usr/bin/python3").stat().st_mode & 0o111)
    isolation.check_worktree(root)  # Also reject mounts and external hardlinks.
    require(not any((root / n).exists() for n in ("home", "root", "run")))
    require(not any((root / "codex-home").glob("*")))
    return hashlib.sha256(raw).hexdigest()


@contextmanager
def _deadline():
    require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), "timer_in_use")
    previous = {
        s: signal.getsignal(s) for s in (signal.SIGALRM, signal.SIGINT, signal.SIGTERM)
    }

    def stop(signum, frame):
        raise Blocked("interrupted" if signum != signal.SIGALRM else "deadline")

    try:
        for s in previous:
            signal.signal(s, stop)
        signal.setitimer(signal.ITIMER_REAL, 14)  # Reserve one second for reaping.
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        for s, handler in previous.items():
            signal.signal(s, handler)


def _fixtures():
    root = TEMP / f"agent-platform-native-canary-{os.getuid()}"
    state.private_directory(root, root, create=True)
    run = root / uuid.uuid4().hex
    run.mkdir(mode=0o700)  # Never reuse or delete an existing run directory.
    for name in ("host", "workspace"):
        (run / name).mkdir(mode=0o700)
    (run / "host" / "codex-home").mkdir(mode=0o700)
    paths = [run / "host" / n for n in ("ssh", "github", "control", "fd-canary")]
    paths += [run / "host" / "codex-home" / n for n in ("auth.json", "session")]
    for path in paths:
        with path.open("xb") as stream:
            stream.write(b"FABRICATED_NATIVE_CANARY_NOT_A_CREDENTIAL")
        path.chmod(0o600)
    (run / "workspace" / "escape").symlink_to(run / "host")
    state.no_symlinks(PROBE)
    require(PROBE.stat().st_size <= 16384 and PROBE.stat().st_nlink == 1)
    with PROBE.open("rb") as stream:
        source = stream.read(16385)
    require(len(source) <= 16384)
    (run / "probe.py").write_bytes(source)
    (run / "probe.py").chmod(0o600)
    return run


def _arguments(run, mode):
    require(mode in ("worker", "same-domain"))
    root = TEMP / f"agent-platform-native-canary-{os.getuid()}"
    require(
        run.parent == root
        and len(run.name) == 32
        and all(c in "0123456789abcdef" for c in run.name)
    )
    state.private_directory(run, root, create=False)
    for name in ("host", "host/codex-home", "workspace"):
        require(state.private_directory(run / name, root, create=False))
    isolation.check_worktree(run / "workspace")
    for name in ("probe.py", "policy.json"):
        state.no_symlinks(run / name)
        state.private_file((run / name).stat())
    args = [str(BWRAP)]
    for namespace in ("user", "ipc", "pid", "net", "uts", "cgroup"):
        args.append("--unshare-" + namespace)  # Never optional -try / unshare-all.
    args += [
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        str(RUNTIME / "rootfs"),
        "/",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--remount-ro",
        "/dev",
        "--clearenv",
        "--setenv",
        "LC_ALL",
        "C",
        "--setenv",
        "HOME",
        "/codex-home",
        "--setenv",
        "CODEX_HOME",
        "/codex-home",
        "--bind",
        str(run / "workspace"),
        "/workspace",
        "--ro-bind",
        str(run / "probe.py"),
        "/canary-probe.py",
        "--ro-bind",
        str(run / "policy.json"),
        "/canary-policy.json",
    ]
    if mode == "same-domain":
        args += ["--ro-bind", str(run / "host" / "codex-home"), "/codex-home"]
    return [
        *args,
        "--chdir",
        "/workspace",
        "--",
        "/usr/bin/python3",
        "-I",
        "-B",
        "/canary-probe.py",
        mode,
    ]


def _parse(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 4096, "invalid_probe_report")
    data = _json(raw)
    require(type(data) is dict and set(data) == CHECKS, "invalid_probe_report")
    require(all(type(v) is bool for v in data.values()), "invalid_probe_report")
    return data


def report():
    return {
        "version": 1,
        "status": "NOT_RUN",
        "reason": "explicit_opt_in_required",
        "evidence": "OFFLINE_SYNTHETIC",
        "host_containment": "NOT_RUN",
        "worker_codex_home": "NOT_RUN",
        "same_domain_codex_home": "NOT_RUN",
        "codex_internal_routes": "UNKNOWN",
        "authentication": "AUTH_E2E_NOT_RUN",
        "launch_allowed": False,
        "checks": {},
        "artifact_admission": {
            "status": "BLOCKED",
            "recorded_candidate_bytes": 308139304,
            "unchanged_cap_bytes": 268435456,
        },
    }


def _ready(child):
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout, selectors.EVENT_READ)
        require(selector.select(1), "sentinel_unavailable")
        raw = os.read(child.stdout.fileno(), 1025)
    require(len(raw) <= 1024, "sentinel_unavailable")
    data = _json(raw)
    require(type(data) is dict and set(data) == {"pid", "port"}, "sentinel_unavailable")
    require(type(data["pid"]) is int and data["pid"] == child.pid and child.pid > 2)
    require(type(data["port"]) is int and 0 < data["port"] < 65536)
    with socket.create_connection(("127.0.0.1", data["port"]), timeout=0.2):
        pass  # Positive control: only our own disposable listener, never outside.
    return data


def _stop(child):
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    child.wait(timeout=1)
    for stream in (child.stdin, child.stdout):
        stream.close()


def _run(result):
    result["runtime_sha256"] = _runtime()
    run = _fixtures()
    result["fixture_id"] = run.name
    result["probe_sha256"] = _hash(run / "probe.py")
    # A fixed sanitized sentinel, not the developer's authenticated process.
    child = None
    fd = None
    try:
        # Defer interruption only while acquiring/stopping a child handle, so a
        # signal cannot skip cleanup between Popen returning and assignment.
        mask = signal.pthread_sigmask(
            signal.SIG_BLOCK, {signal.SIGALRM, signal.SIGINT, signal.SIGTERM}
        )
        try:
            child = subprocess.Popen(
                [sys.executable, "-I", "-B", str(run / "probe.py"), "sentinel"],
                cwd=run,
                env=ENV,
                shell=False,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
                umask=0o077,
            )
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        sentinel = _ready(child)
        with (run / "host" / "fd-canary").open("rb") as stream:
            fd = fcntl.fcntl(stream.fileno(), fcntl.F_DUPFD, 200)
        os.set_inheritable(fd, True)  # Must not reach a probe process.
        info = os.fstat(fd)
        policy = {
            **sentinel,
            "host": str(run / "host"),
            "namespaces": {n: os.readlink("/proc/self/ns/" + n) for n in NAMESPACES},
            "fd_inode": [info.st_dev, info.st_ino],
        }
        (run / "policy.json").write_text(json.dumps(policy))
        (run / "policy.json").chmod(0o600)
        require((run / "policy.json").stat().st_size <= 4096)
        for mode in ("worker", "same-domain"):
            raw = process.read_command(
                _arguments(run, mode), run, ENV, timeout=2, limit=4096
            )
            checks = _parse(raw)
            result["evidence"] = "REAL_KERNEL_SYNTHETIC"
            result["checks"][mode] = checks
            if not all(v for k, v in checks.items() if k != "home_readable"):
                result.update(
                    status="FAIL",
                    reason="negative_canary_failed",
                    host_containment="FAIL",
                )
                return
            result["host_containment"] = "PASS"
            if mode == "worker":
                result["worker_codex_home"] = (
                    "FAIL" if checks["home_readable"] else "PASS"
                )
                if checks["home_readable"]:
                    result.update(status="FAIL", reason="worker_home_exposed")
                    return
            else:
                result["same_domain_codex_home"] = (
                    "FAIL" if checks["home_readable"] else "UNKNOWN"
                )
                result.update(
                    status="BLOCKED",
                    reason="same_domain_credential_exposure"
                    if checks["home_readable"]
                    else "same_domain_unverified",
                )
    finally:
        mask = signal.pthread_sigmask(
            signal.SIG_BLOCK, {signal.SIGALRM, signal.SIGINT, signal.SIGTERM}
        )
        try:
            if fd is not None:
                os.close(fd)
            if child is not None:
                _stop(child)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)


def run_synthetic():
    result = report()
    result.update(status="BLOCKED", reason="preflight_unavailable")
    try:
        with _deadline():
            _run(result)
    except Blocked as exc:
        # All reasons originate in fixed code, never subprocess text.
        result.update(
            status="BLOCKED",
            reason=str(exc) if str(exc) in REASONS else "preflight_unavailable",
        )
    except (
        OSError,
        ValueError,
        RecursionError,
        KeyError,
        TypeError,
        process.CommandError,
        isolation.IsolationError,
        state.PrepareError,
        subprocess.SubprocessError,
    ):
        result.update(status="BLOCKED", reason="preflight_unavailable")
    return result


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "native_canary_invalid_arguments\n")


def main(argv=None):
    parser = _Parser(
        prog="agent-platform-native-canary",
        description="Nonsecret native confinement canaries",
    )
    parser.add_argument(
        "--run-synthetic",
        action="store_true",
        help="Opt in to disposable, unprivileged Linux probes only",
    )
    args = parser.parse_args(argv)
    result = run_synthetic() if args.run_synthetic else report()
    print(json.dumps(result, sort_keys=True))
    return (
        14 if result["status"] == "FAIL" else 13 if result["status"] == "BLOCKED" else 0
    )


if __name__ == "__main__":
    sys.exit(main())
