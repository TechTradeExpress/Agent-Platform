"""CP-08 / AP-CL/1: fixed unprivileged test mechanics, never host enforcement.

No import/construction/parsing launches. Only exercise() starts the fixed helper.
This is trusted contributor code, not a sandbox for hostile Python or descendants.
"""

import errno
import hashlib
import json
import os
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path

from agent_platform import control_plane_fixture as cf

VERSION = "AP-CL/1"
MAX_BYTES = 65536
_SLOT = threading.Lock()
_UNCERTAIN = False
# One child, no fork/exec/plugin/production imports. Alarm is a second, independent
# bound if the supervising test process disappears. No marker is printed/read.
_HELPER = r"""
import os, resource, signal, sys, time
signal.alarm(2)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
limit = min(64, soft, hard)
resource.setrlimit(resource.RLIMIT_NOFILE, (limit, limit))
case = sys.argv[1]
if dict(os.environ) != {"LC_ALL": "C"}:
    sys.exit(21)
names = os.listdir("/proc/self/fd")
if len(names) > 16:
    sys.exit(22)
for name in names:
    fd = int(name)
    if fd > 2:
        try:
            os.fstat(fd)
        except OSError:
            continue
        sys.exit(23)
if case == "hygiene":
    os.write(1, b"CP08_OK\n")
elif case == "deadline":
    time.sleep(1)
elif case == "cancel":
    os.write(1, b"CP08_CANCEL\n")
    time.sleep(1)
elif case == "oversize":
    os.write(1, b"x" * 32768)
    os.write(2, b"x" * 32769)
elif case == "truncated":
    os.write(1, b"CP08_")
else:
    sys.exit(24)
"""


class Case(StrEnum):
    HYGIENE = "hygiene"
    DEADLINE = "deadline"
    CANCEL = "cancel"
    OVERSIZE = "oversize"
    TRUNCATED = "truncated"


class Status(StrEnum):
    LOCAL_MECHANICS_VERIFIED = "LOCAL_MECHANICS_VERIFIED"
    HOST_NOT_RUN = "HOST_NOT_RUN"
    BLOCKED = "BLOCKED"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True, slots=True)
class Pins:
    source_sha256: str
    helper_sha256: str
    fixture_sha256: str
    policy_sha256: str
    runtime_sha256: str


@dataclass(frozen=True, slots=True)
class Config:
    pins: Pins
    probe_ms: int = 500
    case_ms: int = 5000
    output_bytes: int = MAX_BYTES
    version: str = VERSION


class RunnerError(Exception):
    """Fixed redacted errors only."""


def _require(value):
    if not value:
        raise RunnerError("local_runner_blocked")


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _runtime():
    # The active contributor interpreter only; no caller executable or PATH lookup.
    path = os.path.realpath(sys.executable)
    st = os.stat(path, follow_symlinks=False)
    _require(stat.S_ISREG(st.st_mode) and not st.st_mode & 0o6022)
    _require(st.st_uid in (0, os.getuid()))
    try:
        caps = os.getxattr(path, "security.capability", follow_symlinks=False)
    except OSError as exc:
        _require(exc.errno == errno.ENODATA)
    else:
        _require(not caps)
    return path


def _no_capabilities():
    fd = os.open("/proc/self/status", os.O_RDONLY | os.O_NOFOLLOW)
    try:
        data = os.read(fd, 8193)
        _require(len(data) <= 8192)
    finally:
        os.close(fd)
    names = {b"CapInh", b"CapPrm", b"CapEff", b"CapBnd", b"CapAmb"}
    facts = {}
    for line in data.splitlines():
        key, sep, value = line.partition(b":")
        if sep and key in names:
            _require(key not in facts)
            facts[key] = int(value.strip(), 16)
    _require(set(facts) == names)
    # Bounding capabilities alone confer no privilege; all usable sets must be empty.
    _require(all(facts[k] == 0 for k in names - {b"CapBnd"}))


def _read_file(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        _require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit)
        data = bytearray()
        while len(data) <= limit:
            part = os.read(fd, min(65536, limit + 1 - len(data)))
            if not part:
                break
            data.extend(part)

        def pin(st):
            return (
                st.st_dev,
                st.st_ino,
                st.st_uid,
                st.st_gid,
                st.st_mode,
                st.st_nlink,
                st.st_size,
                st.st_mtime_ns,
                st.st_ctime_ns,
            )

        _require(len(data) == before.st_size and pin(os.fstat(fd)) == pin(before))
        return bytes(data)
    finally:
        os.close(fd)


def _file_hash(path, limit):
    return _digest(_read_file(path, limit))


def _policy_bytes(path):
    data = _read_file(path, MAX_BYTES)

    def unique(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result)
            result[key] = value
        return result

    actual = json.loads(data, object_pairs_hook=unique)
    expected = {
        "version": cf.VERSION,
        "status": "DESIGN_ONLY",
        "installable": False,
        "candidates": [asdict(c) for c in cf.policy_candidates()],
    }
    _require(json.dumps(actual, sort_keys=True) == json.dumps(expected, sort_keys=True))
    return data


def reviewed_bytes() -> Pins:
    """Hash fixed source-work artifacts only. Correlation, never approval.

    Explicitly invoked; callers separately retain/review these exact byte pins.
    Runtime hash does not attest its libraries or establish a trusted host image.
    """
    try:
        source = Path(__file__).absolute()
        return Pins(
            _file_hash(source, MAX_BYTES),
            _digest(_HELPER.encode()),
            _file_hash(source.with_name("control_plane_fixture.py"), MAX_BYTES),
            _digest(
                _policy_bytes(
                    source.parents[2] / "docs/control-plane-policy-candidates.json"
                )
            ),
            _file_hash(_runtime(), 64 * 1024 * 1024),
        )
    except Exception:
        raise RunnerError("local_runner_blocked") from None


def _valid_config(config):
    _require(
        type(config) is Config
        and type(config.version) is str
        and config.version == VERSION
    )
    _require(type(config.pins) is Pins)
    _require(
        all(
            type(v) is str and cf.SHA256.fullmatch(v)
            for v in (
                config.pins.source_sha256,
                config.pins.helper_sha256,
                config.pins.fixture_sha256,
                config.pins.policy_sha256,
                config.pins.runtime_sha256,
            )
        )
    )
    for value, maximum in (
        (config.probe_ms, 5000),
        (config.case_ms, 60000),
        (config.output_bytes, MAX_BYTES),
    ):
        _require(type(value) is int and 1 <= value <= maximum)
    _require(config.case_ms >= config.probe_ms + 2500)


def _configuration_hash(config):
    return _digest(
        json.dumps(asdict(config), sort_keys=True, separators=(",", ":")).encode()
    )


@dataclass(frozen=True, slots=True)
class Observation:
    """Internal mechanics accounting; never contains stdout, paths or PIDs."""

    started: int = 0
    reaped: int = 0
    pinned: bool = False
    complete: bool = False
    cleanup: bool = False
    output_bytes: int = 0
    code: str = "not_started"


_CODES = {
    "complete": Status.LOCAL_MECHANICS_VERIFIED,
    "invalid_request": Status.BLOCKED,
    "busy": Status.BLOCKED,
    "retained_uncertainty": Status.BLOCKED,
    "supervision_unavailable": Status.BLOCKED,
    "pins_changed": Status.BLOCKED,
    "platform_unavailable": Status.UNSUPPORTED,
    "privileged_identity": Status.BLOCKED,
    "fixture_uncertain": Status.UNKNOWN,
    "ownership_uncertain": Status.UNKNOWN,
    "cancelled": Status.UNKNOWN,
    "deadline": Status.UNKNOWN,
    "output_limit": Status.FAIL,
    "protocol_invalid": Status.FAIL,
    "child_failed": Status.FAIL,
    "execution_incomplete": Status.FAIL,
    "cleanup_uncertain": Status.UNKNOWN,
    "evidence_changed": Status.UNKNOWN,
}


@dataclass(frozen=True, slots=True)
class Report:
    case: Case | None
    config: Config | None
    observation: Observation
    status: Status
    code: str
    version: str = field(default=VERSION, init=False)
    live: str = field(default="LIVE_NO_GO", init=False)
    gate_73: str = field(default="BLOCKED", init=False)
    launch_allowed: bool = field(default=False, init=False)
    host: str = field(default="HOST_NOT_RUN", init=False)
    provenance: str = field(default="LOCAL_TEST_ONLY", init=False)

    def encode(self) -> bytes:
        _require(type(self) is Report and self.version == VERSION)
        _require(
            all(
                type(v) is str
                for v in (
                    self.version,
                    self.live,
                    self.gate_73,
                    self.host,
                    self.provenance,
                )
            )
        )
        _require(self.live == "LIVE_NO_GO" and self.gate_73 == "BLOCKED")
        _require(self.launch_allowed is False and self.host == "HOST_NOT_RUN")
        _require(self.provenance == "LOCAL_TEST_ONLY")
        _require(self.case is None or type(self.case) is Case)
        if self.config is not None:
            _valid_config(self.config)
        _require(type(self.code) is str and self.code in _CODES)
        _require(type(self.status) is Status and self.status == _CODES[self.code])
        _validate_observation(self.observation)
        obs = self.observation
        _require(obs.code == self.code)
        if self.code in {"invalid_request", "busy"}:
            _require(self.case is None and self.config is None)
        else:
            _require(type(self.case) is Case and type(self.config) is Config)
        if self.code == "complete":
            _require(self.case is Case.HYGIENE and self.config is not None)
            _require(obs.started == obs.reaped == 1 and obs.pinned)
            _require(obs.complete and obs.cleanup and obs.output_bytes == 8)
        else:
            _require(not obs.complete)
        if self.config is not None:
            _require(obs.output_bytes <= self.config.output_bytes)
        raw = asdict(self)
        raw["expected_code"] = {
            Case.HYGIENE: "complete",
            Case.DEADLINE: "deadline",
            Case.CANCEL: "cancelled",
            Case.OVERSIZE: "output_limit",
            Case.TRUNCATED: "protocol_invalid",
        }.get(self.case)
        raw["configuration_sha256"] = (
            _configuration_hash(self.config) if self.config is not None else None
        )
        raw["host_matrix"] = dict.fromkeys(cf.HOST_MATRIX, "HOST_NOT_RUN")
        data = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
        _require(len(data) <= MAX_BYTES)
        return data


def _validate_observation(obs):
    _require(type(obs) is Observation)
    _require(type(obs.started) is int and 0 <= obs.started <= 1)
    _require(type(obs.reaped) is int and 0 <= obs.reaped <= obs.started)
    _require(type(obs.output_bytes) is int and 0 <= obs.output_bytes <= MAX_BYTES)
    _require(all(type(v) is bool for v in (obs.pinned, obs.complete, obs.cleanup)))
    _require(type(obs.code) is str and obs.code in _CODES)
    _require(not obs.pinned or obs.started == 1)
    _require(not obs.cleanup or (obs.started == obs.reaped == 1 and obs.pinned))
    if obs.code in {
        "invalid_request",
        "pins_changed",
        "platform_unavailable",
        "privileged_identity",
        "fixture_uncertain",
        "busy",
        "retained_uncertainty",
        "supervision_unavailable",
    }:
        _require(
            obs.started == obs.reaped == 0
            and not obs.pinned
            and not obs.cleanup
            and obs.output_bytes == 0
        )
    elif obs.code != "execution_incomplete":
        _require(obs.started == 1)


def _report(case, config, obs):
    result = Report(case, config, obs, _CODES[obs.code], obs.code)
    result.encode()  # Validate every result before returning, not just on display.
    return result


def _stop(child, pidfd):
    # Never signal a numeric PID/PGID. A pidfd remains bound after PID reuse.
    # No descendants exist in the reviewed closure; group supervision is deferred.
    if pidfd is not None:
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        child.wait(timeout=2.1)  # helper's own alarm also bounds pin failure
        return True
    except subprocess.TimeoutExpired:
        return False


def _pin_child(child):
    # WNOWAIT checks that the numeric identity is still our unreaped child.
    # Default SIGCHLD and a single main thread exclude concurrent auto-reapers.
    flags = os.WEXITED | os.WNOHANG | os.WNOWAIT
    os.waitid(os.P_PID, child.pid, flags)
    fd = os.pidfd_open(child.pid, 0)
    try:
        os.waitid(os.P_PID, child.pid, flags)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _supervise(config, case, fixture):
    child = None
    pidfd = None
    captured = bytearray()
    count = 0
    code = "ownership_uncertain"
    reaped = False
    pinned = False
    started_at = time.monotonic()
    try:
        child = subprocess.Popen(
            (_runtime(), "-I", "-S", "-c", _HELPER, case.value),
            shell=False,
            close_fds=True,
            pass_fds=(),
            env={"LC_ALL": "C"},
            cwd=f"/proc/self/fd/{fixture._child}",
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # The child has not been waited/reaped and cannot be reused during open.
        pidfd = _pin_child(child)
        pinned = True
        code = "protocol_invalid"
        with selectors.DefaultSelector() as selector:
            for stream in (child.stdout, child.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = config.probe_ms / 1000 - (time.monotonic() - started_at)
                if remaining <= 0:
                    code = "deadline"
                    break
                for key, _ in selector.select(min(remaining, 0.02)):
                    data = os.read(key.fd, min(4096, config.output_bytes - count + 1))
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    if count + len(data) > config.output_bytes:
                        code = "output_limit"
                        break
                    count += len(data)
                    # Never retain stderr; no raw output reaches reports/exceptions.
                    if key.fileobj is child.stdout:
                        captured.extend(data)
                    if case is Case.CANCEL and captured == b"CP08_CANCEL\n":
                        code = "cancelled"
                        break
                if code in ("output_limit", "cancelled"):
                    break
            else:
                remaining = config.probe_ms / 1000 - (time.monotonic() - started_at)
                if remaining <= 0:
                    code = "deadline"
                else:
                    try:
                        rc = child.wait(timeout=remaining)
                        reaped = True
                        code = (
                            "complete"
                            if rc == 0
                            and case is Case.HYGIENE
                            and captured == b"CP08_OK\n"
                            and count == 8
                            else "child_failed"
                            if rc
                            else "protocol_invalid"
                        )
                        if time.monotonic() - started_at >= config.probe_ms / 1000:
                            code = "deadline"
                    except subprocess.TimeoutExpired:
                        code = "deadline"
    except (KeyboardInterrupt, SystemExit):
        code = "cancelled"
    except Exception:
        code = "ownership_uncertain"
    finally:
        if child is not None:
            try:
                if not reaped:
                    reaped = _stop(child, pidfd)
            except Exception:
                code = "ownership_uncertain"
            for stream in (child.stdout, child.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:
                        code = "ownership_uncertain"
        if pidfd is not None:
            try:
                os.close(pidfd)
            except Exception:
                code = "ownership_uncertain"
    if child is None or not reaped:
        code = "execution_incomplete"
    # The caller performs exact owned scratch cleanup only after successful reap.
    return Observation(
        int(child is not None), int(reaped), pinned, False, False, count, code
    )


def _exercise(config: Config, case: Case) -> Report:
    """Explicit one-case test invocation, no path/executable/adapter arguments.

    Run only inside an owned private contributor/pytest cwd. No automatic suite,
    retry, background activity or host capability. Non-success means STOP.
    """
    global _UNCERTAIN
    case_started = time.monotonic()
    try:
        _valid_config(config)
        _require(type(case) is Case)
    except Exception:
        return _report(None, None, Observation(code="invalid_request"))
    if _UNCERTAIN:
        return _report(case, config, Observation(code="retained_uncertainty"))
    if (
        os.getuid() == 0
        or os.geteuid() != os.getuid()
        or os.getegid() != os.getgid()
        or len(set(os.getresuid())) != 1
        or len(set(os.getresgid())) != 1
    ):
        return _report(case, config, Observation(code="privileged_identity"))
    if (
        sys.platform != "linux"
        or not hasattr(os, "pidfd_open")
        or not hasattr(signal, "pidfd_send_signal")
    ):
        return _report(case, config, Observation(code="platform_unavailable"))
    if (
        signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL
        or threading.current_thread() is not threading.main_thread()
        or threading.active_count() != 1
    ):
        return _report(case, config, Observation(code="supervision_unavailable"))
    try:
        _no_capabilities()
    except Exception:
        return _report(case, config, Observation(code="privileged_identity"))
    try:
        own = os.pidfd_open(os.getpid(), 0)
        os.close(own)
    except Exception:
        return _report(case, config, Observation(code="platform_unavailable"))
    try:
        _require(config.pins == reviewed_bytes())
    except Exception:
        return _report(case, config, Observation(code="pins_changed"))
    try:
        fixture = cf.DisposableFixture.create()
    except Exception:
        _UNCERTAIN = True
        return _report(case, config, Observation(code="fixture_uncertain"))
    obs = _supervise(config, case, fixture)
    cleanup = False
    # Retain scratch on uncertain ownership/reaping, never delete underneath a child.
    if obs.started == obs.reaped == 1 and obs.pinned:
        try:
            cleanup = fixture.cleanup()
        except Exception:
            cleanup = False
    else:
        os.close(fixture._child)
        os.close(fixture._root)
    if not cleanup:
        _UNCERTAIN = True
    code = obs.code
    if not cleanup and code != "execution_incomplete":
        code = "cleanup_uncertain"
    try:
        if reviewed_bytes() != config.pins:
            code = "evidence_changed"
    except Exception:
        code = "evidence_changed"
    if (time.monotonic() - case_started) * 1000 >= config.case_ms:
        code = "deadline"
    final = Observation(
        obs.started,
        obs.reaped,
        obs.pinned,
        code == "complete",
        cleanup,
        obs.output_bytes,
        code,
    )
    return _report(case, config, final)


def exercise(config: Config, case: Case) -> Report:
    """One explicit local case, at most one child in this Python process.

    Contention refuses without queuing. Not a host-wide lock or launch authority.
    """
    if not _SLOT.acquire(blocking=False):
        return _report(None, None, Observation(code="busy"))
    try:
        return _exercise(config, case)
    finally:
        _SLOT.release()
