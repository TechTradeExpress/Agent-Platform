"""CP-08 real benign process mechanics + synthetic failure injection, no host tests."""

import ast
import hashlib
import json
import os
import subprocess
import time
import types
from dataclasses import replace
from pathlib import Path

import pytest

from agent_platform import control_plane_fixture as cf
from agent_platform import control_plane_local_runner as lr


@pytest.fixture
def config(tmp_path, monkeypatch):
    # Each test is a separate supervised fixture. No public latch-reset API.
    monkeypatch.setattr(lr, "_UNCERTAIN", False)
    tmp_path.chmod(0o700)
    monkeypatch.chdir(tmp_path)
    return lr.Config(lr.reviewed_bytes())


def check(report):
    raw = json.loads(report.encode())
    assert raw["live"] == "LIVE_NO_GO"
    assert raw["gate_73"] == "BLOCKED"
    assert raw["launch_allowed"] is False
    assert raw["host"] == "HOST_NOT_RUN"
    assert set(raw["host_matrix"].values()) == {"HOST_NOT_RUN"}
    assert raw["provenance"] == "LOCAL_TEST_ONLY"
    assert len(report.encode()) <= 65536
    assert report.encode() == report.encode()
    return raw


@pytest.mark.parametrize(
    "case,code",
    [
        (lr.Case.HYGIENE, "complete"),
        (lr.Case.DEADLINE, "deadline"),
        (lr.Case.CANCEL, "cancelled"),
        (lr.Case.OVERSIZE, "output_limit"),
        (lr.Case.TRUNCATED, "protocol_invalid"),
    ],
)
def test_real_fixed_cases_are_bounded_reaped_and_non_authorizing(config, case, code):
    before = time.monotonic()
    report = lr.exercise(config, case)
    assert time.monotonic() - before < 5
    assert report.code == code
    assert report.observation.started == report.observation.reaped == 1
    assert report.observation.pinned and report.observation.cleanup
    assert list(Path.cwd().iterdir()) == []
    raw = check(report)
    assert raw["expected_code"] == code
    assert (report.status == lr.Status.LOCAL_MECHANICS_VERIFIED) == (
        case is lr.Case.HYGIENE
    )


def test_real_env_fd_hygiene_with_fabricated_canaries(config, monkeypatch, capsys):
    marker = "CP08_FABRICATED_NEVER_A_CREDENTIAL"
    monkeypatch.setenv("CP08_FAKE_MARKER", marker)
    read_fd, write_fd = os.pipe()
    os.set_inheritable(read_fd, True)
    os.set_inheritable(write_fd, True)
    try:
        os.write(write_fd, marker.encode())
        report = lr.exercise(config, lr.Case.HYGIENE)
        assert report.code == "complete"
        assert os.read(read_fd, 128) == marker.encode()  # child's check did not read it
        assert marker not in report.encode().decode()
        assert marker not in repr(report)
        assert capsys.readouterr() == ("", "")
    finally:
        os.close(read_fd)
        os.close(write_fd)


@pytest.mark.parametrize(
    "change",
    [
        {"version": "unknown"},
        {"probe_ms": 0},
        {"probe_ms": True},
        {"probe_ms": 5001},
        {"case_ms": 60001},
        {"case_ms": 1},
        {"output_bytes": 65537},
        {"output_bytes": 0},
        {"pins": None},
    ],
)
def test_bad_config_never_creates_fixture_or_child(config, monkeypatch, change):
    monkeypatch.setattr(lr.cf.DisposableFixture, "create", forbidden)
    monkeypatch.setattr(lr.subprocess, "Popen", forbidden)
    report = lr.exercise(replace(config, **change), lr.Case.HYGIENE)
    assert report.code == "invalid_request"
    check(report)


def forbidden(*args, **kwargs):
    pytest.fail("forbidden operation")


@pytest.mark.parametrize("case", ["hygiene", "sudo", "systemctl", "network", {}, None])
def test_no_host_commands_paths_plugins_or_json_case(config, monkeypatch, case):
    monkeypatch.setattr(lr.subprocess, "Popen", forbidden)
    assert lr.exercise(config, case).code == "invalid_request"


@pytest.mark.parametrize("name", list(lr.Pins.__dataclass_fields__))
@pytest.mark.parametrize("value", [None, "", "g" * 64, "f" * 64])
def test_all_separate_pins_required_and_revalidated(config, monkeypatch, name, value):
    monkeypatch.setattr(lr.subprocess, "Popen", forbidden)
    report = lr.exercise(
        replace(config, pins=replace(config.pins, **{name: value})), lr.Case.HYGIENE
    )
    assert report.code in {"invalid_request", "pins_changed"}
    check(report)


def test_candidate_drift_never_executes(config, monkeypatch):
    monkeypatch.setattr(
        lr, "reviewed_bytes", lambda: replace(config.pins, policy_sha256="f" * 64)
    )
    monkeypatch.setattr(lr.subprocess, "Popen", forbidden)
    assert lr.exercise(config, lr.Case.HYGIENE).code == "pins_changed"


@pytest.mark.parametrize(
    "field,value",
    [
        ("live", "LIVE_GO"),
        ("gate_73", "PASS"),
        ("launch_allowed", True),
        ("launch_allowed", 0),
        ("host", "HOST_PASS"),
        ("version", "unknown"),
        ("provenance", "INDEPENDENT_RETAINED"),
        ("code", "private secret"),
        ("status", "LOCAL_MECHANICS_VERIFIED"),
    ],
)
def test_serialization_revalidates_closed_schema(config, field, value):
    report = lr.exercise(config, lr.Case.HYGIENE)
    object.__setattr__(report, field, value)
    with pytest.raises(lr.RunnerError, match="^local_runner_blocked$"):
        report.encode()


@pytest.mark.parametrize(
    "change",
    [
        {"started": 0},
        {"started": 2},
        {"started": True},
        {"reaped": 0},
        {"reaped": 2},
        {"pinned": False},
        {"cleanup": False},
        {"complete": False},
        {"output_bytes": 0},
        {"output_bytes": 65537},
        {"code": "deadline"},
    ],
)
def test_zero_unaccounted_partial_stale_and_inconsistent_evidence_refused(
    config, change
):
    report = lr.exercise(config, lr.Case.HYGIENE)
    report = replace(report, observation=replace(report.observation, **change))
    with pytest.raises(lr.RunnerError):
        report.encode()


def test_deadline_and_cancel_never_relabelled_as_verified(config):
    for case in (lr.Case.DEADLINE, lr.Case.CANCEL):
        report = lr.exercise(config, case)
        with pytest.raises(lr.RunnerError):
            replace(report, status=lr.Status.LOCAL_MECHANICS_VERIFIED).encode()


def test_spawn_has_exact_hygiene_and_fixed_closure(config, monkeypatch):
    original = subprocess.Popen
    calls = []

    def record(argv, **kwargs):
        calls.append((argv, kwargs))
        assert argv == (lr._runtime(), "-I", "-S", "-c", lr._HELPER, "hygiene")
        assert kwargs["shell"] is False and kwargs["close_fds"] is True
        assert kwargs["pass_fds"] == () and kwargs["env"] == {"LC_ALL": "C"}
        assert kwargs["cwd"].startswith("/proc/self/fd/")
        assert kwargs["stdin"] == subprocess.DEVNULL
        return original(argv, **kwargs)

    monkeypatch.setattr(lr.subprocess, "Popen", record)
    assert lr.exercise(config, lr.Case.HYGIENE).code == "complete"
    assert len(calls) == 1
    # No descendant creation or host APIs in reviewed helper closure.
    for forbidden_text in (
        "fork",
        "exec",
        "subprocess",
        "socket",
        "system(",
        "setuid",
        "setgid",
        "unshare",
        "agent_platform",
    ):
        assert forbidden_text not in lr._HELPER


def test_root_or_changed_identity_refuses_before_launch(config, monkeypatch):
    monkeypatch.setattr(lr.os, "geteuid", lambda: 0)
    monkeypatch.setattr(lr.subprocess, "Popen", forbidden)
    assert lr.exercise(config, lr.Case.HYGIENE).code == "privileged_identity"


def test_missing_pidfd_kernel_support_is_unsupported_not_fallback(config, monkeypatch):
    def unavailable(*args):
        raise OSError("private error must not escape")

    monkeypatch.setattr(lr.os, "pidfd_open", unavailable)
    monkeypatch.setattr(lr.subprocess, "Popen", forbidden)
    report = lr.exercise(config, lr.Case.HYGIENE)
    assert report.code == "platform_unavailable"
    assert b"private" not in report.encode()


def test_pidfd_uncertainty_reaps_benign_helper_but_retains_scratch(config, monkeypatch):
    original = os.pidfd_open
    calls = 0

    def fail_child(pid, flags):
        nonlocal calls
        calls += 1
        if calls > 1:
            raise OSError("uncertain child lifetime")
        return original(pid, flags)

    monkeypatch.setattr(lr.os, "pidfd_open", fail_child)
    report = lr.exercise(config, lr.Case.HYGIENE)
    assert report.status == lr.Status.UNKNOWN
    assert report.observation.reaped == 1
    assert not report.observation.cleanup
    assert len(list(Path.cwd().iterdir())) == 1  # never recursively cleaned
    check(report)


def test_cleanup_drift_retains_unknown_without_retry(config, monkeypatch):
    original = cf.DisposableFixture.cleanup
    calls = []

    def drift(self):
        calls.append(1)
        fd = os.open(
            "extra", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=self._child
        )
        os.close(fd)
        return original(self)

    monkeypatch.setattr(cf.DisposableFixture, "cleanup", drift)
    report = lr.exercise(config, lr.Case.HYGIENE)
    assert report.code == "cleanup_uncertain" and calls == [1]
    assert len(list(Path.cwd().iterdir())) == 1
    check(report)


def test_keyboard_cancellation_signals_only_pidfd_and_reaps(config, monkeypatch):
    original_signal = lr.signal.pidfd_send_signal
    signals = []

    def cancel(*args, **kwargs):
        raise KeyboardInterrupt

    def record(fd, sig):
        signals.append(sig)
        return original_signal(fd, sig)

    monkeypatch.setattr(lr.selectors.DefaultSelector, "select", cancel)
    monkeypatch.setattr(lr.signal, "pidfd_send_signal", record)
    monkeypatch.setattr(os, "kill", forbidden)
    monkeypatch.setattr(os, "killpg", forbidden)
    report = lr.exercise(config, lr.Case.HYGIENE)
    assert report.code == "cancelled"
    assert report.observation.started == report.observation.reaped == 1
    assert signals == [lr.signal.SIGKILL]
    assert list(Path.cwd().iterdir()) == []


def test_construction_and_report_encoding_never_launch(config, monkeypatch):
    monkeypatch.setattr(lr.subprocess, "Popen", forbidden)
    cfg = replace(config)
    report = lr.exercise(replace(cfg, version="bad"), lr.Case.HYGIENE)
    check(report)


def test_reduced_output_cap_refuses_overflow(config):
    report = lr.exercise(replace(config, output_bytes=7), lr.Case.HYGIENE)
    assert report.code == "output_limit"
    assert report.observation.output_bytes <= 7
    assert report.observation.reaped == 1


def test_symlink_or_preexisting_scratch_content_never_adopted(config, monkeypatch):
    # Existing caller content stays intact; runner exclusively creates its own name.
    Path("existing").symlink_to("/nonexistent-cp08-do-not-follow")
    report = lr.exercise(config, lr.Case.HYGIENE)
    assert report.code == "complete"
    assert Path("existing").is_symlink()
    assert len(list(Path.cwd().iterdir())) == 1


def test_real_injected_env_leak_is_failure_and_redacted(config, monkeypatch):
    original = subprocess.Popen
    marker = "CP08_FAKE_ENV_LEAK_ONLY"

    def leak(argv, **kwargs):
        kwargs["env"]["CP08_FAKE"] = marker
        return original(argv, **kwargs)

    monkeypatch.setattr(lr.subprocess, "Popen", leak)
    report = lr.exercise(config, lr.Case.HYGIENE)
    assert report.code == "child_failed"
    assert marker not in report.encode().decode()
    assert report.observation.reaped == 1


def test_real_injected_fd_leak_is_failure(config, monkeypatch):
    original = subprocess.Popen
    fd = os.open("/dev/null", os.O_RDONLY)

    def leak(argv, **kwargs):
        kwargs["pass_fds"] = (fd,)
        return original(argv, **kwargs)

    monkeypatch.setattr(lr.subprocess, "Popen", leak)
    try:
        report = lr.exercise(config, lr.Case.HYGIENE)
        assert report.code == "child_failed"
        assert report.observation.reaped == 1
    finally:
        os.close(fd)


def test_busy_slot_never_starts_or_queues(config, monkeypatch):
    monkeypatch.setattr(lr.subprocess, "Popen", forbidden)
    with lr._SLOT:
        report = lr.exercise(config, lr.Case.HYGIENE)
    assert report.code == "busy"
    check(report)


def test_partial_creation_is_redacted_and_never_retried(config, monkeypatch):
    calls = []

    def fail():
        calls.append(1)
        raise OSError("private scratch creation exception")

    monkeypatch.setattr(cf.DisposableFixture, "create", fail)
    report = lr.exercise(config, lr.Case.HYGIENE)
    assert report.code == "fixture_uncertain" and calls == [1]
    assert b"private" not in report.encode()


def test_synthetic_unreaped_child_retains_scratch(config, monkeypatch):
    # Synthetic only: do not create a deliberately unmanaged real child.
    monkeypatch.setattr(
        lr,
        "_supervise",
        lambda *args: lr.Observation(
            started=1, reaped=0, pinned=True, code="execution_incomplete"
        ),
    )
    monkeypatch.setattr(cf.DisposableFixture, "cleanup", forbidden)
    report = lr.exercise(config, lr.Case.HYGIENE)
    assert report.status == lr.Status.FAIL
    assert not report.observation.cleanup
    assert len(list(Path.cwd().iterdir())) == 1
    check(report)


def test_synthetic_late_case_completion_never_verifies(config, monkeypatch):
    # Simulated clock fault, distinct from the actual real-child deadline test.
    # Avoid altering the clock during subprocess waits: this fault exercises the
    # outer case clock only via a synthetic accounted result.
    monkeypatch.setattr(
        lr,
        "_supervise",
        lambda *args: lr.Observation(
            started=1, reaped=1, pinned=True, output_bytes=8, code="complete"
        ),
    )
    monkeypatch.setattr(lr.time, "monotonic", iter([0, 0, 100]).__next__)
    report = lr.exercise(config, lr.Case.HYGIENE)
    assert report.code == "deadline"
    check(report)


@pytest.mark.parametrize(
    "data", [b"{}", b"[]", b"null", b"{", b'{"version":1,"version":2}']
)
def test_malformed_candidate_schema_cannot_be_pinned(monkeypatch, data):
    monkeypatch.setattr(lr, "_read_file", lambda *args: data)
    with pytest.raises((lr.RunnerError, ValueError)):
        lr._policy_bytes("fixed-source-test-only")


def test_source_drift_during_case_remains_unknown(config, monkeypatch):
    original = lr.reviewed_bytes
    calls = 0

    def drift():
        nonlocal calls
        calls += 1
        return (
            original() if calls == 1 else replace(config.pins, source_sha256="f" * 64)
        )

    monkeypatch.setattr(lr, "reviewed_bytes", drift)
    report = lr.exercise(config, lr.Case.HYGIENE)
    assert report.code == "evidence_changed"
    assert not report.observation.complete
    check(report)


def test_import_is_inert_in_fresh_interpreter():
    # Fixed supervised import test, no arbitrary helper/command input.
    code = (
        "import subprocess; "
        "subprocess.Popen=lambda *a, **k: (_ for _ in ()).throw(AssertionError()); "
        "import agent_platform.control_plane_local_runner"
    )
    result = subprocess.run(
        (os.sys.executable, "-I", "-c", code),
        capture_output=True,
        timeout=5,
        check=False,
        shell=False,
        close_fds=True,
        stdin=subprocess.DEVNULL,
        env={"LC_ALL": "C"},
    )
    assert result.returncode == 0 and result.stdout == result.stderr == b""


def test_retained_uncertainty_blocks_further_children(config, monkeypatch):
    monkeypatch.setattr(
        lr,
        "_supervise",
        lambda *args: lr.Observation(
            started=1, pinned=True, code="execution_incomplete"
        ),
    )
    first = lr.exercise(config, lr.Case.HYGIENE)
    assert first.code == "execution_incomplete"
    monkeypatch.setattr(lr.subprocess, "Popen", forbidden)
    second = lr.exercise(config, lr.Case.HYGIENE)
    assert second.code == "retained_uncertainty"
    check(second)


@pytest.mark.parametrize("fault", ["reaper", "threads", "relationship"])
def test_untrusted_reaping_or_pid_relationship_never_signals_unknown(
    config, monkeypatch, fault
):
    if fault == "reaper":
        monkeypatch.setattr(lr.signal, "getsignal", lambda *args: lr.signal.SIG_IGN)
    elif fault == "threads":
        monkeypatch.setattr(lr.threading, "active_count", lambda: 2)
    else:

        def absent(*args):
            raise ChildProcessError("unknown child")

        monkeypatch.setattr(lr.os, "waitid", absent)
    monkeypatch.setattr(lr.signal, "pidfd_send_signal", forbidden)
    if fault != "relationship":
        monkeypatch.setattr(lr.subprocess, "Popen", forbidden)
    report = lr.exercise(config, lr.Case.HYGIENE)
    assert report.code in {"supervision_unavailable", "cleanup_uncertain"}
    assert report.status != lr.Status.LOCAL_MECHANICS_VERIFIED
    check(report)


def test_inherited_capabilities_or_unknown_privilege_metadata_refuse(
    config, monkeypatch
):
    def unknown():
        raise lr.RunnerError("local_runner_blocked")

    monkeypatch.setattr(lr, "_no_capabilities", unknown)
    monkeypatch.setattr(lr.subprocess, "Popen", forbidden)
    assert lr.exercise(config, lr.Case.HYGIENE).code == "privileged_identity"


@pytest.mark.parametrize(
    "stage", ["source", "fixture", "policy", "runtime_safety", "runtime_bytes"]
)
def test_current_pin_stages_fail_with_only_fixed_stage_ids(stage):
    # No config fixture: CI identifies the failing boundary independently, without
    # reflecting a path, environment, raw exception, token, or captured output.
    source = Path(lr.__file__).absolute()
    try:
        if stage == "source":
            lr._file_hash(source, lr.MAX_BYTES)
        elif stage == "fixture":
            lr._file_hash(source.with_name("control_plane_fixture.py"), lr.MAX_BYTES)
        elif stage == "policy":
            lr._policy_bytes(
                source.parents[2] / "docs/control-plane-policy-candidates.json"
            )
        elif stage == "runtime_safety":
            lr._runtime()
        else:
            lr._file_hash(lr._runtime(), 64 * 1024 * 1024)
    except Exception:
        pytest.fail("pin_stage_" + stage, pytrace=False)


@pytest.mark.parametrize(
    "soft,hard,want", [(-1, -1, 64), (32, -1, 32), (32, 128, 32), (128, 128, 64)]
)
def test_helper_nofile_limit_never_treats_infinity_as_unbounded(soft, hard, want):
    # Evaluate only the exact arithmetic expression from reviewed helper AST;
    # no process or setrlimit operation is involved in these synthetic cases.
    tree = ast.parse(lr._HELPER)
    expression = next(
        node.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "limit" for t in node.targets)
    )
    result = eval(
        compile(ast.Expression(expression), "fixed-helper-limit", "eval"),
        {
            "soft": soft,
            "hard": hard,
            "resource": types.SimpleNamespace(RLIM_INFINITY=-1),
        },
    )
    assert result == want


def test_expired_case_budget_never_creates_fixture_or_child(config, monkeypatch):
    monkeypatch.setattr(lr.time, "monotonic", iter([0, 100]).__next__)
    monkeypatch.setattr(cf.DisposableFixture, "create", forbidden)
    monkeypatch.setattr(lr.subprocess, "Popen", forbidden)
    report = lr.exercise(config, lr.Case.HYGIENE)
    assert report.code == "deadline_before_start"
    assert report.observation.started == 0
    check(report)


def test_unknown_platform_blocks_before_unix_identity_calls(config, monkeypatch):
    monkeypatch.setattr(lr.sys, "platform", "unsupported")
    monkeypatch.setattr(lr.os, "getuid", forbidden)
    monkeypatch.setattr(lr.subprocess, "Popen", forbidden)
    assert lr.exercise(config, lr.Case.HYGIENE).code == "platform_unavailable"


@pytest.mark.parametrize("rc", [None, True, "0"])
def test_missing_or_non_integer_wait_status_never_proves_reaping(rc):
    child = types.SimpleNamespace(wait=lambda **kwargs: rc)
    assert lr._stop(child, None) is False


def test_runtime_hash_cap_is_not_widened_for_ci(config, monkeypatch):
    original = lr._file_hash
    seen = []

    def bounded(path, limit):
        seen.append(limit)
        return original(path, limit)

    monkeypatch.setattr(lr, "_file_hash", bounded)
    assert lr.reviewed_bytes() == config.pins
    assert max(seen) == 64 * 1024 * 1024


def test_fake_file_hash_is_exact_and_oversize_or_symlink_refuses(tmp_path):
    path = tmp_path / "fake"
    path.write_bytes(b"fixed fabricated source")
    assert lr._file_hash(path, 32) == hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(lr.RunnerError):
        lr._file_hash(path, 2)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(OSError):
        lr._file_hash(link, 32)


@pytest.mark.parametrize("case", list(lr.Case))
def test_independent_local_runs_have_identical_redacted_reports(config, case):
    first = lr.exercise(config, case)
    second = lr.exercise(config, case)
    assert first.encode() == second.encode()
    check(first)
    if case is lr.Case.OVERSIZE:
        assert first.observation.output_bytes == config.output_bytes


@pytest.mark.parametrize("drift", ["symlink", "hardlink", "changed_bytes"])
def test_marker_drift_at_cp08_cleanup_retains_evidence(config, monkeypatch, drift):
    original = cf.DisposableFixture.cleanup

    def changed(self):
        if drift == "symlink":
            os.unlink("marker", dir_fd=self._child)
            os.symlink("missing-fake-target", "marker", dir_fd=self._child)
        elif drift == "hardlink":
            os.link(
                "marker",
                "alias",
                src_dir_fd=self._child,
                dst_dir_fd=self._child,
                follow_symlinks=False,
            )
        else:
            fd = os.open("marker", os.O_WRONLY | os.O_NOFOLLOW, dir_fd=self._child)
            try:
                os.write(fd, b"changed-fabricated-marker")
            finally:
                os.close(fd)
        return original(self)

    monkeypatch.setattr(cf.DisposableFixture, "cleanup", changed)
    report = lr.exercise(config, lr.Case.HYGIENE)
    assert report.code == "cleanup_uncertain"
    assert report.observation.reaped == 1 and not report.observation.cleanup
    assert len(list(Path.cwd().iterdir())) == 1
    assert lr.exercise(config, lr.Case.HYGIENE).code == "retained_uncertainty"
    check(report)
