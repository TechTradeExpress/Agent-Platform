"""Offline policy/process tests. Fake Bubblewrap never establishes kernel proof."""

import builtins
import errno
import hashlib
import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from agent_platform import _native_canary_probe as probe
from agent_platform import native_canary as canary
from agent_platform import native_codex, process, state, subscription


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    parent = tmp_path / "runtime"
    root = parent / "rootfs"
    (root / "usr/bin").mkdir(parents=True)
    for name in ("proc", "dev", "workspace", "codex-home"):
        (root / name).mkdir()
    (root / "usr/bin/python3").write_bytes(b"INERT_OFFLINE_RUNTIME")
    (root / "usr/bin/python3").chmod(0o755)
    for name in ("canary-probe.py", "canary-policy.json"):
        (root / name).write_bytes(b"")
    binary = tmp_path / "bwrap"
    binary.write_bytes(b"INERT_OFFLINE_BWRAP")
    binary.chmod(0o755)
    files = {
        p.relative_to(root).as_posix(): digest(p)
        for p in root.rglob("*")
        if p.is_file()
    }
    manifest = parent / "manifest.json"
    manifest.write_text(
        json.dumps({"version": 1, "bwrap_sha256": digest(binary), "files": files})
    )
    for item in [parent, root, *root.rglob("*")]:
        item.chmod(0o755 if item.is_dir() or item.name == "python3" else 0o644)
    manifest.chmod(0o644)
    monkeypatch.setattr(canary, "RUNTIME", parent)
    monkeypatch.setattr(canary, "BWRAP", binary)
    # Simulated administrative ownership only; never execute this inert image.
    monkeypatch.setattr(canary.isolation, "OWNER_UID", os.getuid())
    return root, binary, manifest


@pytest.fixture
def fixture_run(tmp_path, monkeypatch):
    monkeypatch.setattr(canary, "TEMP", tmp_path)
    run = canary._fixtures()
    (run / "policy.json").write_text("{}")
    (run / "policy.json").chmod(0o600)
    return run


def test_default_has_no_io_subprocess_or_auth(tmp_path, monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail("default report must be inert")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(canary, "_runtime", forbidden)
    monkeypatch.setattr(canary, "_fixtures", forbidden)
    assert canary.main([]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result == canary.report()
    assert result["evidence"] == "OFFLINE_SYNTHETIC"
    assert result["authentication"] == "AUTH_E2E_NOT_RUN"
    assert result["launch_allowed"] is False
    assert subscription.readiness()["launch_allowed"] is False
    with pytest.raises(state.PrepareError) as error:
        native_codex.execute({}, 1, ["maintainer"])
    assert error.value.code == 13


@pytest.mark.parametrize(
    "args",
    [
        ["--rootfs", "/"],
        ["--command", "sh"],
        ["--host", "/home"],
        ["--privileged"],
        ["--sudo"],
        ["--run-synthetic", "echo unsafe"],
    ],
)
def test_no_user_paths_commands_or_privileged_flags(args, capsys):
    with pytest.raises(SystemExit) as error:
        canary.main(args)
    assert error.value.code == 2
    assert capsys.readouterr().out == ""


def test_runtime_manifest_hashes_and_mountpoints(runtime):
    _, _, manifest = runtime
    assert canary._runtime() == digest(manifest)


@pytest.mark.parametrize(
    "change",
    [
        "hash",
        "extra_file",
        "symlink",
        "hardlink",
        "setuid",
        "writable",
        "missing_mountpoint",
        "nonempty_placeholder",
        "no_exec",
        "manifest_extra",
        "manifest_duplicate",
        "privileged_capability",
    ],
)
def test_runtime_rejects_unreviewed_or_unsafe_content(runtime, monkeypatch, change):
    root, binary, manifest = runtime
    if change == "hash":
        binary.write_bytes(b"changed")
    elif change == "extra_file":
        (root / "unexpected").write_text("unlisted")
    elif change == "symlink":
        (root / "alias").symlink_to("/usr")
    elif change == "hardlink":
        os.link(root / "usr/bin/python3", root.parent / "external-link")
    elif change == "setuid":
        binary.chmod(0o4755)
    elif change == "writable":
        binary.chmod(0o777)
    elif change == "missing_mountpoint":
        (root / "proc").rmdir()
    elif change == "nonempty_placeholder":
        (root / "canary-policy.json").write_text("unexpected")
    elif change == "no_exec":
        (root / "usr/bin/python3").chmod(0o644)
    elif change == "manifest_extra":
        data = json.loads(manifest.read_text())
        data["command"] = "unsafe"
        manifest.write_text(json.dumps(data))
    elif change == "manifest_duplicate":
        manifest.write_text('{"version":1,"version":1}')
    else:
        monkeypatch.setattr(os, "getxattr", lambda *args: b"privileged")
    with pytest.raises(
        (canary.Blocked, canary.isolation.IsolationError, state.PrepareError)
    ):
        canary._runtime()


@pytest.mark.parametrize("uid", [0])
def test_no_root_or_provisioning(uid, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: uid)

    def forbidden(*args, **kwargs):
        pytest.fail("no root subprocess or fallback")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(canary, "_fixtures", forbidden)
    result = canary.run_synthetic()
    assert result["reason"] == "unprivileged_linux_required"
    assert result["status"] == "BLOCKED" and result["checks"] == {}


def test_fixed_argv_requires_every_namespace_and_only_fixture_binds(fixture_run):
    worker = canary._arguments(fixture_run, "worker")
    domain = canary._arguments(fixture_run, "same-domain")
    assert worker[:7] == [
        str(canary.BWRAP),
        "--unshare-user",
        "--unshare-ipc",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-uts",
        "--unshare-cgroup",
    ]
    assert not any(
        "-try" in a or a in ("--unshare-all", "--share-net", "--preserve-fds")
        for a in worker
    )
    assert (
        "--clearenv" in worker
        and "--die-with-parent" in worker
        and "--new-session" in worker
    )
    assert worker[worker.index("--cap-drop") + 1] == "ALL"
    assert worker[-6:] == [
        "--",
        "/usr/bin/python3",
        "-I",
        "-B",
        "/canary-probe.py",
        "worker",
    ]
    assert str(fixture_run / "host" / "codex-home") not in worker
    assert (
        domain[domain.index(str(fixture_run / "host" / "codex-home")) - 1]
        == "--ro-bind"
    )
    bound = []
    for i, arg in enumerate(worker):
        if arg in ("--bind", "--ro-bind"):
            bound.append(worker[i + 1])
    assert bound == [
        str(canary.RUNTIME / "rootfs"),
        str(fixture_run / "workspace"),
        str(fixture_run / "probe.py"),
        str(fixture_run / "policy.json"),
    ]


@pytest.mark.parametrize(
    "change", ["root_alias", "policy_alias", "external_hardlink", "mode"]
)
def test_fixture_paths_and_aliases_fail_closed(fixture_run, tmp_path, change):
    run = fixture_run
    mode = "worker"
    if change == "root_alias":
        alias = tmp_path / "alias"
        alias.symlink_to(run, target_is_directory=True)
        run = alias
    elif change == "policy_alias":
        (run / "policy.json").unlink()
        (run / "policy.json").symlink_to(run / "host/github")
    elif change == "external_hardlink":
        os.link(run / "host/github", run / "workspace/hardlink")
    else:
        mode = "sh"
    with pytest.raises(
        (canary.Blocked, state.PrepareError, canary.isolation.IsolationError)
    ):
        canary._arguments(run, mode)


def test_fixture_creation_preserves_preexisting_runs_and_rejects_unsafe_root(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(canary, "TEMP", tmp_path)
    first = canary._fixtures()
    marker = first / "preserve"
    marker.write_text("synthetic existing work")
    second = canary._fixtures()
    assert first != second and marker.read_text() == "synthetic existing work"
    assert sum(p.stat().st_size for p in second.rglob("*") if p.is_file()) < 32768
    assert first.parent.stat().st_mode & 0o777 == 0o700
    first.parent.chmod(0o777)
    with pytest.raises(state.PrepareError):
        canary._fixtures()


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\xff",
        b"{",
        b"[]",
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b" " * 4097,
        json.dumps(dict.fromkeys(canary.CHECKS, "true")).encode(),
        json.dumps(dict.fromkeys(canary.CHECKS, 1)).encode(),
        json.dumps(
            {**dict.fromkeys(canary.CHECKS, True), "stderr": "FABRICATED_SECRET"}
        ).encode(),
    ],
)
def test_report_parser_does_not_trust_extra_malformed_or_boolean_like_output(raw):
    with pytest.raises(canary.Blocked):
        canary._parse(raw)


@pytest.fixture
def simulation(tmp_path, monkeypatch):
    monkeypatch.setattr(canary, "TEMP", tmp_path)
    monkeypatch.setattr(canary, "_runtime", lambda: "a" * 64)
    binary = tmp_path / "fake-bwrap"
    binary.write_text(
        f"#!{sys.executable}\nimport json,sys\n"
        f"d=dict.fromkeys({sorted(canary.CHECKS)!r},True)\n"
        'd["home_readable"]=sys.argv[-1]=="same-domain"\n'
        "print(json.dumps(d))\n"
    )
    binary.chmod(0o700)
    monkeypatch.setattr(canary, "BWRAP", binary)
    return binary


def test_offline_control_flow_distinguishes_worker_and_same_domain(
    simulation, monkeypatch
):
    # This mocks bwrap: booleans test reporting, never real kernel evidence.
    original = subprocess.Popen
    children = []

    def guarded(argv, **kwargs):
        assert argv[0] in (sys.executable, str(simulation))
        assert kwargs["env"] == canary.ENV and kwargs["shell"] is False
        assert kwargs.get("pass_fds", ()) == ()
        child = original(argv, **kwargs)
        children.append(child)
        return child

    monkeypatch.setenv("GH_TOKEN", "FABRICATED_ENV_SECRET")
    monkeypatch.setenv("CODEX_HOME", "/DO_NOT_READ_AUTH")
    monkeypatch.setattr(subprocess, "Popen", guarded)
    result = canary.run_synthetic()
    assert result["status"] == "BLOCKED"
    assert result["reason"] == "same_domain_credential_exposure"
    assert result["host_containment"] == result["worker_codex_home"] == "PASS"
    assert result["same_domain_codex_home"] == "FAIL"
    assert (
        result["authentication"] == "AUTH_E2E_NOT_RUN" and not result["launch_allowed"]
    )
    assert len(children) == 3 and all(c.poll() is not None for c in children)
    assert "FABRICATED" not in json.dumps(result) and str(
        simulation.parent
    ) not in json.dumps(result)


@pytest.mark.parametrize(
    "kind", ["negative", "home", "invalid", "timeout", "cancel", "oversize"]
)
def test_failed_probe_never_retries_and_reaps_sentinel(simulation, monkeypatch, kind):
    children = []
    original = subprocess.Popen

    def capture(*args, **kwargs):
        child = original(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", capture)
    calls = []

    def failed(*args, **kwargs):
        calls.append(args)
        if kind in ("timeout", "cancel"):
            raise (
                process.CommandError("timeout")
                if kind == "timeout"
                else canary.Blocked("interrupted")
            )
        if kind == "invalid":
            return b'{"raw":"FABRICATED_SECRET"}'
        if kind == "oversize":
            return b"x" * 4097
        d = dict.fromkeys(canary.CHECKS, True)
        d["home_readable"] = kind == "home"
        if kind == "negative":
            d["namespaces"] = False
        return json.dumps(d).encode()

    monkeypatch.setattr(process, "read_command", failed)
    result = canary.run_synthetic()
    assert result["status"] in ("BLOCKED", "FAIL") and len(calls) == 1
    assert all(c.poll() is not None for c in children)
    assert result["same_domain_codex_home"] == "NOT_RUN"
    assert "FABRICATED_SECRET" not in json.dumps(result)


def test_real_fake_subprocess_timeout_reaps_foreground_group(simulation, monkeypatch):
    simulation.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(10)\n")
    children = []
    original = subprocess.Popen

    def capture(*args, **kwargs):
        child = original(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", capture)
    reader = process.read_command

    def bounded(*args, **kwargs):
        kwargs["timeout"] = 0.1
        return reader(*args, **kwargs)

    monkeypatch.setattr(process, "read_command", bounded)
    assert canary.run_synthetic()["status"] == "BLOCKED"
    assert len(children) == 2 and all(c.poll() is not None for c in children)


def test_sanitized_reasons_and_no_fallback(monkeypatch):
    def blocked():
        raise canary.Blocked("FABRICATED_SECRET")

    monkeypatch.setattr(canary, "_runtime", blocked)

    def forbidden(*args, **kwargs):
        pytest.fail("must not create/launch after dependency failure")

    monkeypatch.setattr(canary, "_fixtures", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    assert canary.run_synthetic()["reason"] == "preflight_unavailable"


def test_probe_namespace_guard_precedes_any_filesystem_or_network_action(monkeypatch):
    monkeypatch.setattr(
        Path, "read_bytes", lambda p: json.dumps({"namespaces": {}}).encode()
    )
    monkeypatch.setattr(probe, "namespaces", lambda p: False)
    monkeypatch.setattr(probe, "capabilities", lambda: True)

    def forbidden(*args, **kwargs):
        pytest.fail("do not probe before kernel identity checks")

    monkeypatch.setattr(probe, "files", forbidden)
    monkeypatch.setattr(probe, "network", forbidden)
    try:
        assert not any(
            probe.probe("worker")[k] for k in ("namespaces", "files", "network")
        )
    finally:
        signal.alarm(0)


@pytest.mark.parametrize(
    "code,expected", [(errno.EPERM, True), (errno.ENOENT, True), (errno.EIO, False)]
)
def test_denial_errno_is_not_any_error(code, expected):
    def fail():
        raise OSError(code, "FABRICATED_SECRET")

    assert probe.denied(fail) is expected


def test_readable_home_is_exposure_even_if_not_read_or_content_differs(monkeypatch):
    opened = []
    monkeypatch.setattr(probe, "open_only", lambda p: opened.append(str(p)))
    assert probe.home_readable() is True
    assert opened == ["/codex-home/auth.json", "/codex-home/session"]


def test_signal_handlers_and_alarm_restored(monkeypatch):
    previous = {
        s: signal.getsignal(s) for s in (signal.SIGALRM, signal.SIGINT, signal.SIGTERM)
    }

    def interrupted():
        os.kill(os.getpid(), signal.SIGTERM)

    monkeypatch.setattr(canary, "_runtime", interrupted)
    assert canary.run_synthetic()["reason"] == "interrupted"
    assert all(signal.getsignal(s) == h for s, h in previous.items())
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)


def test_opt_in_real_linux_kernel(request):
    if not request.config.getoption("--run-native-canary"):
        pytest.skip("explicit --run-native-canary and reviewed runtime required")
    result = canary.run_synthetic()
    if result["evidence"] != "REAL_KERNEL_SYNTHETIC":
        pytest.skip("BLOCKED: " + result["reason"])
    assert result["host_containment"] == result["worker_codex_home"] == "PASS"
    assert result["same_domain_codex_home"] == "FAIL"
    assert result["status"] == "BLOCKED" and result["launch_allowed"] is False


@pytest.mark.parametrize("changed", [True, False])
def test_namespace_ids_not_just_requested_flags(monkeypatch, changed):
    policy = {n: f"{n}:[100]" for n in probe.NAMES}
    monkeypatch.setattr(
        os, "readlink", lambda p: f"{p.rsplit('/', 1)[-1]}:[{200 if changed else 100}]"
    )
    assert probe.namespaces(policy) is changed
    assert probe.namespaces({}) is False


@pytest.mark.parametrize(
    "bad", [None, "CapEff", "CapPrm", "CapInh", "CapAmb", "NoNewPrivs"]
)
def test_actual_capability_metadata_required(monkeypatch, bad):
    fields = {
        "CapEff": "00000000",
        "CapPrm": "00000000",
        "CapInh": "00000000",
        "CapAmb": "00000000",
        "NoNewPrivs": "1",
    }
    if bad:
        fields[bad] = "0" if bad == "NoNewPrivs" else "1"
    monkeypatch.setattr(
        Path, "read_text", lambda p: "\n".join(k + ":\t" + v for k, v in fields.items())
    )
    assert probe.capabilities() is (bad is None)


@pytest.mark.parametrize("escape", [None, "read", "write", "hardlink"])
def test_filesystem_probe_requires_all_denials(monkeypatch, escape):
    paths = []

    def open_fake(path, flags=os.O_RDONLY):
        paths.append((str(path), flags))
        if escape == "read" and str(path) == "/fabricated-host/github":
            return
        if escape == "write" and str(path) == "/dev/outside-write":
            return
        raise OSError(errno.EACCES, "fabricated")

    def link(*args):
        if escape == "hardlink":
            return
        raise OSError(errno.EXDEV, "fabricated")

    monkeypatch.setattr(probe, "open_only", open_fake)
    monkeypatch.setattr(os, "link", link)
    assert probe.files({"host": "/fabricated-host"}) is (escape is None)
    assert paths[0][0] == "/fabricated-host/ssh"


def test_allowed_edit_uses_only_synthetic_workspace(tmp_path, monkeypatch):
    directory = tmp_path / "workspace"
    directory.mkdir()

    def local_path(value):
        assert value == "/workspace/permitted-worker.txt"
        return directory / "permitted-worker.txt"

    monkeypatch.setattr(probe, "Path", local_path)
    assert probe.permitted("worker")
    assert len(list(directory.iterdir())) == 1


@pytest.mark.parametrize("visible", [False, True])
def test_parent_probe_targets_only_fabricated_sentinel(monkeypatch, visible):
    called = []

    def action(path, *args):
        called.append(str(path))
        if visible:
            return []
        raise OSError(errno.ENOENT, "fabricated")

    monkeypatch.setattr(os, "listdir", action)
    monkeypatch.setattr(probe, "open_only", action)
    assert probe.parent_hidden({"pid": 123456}) is (not visible)
    assert set(called) == {"/proc/123456/fd", "/proc/123456/fd/200", "/proc/123456/mem"}


@pytest.mark.parametrize("leaked", [False, True])
def test_fd_probe_checks_inode_without_reading_contents(monkeypatch, leaked):
    from types import SimpleNamespace

    monkeypatch.setattr(os, "listdir", lambda p: ["0", "200"])
    monkeypatch.setattr(
        os,
        "fstat",
        lambda fd: SimpleNamespace(st_dev=1, st_ino=2 if leaked and fd == 200 else 3),
    )
    assert probe.descriptors({"fd_inode": [1, 2]}) is (not leaked)


@pytest.mark.parametrize(
    "code,expected", [(0, False), (errno.ECONNREFUSED, True), (errno.EBADF, False)]
)
def test_network_probe_contacts_only_fixture_listener(monkeypatch, code, expected):
    class Socket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, value):
            assert value == 0.2

        def connect_ex(self, address):
            assert address == ("127.0.0.1", 12345)
            return code

    monkeypatch.setattr(probe.socket, "socket", Socket)
    assert probe.network({"port": 12345}) is expected


@pytest.mark.parametrize("blocked", [False, True])
def test_ipc_probe_only_targets_fixture_socket(monkeypatch, blocked):
    class Socket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, value):
            assert value == 0.2

        def connect(self, address):
            assert address == "/fabricated-host/ipc.sock"
            if blocked:
                raise OSError(errno.ENOENT, "fabricated")

    monkeypatch.setattr(probe.socket, "socket", lambda *args: Socket())
    assert probe.ipc({"host": "/fabricated-host"}) is blocked


def test_descendant_reaping_protocol(monkeypatch):
    calls = []
    monkeypatch.setattr(os, "fork", lambda: 333)
    monkeypatch.setattr(os, "kill", lambda pid, sig: calls.append(("kill", pid, sig)))

    def wait(pid, flags):
        calls.append(("wait", pid, flags))
        return pid, int(signal.SIGTERM)

    monkeypatch.setattr(os, "waitpid", wait)
    assert probe.descendants()
    assert calls == [("kill", 333, signal.SIGTERM), ("wait", 333, 0)]


def test_capability_failure_blocks_before_operations(monkeypatch):
    monkeypatch.setattr(Path, "read_bytes", lambda p: b'{"namespaces":{}}')
    monkeypatch.setattr(probe, "namespaces", lambda p: True)
    monkeypatch.setattr(probe, "capabilities", lambda: False)

    def forbidden(*args):
        pytest.fail("no probes with retained capabilities")

    monkeypatch.setattr(probe, "files", forbidden)
    try:
        assert probe.probe("worker")["files"] is False
    finally:
        signal.alarm(0)


def test_credential_like_runtime_path_rejected_before_open(runtime, monkeypatch):
    root, _, _ = runtime
    (root / "usr/auth.json").write_text("FABRICATED_NOT_REAL")
    original = canary._hash

    def guarded(path):
        assert path.name != "auth.json", (
            "must refuse credential-like paths before hashing"
        )
        return original(path)

    monkeypatch.setattr(canary, "_hash", guarded)
    with pytest.raises(canary.Blocked):
        canary._runtime()


def test_outer_deadline_failure_restores_handlers(monkeypatch):
    def timeout():
        os.kill(os.getpid(), signal.SIGALRM)

    previous = signal.getsignal(signal.SIGALRM)
    monkeypatch.setattr(canary, "_runtime", timeout)
    assert canary.run_synthetic()["reason"] == "deadline"
    assert signal.getsignal(signal.SIGALRM) == previous
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)


def test_cli_argument_rejection_does_not_echo_commands_or_paths(capsys):
    with pytest.raises(SystemExit) as error:
        canary.main(["--command", "FABRICATED_SECRET", "/untrusted/private/path"])
    assert error.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == "native_canary_invalid_arguments\n"


def test_cancellation_during_cleanup_is_deferred_until_children_reaped(
    simulation, monkeypatch
):
    children = []
    original = subprocess.Popen

    def capture(*args, **kwargs):
        child = original(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", capture)
    stop = canary._stop

    def interrupted(child):
        os.kill(os.getpid(), signal.SIGTERM)
        stop(child)

    monkeypatch.setattr(canary, "_stop", interrupted)
    assert canary.run_synthetic()["reason"] == "interrupted"
    assert len(children) == 3 and all(c.poll() is not None for c in children)


def test_inaccessible_runtime_inventory_is_not_silently_skipped(runtime, monkeypatch):
    def inaccessible(root, **kwargs):
        kwargs["onerror"](PermissionError("FABRICATED_NOT_A_DIAGNOSTIC"))
        return []

    monkeypatch.setattr(os, "walk", inaccessible)
    with pytest.raises(canary.Blocked):
        canary._runtime()
