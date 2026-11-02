"""Public legacy refusal: fabricated state and tripwires, no real execution."""

import builtins
import http.client
import io
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from agent_platform import (
    cli,
    doctor,
    execution,
    isolation,
    issues,
    native_codex,
    prepare,
    process,
    state,
    subscription,
)

EXPECTED = {
    "status": "unavailable",
    "reason": "legacy_execution_quarantined",
    "backend": "legacy_api",
    "state": None,
    "launch_allowed": False,
    "resume_authorized": False,
    "native_status": "SUBSCRIPTION_ISOLATION_BLOCKED",
}
COMMANDS = [("run",), ("resume",), ("doctor",), ("doctor", "--resume")]


def tripwires(patch, calls):
    def forbidden(*args, **kwargs):
        calls.append("forbidden side effect")
        raise AssertionError("quarantined CLI crossed its public boundary")

    for module, names in [
        (cli, ("inspect", "git", "parse_origin", "read_command")),
        (doctor, ("diagnose",)),
        (execution, ("execute", "_execute", "runtime_digest")),
        (native_codex, ("execute",)),
        (subscription, ("readiness", "auth_precondition")),
        (issues, ("GitHub", "discover", "validate_candidate")),
        (prepare, ("prepare", "approved", "source_snapshot", "git")),
        (state, ("host_lock", "load_checkpoint", "write_checkpoint")),
        (isolation, ("Profile", "broker_request")),
        (process, ("read_command", "stream_jsonl")),
        (subprocess, ("Popen", "run")),
        (socket, ("socket", "create_connection")),
        (http.client.HTTPConnection, ("connect", "request")),
        (builtins, ("open",)),
        (io, ("open",)),
        (os, ("open", "getcwd")),
        (Path, ("cwd", "open", "read_bytes", "read_text", "write_bytes", "write_text")),
    ]:
        for name in names:
            patch.setattr(module, name, forbidden)


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize("actors", [[], ["--trusted-actor", "maintainer"]])
@pytest.mark.parametrize(
    "scenario",
    [
        "outside",
        "unsafe_path",
        "missing_origin",
        "malformed_origin",
        "READY",
        "PAUSED",
        "missing_runtime",
        "contradictory_runtime",
    ],
)
def test_public_refusal_before_all_io(
    tmp_path, monkeypatch, capsys, command, actors, scenario
):
    root = tmp_path / ("unsafe\npath" if scenario == "unsafe_path" else "target")
    root.mkdir()
    # Inert stand-ins; no Git or task preparation is performed by these fixtures.
    if scenario not in {"outside", "unsafe_path"}:
        (root / ".git").mkdir()
        (root / ".git/config").write_text(
            '[remote "origin"]\nurl = https://fabricated@invalid.example/repo\n'
            if scenario == "malformed_origin"
            else ""
        )
    (root / "checkpoint.json").write_text(json.dumps({"phase": scenario}))
    (root / "auth.json").write_text("FABRICATED_CREDENTIAL_DO_NOT_READ")
    (root / "session.json").write_text("FABRICATED_PAUSED_SESSION")
    if scenario == "contradictory_runtime":
        (root / "profile.json").write_text('{"version": 999, "ready": true}')
    before = {
        p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()
    }
    monkeypatch.chdir(root)
    monkeypatch.setenv("CODEX_HOME", str(root))
    monkeypatch.setenv("GH_TOKEN", "FABRICATED_ONLY")
    monkeypatch.setenv("AGENT_PLATFORM_BACKEND", "legacy_api")
    calls = []
    with monkeypatch.context() as patch:
        patch.setattr(
            sys, "argv", ["agent-platform", *command, "--issue", "47", *actors]
        )
        tripwires(patch, calls)
        assert cli.main() == 13
    output = capsys.readouterr()
    assert output.err == ""
    assert output.out == json.dumps(EXPECTED, sort_keys=True) + "\n"
    assert calls == []
    assert {
        p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()
    } == before


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["--issue", "0"],
        ["--issue", "bad"],
        ["--issue", "47", "--trusted-actor", "bad/login"],
        ["--issue", "47", "--backend", "legacy"],
    ],
)
def test_usage_errors_preserved_without_execution(
    monkeypatch, capsys, command, arguments
):
    calls = []
    with monkeypatch.context() as patch:
        patch.setattr(sys, "argv", ["agent-platform", *command, *arguments])
        tripwires(patch, calls)
        with pytest.raises(SystemExit) as error:
            cli.main()
    assert error.value.code == 2
    assert calls == []
    assert capsys.readouterr().out == ""


def test_subscription_stays_blocked_without_legacy_diagnostics(monkeypatch, capsys):
    calls = []
    with monkeypatch.context() as patch:
        tripwires(patch, calls)
        # Restore only the existing inert subscription report, not any launcher.
        patch.setattr(subscription, "readiness", ORIGINAL_READINESS)
        patch.setattr(sys, "argv", ["agent-platform", "subscription"])
        assert cli.main() == 13
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "SUBSCRIPTION_ISOLATION_BLOCKED"
    assert result["launch_allowed"] is False
    assert result["authentication"] == "NOT_INSPECTED"
    assert calls == []


ORIGINAL_READINESS = subscription.readiness


def test_installed_public_commands_are_quarantined(tmp_path):
    executable = Path(sys.executable).parent / "agent-platform"
    for command in COMMANDS:
        result = subprocess.run(
            [str(executable), *command, "--issue", "47"],
            cwd=tmp_path,
            env={
                **os.environ,
                "PYTHONPATH": str(Path(cli.__file__).resolve().parents[1]),
            },
            capture_output=True,
            timeout=5,
        )
        assert result.returncode == 13
        assert json.loads(result.stdout) == EXPECTED
        assert result.stderr == b""


@pytest.mark.parametrize(
    "arguments",
    [
        ["inspect"],
        ["issues", "--issue", "47"],
        ["prepare", "--issue", "47"],
        ["status", "--issue", "47"],
        ["recovery", "plan", "--issue", "47"],
        ["subscription"],
    ],
)
def test_other_public_routes_do_not_dispatch_legacy(monkeypatch, arguments, capsys):
    from agent_platform import recovery, task_status

    def forbidden(*args, **kwargs):
        pytest.fail("a non-execution public route dispatched historical execution")

    monkeypatch.setattr(execution, "execute", forbidden)
    monkeypatch.setattr(execution, "_execute", forbidden)
    monkeypatch.setattr(doctor, "diagnose", forbidden)
    monkeypatch.setattr(native_codex, "execute", forbidden)
    monkeypatch.setattr(state, "host_lock", forbidden)
    # Replace only each route's own non-execution operation with an inert fake.
    monkeypatch.setattr(cli, "inspect", lambda cwd: {"repository": "example/target"})
    monkeypatch.setattr(cli, "discover", lambda *args: ({}, 0))
    monkeypatch.setattr(prepare, "prepare", lambda *args: {})
    monkeypatch.setattr(task_status, "diagnose", lambda *args: ({}, 0))
    monkeypatch.setattr(recovery, "plan", lambda *args: ({}, 0))
    monkeypatch.setattr(sys, "argv", ["agent-platform", *arguments])
    assert cli.main() == (13 if arguments[0] == "subscription" else 0)
    assert capsys.readouterr().err == ""
