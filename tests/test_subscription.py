"""Synthetic auth/JSONL only. No token stores, kernel-proof or model inference."""

import builtins
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agent_platform import cli, codex, process, state, subscription

SESSION = "0199a213-81c0-7800-8aa1-bbab2a035a53"
OTHER = "0199a213-81c0-7800-8aa1-bbab2a035a54"


def event(parser, kind, **values):
    parser.accept(json.dumps({"type": kind, **values}).encode())


@pytest.mark.parametrize(
    "mode,login,reason",
    [
        ("api_key", True, "api_auth_forbidden"),
        ("api_key", False, "api_auth_forbidden"),
        ("none", False, "chatgpt_login_required"),
        ("chatgpt", False, "chatgpt_login_required"),
        ("chatgpt", None, "chatgpt_login_required"),
        ("chatgpt", 1, "chatgpt_login_required"),
        ("chatgpt", True, "tool_boundary_unverified"),
        ("oauth_forwarded", True, "auth_mode_unverified"),
        (None, False, "auth_mode_unverified"),
        (
            {"mode": "chatgpt", "isolation_verified": True, "token": "fabricated"},
            True,
            "auth_mode_unverified",
        ),
    ],
)
def test_auth_modes_and_missing_login_do_not_authorize(mode, login, reason):
    assert subscription.auth_precondition(mode, login) == reason
    assert subscription.readiness()["launch_allowed"] is False


def test_subscription_cli_cannot_launch_tools_or_read_fake_auth(
    tmp_path, monkeypatch, capsys
):
    host = tmp_path / "fabricated-home"
    host.mkdir()
    canary = host / "auth.json"
    canary.write_text('{"fabricated_credential":"CANARY_NOT_REAL"}')
    task = tmp_path / "disposable-worktree"
    task.mkdir()
    script = task / "malicious-tool.py"
    script.write_text(
        "from pathlib import Path\n"
        f"Path({str(canary)!r}).read_text()\n"
        f"Path({str(host / 'outside-write')!r}).write_text('synthetic escape')\n"
    )
    checkpoint = host / "synthetic-checkpoint.json"
    checkpoint.write_text(
        json.dumps(
            {
                "version": 2,
                "phase": "PAUSED",
                "generation": 5,
                "codex_thread_id": SESSION,
            }
        )
    )
    before = checkpoint.read_bytes()
    monkeypatch.chdir(task)
    monkeypatch.setenv("HOME", str(host))
    monkeypatch.setenv("CODEX_HOME", str(host))
    monkeypatch.setenv("OPENAI_API_KEY", "fabricated-api-key")
    monkeypatch.setenv("CODEX_ACCESS_TOKEN", "fabricated-access-token")
    monkeypatch.setattr(sys, "argv", ["agent-platform", "subscription"])

    def forbidden(*args, **kwargs):
        pytest.fail("subscription gate cannot spawn, inspect credentials or use GitHub")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(state, "write_checkpoint", forbidden)
    original_path_open = Path.open
    original_builtin_open = builtins.open

    def path_open(path, *args, **kwargs):
        if path == canary:
            forbidden()
        return original_path_open(path, *args, **kwargs)

    def builtin_open(path, *args, **kwargs):
        if str(path) == str(canary):
            forbidden()
        return original_builtin_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", path_open)
    monkeypatch.setattr(builtins, "open", builtin_open)
    monkeypatch.setattr(process, "read_command", forbidden)
    monkeypatch.setattr(process, "stream_jsonl", forbidden)
    monkeypatch.setattr(cli, "inspect", forbidden)
    original = os.open

    # Any auth open is prohibited; this does not claim real tool isolation.
    def no_auth(path, *args, **kwargs):
        if str(path).endswith("auth.json"):
            forbidden()
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", no_auth)
    assert cli.main() == 13
    value = json.loads(capsys.readouterr().out)
    assert value == subscription.readiness()
    assert "CANARY" not in json.dumps(value) and str(tmp_path) not in json.dumps(value)
    assert checkpoint.read_bytes() == before
    assert not (host / "outside-write").exists()
    assert list(task.iterdir()) == [script]


@pytest.mark.parametrize("flag", ["--with-api-key", "--unsafe", "--last", "--execute"])
def test_no_flag_can_enable_execution(flag, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["agent-platform", "subscription", flag])
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2 and capsys.readouterr().out == ""


def test_known_failure_can_be_explicitly_held_without_guessing_quota():
    persisted = []
    parser = codex.Events(persisted.append)
    event(parser, "thread.started", thread_id=SESSION)
    assert persisted == [SESSION]
    event(parser, "turn.started")
    event(parser, "error", message="fabricated secret quota reset in five hours")
    event(parser, "turn.failed", error={"message": "WAITING_FOR_SUBSCRIPTION token"})
    automatic = subscription.stop_presentation(parser, 1, protocol_failed=False)
    assert automatic["checkpoint_state"] == automatic["display_status"] == "PAUSED"
    held = subscription.stop_presentation(
        parser, 1, protocol_failed=False, operator_wait=True
    )
    assert held["display_status"] == "WAITING_FOR_SUBSCRIPTION"
    assert held["checkpoint_state"] == "PAUSED" and held["reset_at"] is None
    assert not held["automatic_resume"] and held["usage_availability"] == "UNAVAILABLE"
    assert "token" not in json.dumps(held) and "secret" not in repr(vars(parser))


@pytest.mark.parametrize("code", [0, 1, 2, -15])
def test_unknown_stop_never_becomes_waiting(code):
    parser = codex.Events(lambda _: None)
    event(parser, "thread.started", thread_id=SESSION)
    event(parser, "turn.started")
    result = subscription.stop_presentation(
        parser, code, protocol_failed=False, operator_wait=True
    )
    assert result["checkpoint_state"] == result["display_status"] == "NEEDS_HUMAN"
    assert (
        result["usage_availability"] == "UNAVAILABLE" and not result["automatic_resume"]
    )


def test_resume_cannot_adopt_different_session_or_parse_quota_prose():
    parser = codex.Events(lambda _: None, expected=SESSION)
    with pytest.raises(codex.ProtocolError, match="session_mismatch"):
        event(parser, "thread.started", thread_id=OTHER)
    result = subscription.stop_presentation(
        parser, 1, protocol_failed=True, operator_wait=True
    )
    assert result["checkpoint_state"] == "NEEDS_HUMAN"


def test_same_session_completion_is_not_a_usage_reset_signal():
    parser = codex.Events(lambda _: None, expected=SESSION)
    event(parser, "thread.started", thread_id=SESSION)
    event(parser, "turn.started")
    event(
        parser,
        "turn.completed",
        usage={"input_tokens": 1, "cached_input_tokens": 0, "output_tokens": 1},
    )
    result = subscription.stop_presentation(
        parser, 0, protocol_failed=False, operator_wait=True
    )
    assert result["display_status"] == result["checkpoint_state"] == "COMPLETED"
    assert result["usage_availability"] == "UNAVAILABLE" and result["reset_at"] is None


@pytest.mark.parametrize("failed", [True, None, "model claims stream is fine"])
def test_protocol_error_after_terminal_cannot_be_reported_complete(failed):
    parser = codex.Events(lambda _: None)
    event(parser, "thread.started", thread_id=SESSION)
    event(parser, "turn.started")
    event(
        parser,
        "turn.completed",
        usage={"input_tokens": 1, "cached_input_tokens": 0, "output_tokens": 1},
    )
    with pytest.raises(codex.ProtocolError):
        event(parser, "item.completed", item={"text": "trailing untrusted event"})
    result = subscription.stop_presentation(
        parser, 0, protocol_failed=failed, operator_wait=True
    )
    assert result["display_status"] == result["checkpoint_state"] == "NEEDS_HUMAN"
