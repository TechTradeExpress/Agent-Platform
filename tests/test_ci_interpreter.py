"""CI interpreter binding only, never image/host attestation or permission repair."""

import importlib.util
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location(
    "cp08_ci_pytest", ROOT / "ci/cp08_pytest.py"
)
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)


def test_fixed_image_path_and_bit_mask():
    assert ci.EXPECTED_BINARY == "/usr/bin/python3.12"
    assert sum(bit for bit, _ in ci.FORBIDDEN_BITS) == 0o6022


@pytest.mark.parametrize(
    "mode,present",
    [
        (0o755, set()),
        (0o777, {"group_write", "other_write"}),
        (0o6755, {"setuid", "setgid"}),
    ],
)
def test_safe_permission_categories_only(monkeypatch, mode, present):
    monkeypatch.setattr(ci.os, "stat", lambda *a, **k: SimpleNamespace(st_mode=mode))
    facts = ci.mode_categories()
    assert {name for name, value in facts.items() if value == "PRESENT"} == present
    assert set(facts.values()) <= {"PRESENT", "ABSENT"}


def test_unknown_metadata_does_not_echo_error(monkeypatch, capsys):
    def unknown(*args, **kwargs):
        raise OSError("PRIVATE_DETAIL_NEVER_LOG")

    monkeypatch.setattr(ci.os, "stat", unknown)
    ci._emit("ci_interpreter_blocked")
    text = capsys.readouterr().out
    assert "PRIVATE_DETAIL" not in text
    assert set(json.loads(text)["permission_bits"].values()) == {"UNKNOWN"}


def test_refusal_never_enters_pytest(monkeypatch, capsys):
    def refused():
        raise ci.lr.RunnerError("local_runner_blocked")

    monkeypatch.setattr(ci, "snapshot", refused)
    monkeypatch.setattr(pytest, "main", lambda *args: pytest.fail("must not run"))
    assert ci.main() == 13
    assert json.loads(capsys.readouterr().out)["code"] == "ci_interpreter_blocked"


def test_validated_pytest_uses_same_process_and_no_subprocess(monkeypatch, capsys):
    pid = os.getpid()
    calls = []
    monkeypatch.setattr(ci, "snapshot", lambda: (pid, "fixed-test-pin"))

    def run(args):
        assert os.getpid() == pid and args == []
        calls.append(1)
        return 0

    monkeypatch.setattr(pytest, "main", run)
    assert ci.main() == 0 and calls == [1]
    assert (
        json.loads(capsys.readouterr().out)["code"]
        == "ci_interpreter_verified_same_process"
    )


@pytest.mark.parametrize(
    "pins,code",
    [([1, 2], "ci_interpreter_blocked"), ([1, 1, 2], "ci_interpreter_changed")],
)
def test_changed_identity_or_hash_is_not_pass(monkeypatch, capsys, pins, code):
    seq = iter(pins)
    monkeypatch.setattr(ci, "snapshot", lambda: next(seq))
    monkeypatch.setattr(pytest, "main", lambda *args: 0)
    assert ci.main() == 13
    assert code in capsys.readouterr().out


def test_test_failure_exit_is_preserved(monkeypatch):
    monkeypatch.setattr(ci, "snapshot", lambda: "fixed-test-pin")
    monkeypatch.setattr(pytest, "main", lambda *args: 1)
    assert ci.main() == 1


def test_real_runtime_checks_preserved_with_only_expected_image_path_mocked(
    monkeypatch,
):
    # Real unprivileged local runtime checks and hash, not a forged stat/capability
    # or kernel fact. Path/version substitution models the local test image only.
    monkeypatch.setattr(ci, "EXPECTED_BINARY", os.path.realpath(sys.executable))
    monkeypatch.setattr(
        ci,
        "sys",
        SimpleNamespace(
            platform=sys.platform, version_info=(3, 12), executable=sys.executable
        ),
    )
    first = ci.snapshot()
    assert first == ci.snapshot()
    assert first[0] == os.getpid()
    assert len(first[-1]) == 64


def test_wrong_real_interpreter_never_admitted(monkeypatch):
    monkeypatch.setattr(ci, "EXPECTED_BINARY", "/nonexistent-cp08-fixed-test-binary")
    monkeypatch.setattr(
        ci,
        "sys",
        SimpleNamespace(
            platform=sys.platform, version_info=(3, 12), executable=sys.executable
        ),
    )
    with pytest.raises(ci.lr.RunnerError):
        ci.snapshot()


def test_import_has_no_launch_or_pytest_side_effect(monkeypatch):
    monkeypatch.setattr(pytest, "main", lambda *a: pytest.fail("import must be inert"))
    module = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(module)
    assert module.EXPECTED_BINARY == ci.EXPECTED_BINARY
