"""APT acquisition only, with private state and a dpkg sentinel; never installs."""

import importlib.util
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load():
    spec = importlib.util.spec_from_file_location(
        "pkg09_command_diagnostics",
        ROOT / "packaging/debian/worker_upgrade_lifecycle.py",
    )
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_failed_apt_has_bounded_fixed_messages_no_raw_output(monkeypatch, capsys):
    m = load()
    result = SimpleNamespace(
        returncode=100,
        stdout="PRIVATE_ENV=SECRET\x1b[31m\n" * 10000,
        stderr="-----BEGIN PRIVATE KEY-----\n"
        * 1000
        + "E: Internal Error, Pathname to install is not absolute "
        "'/private/SECRET.deb'\n",
    )
    monkeypatch.setattr(m.subprocess, "run", lambda *args, **kwargs: result)
    with pytest.raises(AssertionError):
        m.call(
            ["apt-get", "install", "/private/SECRET.deb"], stage="historical_install"
        )
    output = capsys.readouterr().out
    assert len(output) < 4096
    assert all(
        value not in output for value in ["SECRET", "PRIVATE", "/private", "\x1b"]
    )
    data = json.loads(output)
    assert data["reasons"] == ["apt_local_archive_path_not_absolute"]
    assert data["returncode"] == 100 and data["expected"] == 0
    assert data["stage"] == "historical_install" and data["sample_truncated"]


def test_unknown_failure_is_not_guessed_or_exposed(monkeypatch, capsys):
    m = load()
    monkeypatch.setattr(
        m.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=100, stdout="SECRET", stderr="UNKNOWN_SECRET"
        ),
    )
    with pytest.raises(AssertionError):
        m.call(["/private/SECRET"], stage="SECRET")
    output = capsys.readouterr().out
    assert "SECRET" not in output
    record = json.loads(output)
    assert record["command"] == "fixture_command" and record["stage"] == "fixture"
    assert record["reasons"] == ["unclassified_command_failure"]


def test_expected_exit_13_is_returned_without_failure_output(monkeypatch, capsys):
    m = load()
    monkeypatch.setattr(
        m.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=13, stdout='{"status":"BLOCKED"}', stderr=""
        ),
    )
    assert m.call(["agent-platform-worker", "doctor"], 13) == '{"status":"BLOCKED"}'
    assert capsys.readouterr().out == ""


@pytest.fixture
def apt_state(tmp_path):
    # All APT state/config/cache and dpkg bookkeeping are private synthetic data.
    # No root, namespaces, host package DB, maintainer scripts, services or network.
    for folder in [
        "state/lists/partial",
        "cache/archives/partial",
        "etc/parts",
        "etc/sources.list.d",
        "etc/preferences.d",
        "log",
    ]:
        (tmp_path / folder).mkdir(parents=True)
    status = tmp_path / "state/status"
    status.write_text("")
    for name in ["sources.list", "apt.conf"]:
        (tmp_path / "etc" / name).write_text("")
    marker = tmp_path / "dpkg-boundary"
    sentinel = tmp_path / "forbidden-dpkg"
    sentinel.write_text(
        """#!/bin/sh
for arg do
    case "$arg" in
        --assert-*|--print-foreign-architectures) exit 0;;
        --print-architecture) echo amd64; exit 0;;
        --version) exec /usr/bin/dpkg --version;;
    esac
done
printf '%s\\n' "$@" > "@MARKER@"
exit 99
""".replace("@MARKER@", str(marker))
    )
    sentinel.chmod(0o755)
    config = tmp_path / "config"
    config.write_text(f'''Dir::State "{tmp_path}/state";
Dir::State::status "{status}";
Dir::Cache "{tmp_path}/cache";
Dir::Log "{tmp_path}/log";
Dir::Etc "{tmp_path}/etc";
Dir::Etc::sourcelist "sources.list";
Dir::Etc::sourceparts "sources.list.d";
Dir::Etc::main "apt.conf";
Dir::Etc::parts "parts";
Dir::Bin::dpkg "{sentinel}";
APT::Architecture "amd64";
Debug::NoLocking "true";
''')
    archives = []
    for name in ["one", "two"]:
        stage = tmp_path / name
        (stage / "DEBIAN").mkdir(parents=True)
        (stage / "DEBIAN").chmod(0o755)
        (stage / "DEBIAN/control").write_text(
            f"Package: ap-pkg09-acquire-{name}\nVersion: 1.0\nArchitecture: amd64\n"
            "Maintainer: Fixture <fixture@example.invalid>\n"
            "Description: inert fixture\n"
        )
        (stage / "data").write_text("synthetic only\n")
        archive = tmp_path / (name + ".deb")
        subprocess.run(
            ["dpkg-deb", "--build", str(stage), str(archive)],
            check=True,
            capture_output=True,
            timeout=15,
        )
        archives.append(archive)
    return (
        status,
        marker,
        archives,
        {"PATH": os.defpath, "LC_ALL": "C", "APT_CONFIG": str(config)},
    )


def test_real_apt_local_archives_reach_blocked_dpkg_without_any_install(apt_state):
    status, marker, archives, env = apt_state
    argv = load().local_install_argv(*archives)
    assert "--no-download" not in argv
    result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=20)
    # Expected nonzero is ONLY the sentinel refusing an actual dpkg operation.
    assert result.returncode == 100
    assert marker.exists() and "--unpack" in marker.read_text()
    assert all(str(archive) in marker.read_text() for archive in archives)
    assert "Pathname to install is not absolute" not in result.stderr
    assert status.read_text() == ""


def test_real_apt_downgrade_failure_is_policy_not_disabled_acquisition(apt_state):
    status, marker, archives, env = apt_state
    data = "".join(
        f"Package: ap-pkg09-acquire-{name}\nStatus: install ok installed\n"
        "Architecture: amd64\nVersion: 2.0\nDescription: synthetic\n\n"
        for name in ["one", "two"]
    )
    status.write_text(data)
    m = load()
    result = subprocess.run(
        m.local_install_argv(*archives),
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )
    diagnostic = m.command_diagnostic(["apt-get"], result, None, "downgrade")
    assert result.returncode == 100
    assert diagnostic["reasons"] == ["apt_downgrade_not_authorized"]
    assert not marker.exists() and status.read_text() == data


def test_ci_keeps_both_independent_cases_and_rejects_either_failure():
    workflow = (ROOT / ".github/workflows/debian-package.yml").read_text()
    part = workflow.split("      - name: Real worker01 historical", 1)[1].split(
        "      - name:", 1
    )[0]
    assert "for journal_case in empty unknown" in part
    assert "if ! docker run" in part and 'test "$upgrade_failed" -eq 0' in part
    assert "--network none" in part
