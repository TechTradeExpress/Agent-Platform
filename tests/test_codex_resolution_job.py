"""Offline policy/resource tests; no network or Cargo invocation."""

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "resolution_job", ROOT / "packaging/codex/resolution_job.py"
)
job = importlib.util.module_from_spec(spec)
spec.loader.exec_module(job)


def test_pinned_job_has_large_fs_and_bounded_resources():
    pin = job.read_pin()
    limits = pin["limits"]
    assert pin["codex_source_commit"] == "6ff1e1ca3b30fc8b914720681fcf5fe62e95f856"
    assert len(pin["toolchain_files"]) == 147
    assert limits["minimum_free_bytes"] == 64 * 1024**3
    assert limits["maximum_cache_bytes"] == 32 * 1024**3
    assert limits["maximum_network_bytes"] == 16 * 1024**3
    assert limits["maximum_seconds"] == 900
    assert not pin["production_authorized"]


def test_small_filesystem_refuses_before_input_reads_or_network(tmp_path, monkeypatch):
    monkeypatch.setattr(
        job.os,
        "statvfs",
        lambda _: SimpleNamespace(
            f_blocks=3 * 1024**3,
            f_frsize=1,
            f_bavail=1024**3,
        ),
    )
    monkeypatch.setattr(job, "verify_inputs", lambda *a: pytest.fail("input I/O"))
    monkeypatch.setattr(job, "Proxy", lambda *a: pytest.fail("network"))
    with pytest.raises(ValueError, match="larger_filesystem_unavailable"):
        job.run(tmp_path, tmp_path, tmp_path, tmp_path)


@pytest.mark.parametrize(
    "header",
    [
        b"GET https://github.com/ HTTP/1.1\r\n\r\n",
        b"CONNECT github.com:80 HTTP/1.1\r\n\r\n",
        b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n",
        b"CONNECT example.com:443 HTTP/1.1\r\n\r\n",
        b"CONNECT github.com.evil:443 HTTP/1.1\r\n\r\n",
        b"CONNECT github.com:443 HTTP/1.1\r\nProxy-Authorization: secret\r\n\r\n",
        b"X" * 4097,
    ],
)
def test_network_proxy_rejects_nonallowlisted_or_secret_bearing_requests(header):
    with pytest.raises(ValueError):
        job.connect_host(header, ["github.com"])


def test_proxy_accepts_only_fixed_https_connect():
    assert (
        job.connect_host(
            b"CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n",
            ["github.com"],
        )
        == "github.com"
    )


def test_transfer_budget_never_grants_bytes_past_limit():
    budget = job.TransferBudget(10, 2)
    assert budget.admit(connection=True)
    assert budget.admit(8)
    assert not budget.admit(3)
    assert budget.bytes == 8 and budget.reason == "NETWORK_BUDGET"
    assert not budget.admit(1)


def test_connection_budget_is_retained_after_exhaustion():
    budget = job.TransferBudget(100, 1)
    assert budget.admit(connection=True)
    assert not budget.admit(connection=True)
    assert budget.connections == 1
    assert not budget.admit(1)


def test_command_keeps_locked_sources_and_credential_free_environment(tmp_path):
    command = [
        "metadata",
        "--locked",
        "--format-version",
        "1",
        "--filter-platform",
        "x86_64-unknown-linux-musl",
    ]
    args = job.argv_for(
        tmp_path,
        tmp_path,
        tmp_path,
        "http://127.0.0.1:1234",
        job.read_pin()["limits"],
        command,
    )
    assert args[-len(command) :] == command
    assert "--clearenv" in args and "--unshare-all" in args
    pairs = [args[i + 1 : i + 3] for i, a in enumerate(args) if a == "--setenv"]
    env = dict(pairs)
    assert env["HOME"] == "/home" and env["CARGO_HOME"] == "/cargo"
    assert env["GIT_ALLOW_PROTOCOL"] == "https"
    assert env["GIT_CONFIG_VALUE_1"] == ""
    assert env["CARGO_NET_RETRY"] == "0"
    assert (
        not {"GH_TOKEN", "GITHUB_TOKEN", "SSH_AUTH_SOCK", "OPENAI_API_KEY"} & env.keys()
    )
    assert all("--no-default-features" != a and "--exclude" != a for a in args)


def test_inventory_rejects_directory_aliases(tmp_path):
    (tmp_path / "original").mkdir()
    (tmp_path / "alias").symlink_to(tmp_path / "original", target_is_directory=True)
    with pytest.raises(ValueError, match="unexpected_directory_alias"):
        job.file_inventory(tmp_path)


def test_untracked_configuration_is_not_silently_accepted(tmp_path):
    source, tools = tmp_path / "source", tmp_path / "tools"
    source.mkdir()
    tools.mkdir()
    data = b"[workspace]\nmembers = []\n"
    (source / "Cargo.toml").write_bytes(data)
    tree = json.dumps(
        {
            "truncated": False,
            "tree": [
                {
                    "path": "Cargo.toml",
                    "type": "blob",
                    "mode": "100644",
                    "sha": hashlib.sha1(
                        b"blob " + str(len(data)).encode() + b"\0" + data
                    ).hexdigest(),
                }
            ],
        }
    ).encode()
    tree_path = tmp_path / "tree.json"
    tree_path.write_bytes(tree)
    pin = {"tree_json_sha256": hashlib.sha256(tree).hexdigest(), "toolchain_files": []}
    job.verify_inputs(source, tools, tree_path, pin)
    (source / ".cargo").mkdir()
    (source / ".cargo/config.toml").write_text("[http]\nproxy = 'unexpected'\n")
    with pytest.raises(ValueError, match="source_inventory_changed"):
        job.verify_inputs(source, tools, tree_path, pin)


def test_pidfd_unavailable_stops_before_source_inspection(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    monkeypatch.setattr(job, "capacity", lambda *a: {})
    monkeypatch.setattr(job, "verify_inputs", lambda *a: pytest.fail("source I/O"))

    def unavailable(_):
        raise OSError("synthetic unavailable")

    monkeypatch.setattr(job.os, "pidfd_open", unavailable)
    with pytest.raises(OSError):
        job.run(tmp_path, tmp_path, tmp_path, tmp_path)


def test_without_explicit_execute_no_input_inspection_or_network(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(ROOT / "packaging/codex/resolution_job.py"),
            "--source",
            str(tmp_path / "missing"),
            "--tools",
            str(tmp_path / "missing"),
            "--tree",
            str(tmp_path / "missing"),
            "--fixture",
            str(tmp_path / "missing"),
        ],
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 13 and not result.stderr
    assert json.loads(result.stdout) == {
        "status": "NOT_RUN",
        "runtime_authorized": False,
    }
    assert not list(tmp_path.iterdir())
