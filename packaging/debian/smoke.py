"""Real installed-package tests, only inside the explicit disposable CI fixture."""

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path


def guard():
    assert Path("/.dockerenv").is_file()
    assert Path("/ap-package-ci-fixture").read_text() == "AP-PKG-CI-DISPOSABLE-v1\n"
    assert "VERSION_CODENAME=trixie\n" in Path("/etc/os-release").read_text()
    assert os.geteuid() == 0
    assert not Path("/var/run/docker.sock").exists()


def call(argv, code=0):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=90)
    if result.returncode != code:
        # Inputs are fixed CI fixtures, never real credentials or account output.
        print(result.stdout[-8000:], result.stderr[-8000:])
        raise AssertionError((argv[0], result.returncode, code))
    return result.stdout


def digest(path):
    meta = path.stat()
    return [
        hashlib.sha256(path.read_bytes()).hexdigest(),
        meta.st_uid,
        meta.st_gid,
        stat.S_IMODE(meta.st_mode),
    ]


def smoke():
    for name in (
        "agent-platform",
        "agent-platform-broker",
        "agent-platform-native-canary",
        "agent-platform-native-artifact",
    ):
        call([name, "--help"])
        assert "0.1.0 (Debian 0.1.0-" in call([name, "--version"])
    for command in ("run", "resume", "doctor"):
        result = json.loads(call(["agent-platform", command, "--issue", "1"], 13))
        assert result["reason"] == "legacy_execution_quarantined"
        assert result["launch_allowed"] is result["resume_authorized"] is False
    result = json.loads(call(["agent-platform", "subscription"], 13))
    assert "SUBSCRIPTION_ISOLATION_BLOCKED" in json.dumps(result)
    call(["agent-platform-native-canary"], 13)  # inert report, never --run-synthetic
    assert not Path("/var/lib/agent-platform").exists()
    assert not Path("/run/agent-platform").exists()
    files = call(["dpkg-query", "-L", "agent-platform"]).splitlines()
    assert not any("/systemd/" in name or "/init.d/" in name for name in files)
    assert not Path("/tmp/ap-forbidden-call").exists()


def fixture(path):
    path.mkdir(mode=0o700)
    (path / "EXAMPLE_ONLY").write_text("AP-PKG-EXAMPLE-ONLY v1\n")
    (path / "example.json").write_text(
        '{"format":"AP-PKG-SYNTHETIC","schema":1,"label":"offline demo"}\n'
    )
    for file in path.iterdir():
        file.chmod(0o600)


def lifecycle():
    evidence = Path("/evidence")
    assert evidence.is_dir()
    phases = []
    # Initial apt install already ran with the container-only fake tripwires.
    assert shutil.which("codex") == "/usr/local/bin/codex"
    smoke()
    phases.append("clean_install_and_gates")
    cfg = Path("/etc/agent-platform/package.conf")
    cfg.write_text(cfg.read_text() + "# administrator edit retained\n")
    cfg.chmod(0o640)
    config = digest(cfg)
    notes = Path("/etc/agent-platform/operator-notes")
    notes.write_text("unowned administrator note\n")
    state = Path("/opt/operator-fixture")
    fixture(state)
    retained = {}
    for name in ("checkpoint.json", "unknown-journal.json", "backup.json"):
        file = Path("/opt") / name
        file.write_text('{"synthetic":true,"state":"UNKNOWN"}\n')
        file.chmod(0o640)
        retained[str(file)] = digest(file)

    def retained_ok():
        assert all(digest(Path(p)) == expected for p, expected in retained.items())

    before = (state / "example.json").read_bytes()
    newer = "/packages/next/agent-platform_0.1.0-2_amd64.deb"
    # Real rejected archive operation must leave configured N and all data intact.
    bad = Path("/tmp/corrupt.deb")
    bad.write_bytes(b"not a Debian archive\n")
    result = subprocess.run(["dpkg", "--unpack", str(bad)], capture_output=True)
    assert result.returncode != 0
    assert call(["dpkg-query", "-W", "-f=${Version}", "agent-platform"]) == "0.1.0-1"
    assert digest(cfg) == config
    retained_ok()
    phases.append("corrupt_archive_rejected")
    # Stop at a real unpacked state, then explicitly recover with configure.
    call(["dpkg", "--force-confdef", "--force-confold", "--unpack", newer])
    assert (
        call(["dpkg-query", "-W", "-f=${Status}", "agent-platform"])
        == "install ok unpacked"
    )
    assert digest(cfg) == config and (state / "example.json").read_bytes() == before
    call(
        ["dpkg", "--force-confdef", "--force-confold", "--configure", "agent-platform"]
    )
    assert (
        call(["dpkg-query", "-W", "-f=${Status}", "agent-platform"])
        == "install ok installed"
    )
    assert call(["dpkg-query", "-W", "-f=${Version}", "agent-platform"]) == "0.1.0-2"
    retained_ok()
    phases.append("n_to_next_unpacked_recovery")
    # Package manager NEVER migrates this data. Explicit synthetic operation only.
    helper = ["/usr/lib/agent-platform/migrate-example", "--directory", str(state)]
    assert json.loads(call(helper))["outcome"] == "migrated"
    assert json.loads((state / "example.json").read_text())["schema"] == 2
    assert (state / "v1.backup").read_bytes() == before
    migrated = {p.name: digest(p) for p in state.iterdir()}
    assert json.loads(call(helper))["outcome"] == "already_migrated"
    assert {p.name: digest(p) for p in state.iterdir()} == migrated
    # Unsupported schema: fail closed without writes, then restore explicit backup.
    bad_state = Path("/opt/rejected-example")
    fixture(bad_state)
    (bad_state / "example.json").write_text(
        '{"format":"AP-PKG-SYNTHETIC","schema":99}\n'
    )
    rejected = {p.name: digest(p) for p in bad_state.iterdir()}
    call(["/usr/lib/agent-platform/migrate-example", "--directory", str(bad_state)], 13)
    assert {p.name: digest(p) for p in bad_state.iterdir()} == rejected
    retained_ok()
    phases.append("explicit_migration_idempotent_and_rejection")
    smoke()
    call(["apt-get", "--no-download", "-y", "remove", "agent-platform"])
    assert not Path("/usr/bin/agent-platform").exists() and digest(cfg) == config
    assert {p.name: digest(p) for p in state.iterdir()} == migrated
    retained_ok()
    phases.append("remove_retains_configuration_and_data")
    call(["apt-get", "-y", "install", newer])
    assert digest(cfg) == config
    retained_ok()
    phases.append("reinstall_after_remove_keeps_configuration")
    call(["apt-get", "--no-download", "-y", "purge", "agent-platform"])
    assert not cfg.exists() and notes.read_text() == "unowned administrator note\n"
    assert {p.name: digest(p) for p in state.iterdir()} == migrated
    retained_ok()
    phases.append("purge_retains_unowned_data")
    call(["apt-get", "-y", "install", newer])
    assert (
        "package_schema=2" in cfg.read_text()
        and "# administrator" not in cfg.read_text()
    )
    assert {p.name: digest(p) for p in state.iterdir()} == migrated
    # Restore to a NEW explicit directory; never overwrite retained/uncertain data.
    restored = Path("/opt/restored-example")
    fixture(restored)
    (restored / "example.json").write_bytes((state / "v1.backup").read_bytes())
    call(["/usr/lib/agent-platform/migrate-example", "--directory", str(restored)])
    assert (restored / "example.json").read_bytes() == (
        state / "example.json"
    ).read_bytes()
    assert all(digest(Path(p)) == snapshot for p, snapshot in retained.items())
    smoke()
    retained_ok()
    phases.append("reinstall_and_restore_reconciliation")
    assert len(phases) == 8
    (evidence / "lifecycle.json").write_text(
        json.dumps(
            {
                "status": "PASS",
                "phases": phases,
                "systemd_boot": "NOT_RUN",
                "piuparts": "NOT_RUN",
                "live_runtime": "NOT_RUN",
            },
            indent=2,
        )
        + "\n"
    )
    (evidence / "installed-packages.txt").write_text(call(["dpkg-query", "-W"]))
    print("REAL_DISPOSABLE_LIFECYCLE_PASS")


if __name__ == "__main__":
    guard()
    if sys.argv[1:] == ["--lifecycle"]:
        lifecycle()
    else:
        assert sys.argv[1:] == []
        smoke()
