"""PKG-09 real dpkg upgrade; disposable Debian13 only, no real credentials."""

import hashlib
import json
import os
import pwd
import subprocess
import sys
from pathlib import Path

BASE_COMMIT = "938c5543757c4184635e08330115527f0108064a"
BASE_MANIFEST = "80519eb56b98c4a5cd1ff222676dea2639c691f08fc318254d68b891d35152fa"
DOC = Path("/usr/share/doc/agent-platform-worker")
RECEIPT = Path("/var/lib/agent-platform-worker-provisioning/receipt.json")


def call(argv, code=0):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=90)
    assert result.returncode == code, (argv[0], result.returncode, code)
    return result.stdout


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def guard():
    assert os.getuid() == 0 and Path("/.dockerenv").is_file()
    assert Path("/ap-package-ci-fixture").read_text() == "AP-PKG-CI-DISPOSABLE-v1\n"
    assert "VERSION_CODENAME=trixie\n" in Path("/etc/os-release").read_text()
    assert not Path("/var/run/docker.sock").exists()


def installed_smoke():
    guard()
    data = json.loads(call(["agent-platform-worker", "doctor"], 13))
    assert data["installation"] == "INSTALLED", data["checks"]["package"]
    assert data["status"] == "BLOCKED" and not data["launch_allowed"]
    assert data["runtime"] == "LIVE_NO_GO" and data["host_evidence"] == "HOST_NOT_RUN"
    assert data["gate_73"] == "BLOCKED"
    assert data["subscription"] == "SUBSCRIPTION_ISOLATION_BLOCKED"
    assert data["checks"]["bpf"]["state"] == "BLOCKED"
    for name in ["job_namespace", "credential_handoff"]:
        assert data["checks"][name]["state"] == "NOT_RUN"
    subscription = call(["agent-platform-control", "subscription"], 13)
    assert "SUBSCRIPTION_ISOLATION_BLOCKED" in subscription
    for role in ["control", "worker"]:
        for command in ["run", "resume", "doctor"]:
            report = json.loads(
                call(["agent-platform-" + role, command, "--issue", "1"], 13)
            )
            assert report["launch_allowed"] is report["resume_authorized"] is False
    for name in ["ap-worker-publisher", "ap-worker-publisher-signer"]:
        unit = Path("/usr/lib/systemd/system/" + name + ".service").read_text()
        assert "Restart=no" in unit and "\n[Install]" not in unit
        assert not Path("/etc/systemd/system/" + name + ".service").exists()
    assert not Path("/usr/bin/codex").exists()
    return data


def snapshot():
    # Only synthetic fixture journals/receipt; never production data.
    paths = [RECEIPT, Path("/etc/ap-publisher")]
    paths += [
        Path("/var/lib/" + role) / "journal"
        for role in ["ap-publisher", "ap-publisher-signer"]
    ]
    result = {}
    for path in paths:
        m = path.stat()
        result[str(path)] = [
            m.st_dev,
            m.st_ino,
            m.st_uid,
            m.st_gid,
            m.st_mode,
            None if path.is_dir() else digest(path),
        ]
    result["accounts"] = [
        list(pwd.getpwnam(role)) for role in ["ap-publisher", "ap-publisher-signer"]
    ]
    result["acl"] = call(["getfacl", "-n", "-p", "/etc/ap-publisher"])
    return result


def main():
    guard()
    case = sys.argv[1]
    assert case in ("empty", "unknown")
    baseline = Path("/packages/worker01-baseline")
    verification = json.loads((baseline / "baseline-verification.json").read_text())
    assert verification["schema"] == "AP-PKG-BASELINE-VERIFIED/1"
    assert verification["source_commit"] == BASE_COMMIT
    assert verification["worker_manifest_sha256"] == BASE_MANIFEST
    old = baseline / "agent-platform-worker_0.1.0-6_amd64.deb"
    old_control = baseline / "agent-platform-control_0.1.0-6_amd64.deb"
    newer = Path("/packages/pkg09-upgrade-test/agent-platform-worker_0.1.0-7_amd64.deb")
    new_control = newer.with_name("agent-platform-control_0.1.0-7_amd64.deb")
    assert digest(old) == verification["rebuilt_archive_sha256"]
    assert (
        pwd.getpwnam("ap-publisher").pw_uid,
        pwd.getpwnam("ap-publisher").pw_gid,
    ) == (999, 989)
    assert (
        pwd.getpwnam("ap-publisher-signer").pw_uid,
        pwd.getpwnam("ap-publisher-signer").pw_gid,
    ) == (995, 987)
    # Dependencies are already configured, with policy-rc.d, in the test image.
    marker = Path("/tmp/pkg09-activation-forbidden")
    for name in [
        "systemctl",
        "service",
        "invoke-rc.d",
        "deb-systemd-invoke",
        "systemd-sysusers",
        "systemd-tmpfiles",
        "codex",
    ]:
        stub = Path("/usr/local/bin") / name
        assert not stub.exists()
        stub.write_text(
            "#!/bin/sh\nprintf forbidden >> /tmp/pkg09-activation-forbidden\nexit 99\n"
        )
        stub.chmod(0o755)
    call(
        [
            "apt-get",
            "--no-download",
            "--no-install-recommends",
            "-y",
            "install",
            str(old_control),
            str(old),
        ]
    )
    assert digest(DOC / "manifest.json") == BASE_MANIFEST
    assert json.loads((DOC / "build.json").read_text())["source_commit"] == BASE_COMMIT
    assert (
        json.loads(call(["agent-platform-worker", "doctor"], 13))["installation"]
        == "INSTALLED"
    )
    call(["agent-platform-worker", "provision", "--approve", "--initialize-journals"])
    if case == "unknown":
        for role in ["ap-publisher", "ap-publisher-signer"]:
            Path("/var/lib/" + role + "/journal").write_text(
                "UNKNOWN synthetic retained state\n"
            )
    before = snapshot()
    profiles = {
        name: digest(Path("/etc/apparmor.d/" + name))
        for name in ["ap-worker-publisher", "ap-worker-publisher-signer"]
    }
    call(
        [
            "dpkg",
            "--force-confdef",
            "--force-confold",
            "--unpack",
            str(new_control),
            str(newer),
        ]
    )
    assert "unpacked" in call(
        ["dpkg-query", "-W", "-f=${Status}", "agent-platform-worker"]
    )
    assert snapshot() == before  # Interrupted configure preserves all protected state.
    # Unconfigured package is never INSTALLED/ready; doctor does not repair it.
    assert (
        json.loads(call(["agent-platform-worker", "doctor"], 13))["installation"]
        == "BLOCKED"
    )
    call(["dpkg", "--configure", "agent-platform-control", "agent-platform-worker"])
    post = installed_smoke()
    assert post["checks"]["state"]["state"] == "CONFIGURED"
    assert snapshot() == before
    call(["agent-platform-worker", "provision", "--approve"])
    assert snapshot() == before
    for name, expected in profiles.items():
        assert digest(Path("/etc/apparmor.d/" + name)) == expected
    # Ordinary APT must refuse a downgrade; never force one to test recovery.
    result = subprocess.run(
        ["apt-get", "--no-download", "-y", "install", str(old)],
        capture_output=True,
        timeout=90,
    )
    assert result.returncode != 0
    assert (
        call(["dpkg-query", "-W", "-f=${Version}", "agent-platform-worker"])
        == "0.1.0-7"
    )
    # Administrator-edited conffile is retained, but integrity/readiness blocks.
    profile = Path("/etc/apparmor.d/ap-worker-publisher")
    original_profile = profile.read_bytes()
    profile.write_bytes(original_profile + b"\n# synthetic administrator change\n")
    call(["dpkg", "--force-confdef", "--force-confold", "-i", str(newer)])
    assert (
        json.loads(call(["agent-platform-worker", "doctor"], 13))["installation"]
        == "BLOCKED"
    )
    assert snapshot() == before
    assert not marker.exists() and not Path("/run/ap-publisher-signer/app-jwt").exists()
    # Restore only the exact synthetic edit above, so the next probe reaches state.
    profile.write_bytes(original_profile)
    assert installed_smoke()["checks"]["state"]["state"] == "CONFIGURED"
    # Never regenerate a missing/corrupt receipt to make the upgrade appear good.
    RECEIPT.write_bytes(b"{}\n")
    damaged = digest(RECEIPT)
    call(["agent-platform-worker", "provision", "--approve"], 13)
    assert digest(RECEIPT) == damaged
    assert installed_smoke()["checks"]["state"]["state"] == "BLOCKED"
    Path("/evidence/pkg09-upgrade-" + case + ".json").write_text(
        json.dumps(
            {
                "status": "PASS",
                "case": case,
                "baseline_source": BASE_COMMIT,
                "baseline_manifest": BASE_MANIFEST,
                "old_archive_sha256": digest(old),
                "new_archive_sha256": digest(newer),
                "new_source": post["artifacts"]["source_commit"],
                "new_manifest": post["artifacts"]["manifest_sha256"],
                "inert": True,
                "state_retained": True,
                "host": "HOST_NOT_RUN",
                "effective_systemd_apparmor_bpf": "NOT_RUN",
            },
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
