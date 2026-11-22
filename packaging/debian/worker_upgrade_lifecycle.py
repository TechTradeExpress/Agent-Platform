"""PKG-09/11 real dpkg upgrade; disposable Debian13 only, no real credentials."""

import hashlib
import io
import json
import os
import pwd
import subprocess
import sys
import tarfile
from pathlib import Path

BASE_COMMIT = "938c5543757c4184635e08330115527f0108064a"
BASE_MANIFEST = "80519eb56b98c4a5cd1ff222676dea2639c691f08fc318254d68b891d35152fa"
DOC = Path("/usr/share/doc/agent-platform-worker")
RECEIPT = Path("/var/lib/agent-platform-worker-provisioning/receipt.json")


# Immutable -7 profile digests, not the current source profile digests.
HISTORICAL_PROFILES = {
    "ap-worker-publisher": (
        "7f96b5449f992d3877dab4bc4304ca35831e12fb816b4fca040924de3f0ebad0"
    ),
    "ap-worker-publisher-signer": (
        "bf77deda8d838ae6bdda687a1a514db802b955022f4a56f993b605e0eca9ec6a"
    ),
}
# Exact reviewed F-02 delta, not a general policy parser or release authority.
PROFILE_ADDITIONS = {
    "ap-worker-publisher": """  # PKG-14: descriptor walks; r permits listing.
  / r,
  /etc/ r,
  /etc/ap-publisher/ r,
  /run/ r,
  /run/credentials/ r,
  /run/credentials/ap-worker-publisher.service/ r,
  /usr/ r,
  /usr/lib/ r,
  /usr/lib/ap-worker-publisher/ r,
  /usr/lib/ap-worker-publisher/agent_platform/ r,
  /var/ r,
  /var/lib/ r,
  /var/lib/ap-publisher/ r,
  deny /etc/ap-publisher-keys/ rwklmx,
  deny /var/lib/ap-publisher-signer/ rwklmx,
  deny /var/lib/ap-publisher-signer/** rwklmx,
  deny /run/ap-publisher-signer/ rwklmx,
  deny /run/ap-publisher-signer/** rwklmx,
  deny /run/credentials/ap-worker-publisher-signer.service/ rwklmx,
""",
    "ap-worker-publisher-signer": """  # PKG-14: descriptor walks; r permits listing.
  / r,
  /etc/ r,
  /etc/ap-publisher/ r,
  /run/ r,
  /run/credentials/ r,
  /run/credentials/ap-worker-publisher-signer.service/ r,
  /usr/ r,
  /usr/lib/ r,
  /usr/lib/ap-worker-publisher/ r,
  /usr/lib/ap-worker-publisher/agent_platform/ r,
  /var/ r,
  /var/lib/ r,
  /var/lib/ap-publisher-signer/ r,
  deny /etc/ap-publisher/candidate.json rwklmx,
  deny /etc/ap-publisher-keys/ rwklmx,
  deny /etc/ap-publisher-keys/** rwklmx,
  deny /var/lib/ap-publisher/ rwklmx,
  deny /run/credentials/ap-worker-publisher.service/ rwklmx,
  deny /run/credentials/ap-worker-publisher.service/** rwklmx,
""",
}


def validate_profile_transition(old, new, series):
    assert series in ("pkg09", "pkg11")
    assert set(old) == set(new) == set(HISTORICAL_PROFILES)
    anchor = b"  #include <abstractions/python>\n"
    for name, historical_hash in HISTORICAL_PROFILES.items():
        assert hashlib.sha256(old[name]).hexdigest() == historical_hash
        if series == "pkg09":
            assert new[name] == old[name]  # Historical -6 -> -7 stays immutable.
        else:
            assert old[name].count(anchor) == 1
            expected = old[name].replace(
                anchor, anchor + PROFILE_ADDITIONS[name].encode(), 1
            )
            if name == "ap-worker-publisher":
                expected = expected.replace(
                    b"{job,receipts,candidate}.json",
                    b"{job,receipts,candidate,homelab-candidate}.json",
                )
            else:
                expected = expected.replace(
                    b"deny /etc/ap-publisher/candidate.json",
                    b"deny /etc/ap-publisher/{candidate,homelab-candidate}.json",
                )
                expected = expected.replace(
                    b"  /run/ap-publisher-signer/app-jwt rw,\n",
                    b"  /run/ap-publisher-signer/ r,\n"
                    b"  /run/ap-publisher-signer/app-jwt rw,\n",
                )
            assert new[name] == expected, "unapproved_profile_delta"


def archive_profiles(path):
    raw = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(path)], timeout=30)
    result = {}
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        for name in HISTORICAL_PROFILES:
            members = [
                m for m in archive.getmembers() if m.name == "./etc/apparmor.d/" + name
            ]
            assert len(members) == 1 and members[0].isreg()
            result[name] = archive.extractfile(members[0]).read()
    return result


FIXTURE_ENV = {
    "PATH": "/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C",
    "DEBIAN_FRONTEND": "noninteractive",
}
DIAGNOSTICS = (
    (
        "apt_local_archive_path_not_absolute",
        "Internal Error, Pathname to install is not absolute",
        "APT: Internal Error, Pathname to install is not absolute [local archive]",
    ),
    (
        "apt_downgrade_not_authorized",
        "-y was used without --allow-downgrades",
        "APT: downgrade refused without explicit --allow-downgrades",
    ),
    (
        "package_path_conflict",
        "worker_package_path_conflict",
        "preinst: worker_package_path_conflict",
    ),
    ("apt_unmet_dependencies", "unmet dependencies", "APT: unmet dependencies"),
    (
        "apt_broken_packages",
        "held broken packages",
        "APT: dependency resolution failed",
    ),
    (
        "dpkg_preinst_failed",
        "pre-installation script subprocess returned error",
        "dpkg: pre-installation script failed",
    ),
    (
        "archive_access_denied",
        "Permission denied",
        "package command: permission denied",
    ),
)


def command_diagnostic(argv, result, expected, stage):
    """Closed bounded report, never raw stdout/stderr, argv paths or environment.

    Only public fixed APT/dpkg messages are recognized. Unknown output stays
    unclassified/failed rather than being exposed or guessed into a cause.
    """
    program = Path(argv[0]).name
    if program not in {
        "apt-get",
        "dpkg",
        "dpkg-query",
        "agent-platform-worker",
        "agent-platform-control",
        "getfacl",
    }:
        program = "fixture_command"
    if stage not in {"fixture", "historical_install", "downgrade"}:
        stage = "fixture"
    stdout, stderr = result.stdout or "", result.stderr or ""
    sample = stdout[-8192:] + "\n" + stderr[-8192:]
    matched = [
        (code, message) for code, needle, message in DIAGNOSTICS if needle in sample
    ]
    return {
        "schema": "AP-PKG-COMMAND-FAILURE/1",
        "stage": stage,
        "command": program,
        "returncode": result.returncode,
        "expected": expected,
        "stdout_chars": len(stdout),
        "stderr_chars": len(stderr),
        "sample_truncated": len(stdout) > 8192 or len(stderr) > 8192,
        "reasons": [item[0] for item in matched] or ["unclassified_command_failure"],
        "messages": [item[1] for item in matched],
    }


def local_install_argv(*archives):
    # Offline is enforced by the disposable container's --network none.
    # Do not disable APT's local archive acquisition with --no-download.
    return [
        "apt-get",
        "--no-install-recommends",
        "-y",
        "install",
        *(str(path) for path in archives),
    ]


def call(argv, code=0, *, stage="fixture"):
    result = subprocess.run(
        argv, capture_output=True, text=True, timeout=90, env=FIXTURE_ENV
    )
    if result.returncode != code:
        report = command_diagnostic(argv, result, code, stage)
        print(json.dumps(report, sort_keys=True), flush=True)
        raise AssertionError((report["command"], result.returncode, code))
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
    assert not Path("/usr/bin/claude").exists()
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
    series = sys.argv[2] if len(sys.argv) == 3 else "pkg09"
    assert series in ("pkg09", "pkg11") and len(sys.argv) in (2, 3)
    baseline = Path(
        "/packages/worker01-baseline" if series == "pkg09" else "/packages/historical-7"
    )
    verification = json.loads((baseline / "baseline-verification.json").read_text())
    if series == "pkg09":
        base_commit, base_manifest = BASE_COMMIT, BASE_MANIFEST
        old_version, new_version = "0.1.0-6", "0.1.0-7"
        next_dir = Path("/packages/historical-7")
        assert verification["schema"] == "AP-PKG-BASELINE-VERIFIED/1"
        assert verification["worker_manifest_sha256"] == base_manifest
        old_hash = verification["rebuilt_archive_sha256"]
    else:
        base_commit = "0fbc940ae94144f8cc29c9a0fd98afc704f58168"
        base_manifest = (
            "9174f8ee35499b76d9b9f781d64826029c22cd802e3223015a32e53040afcfa9"
        )
        old_version, new_version = "0.1.0-7", "0.1.0-8"
        next_dir = Path("/packages/pkg11-upgrade-test")
        assert verification["schema"] == "AP-PKG11-BASELINE-VERIFIED/1"
        assert verification["result"] == "RECONSTRUCTED_MATCHES_REPORTED_HASHES"
        assert verification["installed_artifact_verified"] is False
        assert verification["roles"]["worker"]["manifest_sha256"] == base_manifest
        old_hash = verification["roles"]["worker"]["archive_sha256"]
    assert verification["source_commit"] == base_commit
    old = baseline / ("agent-platform-worker_" + old_version + "_amd64.deb")
    old_control = baseline / ("agent-platform-control_" + old_version + "_amd64.deb")
    newer = next_dir / ("agent-platform-worker_" + new_version + "_amd64.deb")
    new_control = next_dir / ("agent-platform-control_" + new_version + "_amd64.deb")
    assert digest(old) == old_hash
    if series == "pkg11":
        assert digest(old_control) == verification["roles"]["control"]["archive_sha256"]
    expected = json.loads(
        (next_dir / "agent-platform-worker.provenance.json").read_text()
    )
    assert digest(newer) == expected["sha256"]
    assert expected["debian_version"] == new_version
    control_expected = json.loads(
        (next_dir / "agent-platform-control.provenance.json").read_text()
    )
    assert digest(new_control) == control_expected["sha256"]
    for key in ("source_commit", "source_tree", "debian_version", "build_kind"):
        assert control_expected[key] == expected[key]
    if series == "pkg11":
        assert expected["build_kind"] == "ci-final-fixture"
        assert expected["ci_only"] is True and expected["release_authorized"] is False
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
        "claude",
    ]:
        stub = Path("/usr/local/bin") / name
        assert not stub.exists()
        stub.write_text(
            "#!/bin/sh\nprintf forbidden >> /tmp/pkg09-activation-forbidden\nexit 99\n"
        )
        stub.chmod(0o755)
    old_profiles, new_profiles = archive_profiles(old), archive_profiles(newer)
    validate_profile_transition(old_profiles, new_profiles, series)
    call(local_install_argv(old_control, old), stage="historical_install")
    assert digest(DOC / "manifest.json") == base_manifest
    assert json.loads((DOC / "build.json").read_text())["source_commit"] == base_commit
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
    for name, content in old_profiles.items():
        assert Path("/etc/apparmor.d/" + name).read_bytes() == content
    # Test real dpkg old->new conffile conflict, not only reinstall after upgrade.
    edited_name = "ap-worker-publisher" + ("-signer" if case == "unknown" else "")
    edited_path = Path("/etc/apparmor.d/" + edited_name)
    edited_bytes = old_profiles[edited_name] + b"\n# synthetic pre-upgrade admin edit\n"
    if series == "pkg11":
        edited_path.write_bytes(edited_bytes)
    conffile = Path("/etc/agent-platform-worker/package.conf")
    if series == "pkg11":
        edited_conf = conffile.read_bytes() + b"# synthetic administrator setting\n"
        conffile.write_bytes(edited_conf)
    # Controlled interruption boundaries, not a simulated successful transaction:
    # first only Control N+1 is unpacked while Worker is still N.
    call(["dpkg", "--force-confdef", "--force-confold", "--unpack", str(new_control)])
    assert (
        call(["dpkg-query", "-W", "-f=${Version}", "agent-platform-worker"])
        == old_version
    )
    assert snapshot() == before
    call(["dpkg", "--force-confdef", "--force-confold", "--unpack", str(newer)])
    assert "unpacked" in call(
        ["dpkg-query", "-W", "-f=${Status}", "agent-platform-worker"]
    )
    assert snapshot() == before  # Interrupted configure preserves all protected state.
    if series == "pkg11":
        assert edited_path.read_bytes() == edited_bytes
    # Unconfigured package is never INSTALLED/ready; doctor does not repair it.
    assert (
        json.loads(call(["agent-platform-worker", "doctor"], 13))["installation"]
        == "BLOCKED"
    )
    call(["dpkg", "--configure", "agent-platform-control"])
    assert "unpacked" in call(
        ["dpkg-query", "-W", "-f=${Status}", "agent-platform-worker"]
    )
    assert snapshot() == before
    call(
        [
            "dpkg",
            "--force-confdef",
            "--force-confold",
            "--configure",
            "agent-platform-worker",
        ]
    )
    if series == "pkg11":
        assert edited_path.read_bytes() == edited_bytes
        assert conffile.read_bytes() == edited_conf
        assert (
            json.loads(call(["agent-platform-worker", "doctor"], 13))["installation"]
            == "BLOCKED"
        )
        # Reset only our synthetic edit to the exact new default so subsequent
        # probes can independently assess configured state and manifest integrity.
        # Only this fixture's known synthetic edit is reset, never host edits.
        edited_path.write_bytes(new_profiles[edited_name])
        raw = subprocess.check_output(
            ["dpkg-deb", "--fsys-tarfile", str(newer)], timeout=30
        )
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            conffile.write_bytes(
                archive.extractfile("./etc/agent-platform-worker/package.conf").read()
            )
    post = installed_smoke()
    assert post["checks"]["state"]["state"] == "CONFIGURED"
    assert digest(DOC / "manifest.json") == expected["manifest_sha256"]
    installed = json.loads((DOC / "build.json").read_text())
    for key in ("source_commit", "source_tree", "debian_version", "build_kind"):
        assert installed[key] == expected[key]
    assert (
        digest(Path("/usr/share/doc/agent-platform-control/manifest.json"))
        == control_expected["manifest_sha256"]
    )
    assert (
        call(["dpkg", "--verify", "agent-platform-control", "agent-platform-worker"])
        == ""
    )
    assert snapshot() == before
    if series == "pkg11":
        denied = json.loads(
            call(
                [
                    "/usr/bin/setpriv",
                    "--reuid=2000",
                    "--regid=2000",
                    "--clear-groups",
                    "/usr/libexec/ap-worker-publisher-operator",
                    "readiness",
                ],
                1,
            )
        )
        assert denied["check"] == "root_required"
        assert denied["external_rollback_protection"] == "NOT_PROVIDED"
        assert snapshot() == before
    call(["agent-platform-worker", "provision", "--approve"])
    assert snapshot() == before
    for name, content in new_profiles.items():
        assert Path("/etc/apparmor.d/" + name).read_bytes() == content
    # Ordinary APT must refuse a downgrade; never force one to test recovery.
    result = subprocess.run(
        local_install_argv(old),
        capture_output=True,
        text=True,
        timeout=90,
        env=FIXTURE_ENV,
    )
    refusal = command_diagnostic(["apt-get"], result, None, "downgrade")
    if (
        result.returncode == 0
        or "apt_downgrade_not_authorized" not in refusal["reasons"]
    ):
        print(json.dumps(refusal, sort_keys=True), flush=True)
        raise AssertionError("expected_explicit_APT_downgrade_refusal")
    assert (
        call(["dpkg-query", "-W", "-f=${Version}", "agent-platform-worker"])
        == new_version
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
    Path("/evidence/" + series + "-upgrade-" + case + ".json").write_text(
        json.dumps(
            {
                "status": "PASS",
                "case": case,
                "series": series,
                "old_version": old_version,
                "new_version": new_version,
                "baseline_kind": "historical_reconstruction_not_installed_artifact",
                "installed_host_verified": False,
                "interruption": "mixed_roles_then_unpacked_then_explicit_configure",
                "conffile_retained_then_fixture_reset": series == "pkg11",
                "profile_transition": "exact_pkg14_and_pub03_delta"
                if series == "pkg11"
                else "historical_identical",
                "profile_admin_edit_retained": series == "pkg11",
                "profile_kernel_enforcement": "NOT_RUN",
                "baseline_source": base_commit,
                "baseline_manifest": base_manifest,
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
