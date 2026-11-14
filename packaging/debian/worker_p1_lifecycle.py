"""Real multi-UID P1 lifecycle, only in the explicit disposable Debian CI image."""

import hashlib
import importlib.util
import json
import os
import pwd
import subprocess
from pathlib import Path


def call(argv, code=0):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=90)
    if result.returncode != code:
        # Fixed synthetic testbed commands; no credentials used.
        print(result.stdout[-4000:], result.stderr[-4000:])
        raise AssertionError((argv[0], result.returncode, code))
    return result.stdout


def fingerprint(path):
    s = path.stat()
    return (
        s.st_uid,
        s.st_gid,
        s.st_mode,
        hashlib.sha256(path.read_bytes()).hexdigest(),
    )


def main():
    assert Path("/.dockerenv").exists() and os.getuid() == 0
    assert Path("/ap-package-ci-fixture").read_text() == "AP-PKG-CI-DISPOSABLE-v1\n"
    assert "VERSION_CODENAME=trixie\n" in Path("/etc/os-release").read_text()
    assert not Path("/var/run/docker.sock").exists()
    assert not Path("/usr/bin/codex").exists()
    marker = Path("/tmp/forbidden-p1-call")
    # Dependencies were configured at image construction with policy-rc.d=101.
    for name in [
        "codex",
        "systemctl",
        "service",
        "invoke-rc.d",
        "systemd-sysusers",
        "systemd-tmpfiles",
    ]:
        path = Path("/usr/local/bin") / name
        assert not path.exists()
        path.write_text(
            "#!/bin/sh\nprintf forbidden >> /tmp/forbidden-p1-call\nexit 99\n"
        )
        path.chmod(0o755)
    worker = "/packages/p1/agent-platform-worker_0.1.0-5_amd64.deb"
    newer = "/packages/p1-next/agent-platform-worker_0.1.0-6_amd64.deb"
    case = Path("/ap-worker-p1-case").read_text().strip()
    assert case in ("clean", "existing")
    if case == "existing":
        original = pwd.getpwnam("ap-publisher")
        assert (original.pw_uid, original.pw_gid) == (999, 989)
        retained = Path("/var/lib/ap-publisher")
        retained.mkdir(mode=0o700)
        os.chown(retained, 999, 989)
        journal = retained / "journal"
        journal.write_text("UNKNOWN existing synthetic publication\n")
        journal.chmod(0o600)
        os.chown(journal, 999, 989)
        before = fingerprint(journal)
    else:
        try:
            pwd.getpwnam("ap-publisher")
        except KeyError:
            pass
        else:
            raise AssertionError("unexpected existing identity")
        original = None
        before = None
        journal = Path("/var/lib/ap-publisher/journal")
    alias = Path("/etc/systemd/system/synthetic-p1-alias.service")
    assert not alias.exists() and not alias.is_symlink()
    alias.symlink_to("/usr/lib/systemd/system/ap-worker-publisher.service")
    assert (
        subprocess.run(["dpkg", "--unpack", worker], capture_output=True).returncode
        != 0
    )
    assert alias.is_symlink()
    alias.unlink()  # Only the exact synthetic fixture created above.
    # New P1 leaf collisions must fail before adoption; retry only after removing
    # this exact test-created foreign fixture, never an unknown host resource.
    foreign = Path("/usr/libexec/ap-worker-publisher")
    foreign.parent.mkdir(exist_ok=True)
    foreign.write_text("foreign sentinel")
    foreign.chmod(0o755)
    assert (
        subprocess.run(["dpkg", "--unpack", worker], capture_output=True).returncode
        != 0
    )
    assert foreign.read_text() == "foreign sentinel" and (
        before is None or fingerprint(journal) == before
    )
    foreign.unlink()
    call(["apt-get", "--no-install-recommends", "-y", "install", worker])
    if original is not None:
        assert pwd.getpwnam("ap-publisher") == original
    else:
        try:
            pwd.getpwnam("ap-publisher")
        except KeyError:
            pass
        else:
            raise AssertionError("install created an account")
    assert not Path("/var/lib/ap-publisher-signer").exists()
    assert not marker.exists()
    spec = importlib.util.spec_from_file_location(
        "installed_provision",
        "/usr/lib/agent-platform-worker/provisioning/provision.py",
    )
    provision = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(provision)

    def interrupt(phase):
        if phase == "receipt":
            raise OSError("fabricated post-receipt interruption")

    provision.checkpoint = interrupt
    try:
        provision.provision(provision.System(), initialize=True)
    except OSError:
        pass
    else:
        raise AssertionError("interruption missing")
    call(["agent-platform-worker", "provision", "--approve"], 13)
    call(["agent-platform-worker", "provision", "--approve", "--recover"])
    signer = pwd.getpwnam("ap-publisher-signer")
    publisher = pwd.getpwnam("ap-publisher")
    assert signer.pw_uid != publisher.pw_uid and signer.pw_gid != publisher.pw_gid
    # Actual kernel DAC negative probes; no credentials or real home data.
    denied = """import os,sys
for path in sys.argv[1:]:
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK)
    except PermissionError:
        continue
    else:
        os.close(fd)
        raise SystemExit(97)
"""
    for user, paths in [
        (publisher, ["/var/lib/ap-publisher-signer/journal"]),
        (signer, ["/var/lib/ap-publisher/journal"]),
        (
            pwd.getpwnam("agentdev"),
            [
                "/var/lib/ap-publisher/journal",
                "/var/lib/ap-publisher-signer/journal",
                "/etc/ap-publisher",
            ],
        ),
    ]:
        call(
            [
                "/usr/bin/setpriv",
                "--reuid",
                str(user.pw_uid),
                "--regid",
                str(user.pw_gid),
                "--clear-groups",
                "/usr/bin/python3",
                "-IB",
                "-c",
                denied,
                *paths,
            ]
        )
    if before is None:
        journal.write_text("UNKNOWN synthetic retained publication\n")
        before = fingerprint(journal)
        original = publisher
    assert fingerprint(journal) == before
    receipt = Path("/var/lib/agent-platform-worker-provisioning/receipt.json")
    previous = receipt.read_bytes()
    call(["agent-platform-worker", "provision", "--approve"])
    assert receipt.read_bytes() == previous and (
        before is None or fingerprint(journal) == before
    )
    for command in ["run", "resume", "doctor"]:
        result = json.loads(
            call(["agent-platform-worker", command, "--issue", "1"], 13)
        )
        assert result["launch_allowed"] is False
    # Changed ACL/profile is detected without repair or credential access.
    profile = Path("/etc/apparmor.d/ap-worker-publisher")
    old = profile.read_bytes()
    profile.write_bytes(old + b"\n# administrator edit\n")
    assert (
        json.loads(call(["agent-platform-worker", "provision", "--approve"], 13))[
            "status"
        ]
        == "BLOCKED"
    )
    assert profile.read_bytes() == old + b"\n# administrator edit\n"
    call(["dpkg", "--force-confdef", "--force-confold", "--unpack", newer])
    assert "unpacked" in call(
        ["dpkg-query", "-W", "-f=${Status}", "agent-platform-worker"]
    )
    call(
        [
            "dpkg",
            "--force-confdef",
            "--force-confold",
            "--configure",
            "agent-platform-worker",
        ]
    )
    assert fingerprint(journal) == before and not marker.exists()
    call(["apt-get", "-y", "remove", "agent-platform-worker"])
    assert fingerprint(journal) == before and receipt.read_bytes() == previous
    call(["apt-get", "-y", "purge", "agent-platform-worker"])
    assert fingerprint(journal) == before and pwd.getpwnam("ap-publisher") == original
    assert pwd.getpwnam("ap-publisher-signer") == signer
    assert not marker.exists() and not Path("/usr/bin/codex").exists()
    Path("/evidence/worker-p1-lifecycle-" + case + ".json").write_text(
        json.dumps(
            {
                "status": "PASS",
                "case": case,
                "publisher_identity": [publisher.pw_uid, publisher.pw_gid],
                "no_activation": True,
                "retained_unknown_history": True,
                "uid_gid_separation": "PASS",
                "kernel_apparmor_bpf_boot": "NOT_RUN",
                "real_credentials_and_runtime": "NOT_RUN",
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
