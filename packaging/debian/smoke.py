"""Real installed-package tests, only inside the explicit disposable CI fixture."""

import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True


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


def signer_smoke():
    # Only generated throwaway keys inside guard()'s approved disposable fixture.
    sys.path.insert(0, "/usr/lib/agent-platform-control")
    import socket
    import threading
    import time

    from cryptography.hazmat.primitives.asymmetric import rsa

    from agent_platform import app_signer as signer
    from agent_platform import app_signer_ipc as ipc
    from agent_platform.app_api_adapter import Claims

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    peer = signer.Peer(os.getpid(), os.getuid(), os.getgid())
    policy = signer.Policy(
        12345, "a" * 64, signer.public_fingerprint(key.public_key()), peer, peer
    )
    now = int(time.time())
    admission = signer.Admission(
        "b" * 64,
        "c" * 64,
        policy.digest,
        now,
        now + 300,
        (signer.Pass("d" * 64, "e" * 64), signer.Pass("f" * 64, "1" * 64)),
    )

    class Credentials:
        def private_key(self, app_id, key_sha256):
            return key

    class OfflineAuthority:
        used = False

        def lookup(self, run_id):
            assert run_id == admission.run_id
            return admission

        def consume(self, approved, request, actual_peer):
            assert approved == admission and actual_peer == peer and not self.used
            self.used = True

        def finish(self, approved, request, outcome):
            assert outcome == "SIGNED" and self.used

    authority = OfflineAuthority()
    session = signer.SignerSession(
        policy=policy,
        approved_run_id=admission.run_id,
        authority=authority,
        credentials=Credentials(),
    )
    client = ipc.SignerClient(policy=policy, public_key=key.public_key())
    server_socket, client_socket = socket.socketpair()
    outcome = []

    def run():
        try:
            ipc.serve_one(server_socket, session, timeout=2)
            outcome.append("OK")
        except signer.SignerError:
            outcome.append("BLOCKED")

    worker = threading.Thread(target=run)
    worker.start()
    try:
        request = signer.Request(
            admission.run_id,
            admission.nonce,
            "d" * 64,
            "e" * 64,
            policy.digest,
            Claims(12345, now - 30, now + 250),
        )
        token = client.exchange(client_socket, request, timeout=2)
        assert "eyJ" not in repr(
            token
        )  # Client has independently verified the RSA signature.
        assert token.take_for_custody()
    finally:
        client_socket.close()
        worker.join(3)
        session.close()
    assert not worker.is_alive() and outcome == ["OK"]


ROLES = ("control", "worker")
COMMANDS = {
    "control": ("agent-platform-control",),
    "worker": ("agent-platform-worker", "agent-platform-worker-native-artifact"),
}


def smoke(roles=ROLES):
    if "control" in roles:
        signer_smoke()
        result = json.loads(call(["agent-platform-control", "subscription"], 13))
        assert "SUBSCRIPTION_ISOLATION_BLOCKED" in json.dumps(result)
    for role in roles:
        # Import the whole installed closure in a fresh isolated interpreter.
        # No checkout/PYTHONPATH, global wheel or other role may satisfy imports.
        script = """import hashlib,importlib,json,stat,sys
from pathlib import Path
root=Path('/usr/lib/agent-platform-')
role=sys.argv[1]
private=Path(str(root)+role)
sys.dont_write_bytecode=True
sys.path.insert(0,str(private))
report=json.loads(Path('/usr/share/doc/agent-platform-'+role+'/build.json').read_text())
for name in report['modules']:
    module=importlib.import_module('agent_platform.'+name)
    assert Path(module.__file__).is_relative_to(private)
manifest=json.loads(Path('/usr/share/doc/agent-platform-'+role+'/manifest.json').read_text())
for item in manifest['files']:
    file=Path(item['path'])
    assert file.is_file() and not file.is_symlink()
    if str(file).startswith('/etc/'):
        continue  # Administrator conffile content/modes may differ.
    assert file.stat().st_uid == file.stat().st_gid == 0
    assert stat.S_IMODE(file.stat().st_mode) == item['mode']
    if item['sha256'] is not None:
        assert hashlib.sha256(file.read_bytes()).hexdigest() == item['sha256']
assert not list(private.rglob('*.pyc'))
"""
        call(["/usr/bin/python3", "-I", "-c", script, role])
        for name in COMMANDS[role]:
            call([name, "--help"])
            assert "0.1.0 (Debian 0.1.0-" in call([name, "--version"])
        for command in ("run", "resume", "doctor"):
            result = json.loads(
                call(["agent-platform-" + role, command, "--issue", "1"], 13)
            )
            assert result["reason"] == "legacy_execution_quarantined"
            assert result["launch_allowed"] is result["resume_authorized"] is False
        files = call(["dpkg-query", "-L", "agent-platform-" + role]).splitlines()
        assert not any("/systemd/" in name or "/init.d/" in name for name in files)
        assert not Path("/var/lib/agent-platform-" + role).exists()
    assert not Path("/usr/bin/codex").exists()
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
    retained = {}
    for path in (
        "/opt/checkpoint.json",
        "/opt/unknown-journal.json",
        "/opt/backup.json",
        "/var/lib/agent-platform/custody/unknown.json",
        "/opt/operator-home/.local/bin/codex",
    ):
        file = Path(path)
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text('{"synthetic":true,"state":"UNKNOWN"}\n')
        file.chmod(0o640)
        retained[path] = digest(file)
    passwd = Path("/etc/passwd").read_bytes()
    group = Path("/etc/group").read_bytes()

    def retained_ok():
        assert all(digest(Path(p)) == expected for p, expected in retained.items())
        assert Path("/etc/passwd").read_bytes() == passwd
        assert Path("/etc/group").read_bytes() == group
        assert not Path("/tmp/ap-forbidden-call").exists()

    def package(role, revision):
        folder = "n" if revision == 3 else "next"
        return f"/packages/{folder}/agent-platform-{role}_0.1.0-{revision}_amd64.deb"

    def install(*paths):
        call(
            [
                "apt-get",
                "--no-install-recommends",
                "-o",
                "Dpkg::Options::=--force-confold",
                "-y",
                "install",
                *paths,
            ]
        )

    def status(name):
        return call(["dpkg-query", "-W", "-f=${Status}", name])

    # Each role works alone without Codex. Worker precedes crypto/Git/gh.
    for role in ("worker", "control"):
        install(package(role, 3))
        smoke((role,))
        assert not any(
            Path("/usr/bin/" + command).exists()
            for other in ROLES
            if other != role
            for command in COMMANDS[other]
        )
        call(["apt-get", "-y", "purge", "agent-platform-" + role])
        retained_ok()
    phases.append("independent_install_without_codex")
    install(*(package(role, 3) for role in ROLES))
    smoke()
    configs = {}
    migrated = {}
    for role in ROLES:
        pkg = "agent-platform-" + role
        cfg = Path("/etc/" + pkg + "/package.conf")
        cfg.write_text(cfg.read_text() + "# administrator edit retained\n")
        cfg.chmod(0o640)
        configs[role] = digest(cfg)
        note = cfg.parent / "operator-notes"
        note.write_text("foreign note\n")
        retained[str(note)] = digest(note)
        state = Path("/opt/example-" + role)
        fixture(state)
        before = (state / "example.json").read_bytes()
        bad = Path("/tmp/corrupt.deb")
        bad.write_bytes(b"not a Debian archive\n")
        assert (
            subprocess.run(
                ["dpkg", "--unpack", str(bad)], capture_output=True
            ).returncode
            != 0
        )
        assert call(["dpkg-query", "-W", "-f=${Version}", pkg]) == "0.1.0-3"
        assert digest(cfg) == configs[role]
        call(
            ["dpkg", "--force-confdef", "--force-confold", "--unpack", package(role, 4)]
        )
        assert status(pkg) == "install ok unpacked"
        assert digest(cfg) == configs[role]
        assert (state / "example.json").read_bytes() == before
        retained_ok()
        call(["dpkg", "--force-confdef", "--force-confold", "--configure", pkg])
        assert status(pkg) == "install ok installed"
        assert call(["dpkg-query", "-W", "-f=${Version}", pkg]) == "0.1.0-4"
        assert digest(cfg) == configs[role]
        helper = ["/usr/lib/" + pkg + "/migrate-example", "--directory", str(state)]
        assert json.loads(call(helper))["outcome"] == "migrated"
        assert (state / "v1.backup").read_bytes() == before
        assert json.loads((state / "example.json").read_bytes())["schema"] == 2
        migrated[role] = {p.name: digest(p) for p in state.iterdir()}
        assert json.loads(call(helper))["outcome"] == "already_migrated"
        assert {p.name: digest(p) for p in state.iterdir()} == migrated[role]
        rejected = Path("/opt/rejected-" + role)
        fixture(rejected)
        (rejected / "example.json").write_text(
            '{"format":"AP-PKG-SYNTHETIC","schema":99}\n'
        )
        prior = {p.name: digest(p) for p in rejected.iterdir()}
        call([helper[0], "--directory", str(rejected)], 13)
        assert {p.name: digest(p) for p in rejected.iterdir()} == prior
        # Retained uncertain temporary state refuses without cleanup or blind replay.
        uncertain = Path("/opt/uncertain-" + role)
        fixture(uncertain)
        (uncertain / "next.tmp").write_text("unknown\n")
        (uncertain / "next.tmp").chmod(0o600)
        prior = {p.name: digest(p) for p in uncertain.iterdir()}
        call([helper[0], "--directory", str(uncertain)], 13)
        assert {p.name: digest(p) for p in uncertain.iterdir()} == prior
        # Explicit downgrade changes code only; no reverse data/schema migration.
        call(["dpkg", "--force-confdef", "--force-confold", "-i", package(role, 3)])
        assert not Path(helper[0]).exists()
        assert {p.name: digest(p) for p in state.iterdir()} == migrated[role]
        call(["dpkg", "--force-confdef", "--force-confold", "-i", package(role, 4)])
        retained_ok()
    phases.append("coinstall_upgrade_interrupted_configure_corrupt_and_migration")
    smoke()
    # Both removal orders: peer remains fully usable and import independent.
    for order in (ROLES, tuple(reversed(ROLES))):
        for index, role in enumerate(order):
            call(["apt-get", "-y", "remove", "agent-platform-" + role])
            assert (
                digest(Path("/etc/agent-platform-" + role + "/package.conf"))
                == configs[role]
            )
            if index == 0:
                smoke((order[1],))
            retained_ok()
        call(
            [
                "apt-get",
                "-o",
                "Dpkg::Options::=--force-confold",
                "-y",
                "install",
                *(package(role, 4) for role in ROLES),
            ]
        )
        smoke()
    phases.append("both_removal_orders_and_reinstall")
    # New roles reject old experimental artifacts while either role is installed.
    for revision in (1, 2):
        old = f"/packages/legacy-{revision}/agent-platform_0.1.0-{revision}_amd64.deb"
        assert (
            subprocess.run(["dpkg", "--unpack", old], capture_output=True).returncode
            != 0
        )
        assert all(
            status("agent-platform-" + role) == "install ok installed" for role in ROLES
        )
    for role in ROLES:
        call(["apt-get", "-y", "purge", "agent-platform-" + role])
        assert not Path("/etc/agent-platform-" + role + "/package.conf").exists()
        retained_ok()
    # Exact old candidate -> explicit remove (not purge) -> split for both revisions.
    for revision in (1, 2):
        old = f"/packages/legacy-{revision}/agent-platform_0.1.0-{revision}_amd64.deb"
        install(old)
        oldcfg = Path("/etc/agent-platform/package.conf")
        oldcfg.write_text(oldcfg.read_text() + "# legacy administrator config\n")
        oldcfg.chmod(0o640)
        retained[str(oldcfg)] = digest(oldcfg)
        for role in ROLES:
            assert (
                subprocess.run(
                    ["dpkg", "--unpack", package(role, 3)], capture_output=True
                ).returncode
                != 0
            )
            assert status("agent-platform") == "install ok installed"
        call(["apt-get", "-y", "remove", "agent-platform"])
        retained_ok()
        install(*(package(role, 3) for role in ROLES))
        smoke()
        assert not Path("/usr/bin/agent-platform").exists()
        assert all(
            "legacy administrator"
            not in Path("/etc/agent-platform-" + role + "/package.conf").read_text()
            for role in ROLES
        )
        for role in ROLES:
            call(["apt-get", "-y", "purge", "agent-platform-" + role])
        retained_ok()
    phases.append(
        "both_legacy_conflict_directions_and_explicit_residual_config_transition"
    )
    install(*(package(role, 4) for role in ROLES))
    smoke()
    for role in ROLES:
        state = Path("/opt/example-" + role)
        assert {p.name: digest(p) for p in state.iterdir()} == migrated[role]
        # Restore only into a new, marked synthetic directory.
        restored = Path("/opt/restored-" + role)
        fixture(restored)
        (restored / "example.json").write_bytes((state / "v1.backup").read_bytes())
        call(
            [
                "/usr/lib/agent-platform-" + role + "/migrate-example",
                "--directory",
                str(restored),
            ]
        )
        assert (restored / "example.json").read_bytes() == (
            state / "example.json"
        ).read_bytes()
    retained_ok()
    phases.append("purge_foreign_state_and_restore_preservation")
    (evidence / "lifecycle.json").write_text(
        json.dumps(
            {
                "status": "PASS",
                "phases": phases,
                "codex_installed": False,
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
