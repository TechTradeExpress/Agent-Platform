"""Stage A process, fixed-path and handoff contracts. No online credentials."""

import os
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

import pytest
from test_worker_publisher import artifact, homelab_job, job_for

from agent_platform import worker_publish_artifact as art
from agent_platform import worker_publish_case as case
from agent_platform import worker_publish_recovery_paths as recovery

ROOT = Path(__file__).resolve().parents[1]
UNITS = ROOT / "packaging/worker-publisher"


@pytest.fixture
def pair():
    data, head, tree, _ = artifact()
    job = homelab_job(job_for(data, head, tree))
    job.update(
        contract="homelab-supervised",
        ref=recovery.REF,
        issue=169,
        journal_sha256=art.digest(b""),
        signer_journal_sha256=art.digest(b""),
    )
    old = dict(
        job, id="f" * 32, head=case.HEAD, ref=case.REF, artifact_sha256=case.ARTIFACT
    )
    return job, old


@pytest.mark.parametrize("key", ["id", "ref", "head", "artifact_sha256", "signer_uid"])
def test_reject_old_identity(pair, key):
    job, old = pair
    assert recovery.check_job(job, old, job["expires"] - 1) == job
    job[key] = old[key] if key != "signer_uid" else old[key] + 10
    with pytest.raises(art.Blocked):
        recovery.check_job(job, old, job["expires"] - 1)


@pytest.fixture(params=[False, True], ids=["process", "kernel_namespaces"])
def child(request):
    isolated = request.param
    prefix = []
    source = ROOT / "src"
    if isolated:
        bwrap = shutil.which("bwrap")
        if bwrap is None:
            pytest.skip("bubblewrap unavailable")
        prefix = [
            bwrap,
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--tmpfs",
            "/usr/lib/ap-worker-publisher",
        ]
        check = subprocess.run(
            [*prefix, "--", "/usr/bin/true"], capture_output=True, timeout=10
        )
        if check.returncode:
            pytest.skip("mandatory bubblewrap namespaces unavailable")
        source = Path("/source")
        prefix += [
            "--ro-bind",
            str(ROOT / "src"),
            str(source),
            "--ro-bind",
            str(UNITS),
            "/wrappers",
        ]
        for path in sorted({sys.prefix, sys.base_prefix} - {"/usr"}):
            prefix += ["--ro-bind", path, path]

    def run(code, directory, *args):
        bootstrap = f"import sys; sys.path.insert(0, {str(source)!r}); "
        executable = sys.executable
        if isolated:
            executable = str(Path(executable).resolve())
            uid = 1101 if directory.name == "signer" else 1102
            bootstrap += (
                f"sys.path.append({sysconfig.get_path('purelib')!r}); "
                "import os; "
                f"assert os.getuid() == os.getgid() == {uid}; "
                f"assert not os.path.lexists({str(directory.parent)!r}); "
            )
        runner = [executable, "-I", "-B", "-c", bootstrap + code]
        if isolated:
            runner = [
                *prefix,
                "--uid",
                str(uid),
                "--gid",
                str(uid),
                "--bind",
                str(directory),
                "/fixture",
                "--chdir",
                "/fixture",
                "--",
                *runner,
            ]
            args = tuple("/wrappers/" + path.name for path in args)
        return subprocess.run(
            [*runner, *map(str, args)],
            cwd=directory,
            env={"PATH": "/usr/bin:/bin"},
            capture_output=True,
            timeout=10,
        )

    return run


def test_separate_processes_transfer_and_services_block(tmp_path, pair, child):
    signer, publisher = (tmp_path / role for role in ("signer", "publisher"))
    for path in (signer, publisher):
        path.mkdir(mode=0o700)
    job, _ = pair
    for path in (signer, publisher):
        (path / "job.json").write_bytes(art.encoded(job))
    # These subprocesses exercise data I/O only. The packaged entrypoints
    # below are called separately and can never reach this I/O in stage A.
    signed = child(
        "from pathlib import Path; "
        "from agent_platform import worker_publish_recovery_paths as r; "
        "r.SIGNER_OUTPUT = Path.cwd() / 'app-jwt'; "
        "r.SIGNER_RESULT = Path.cwd() / 'result.json'; "
        "r.write_signer_handoff(Path('job.json').read_bytes(), 'fabricated.jwt');",
        signer,
    )
    assert signed.returncode == 0, signed.stderr
    for source, target in (("app-jwt", "app-jwt"), ("result.json", "signer-result")):
        copy = publisher / target
        copy.write_bytes((signer / source).read_bytes())
        copy.chmod(0o400)
    received = child(
        "from pathlib import Path; "
        "from agent_platform import worker_publish_recovery_paths as r; "
        "assert r.verify_handoff(Path('job.json').read_bytes(), "
        "Path('app-jwt').read_bytes(), Path('signer-result').read_bytes()) "
        "== 'fabricated.jwt';",
        publisher,
    )
    assert received.returncode == 0, received.stderr
    for directory, suffix in ((signer, "-signer"), (publisher, "")):
        wrapper = UNITS / ("ap-worker-publisher-recovery" + suffix)
        result = child(
            "import runpy; import agent_platform; runpy.run_path(sys.argv[1]);",
            directory,
            wrapper,
        )
        assert result.returncode == 1
        assert art.decode(result.stdout.strip()) == {
            "status": "BLOCKED",
            "code": "recovery_authorization_unavailable",
        }
        assert b"fabricated" not in result.stdout + result.stderr


@pytest.mark.parametrize(
    "fault", ["mode", "owner", "parent_symlink", "leaf_symlink", 1, 2, 3, 4]
)
def test_handoff_fails_closed(tmp_path, pair, monkeypatch, fault):
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    target = runtime
    if fault == "parent_symlink":
        target = tmp_path / "link"
        target.symlink_to(runtime, target_is_directory=True)
    monkeypatch.setattr(recovery, "SIGNER_OUTPUT", target / "app-jwt")
    monkeypatch.setattr(recovery, "SIGNER_RESULT", target / "result.json")
    if fault == "mode":
        runtime.chmod(0o750)
    if fault == "owner":
        uid = os.getuid()
        monkeypatch.setattr(recovery.os, "getuid", lambda: uid + 1)
    if fault == "leaf_symlink":
        (runtime / "result.json").symlink_to(tmp_path / "missing")
    fsync = os.fsync
    calls = 0

    def failing_sync(fd):
        nonlocal calls
        calls += 1
        if calls == fault:
            raise OSError("synthetic fsync failure")
        fsync(fd)

    monkeypatch.setattr(recovery.os, "fsync", failing_sync)
    job, _ = pair
    args = art.encoded(job), "fabricated.jwt"
    with pytest.raises((art.Blocked, OSError)):
        recovery.write_signer_handoff(*args)
    retained = sorted(runtime.iterdir())
    with pytest.raises((art.Blocked, OSError)):
        recovery.write_signer_handoff(*args)
    assert sorted(runtime.iterdir()) == retained


def test_handoff_rejects_mismatched_job_or_result(pair):
    job, _ = pair
    original = art.encoded(job)
    jwt, result = recovery.signer_payload(original, "fabricated.jwt")
    with pytest.raises(art.Blocked):
        recovery.verify_handoff(art.encoded(dict(job, id="e" * 32)), jwt, result)
    with pytest.raises(art.Blocked):
        recovery.verify_handoff(
            original, jwt, art.encoded(dict(art.decode(result), generation="stale"))
        )


@pytest.mark.parametrize("role", ["publisher", "signer"])
def test_stage_a_units_have_no_credential_or_network_grant(role):
    suffix = "-signer" if role == "signer" else ""
    name = "ap-worker-publisher-recovery" + suffix
    unit = (UNITS / (name + ".service")).read_text()
    profile = (UNITS / (name + ".apparmor")).read_text()
    account = "ap-publisher" + suffix
    assert "[Install]" not in unit and "LoadCredential=" not in unit
    assert "IPAddressAllow=" not in unit
    for line in (
        "Type=oneshot",
        "Restart=no",
        "PrivateNetwork=yes",
        "IPAddressDeny=any",
        "SocketBindDeny=any",
        "RestrictAddressFamilies=AF_UNIX",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "RuntimeDirectoryMode=0700",
        f"AppArmorProfile={name}",
        f"User={account}",
        f"Group={account}",
        f"RuntimeDirectory=ap-publisher-recovery-169-{role}",
    ):
        assert line in unit.splitlines()
    assert "deny network," in profile
    assert "deny /run/credentials/{,**} rwklmx," in profile
    assert "/etc/ap-publisher-recovery-169/job.json r," not in profile
