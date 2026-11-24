"""Stage A process, fixed-path and handoff contracts. No online credentials."""

import base64
import os
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

import pytest
from test_worker_publisher import Wire, artifact, homelab_job, job_for

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
def test_recovery_units_pin_credentials_and_deny_network(role):
    suffix = "-signer" if role == "signer" else ""
    name = "ap-worker-publisher-recovery" + suffix
    unit = (UNITS / (name + ".service")).read_text()
    profile = (UNITS / (name + ".apparmor")).read_text()
    account = "ap-publisher" + suffix
    assert "[Install]" not in unit
    assert (
        f"LoadCredential=handoff:/run/ap-publisher-recovery-169-grants/{role}.json"
        in unit
    )
    assert ("LoadCredential=app-key:" in unit) == (role == "signer")
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
    assert "deny /run/ap-publisher-recovery-169-grants/{,**} rwklmx," in profile
    assert "/etc/ap-publisher-recovery-169/job.json r," not in profile


@pytest.mark.parametrize(
    ("role", "fault"),
    [
        ("live", None),
        ("live", "unsigned"),
        ("live", "offline_domain"),
        ("live", "same_actor"),
        ("live", "peer"),
        ("live", "policy_expired"),
        ("live", "old_generation"),
        ("live", "ref"),
        ("live", "app"),
        ("live", "install"),
        ("live", "wrong_policy_namespace"),
        ("live", "controller_lost"),
        ("live", "expired_at_write"),
        ("live", "wrong_author"),
        ("live", "wrong_head"),
        ("signer", None),
        ("publisher", None),
        ("signer", "role"),
        ("signer", "signature"),
        ("signer", "pin"),
        ("signer", "audience"),
        ("publisher", "launch"),
        ("publisher", "artifact"),
        ("publisher", "unknown"),
        ("publisher", "jwt"),
        ("publisher", "observation"),
        ("publisher", "expiry"),
        ("publisher", "receipt"),
    ],
)
def test_recovery_grant_binds_exact_terminal_handoff(
    pair, role, fault, tmp_path, monkeypatch, capsys
):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from agent_platform import worker_publish_observer as observer
    from agent_platform import worker_publish_pre_spend as pre_spend

    live = role == "live"
    role = "publisher" if live else role
    job, _ = pair
    job_bytes = art.encoded(job)
    launch = "2" * 64
    artifact_bytes = artifact()[0]
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    pin = art.digest(public)
    now = job["expires"] - 10
    observation = b"synthetic observation"
    decision = art.encoded(
        {
            "schema": "AP-worker01-create-draft/1",
            "report_sha256": art.digest(observation),
            "expires": job["expires"],
            "binding": {
                "job": art.digest(job_bytes),
                "artifact": job["artifact_sha256"],
                "main": job["parent"],
            },
        }
    )
    request = pre_spend.challenge(art.digest(decision), launch, job["expires"])
    receipt = art.encoded(
        {
            "record": request,
            "signature": observer.sign(key, "pre-spend", request).hex(),
        }
    )
    jwt, result = recovery.signer_payload(
        job_bytes, "JWT_FAKE" if live else "synthetic.jwt"
    )
    identity = {"job": job["id"], "ref": job["ref"], "head": job["head"], "issue": 169}
    operation = {"job": job["id"], "operation": "sign", "launch_id": launch}
    previous = art.digest(b"")
    lines = []
    for record in (
        {"phase": "CLAIM", **identity},
        {"phase": "UNKNOWN", **operation},
        {
            "phase": "UNKNOWN" if fault == "unknown" else "COMPLETE",
            **identity,
            **operation,
            "jwt_sha256": art.digest(jwt),
            "result_sha256": art.digest(result),
        },
    ):
        line = art.encoded({"previous": previous, "record": record})
        lines.append(line + b"\n")
        previous = art.digest(line)
    journal = b"".join(lines)
    audience = "ap-worker-publisher-recovery"
    audience += "-signer" if role == "signer" else ""
    value = {
        "schema": "AP-worker01-recovery-grant/1",
        "case": case.CASE,
        "generation": recovery.GENERATION,
        "role": role,
        "audience": audience + ".service",
        "launch_id": launch,
        "job_sha256": art.digest(job_bytes),
        "artifact_sha256": job["artifact_sha256"],
        "approval_sha256": art.digest(decision),
        "pre_spend_sha256": art.digest(receipt),
        "observation_sha256": art.digest(observation),
        "main": job["parent"],
        "expires": now if fault == "expiry" else job["expires"],
    }
    if role == "publisher":
        value.update(
            signer_result_sha256=art.digest(result),
            signer_journal_sha256=art.digest(journal),
        )
    if fault == "role":
        value["role"] = "publisher"
    if fault == "audience":
        value["audience"] = "other.service"
    purpose = "recovery-" + role
    policy = None
    if live:
        observer_key = key if fault == "same_actor" else Ed25519PrivateKey.generate()
        observer_public = observer_key.public_key().public_bytes_raw()
        policy_value = {
            "schema": "AP-worker01-recovery-egress/1",
            "unit": recovery.LIVE_UNIT,
            "generation": recovery.GENERATION,
            "job_sha256": art.digest(job_bytes),
            "observation_sha256": art.digest(observation),
            "github_ipv4": "140.82.112.7" if fault == "peer" else job["github_ipv4"],
            "port": 443,
            "transport": "tcp/ipv4",
            "signer_network": "denied",
            "boot_id": "12345678-0000-0000-0000-000000000000",
            "netns_device": 100,
            "netns_inode": 183,
            "pid1_sha256": "4" * 64,
            "kernel_evidence_sha256": "5" * 64,
            "at": now,
            "expires": now if fault == "policy_expired" else job["expires"],
        }
        policy_raw = art.encoded(policy_value)
        policy_signature = observer.sign(
            observer_key, recovery.POLICY_PURPOSE, policy_value
        )
        policy = (
            observer_public,
            art.digest(observer_public),
            policy_raw,
            policy_signature,
        )
        value.update(
            audience=recovery.LIVE_UNIT, live=recovery.live_binding(job, policy_raw)
        )
        if fault == "old_generation":
            value["generation"] = "worker01/169/v4"
        for name in ("ref", "app", "install"):
            if fault == name:
                value["live"]["installation" if name == "install" else name] = "other"
        if fault != "offline_domain":
            purpose = recovery.LIVE_PURPOSE
    signature = observer.sign(key, purpose, value)
    if fault == "unsigned":
        signature = b"0" * 64
    kwargs = dict(
        public_key=public,
        key_pin="a" * 64 if fault == "pin" else pin,
        job_bytes=job_bytes,
        artifact=b"wrong" if fault == "artifact" else artifact_bytes,
        approval=decision,
        pre_spend_receipt=(receipt + b" " if fault == "receipt" else receipt),
        observation=b"wrong" if fault == "observation" else observation,
        launch_id="4" * 64 if fault == "launch" else launch,
        now=now,
        handoff=(
            jwt if fault != "jwt" else jwt.replace(b"synthetic", b"other"),
            result,
            journal,
        )
        if role == "publisher"
        else None,
        policy=policy,
    )
    runtime_faults = {
        "wrong_policy_namespace",
        "controller_lost",
        "expired_at_write",
        "wrong_author",
        "wrong_head",
    }
    if fault and fault not in runtime_faults:
        with pytest.raises(art.Blocked):
            recovery.verify_grant(
                role,
                art.encoded(value),
                b"0" * 64 if fault == "signature" else signature,
                **kwargs,
            )
    else:
        assert (
            recovery.verify_grant(role, art.encoded(value), signature, **kwargs) == job
        )
        if not live:
            return

        from agent_platform import worker_publish_io as io

        identity = [1, 183]
        value["artifact_identity"] = identity
        signature = observer.sign(key, purpose, value)
        evidence = {
            "grant": art.encoded(value),
            "signature": signature,
            "public_key": public,
            "job": job_bytes,
            "spent": decision,
            "pre_spend_receipt": receipt,
            "observation": observation,
            "jwt": jwt,
            "result": result,
            "signer_journal": journal,
            "observer_key": observer_public,
            "policy": policy_raw,
            "policy_signature": policy_signature,
        }
        leaves = {
            "handoff": art.encoded(
                dict(
                    {
                        name: base64.b64encode(raw).decode()
                        for name, raw in evidence.items()
                    },
                    launch_id=launch,
                )
            ),
            "approval-pin": pin.encode(),
            "observer-pin": policy[1].encode(),
            "boot-id": policy_value["boot_id"].encode() + b"\n",
        }
        destination = tmp_path / "journal"
        destination.touch(mode=0o600)
        monkeypatch.setattr(recovery, "PUBLISHER_JOURNAL", destination)

        def staged_artifact(actual, pin):
            assert (actual, pin) == (job, identity)
            return artifact_bytes

        monkeypatch.setattr(recovery, "read_role_artifact", staged_artifact)
        monkeypatch.setattr(io, "read_file", lambda *a, **kw: b"")
        monkeypatch.setattr(
            recovery,
            "read_role_credential",
            lambda role, leaf, limit, *, live: leaves[leaf],
        )
        monkeypatch.setattr(recovery.pub, "confinement", lambda *a, **kw: None)
        monkeypatch.setattr(recovery.time, "time", lambda: now)

        def namespace(evidence, path, current_boot):
            assert path == "/proc/self/ns/net" and current_boot == evidence["boot_id"]
            art.need(fault != "wrong_policy_namespace")

        def liveness(actual_launch):
            assert actual_launch == launch
            art.need(fault != "controller_lost")

        monkeypatch.setattr(recovery, "check_live_namespace", namespace)
        monkeypatch.setattr(recovery, "require_live_controller", liveness)
        observed = []

        class TestWire(Wire):
            def exchange(self, method, path, body, secret, limit=256 * 1024):
                response = super().exchange(method, path, body, secret, limit)
                if fault == "expired_at_write" and path.endswith("/access_tokens"):
                    # Mint has an UNKNOWN and a known token. Expiry at the next
                    # effect must suppress writes other than cleanup.
                    monkeypatch.setattr(recovery.time, "time", lambda: job["expires"])
                return response

        def transport(actual_job, *, before_request=None):
            if before_request is None:
                return
            assert actual_job == job
            # Keep the production flow and real publisher journal, but no socket.
            wire = TestWire(current_journal[0], job)
            if fault == "wrong_author":
                wire.mutate = lambda path, payload: (
                    dict(payload, user={"id": -1}) if "/pulls/" in path else payload
                )
            if fault == "wrong_head":
                wire.mutate = lambda path, payload: (
                    dict(payload, head={"sha": "0" * 40})
                    if "/pulls/" in path
                    else payload
                )
            observed.append(wire)
            return wire

        opened = recovery.Journal
        current_journal = []

        def open_journal(*args, **kwargs):
            opened_journal = opened(*args, **kwargs)
            current_journal.append(opened_journal)
            return opened_journal

        monkeypatch.setattr(recovery, "Journal", open_journal)
        monkeypatch.setattr(recovery.pub, "transport", transport)
        code = recovery.run_publisher_handoff(live=True)
        output = art.decode(capsys.readouterr().out.encode())
        if fault in {"wrong_policy_namespace", "controller_lost"}:
            assert (code, output) == (2, {"status": "STOP"})
            assert not observed and not destination.read_bytes()
            return
        wire = observed[0]
        assert not wire.token
        assert ("DELETE", "/installation/token") in wire.calls
        events = [art.decode(line) for line in destination.read_bytes().splitlines()]
        if fault:
            assert (code, output) == (1, {"status": "UNKNOWN"})
            with pytest.raises(art.Blocked):
                recovery.live_outcome(job, events, 0)
        else:
            assert code == 0 and output["status"] == "DRAFT_VERIFIED"
            assert recovery.live_outcome(job, events, code) == {
                "status": "DRAFT_VERIFIED",
                "head": job["head"],
                "pr": wire.pr_number,
            }
            assert wire.tip == job["head"]
        recovery.run_publisher_handoff(live=True)
        assert observed == [wire]


def test_root_inspects_signer_handoff_under_original_journal_lock(
    pair, tmp_path, monkeypatch
):
    import fcntl

    from agent_platform import worker_publish_io as io

    job, _ = pair
    job.update(signer_uid=os.getuid(), signer_gid=os.getgid())
    job_bytes = art.encoded(job)
    launch = "3" * 64
    journal_path = tmp_path / "journal"
    journal_path.touch(mode=0o600)
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    jwt_path = runtime / "app-jwt"
    result_path = runtime / "result.json"
    monkeypatch.setattr(recovery, "SIGNER_JOURNAL", journal_path)
    monkeypatch.setattr(recovery, "SIGNER_OUTPUT", jwt_path)
    monkeypatch.setattr(recovery, "SIGNER_RESULT", result_path)
    recovery.write_signer_handoff(job_bytes, "synthetic.jwt")

    def fixture_read(path, owner, limit, **kwargs):
        assert Path(path) in (journal_path, jwt_path, result_path)
        assert owner == job["signer_uid"]
        assert kwargs["private"] is True
        assert Path(path).stat().st_size <= limit
        return Path(path).read_bytes()

    monkeypatch.setattr(io, "read_file", fixture_read)
    monkeypatch.setattr(recovery, "read_file", fixture_read)
    store = io.Journal(str(journal_path), art.digest(b""))
    jwt, result = jwt_path.read_bytes(), result_path.read_bytes()
    store.claim(job, signer=True)
    operation = {"job": job["id"], "operation": "sign", "launch_id": launch}
    store.append({"phase": "UNKNOWN", **operation})
    store.append(
        {
            "phase": "COMPLETE",
            **operation,
            "ref": job["ref"],
            "head": job["head"],
            "issue": job["issue"],
            "jwt_sha256": art.digest(jwt),
            "result_sha256": art.digest(result),
        }
    )
    identity = store.identity
    store.close()
    monkeypatch.setattr(io.os, "getuid", lambda: 0)
    monkeypatch.setattr(io.os, "geteuid", lambda: 0)
    assert recovery.inspect_signer_handoff(job_bytes, launch, identity) == (
        jwt,
        result,
        journal_path.read_bytes(),
    )
    with journal_path.open("rb") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            recovery.inspect_signer_handoff(job_bytes, launch, identity)
    with pytest.raises(art.Blocked):
        recovery.inspect_signer_handoff(job_bytes, launch, (0, 0))
    jwt_path.chmod(0o440)
    with pytest.raises(art.Blocked):
        recovery.inspect_signer_handoff(job_bytes, launch, identity)


def test_external_live_signature_is_single_use(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from agent_platform import worker_publish_observer as observer
    from agent_platform import worker_publish_pre_spend as pre_spend

    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    key = Ed25519PrivateKey.generate()
    now = 20000
    reservation = recovery.pre_spend_challenge("a" * 64, "b" * 64, now + 10)
    grant = art.encoded(
        {
            **reservation,
            "schema": "AP-worker01-recovery-grant/1",
            "role": "publisher",
            "audience": recovery.LIVE_UNIT,
            "live": {"purpose": "create-draft-live"},
        }
    )
    directory = os.open(outside, os.O_RDONLY | os.O_DIRECTORY)
    try:
        pre_spend.reserve(directory, art.encoded(reservation), key, now)
        with pytest.raises(art.Blocked):
            pre_spend.sign_grant(directory, "publisher", grant, key, now)
        signature = pre_spend.sign_grant(directory, "publisher-live", grant, key, now)
        public = key.public_key().public_bytes_raw()
        assert observer.verify(
            public, art.digest(public), recovery.LIVE_PURPOSE, grant, signature
        ) == art.decode(grant)
        assert (outside / pre_spend.LIVE_RECORD).read_bytes() == grant
        with pytest.raises(FileExistsError):
            pre_spend.sign_grant(directory, "publisher-live", grant, key, now)
    finally:
        os.close(directory)


@pytest.mark.parametrize(
    "fault",
    [None, "peer", "signer", "pid1_digest", "busy", "sandbox", "credentials", "bind"],
)
def test_live_preflight_matches_effective_unit(pair, fault, monkeypatch):
    from types import SimpleNamespace

    job, _ = pair
    policy = {"netns_device": 4, "netns_inode": 200}
    publisher = {
        "Id": recovery.LIVE_UNIT,
        "LoadState": "loaded",
        "UnitFileState": "static",
        "FragmentPath": "/etc/systemd/system/" + recovery.LIVE_UNIT,
        "DropInPaths": "",
        "NeedDaemonReload": "no",
        "PrivateNetwork": "no",
        "NetworkNamespacePath": recovery.LIVE_NAMESPACE,
        "RestrictAddressFamilies": "AF_INET",
        "IPAddressAllow": job["github_ipv4"] + "/32",
        "IPAddressDeny": "::/0 0.0.0.0/0",
        "AppArmorProfile": "ap-worker-publisher-recovery-live",
        "User": "ap-publisher",
        "Group": "ap-publisher",
        "Restart": "no",
        "Type": "oneshot",
        "NoNewPrivileges": "yes",
        "JoinsNamespaceOf": "",
        "CapabilityBoundingSet": "",
        "AmbientCapabilities": "",
        "ProtectSystem": "strict",
        "ProtectHome": "yes",
        "PrivateDevices": "yes",
        "ProtectProc": "invisible",
        "ProcSubset": "pid",
        "RestrictNamespaces": "yes",
        "SocketBindDeny": "any",
    }
    signer = recovery.role_unit("signer")
    signer_values = {
        **publisher,
        "Id": signer,
        "FragmentPath": "/usr/lib/systemd/system/" + signer,
        "PrivateNetwork": "no" if fault == "signer" else "yes",
        "NetworkNamespacePath": "",
        "RestrictAddressFamilies": "AF_UNIX",
        "IPAddressAllow": "",
        "AppArmorProfile": "ap-worker-publisher-recovery-signer",
        "User": "ap-publisher-signer",
        "Group": "ap-publisher-signer",
    }
    policy["pid1_sha256"] = (
        "a" * 64 if fault == "pid1_digest" else art.digest(art.encoded(publisher))
    )
    if fault == "peer":
        publisher["IPAddressAllow"] = "140.82.112.7/32"
    if fault == "sandbox":
        publisher["ProtectSystem"] = "no"
        policy["pid1_sha256"] = art.digest(art.encoded(publisher))
    state = {
        "ActiveState": "inactive",
        "SubState": "dead",
        "Job": "1" if fault == "busy" else "",
    }

    def show(operation, all_properties, properties, unit):
        assert (operation, all_properties) == ("show", "--all")
        fields = properties.removeprefix("--property=").split(",")
        values = signer_values if unit == signer else {**publisher, **state}
        return "\n".join(f"{field}={values[field]}" for field in fields)

    def namespace(actual, path, current_boot):
        assert (actual, path, current_boot) == (policy, recovery.LIVE_NAMESPACE, "boot")

    from agent_platform import worker_publish_operator as operator_module

    def busctl(argv):
        path = "/usr/libexec/" + (
            signer if "_2dsigner" in argv[6] else recovery.LIVE_UNIT
        ).removesuffix(".service")
        start = {
            "type": "a(sasasttttuii)",
            "data": [[path, [path], [], 0, 0, 0, 0, 0, 0, 0]],
        }
        role = "signer" if path.endswith("-signer") else "publisher"
        credentials = [
            ["handoff", f"{recovery.GRANT_DIRECTORY}/{role}.json"],
            ["approval-pin", str(recovery.INPUT / "approval-pin")],
        ]
        if role == "signer":
            credentials.append(["app-key", "/etc/ap-publisher-keys/worker.pem"])
            journal = recovery.SIGNER_JOURNAL
        else:
            credentials.extend(
                [
                    ["observer-pin", recovery.POLICY_PIN],
                    ["boot-id", recovery.BOOT_ID_PATH],
                ]
            )
            journal = recovery.PUBLISHER_JOURNAL
        if fault == "credentials":
            credentials[0][1] += ".wrong"
        properties = {
            "LoadCredential": ("a(ss)", credentials),
            "LoadCredentialEncrypted": ("a(ss)", []),
            "ImportCredentialEx": ("a(ss)", []),
            "SocketBindAllow": ("a(iiqq)", []),
            "SupplementaryGroups": ("as", []),
            "ReadWritePaths": ("as", [str(journal)]),
            "ReadOnlyPaths": (
                "as",
                [
                    str(recovery.ARTIFACT_CHANNEL),
                    "-" + str(recovery.INPUT),
                    "/usr/lib/ap-worker-publisher",
                ],
            ),
            "BindPaths": ("a(ssbt)", []),
            "BindReadOnlyPaths": ("a(ssbt)", []),
            "Environment": ("as", []),
            "EnvironmentFiles": ("a(sb)", []),
            "PassEnvironment": ("as", []),
        }
        if fault == "bind":
            properties["BindPaths"] = ("a(ssbt)", [["/tmp", "/run", False, 0]])
        rows = [start]
        for name in argv[9:]:
            signature, data = properties.get(name, ("a(sasasttttuii)", []))
            rows.append({"type": signature, "data": data})
        return "\n".join(art.encoded(row).decode() for row in rows)

    monkeypatch.setattr(operator_module, "command", busctl)

    # Patch the module's binding, leaving the process-wide os module untouched.
    monkeypatch.setattr(
        recovery,
        "os",
        SimpleNamespace(stat=lambda path: SimpleNamespace(st_dev=4, st_ino=100)),
    )
    monkeypatch.setattr(recovery, "check_live_namespace", namespace)
    monkeypatch.setattr(recovery, "boot_id", lambda: "boot")
    operator = SimpleNamespace(systemctl=show, verify_exec=operator_module.verify_exec)
    if fault is None:
        recovery.check_live_unit(operator, policy, job)
    else:
        with pytest.raises(art.Blocked):
            recovery.check_live_unit(operator, policy, job)


def test_repository_scale_artifact_is_outside_credentials(pair):
    job, _ = pair
    count, total = 358, 4_843_889
    size, extra = divmod(total, count)
    entries = []
    objects = {}

    def include(kind, payload):
        oid = art.oid(kind, payload)
        objects[oid] = {
            "oid": oid,
            "kind": kind,
            "data": base64.b64encode(payload).decode(),
        }
        return oid

    for index in range(count):
        width = size + (index < extra)
        blob = include("blob", index.to_bytes(4, "little") + bytes(width - 4))
        entries.append(f"100644 file-{index:04}.txt\0".encode() + bytes.fromhex(blob))
    assert len(objects) == count
    tree = include("tree", b"".join(entries))
    commit = (
        f"tree {tree}\nparent {job['parent']}\n"
        "author Fixture <a@example.test> 1 +0000\n"
        "committer Fixture <a@example.test> 1 +0000\n\nRepository-size fixture\n"
    ).encode()
    head = include("commit", commit)
    artifact_bytes = art.encoded(
        {
            "version": art.VERSION,
            "head": head,
            "objects": list(objects.values()),
        }
    )
    job.update(head=head, tree=tree, artifact_sha256=art.digest(artifact_bytes))
    decoded, *_ = art.validate(artifact_bytes, head, tree, job["parent"])
    blobs = [value for kind, value in decoded.values() if kind == "blob"]
    assert len(blobs) == count and sum(map(len, blobs)) == total
    job_bytes = art.encoded(job)
    recovery.check_delivery_bounds(
        job_bytes, artifact_bytes, b"report", bytes(32), b"approval", None
    )
    with pytest.raises(art.Blocked):
        recovery.credential_packet(
            "a" * 64, {"job": job_bytes, "artifact": artifact_bytes}
        )
    packet = recovery.credential_packet("a" * 64, {"job": job_bytes})
    assert len(packet) < recovery.CREDENTIAL_LIMIT < len(artifact_bytes)


@pytest.mark.parametrize(
    "fault", [None, "acl", "pin", "mode", "hardlink", "symlink", "replace"]
)
def test_artifact_reader_uses_one_pinned_root_owned_leaf(
    tmp_path, pair, monkeypatch, fault
):
    import stat
    from types import SimpleNamespace

    from agent_platform import worker_publish_io as io

    job, _ = pair
    parent = tmp_path / "channel"
    parent.mkdir(mode=0o755)
    leaf = parent / "candidate.json"
    leaf.write_bytes(b"artifact")
    leaf.chmod(0o440 if fault != "mode" else 0o640)
    info = leaf.stat()
    identity = [info.st_dev, info.st_ino + (fault == "pin")]
    if fault == "hardlink":
        os.link(leaf, tmp_path / "hardlink")
    if fault == "symlink":
        leaf.rename(parent / "real")
        leaf.symlink_to(parent / "real")

    def metadata(info):
        names = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_nlink",
            "st_mode",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        fields = {name: getattr(info, name) for name in names}
        # Simulate root ancestry in this non-root sandbox. File links, mode,
        # inode and read use the real descriptor and filesystem.
        if stat.S_ISDIR(info.st_mode):
            fields["st_mode"] = stat.S_IFDIR | 0o755
        return SimpleNamespace(st_uid=0, st_gid=0, **fields)

    def named(*args, **kwargs):
        info = metadata(os.stat(*args, **kwargs))
        if fault == "replace":
            info.st_ino += 1
        return info

    acl = recovery.artifact_acl(job)

    class FileSystem:
        def __getattr__(self, name):
            return getattr(os, name)

        def fstat(self, fd):
            return metadata(os.fstat(fd))

        def stat(self, *args, **kwargs):
            return named(*args, **kwargs)

        def getxattr(self, fd, name):
            assert name == io.ACL_XATTR
            return b"wrong" if fault == "acl" else acl

    monkeypatch.setattr(io, "os", FileSystem())
    monkeypatch.setattr(recovery, "ARTIFACT_CHANNEL", leaf)
    if fault is None:
        assert recovery.read_role_artifact(job, identity) == b"artifact"
    else:
        with pytest.raises((art.Blocked, OSError)):
            recovery.read_role_artifact(job, identity)
