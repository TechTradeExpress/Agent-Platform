"""Offline fresh-generation custody and integration regressions."""

import os
from contextlib import contextmanager

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_worker_publish_case import inputs, store  # noqa: F401
from test_worker_publish_observer import sample  # noqa: F401
from test_worker_publish_reconciliation import case as evidence_case  # noqa: F401

from agent_platform import worker_publish_artifact as art
from agent_platform import worker_publish_case as case
from agent_platform import worker_publish_generation as generation
from agent_platform import worker_publish_observer as observer
from agent_platform import worker_publish_operator as operator
from agent_platform import worker_publish_pre_spend as pre_spend
from agent_platform import worker_publish_recovery_paths as recovery


@pytest.fixture
def scenario(store, inputs, sample, evidence_case, monkeypatch):  # noqa: F811
    fs, archive_fd, path = store
    archive_pin = case._record(archive_fd, *inputs)
    args = evidence_case.args()
    now = args["now"]
    original = args["proposed_job"]
    key, operator_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    observer_key = key.public_key().public_bytes_raw()
    approval_key = operator_key.public_key().public_bytes_raw()
    observer_pin = art.digest(observer_key)
    challenge = "2" * 64
    root = path / generation.GENERATION
    root.mkdir(mode=0o700)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    monkeypatch.setattr(generation, "os", fs)
    monkeypatch.setattr(fs, "getuid", lambda: 0)
    monkeypatch.setattr(fs, "geteuid", lambda: 0)

    def packets(job):
        bound = observer.binding(
            args["pins"].snapshot, job, archive_pin, challenge, now
        )
        selection = dict(sample[3], binding=bound)
        report = dict(
            sample[1](),
            binding=bound,
            selection_sha256=art.digest(art.encoded(selection)),
        )
        return dict(
            job=job,
            observer_key=observer_key,
            observer_pin=observer_pin,
            report=art.encoded(report),
            report_signature=observer.sign(key, "report", report),
            selection=art.encoded(selection),
            selection_signature=observer.sign(key, "selection", selection),
        )

    fresh = art.decode(original)
    fresh["ref"] = recovery.REF
    fresh["journal_sha256"] = fresh["signer_journal_sha256"] = art.digest(b"")
    proposed = packets(art.encoded(fresh))
    approval = {
        "schema": "AP-worker01-create-draft/1",
        "binding": art.decode(proposed["report"])["binding"],
        "report_sha256": art.digest(proposed["report"]),
        "issued": now,
        "expires": now + 10,
    }
    parameters = dict(
        snapshot=evidence_case.snapshot,
        snapshot_pin=args["pins"].snapshot,
        archive_pin=archive_pin,
        archive_directory=archive_fd,
        challenge=challenge,
        object_id=args["object_id"],
        artifact=args["proposed_artifact"],
        approval_key=approval_key,
        approval_pin=art.digest(approval_key),
        approval=art.encoded(approval),
        approval_signature=observer.sign(operator_key, "create-draft", approval),
        clock=lambda: now,
        **proposed,
    )
    try:
        yield fd, root, parameters, packets(original), fs, path
    finally:
        os.close(fd)


def test_verify_observation_success_through_operator(scenario, monkeypatch, capsys):
    fd, _, args, packet, _, path = scenario
    del fd
    for name, key in (
        ("observer-public-key", "observer_key"),
        ("observer-report.json", "report"),
        ("observer-report.sig", "report_signature"),
        ("observer-selection.json", "selection"),
        ("observer-selection.sig", "selection_signature"),
    ):
        leaf = path / name
        leaf.write_bytes(packet[key])
        leaf.chmod(0o600)

    @contextmanager
    def custody():
        yield args["archive_directory"]

    monkeypatch.setattr(case, "case_directory", custody)
    monkeypatch.setattr(
        operator,
        "exclusive_config",
        lambda: os.open(path, os.O_RDONLY | os.O_DIRECTORY),
    )
    monkeypatch.setattr(case, "frozen_snapshot", lambda *unused: args["snapshot"])
    monkeypatch.setattr(
        case,
        "read_file",
        lambda name, *a, **kw: (
            args["challenge"] if name.endswith("/challenge") else packet["observer_pin"]
        ).encode(),
    )
    argv = [
        "reconcile-v4",
        "verify-observation",
        "--snapshot-sha256",
        args["snapshot_pin"],
        "--continuity-sha256",
        args["archive_pin"],
    ]
    assert operator.main(argv) == 0
    result = art.decode(capsys.readouterr().out.encode())
    assert result["status"] == "OBSERVATION_VERIFIED"
    assert result["admission_allowed"] is result["publish_allowed"] is False


def test_generation_handoff_and_contention(scenario):
    fd, root, args, _, _, path = scenario
    archives = {p.name: p.read_bytes() for p in path.iterdir() if p.is_file()}
    job, result = art.digest(args["job"]), "b" * 64
    with generation.consume(fd, **args) as lease:
        with pytest.raises(BlockingIOError), generation.consume(fd, **args):
            pytest.fail("competing lease")
        lease.signer_claim(job)
        lease.signer_handoff(result)
        lease.publisher_claim(job, result)
        with pytest.raises(art.Blocked):
            lease.publisher_claim(job, result)
    with pytest.raises(art.Blocked), generation.consume(fd, **args):
        pytest.fail("spent approval replayed")
    assert (root / generation.JOB).read_bytes() == args["job"]
    assert archives == {p.name: p.read_bytes() for p in path.iterdir() if p.is_file()}


@pytest.mark.parametrize("boundary", range(1, 13))
def test_fsync_loss_stops_admission_and_never_recovers_lease(
    scenario, monkeypatch, boundary
):
    fd, root, args, _, fs, _ = scenario
    calls = 0

    def fail(descriptor):
        nonlocal calls
        calls += 1
        if calls == boundary:
            raise OSError("lost confirmation")
        os.fsync(descriptor)

    monkeypatch.setattr(fs, "fsync", fail)
    with pytest.raises(OSError), generation.consume(fd, **args) as lease:
        job = art.digest(args["job"])
        lease.signer_claim(job)
        lease.signer_handoff("a" * 64)
        lease.publisher_claim(job, "a" * 64)
    assert (root / generation.SPENT).exists()
    with pytest.raises(art.Blocked), generation.consume(fd, **args):
        pytest.fail("restart reconstructed the lease")


@pytest.mark.parametrize(
    "fault", ["old_job", "old_ref", "stale", "archive", "approval"]
)
def test_rejects_unbound_admission_before_consumption(scenario, fault):
    fd, root, args, _, _, _ = scenario
    if fault in {"old_job", "old_ref"}:
        old = art.decode(args["snapshot"].job)
        current = art.decode(args["job"])
        field = "id" if fault == "old_job" else "ref"
        current[field] = old[field]
        args["job"] = art.encoded(current)
    elif fault == "stale":
        args["clock"] = lambda: 10**9
    elif fault == "archive":
        args["archive_pin"] = "f" * 64
    else:
        args["approval_signature"] = b"x" * 64
    with pytest.raises(art.Blocked), generation.consume(fd, **args):
        pytest.fail("invalid evidence produced a lease")
    assert not list(root.iterdir())


def test_same_approval_cannot_move_to_another_directory(scenario):
    _, _, args, _, _, path = scenario
    other = path / "other"
    other.mkdir(mode=0o700)
    fd = os.open(other, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(art.Blocked), generation.consume(fd, **args):
            pytest.fail("foreign generation consumed approval")
    finally:
        os.close(fd)
    assert not list(other.iterdir())


def test_bad_signer_handoff_poisoned_for_this_process(scenario):
    fd, _, args, _, _, _ = scenario
    job = art.digest(args["job"])
    with generation.consume(fd, **args) as lease:
        lease.signer_claim(job)
        lease.signer_handoff("a" * 64)
        with pytest.raises(art.Blocked):
            lease.publisher_claim(job, "b" * 64)
        with pytest.raises(art.Blocked):
            lease.publisher_claim(job, "a" * 64)


@pytest.fixture
def witness(scenario):
    _, _, args, _, _, _ = scenario
    key = Ed25519PrivateKey.generate()
    args["witness_key"] = key.public_key().public_bytes_raw()
    args["witness_pin"] = art.digest(args["witness_key"])
    return key


def test_confirmed_spend_flatly_binds_challenge_to_consumption(scenario, witness):
    fd, root, args, _, _, _ = scenario
    job = art.digest(args["job"])
    with generation.consume(fd, **args) as lease:
        packet = lease.continuity_challenge()
        value = art.decode(packet)
        assert value["binding"]["job"] == job
        assert value["binding"]["artifact"] == art.digest(args["artifact"])
        assert value["binding"]["main"] == art.decode(args["job"])["parent"]
        assert value["approval_sha256"] == art.digest(args["approval"])
        assert value["observer_key_sha256"] == args["observer_pin"]
        signature = observer.sign(witness, "spent-continuity", value)
        assert lease.confirm_continuity(signature) == art.digest(packet)
        assert art.decode((root / generation.CONTINUITY).read_bytes()) == {
            "record": value,
            "signature": signature.hex(),
        }
        lease.signer_claim(job)
    with pytest.raises(art.Blocked), generation.consume(fd, **args):
        pytest.fail("a retained continuity receipt recreated a lease")


@pytest.mark.parametrize("fault", ["missing", "foreign_launch", "wrong_domain", "sync"])
def test_uncertain_continuity_stops_before_signer(
    scenario, witness, monkeypatch, fault
):
    fd, root, args, _, fs, _ = scenario
    with generation.consume(fd, **args) as lease:
        value = art.decode(lease.continuity_challenge())
        if fault == "foreign_launch":
            value["launch_id"] = "0" * 64
        if fault == "sync":

            def unavailable(_):
                raise OSError("synthetic lost fsync acknowledgment")

            monkeypatch.setattr(fs, "fsync", unavailable)
        if fault != "missing":
            signature = observer.sign(
                witness,
                "create-draft" if fault == "wrong_domain" else "spent-continuity",
                value,
            )
            with pytest.raises((art.Blocked, OSError)):
                lease.confirm_continuity(signature)
        with pytest.raises(art.Blocked):
            lease.signer_claim(art.digest(args["job"]))
    assert not (root / generation.SIGNER).exists()
    with pytest.raises(art.Blocked), generation.consume(fd, **args):
        pytest.fail("uncertain acknowledgment recreated a lease")


def test_observer_key_cannot_also_witness_spend(scenario):
    fd, root, args, _, _, _ = scenario
    args.update(witness_key=args["observer_key"], witness_pin=args["observer_pin"])
    with pytest.raises(art.Blocked), generation.consume(fd, **args):
        pytest.fail("observer and witness trust were combined")
    assert not list(root.iterdir())


def test_spent_continuity_must_remain_intact_at_signer_claim(scenario, witness):
    fd, root, args, _, _, _ = scenario
    with generation.consume(fd, **args) as lease:
        value = art.decode(lease.continuity_challenge())
        lease.confirm_continuity(observer.sign(witness, "spent-continuity", value))
        (root / generation.CONTINUITY).write_bytes(b"{}")
        with pytest.raises(art.Blocked):
            lease.signer_claim(art.digest(args["job"]))
    assert not (root / generation.SIGNER).exists()


def test_lost_local_spent_cannot_reuse_operator_approval(scenario, monkeypatch):
    fd, root, args, _, fs, path = scenario
    outside = path / "external-fixture"
    outside.mkdir(mode=0o700)
    operator_key = Ed25519PrivateKey.generate()
    args["approval_key"] = operator_key.public_key().public_bytes_raw()
    args["approval_pin"] = art.digest(args["approval_key"])
    args["approval_signature"] = observer.sign(
        operator_key, "create-draft", art.decode(args["approval"])
    )
    receipts = []

    def reserve(raw):
        descriptor = os.open(outside, os.O_RDONLY | os.O_DIRECTORY)
        try:
            signature = pre_spend.reserve(
                descriptor, raw, operator_key, args["clock"]()
            )
            receipts.append(signature)
            return signature
        finally:
            os.close(descriptor)

    def fail_after_creating_spent(descriptor):
        if (root / generation.SPENT).exists():
            raise OSError("synthetic uncertain local SPENT")
        os.fsync(descriptor)

    with monkeypatch.context() as m:
        m.setattr(fs, "fsync", fail_after_creating_spent)
        with pytest.raises(OSError, match="uncertain local SPENT"):
            with generation.consume(fd, **args, reserve_outside_worker=reserve):
                pytest.fail("an uncertain local write yielded a lease")
    assert len(receipts) == 1
    assert (outside / pre_spend.RECORD).exists()
    # Model loss of only fixture-owned local state before restart.
    (root / generation.PRE_SPEND).unlink()
    (root / generation.SPENT).unlink()
    with pytest.raises(FileExistsError):
        with generation.consume(fd, **args, reserve_outside_worker=reserve):
            pytest.fail("the external ledger reissued a receipt")
    with pytest.raises(art.Blocked):
        with generation.consume(
            fd, **args, reserve_outside_worker=lambda _: receipts[0]
        ):
            pytest.fail("a saved receipt matched the new live challenge")
    assert not list(root.iterdir())


@pytest.mark.parametrize(
    "mode",
    [
        "offline",
        "published",
        "object",
        "ref",
        "draft",
        "death_before_mint",
        "death_after_object",
        "signer_preclaim_exit",
        "signer_unknown_exit",
        "signer_return_loss",
        "bad_grant",
        "bad_mode",
        "publisher_partial_write",
        "revoke_reply_loss",
    ],
)
def test_recovery_handoff_cli_processes(scenario, monkeypatch, mode):
    import fcntl
    import subprocess
    import sys
    from pathlib import Path
    from types import SimpleNamespace

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    fd, _, args, _, _, path = scenario
    key = Ed25519PrivateKey.generate()
    args["approval_key"] = key.public_key().public_bytes_raw()
    args["approval_pin"] = art.digest(args["approval_key"])
    args["approval_signature"] = observer.sign(
        key, "create-draft", art.decode(args["approval"])
    )
    outside = path / "outside"
    staging = path / "staging"
    runtime = path / "runtime"
    for private in (outside, staging, runtime):
        private.mkdir(mode=0o700)
    signer_journal = path / "signer-journal"
    publisher_journal = path / "publisher-journal"
    for journal in (signer_journal, publisher_journal):
        journal.touch(mode=0o600)
    live = path / "live"
    monkeypatch.setattr(recovery, "LIVE_PATH", str(live))
    monkeypatch.setattr(recovery, "GRANT_DIRECTORY", str(staging))
    monkeypatch.setattr(recovery, "SIGNER_JOURNAL", signer_journal)

    def root_journal(location, previous, *, inspect_owner):
        assert location == str(signer_journal)
        target = Path(location)
        stream = target.open("rb")
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        data = stream.read()
        metadata = os.fstat(stream.fileno())
        assert previous is None or art.digest(data) == previous
        return SimpleNamespace(
            identity=(metadata.st_dev, metadata.st_ino),
            size=len(data),
            sha256=art.digest(data),
            fd=stream.fileno(),
            close=stream.close,
        )

    monkeypatch.setattr(recovery, "Journal", root_journal)
    monkeypatch.setattr(recovery, "SIGNER_OUTPUT", runtime / "app-jwt")
    monkeypatch.setattr(recovery, "SIGNER_RESULT", runtime / "result.json")
    monkeypatch.setattr(
        recovery, "read_file", lambda name, *_a, **_kw: Path(name).read_bytes()
    )
    role_job = art.decode(args["job"])

    def uid(role, gid=False):
        return role_job[role + ("_gid" if gid else "_uid")]

    original_lstat = Path.lstat

    def mapped_lstat(target):
        info = original_lstat(target)
        if target in (recovery.SIGNER_OUTPUT, recovery.SIGNER_RESULT):
            props = dict(
                zip(
                    (
                        "st_mode",
                        "st_ino",
                        "st_dev",
                        "st_nlink",
                        "st_uid",
                        "st_gid",
                        "st_size",
                        "st_atime",
                        "st_mtime",
                        "st_ctime",
                    ),
                    info,
                    strict=True,
                )
            )
            props.update(
                st_uid=uid("signer"),
                st_gid=uid("signer", gid=True),
                st_mtime_ns=info.st_mtime_ns,
                st_ctime_ns=info.st_ctime_ns,
            )
            return SimpleNamespace(**props)
        return info

    monkeypatch.setattr(Path, "lstat", mapped_lstat)

    def reserve(raw):
        ledger = os.open(outside, os.O_RDONLY | os.O_DIRECTORY)
        try:
            return pre_spend.reserve(ledger, raw, key, args["clock"]())
        finally:
            os.close(ledger)

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = rsa_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    program = """
import fcntl
import os
import sys
from pathlib import Path
from agent_platform import worker_publish_recovery_paths as r
from agent_platform import worker_publish_io as io
from agent_platform import worker_publish_signer as s
from agent_platform import worker_publisher as p

role, base, credentials, raw_time, mode, test_dir = sys.argv[1:]
base, credentials = Path(base), Path(credentials)
r.time.time = lambda: int(raw_time)
p.confinement = lambda job, actual, recovery: None

def read_credential(file_path, owner, limit, *, credential=False, **kwargs):
    if credential:
        exact = '/run/credentials/' + r.role_unit(role)
        assert file_path.startswith(exact + '/')
        target = credentials / Path(file_path).name
        if target.name == 'app-key' and mode == 'signer_unknown_exit':
            os._exit(73)
        with target.open('rb') as stream:
            io.systemd_credential(stream.fileno(), os.fstat(stream.fileno()),
                                  owner, directory=False)
            data = stream.read(limit + 1)
        assert 0 < len(data) <= limit
        return data
    return Path(file_path).read_bytes()

def live(launch):
    if mode == 'death_before_mint' and role == 'publisher':
        journal = (base / 'publisher-journal').read_bytes()
        if b'"operation":"mint"' in journal:
            r.art.need(False)
    if role == 'publisher':
        r.art.need(not (base / 'lost-controller').exists())
    with (base / 'live').open('rb') as stream:
        assert stream.read() == launch.encode('ascii')
        request = r._FLOCK.pack(fcntl.F_WRLCK, os.SEEK_SET, 0, 0, 0)
        status = fcntl.fcntl(stream.fileno(), fcntl.F_GETLK, request)
        kind, _, _, _, owner = r._FLOCK.unpack(status)
        r.art.need(kind == fcntl.F_WRLCK and owner > 0)

r.read_file = io.read_file = read_credential
r.require_live_controller = live
r.SIGNER_JOURNAL = base / 'signer-journal'
r.PUBLISHER_JOURNAL = base / 'publisher-journal'
r.SIGNER_OUTPUT = base / 'runtime' / 'app-jwt'
r.SIGNER_RESULT = base / 'runtime' / 'result.json'
if role == 'signer':
    if mode == 'signer_preclaim_exit':
        receive = r.receive
        def preclaim(*args):
            receive(*args)
            os._exit(73)
        r.receive = preclaim
    raise SystemExit(s.recovery_main())
if mode in ('offline', 'publisher_partial_write'):
    if mode == 'publisher_partial_write':
        write = os.write
        def partial(fd, data):
            if b'"phase":"HANDOFF_VERIFIED"' in data:
                return write(fd, data[:8])
            return write(fd, data)
        os.write = partial
    raise SystemExit(p.recovery_main())

sys.path.insert(0, test_dir)
from test_worker_publisher import Wire

def wire(journal, job, jwt):
    wire = Wire(journal, job)
    original = wire.exchange

    def exchange(method, path, body, secret, limit=256*1024):
        auth = 'JWT_FAKE' if secret == jwt else secret
        response = original(method, path, body, auth, limit)
        effect = (
            'object' if method == 'POST' and path.startswith(p.ROOT + '/git/')
            else 'ref' if path == '/graphql' and body['query'] == p.CAS
            else 'draft' if method == 'POST' and path == p.ROOT + '/pulls'
            else ''
        )
        if effect == 'object' and mode == 'death_after_object':
            (base / 'lost-controller').touch()
        if effect == mode or (mode == 'revoke_reply_loss' and path.endswith('/token')):
            raise TimeoutError('synthetic reply loss after mutation')
        return response

    wire.exchange = exchange
    def save(code):
        (base / 'wire-result.json').write_bytes(r.art.encoded({
            'token': wire.token, 'tip': wire.tip, 'pr': wire.pr_number,
            'calls': wire.calls, 'objects': len(wire.objects),
        }))
    import atexit
    atexit.register(save, 0)
    return wire

raise SystemExit(p.recovery_main(transport_factory=wire))
"""
    seen = []
    signer_stops = {
        "signer_preclaim_exit",
        "signer_unknown_exit",
        "signer_return_loss",
        "bad_grant",
        "bad_mode",
    }

    def start(unit):
        role = "signer" if unit == recovery.role_unit("signer") else "publisher"
        copies = path / (role + "-credentials")
        copies.mkdir(mode=0o700)
        entries = {
            "handoff": (staging / (role + ".json")).read_bytes(),
            "approval-pin": args["approval_pin"].encode("ascii"),
        }
        if role == "signer":
            entries["app-key"] = private_key
        else:
            # Signer-controlled bytes change only after the operator has copied them.
            recovery.SIGNER_OUTPUT.chmod(0o600)
            recovery.SIGNER_OUTPUT.write_bytes(b"changed")
        if mode == "bad_grant" and role == "signer":
            packet = art.decode(entries["handoff"])
            packet["signature"] = "AAAA"
            entries["handoff"] = art.encoded(packet)
        for name, value in entries.items():
            target = copies / name
            target.write_bytes(value)
            target.chmod(
                0o444
                if mode == "bad_mode" and role == "signer" and name == "handoff"
                else 0o400
            )

        def invoke():
            return subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    program,
                    role,
                    str(path),
                    str(copies),
                    str(args["clock"]()),
                    mode,
                    str(Path(__file__).parent),
                ],
                env={"CREDENTIALS_DIRECTORY": "/run/credentials/" + unit},
                capture_output=True,
                timeout=10,
            )

        result = invoke()
        if role == "signer" and mode in signer_stops:
            expected = (
                73
                if mode.endswith("_exit")
                else 0
                if mode == "signer_return_loss"
                else 1
            )
            assert result.returncode == expected, (result.stdout, result.stderr)
            raise art.Blocked()
        if role == "publisher" and mode not in ("offline", "published"):
            assert result.returncode == 1 and b"UNKNOWN_NEEDS_HUMAN" in result.stdout
            raise art.Blocked()
        assert result.returncode == 0, (result.stdout, result.stderr)
        if role == "publisher":
            expected = b'"publication":"DISABLED"' if mode == "offline" else b'"pr":111'
            assert expected in result.stdout
        if role == "signer" and mode == "offline":
            evidence = signer_journal.read_bytes()
            duplicate = invoke()
            assert duplicate.returncode == 1 and b"BLOCKED" in duplicate.stdout
            assert signer_journal.read_bytes() == evidence
        seen.append(unit)

    def sign(role, raw):
        ledger = os.open(outside, os.O_RDONLY | os.O_DIRECTORY)
        try:
            return pre_spend.sign_grant(ledger, role, raw, key, args["clock"]())
        finally:
            os.close(ledger)

    for filename, field in (
        ("proposed-job.json", "job"),
        ("proposed-candidate.json", "artifact"),
        ("observer-report.json", "report"),
        ("observer-report.sig", "report_signature"),
        ("observer-selection.json", "selection"),
        ("observer-selection.sig", "selection_signature"),
        ("observer-public-key", "observer_key"),
        ("approval-public-key", "approval_key"),
        ("create-draft-approval.json", "approval"),
        ("create-draft-approval.sig", "approval_signature"),
    ):
        leaf = path / filename
        leaf.write_bytes(args[field])
        leaf.chmod(0o600)

    from agent_platform import worker_publish_io as io

    @contextmanager
    def archive():
        yield args["archive_directory"]

    def trust_pin(filename, *_a, **_kw):
        if filename.endswith("/challenge"):
            return args["challenge"].encode()
        return args[
            "approval_pin" if filename.endswith("approval-pin") else "observer_pin"
        ].encode()

    def systemctl(command, *options, **kwargs):
        unit = options[-1]
        if command == "show":
            return (
                "FragmentPath=/usr/lib/systemd/system/"
                + unit
                + "\nDropInPaths=\nNeedDaemonReload=no"
            )
        assert command == "start"
        start(unit)

    monkeypatch.setattr(case, "case_directory", archive)
    monkeypatch.setattr(case, "frozen_snapshot", lambda *_: args["snapshot"])
    monkeypatch.setattr(case, "OBJECT", args["object_id"])
    monkeypatch.setattr(
        operator,
        "exclusive_config",
        lambda: os.open(path, os.O_RDONLY | os.O_DIRECTORY),
    )
    monkeypatch.setattr(operator, "systemctl", systemctl)
    monkeypatch.setattr(io, "read_file", trust_pin)
    monkeypatch.setattr(recovery.time, "time", args["clock"])

    inbox, to_operator = os.pipe()
    from_operator, outbox = os.pipe()
    child = os.fork()
    if child == 0:
        try:
            os.close(to_operator)
            os.close(from_operator)
            os.dup2(inbox, 0)
            os.dup2(outbox, 1)
            os.close(inbox)
            os.close(outbox)
            with os.fdopen(os.dup(1), "w", buffering=1) as stream:
                sys.stdout = stream
                result = operator.main(
                    [
                        "recovery-handoff",
                        "--snapshot-sha256",
                        args["snapshot_pin"],
                        "--continuity-sha256",
                        args["archive_pin"],
                    ]
                )
                stream.flush()
        except BaseException:
            os._exit(99)
        os._exit(result)
    os.close(inbox)
    os.close(outbox)
    purposes = []
    with (
        os.fdopen(to_operator, "wb", buffering=0) as tx,
        os.fdopen(from_operator, "rb") as rx,
    ):
        for line in rx:
            response = art.decode(line)
            if "purpose" not in response:
                ending = response
                continue
            purpose = response["purpose"]
            purposes.append(purpose)
            request = art.encoded(response["request"])
            signature = (
                reserve(request)
                if purpose == "pre-spend"
                else sign(purpose.removeprefix("recovery-"), request)
            )
            tx.write(signature.hex().encode("ascii") + b"\n")
    _, status = os.waitpid(child, 0)
    success = mode in ("offline", "published")
    assert os.waitstatus_to_exitcode(status) == (0 if success else 1)
    expected_purposes = ["pre-spend", "recovery-signer"]
    if mode not in signer_stops:
        expected_purposes.append("recovery-publisher")
    assert purposes == expected_purposes
    assert ending["status"] == ("HANDOFF_VERIFIED" if success else "STOP")
    evidence = publisher_journal.read_bytes()
    if mode in signer_stops:
        assert evidence == b""
        retention = signer_journal.read_bytes()
        if mode in {"signer_preclaim_exit", "bad_grant", "bad_mode"}:
            assert retention == b""
        elif mode == "signer_unknown_exit":
            assert b'"phase":"UNKNOWN"' in retention
            assert b'"phase":"COMPLETE"' not in retention
        else:
            assert b'"phase":"COMPLETE"' in retention
        assert not (staging / "publisher.json").exists()
        assert (path / generation.GENERATION / generation.SPENT).exists()
        return
    if mode == "offline":
        assert b"HANDOFF_VERIFIED" in evidence
    elif mode == "publisher_partial_write":
        assert b'"phase":"CLAIM"' in evidence
        assert not evidence.endswith(b"\n")
    else:
        wire = art.decode((path / "wire-result.json").read_bytes())
        assert wire["token"] is False
        if mode == "published":
            assert b'"phase":"COMPLETE"' in evidence
            assert wire["pr"] == 111
        else:
            assert b'"phase":"COMPLETE"' not in evidence
            assert b'"phase":"UNKNOWN"' in evidence
            if mode == "death_before_mint":
                assert not any(
                    url.endswith("/access_tokens") for _, url in wire["calls"]
                )
            elif mode in ("draft", "revoke_reply_loss"):
                assert wire["pr"] == 111
            elif mode == "ref":
                assert wire["tip"] == role_job["head"]
            else:
                assert wire["objects"] > 0 and wire["tip"] is None
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            program,
            "publisher",
            str(path),
            str(path / "publisher-credentials"),
            str(args["clock"]()),
            "offline",
            str(Path(__file__).parent),
        ],
        env={
            "CREDENTIALS_DIRECTORY": "/run/credentials/"
            + recovery.role_unit("publisher")
        },
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 1 and b"BLOCKED" in result.stdout
    assert publisher_journal.read_bytes() == evidence
