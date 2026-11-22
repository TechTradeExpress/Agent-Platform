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
