"""Offline durability boundaries, including a real process exit with partial bytes."""

import importlib
import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def ledger(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "packaging"))
    return importlib.import_module("release_continuity")


@pytest.fixture
def observation(ledger):
    historic = json.loads((ROOT / "packaging/debian/pkg11-baseline.json").read_bytes())
    recipes = dict.fromkeys(ledger.RECIPE_PATHS, "a" * 64)
    return ledger.Observation(
        ledger.encoded(
            dict(
                repository=ledger.REPOSITORY,
                repository_identity="REPOSITORY_IDENTITY_NOT_ATTESTED",
                commit="a" * 40,
                tree="b" * 40,
                epoch=42,
                parents=[],
                recipes=recipes,
                source_inputs=recipes
                | {
                    "packaging/debian/pkg11-baseline.json": ledger.BASELINE,
                    "debian/control": "e" * 64,
                },
                historical_source=historic,
            )
        ),
        ledger.encoded(
            dict(
                platform="debian-13/amd64",
                image_digest="UNKNOWN",
                image_provenance="IMAGE_PROVENANCE_UNKNOWN",
                packages_sha256="b" * 64,
                tools={
                    name: {"version": "fixture 1.0", "sha256": "c" * 64}
                    for name in ("python", "dpkg_deb", "xz", "git")
                },
            )
        ),
        ledger.encoded(
            {
                role: {
                    "archive_sha256": historic["roles"][role]["archive_sha256"],
                    "size": 42,
                }
                for role in ledger.ROLES
            }
        ),
    )


@pytest.fixture
def attempt(ledger, observation, tmp_path):
    root = tmp_path / "ledger"
    root.mkdir(mode=0o700)
    checkpoint = ledger.FixtureCheckpoint(
        ledger.KEY,
        ledger.fixture_slot_sha256(root),
        ledger.fixture_bundle_sha256(observation),
        0,
        None,
    )
    return root, checkpoint


def blocked(report):
    assert report["status"] == "BLOCKED"
    assert report["history"] == "UNKNOWN"
    assert report["custody"] == report["operator_authority"] == "NOT_CONFIGURED"
    assert report["input_provenance"] == "UNVERIFIED_CALLER_FIXTURE"
    assert all(
        report[key] is False
        for key in (
            "history_authenticated",
            "final_generation_allowed",
            "release_authorized",
            "installation_allowed",
            "publication_allowed",
        )
    )


def record(ledger, root, observation, checkpoint):
    report = ledger.record_fixture(
        root, observation, generation=1, checkpoint=checkpoint
    )
    blocked(report)
    assert report["local_integrity"] == "LOCAL_FSYNC_COMPLETED"
    return checkpoint._replace(
        generation=1, receipt_sha256=report["fixture_receipt_sha256"]
    )


def test_empty_store_and_forged_custody(ledger, attempt, observation):
    root, checkpoint = attempt
    blocked(ledger.reconcile(root, observation))
    binding = ledger.CustodyQuery(
        ledger.KEY, checkpoint.slot_sha256, checkpoint.bundle_sha256, 0, None, "f" * 64
    )
    for forged in (
        None,
        {"state": "EMPTY"},
        checkpoint._asdict(),
        ledger.CustodyEvidence(binding, "operator", b"EMPTY", b"approved"),
    ):
        report = ledger.record_fixture(
            root, observation, generation=1, checkpoint=forged
        )
        blocked(report)
        assert report["reason"] == "checkpoint_unavailable"
    assert list(root.iterdir()) == []


def test_reconcile_requires_current_checkpoint_and_never_replays(
    ledger, attempt, observation
):
    root, checkpoint = attempt
    completed = record(ledger, root, observation, checkpoint)
    for evidence in (
        None,
        checkpoint,
        completed._replace(generation=2),
        completed._replace(receipt_sha256="0" * 64),
    ):
        report = ledger.reconcile(root, observation, checkpoint=evidence)
        blocked(report)
        assert report["local_integrity"] == "UNKNOWN"

    report = ledger.reconcile(root, observation, checkpoint=completed)
    blocked(report)
    assert report["local_integrity"] == "LOCAL_RECORDS_MATCH"
    for generation in (0, 1, 2, True):
        replay = ledger.record_fixture(
            root, observation, generation=generation, checkpoint=checkpoint
        )
        blocked(replay)
        assert replay["local_integrity"] == "UNKNOWN"

    (root / ledger.SLOT / ledger.RECEIPT).unlink()
    assert (
        ledger.reconcile(root, observation, checkpoint=completed)["local_integrity"]
        == "UNKNOWN"
    )
    # A rolled-back filesystem still disagrees with the separately retained checkpoint.
    (root / ledger.SLOT / ledger.INTENT).unlink()
    (root / ledger.SLOT).rmdir()
    report = ledger.record_fixture(
        root, observation, generation=1, checkpoint=completed
    )
    assert report["reason"] == "checkpoint_mismatch"
    assert list(root.iterdir()) == []


@pytest.mark.parametrize(
    "field,index", [("commit", 0), ("source_inputs", 0), ("packages_sha256", 1)]
)
def test_bundle_conflict(ledger, attempt, observation, field, index):
    root, checkpoint = attempt
    completed = record(ledger, root, observation, checkpoint)
    changed = list(observation)
    facts = json.loads(changed[index])
    if field == "source_inputs":
        facts[field]["debian/control"] = "0" * 64
    else:
        facts[field] = "0" * len(facts[field])
    changed[index] = ledger.encoded(facts)
    assert (
        ledger.reconcile(root, ledger.Observation(*changed), checkpoint=completed)[
            "reason"
        ]
        == "bundle_conflict"
    )


@pytest.mark.parametrize(
    "mutation", ["missing", "wrong_hash", "duplicates", "unsafe_path"]
)
def test_invalid_observations(ledger, attempt, observation, mutation):
    root, checkpoint = attempt
    archives = json.loads(observation.historical_archives)
    source = json.loads(observation.source)
    if mutation == "missing":
        del archives["worker"]
    elif mutation == "wrong_hash":
        archives["control"]["archive_sha256"] = "e" * 64
    elif mutation == "unsafe_path":
        source["source_inputs"]["../secret"] = "e" * 64
    changed = observation._replace(
        source=ledger.encoded(source), historical_archives=ledger.encoded(archives)
    )
    if mutation == "duplicates":
        changed = changed._replace(source=b'{"commit":"a",' + changed.source[1:])
    report = ledger.record_fixture(root, changed, generation=1, checkpoint=checkpoint)
    blocked(report)
    assert list(root.iterdir()) == []


@pytest.mark.parametrize("cut", range(1, 6))
def test_all_fsync_failures_preserve_evidence(
    ledger, attempt, observation, monkeypatch, cut
):
    root, checkpoint = attempt
    sync = os.fsync
    calls = 0

    def fail(fd):
        nonlocal calls
        calls += 1
        if calls == cut:
            raise OSError("private diagnostic")
        sync(fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", fail)
        result = ledger.record_fixture(
            root, observation, generation=1, checkpoint=checkpoint
        )
    blocked(result)
    assert result["reason"] == "ledger_unavailable_or_interrupted"
    assert calls == cut
    assert (root / ledger.SLOT).is_dir()
    assert (root / ledger.SLOT / ledger.INTENT).exists() == (cut >= 2)
    assert (root / ledger.SLOT / ledger.RECEIPT).exists() == (cut >= 4)
    assert (
        ledger.reconcile(root, observation, checkpoint=checkpoint)["local_integrity"]
        == "UNKNOWN"
    )
    assert (
        ledger.record_fixture(root, observation, generation=1, checkpoint=checkpoint)[
            "reason"
        ]
        == "slot_already_exists"
    )


def test_process_crash_leaves_partial_bytes(ledger, attempt, observation, monkeypatch):
    root, checkpoint = attempt

    def crash(fd, name, data):
        child_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
        os.write(child_fd, data[:15])
        os._exit(17)

    with monkeypatch.context() as patch:
        patch.setattr(ledger, "_write", crash)
        child = os.fork()
        if child == 0:
            ledger.record_fixture(
                root, observation, generation=1, checkpoint=checkpoint
            )
            os._exit(18)
        assert os.waitstatus_to_exitcode(os.waitpid(child, 0)[1]) == 17
    intent = root / ledger.SLOT / ledger.INTENT
    before = intent.read_bytes()
    assert len(before) == 15
    assert (
        ledger.reconcile(root, observation, checkpoint=checkpoint)["reason"]
        == "record_invalid"
    )
    assert (
        ledger.record_fixture(root, observation, generation=1, checkpoint=checkpoint)[
            "reason"
        ]
        == "slot_already_exists"
    )
    assert intent.read_bytes() == before


def test_concurrent_process_refused(ledger, attempt, observation):
    root, checkpoint = attempt
    with ledger._root(root, True) as lock_fd:
        child = os.fork()
        if child == 0:
            os.close(lock_fd)
            result = ledger.record_fixture(
                root, observation, generation=1, checkpoint=checkpoint
            )
            os._exit(
                0 if result["reason"] == "ledger_unavailable_or_interrupted" else 1
            )
        assert os.waitstatus_to_exitcode(os.waitpid(child, 0)[1]) == 0
        assert list(root.iterdir()) == []


def test_other_output_slot_and_symlink_root(ledger, attempt, observation, tmp_path):
    root, checkpoint = attempt
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    assert (
        ledger.record_fixture(other, observation, generation=1, checkpoint=checkpoint)[
            "reason"
        ]
        == "checkpoint_mismatch"
    )
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)
    assert (
        ledger.record_fixture(alias, observation, generation=1, checkpoint=checkpoint)[
            "local_integrity"
        ]
        == "UNKNOWN"
    )
    assert list(other.iterdir()) == list(root.iterdir()) == []


@pytest.mark.parametrize(
    "attack", ["symlink", "hardlink", "swap", "permissions", "slot_copy"]
)
def test_reconcile_detects_path_substitution(
    ledger, attempt, observation, monkeypatch, attack
):
    root, checkpoint = attempt
    completed = record(ledger, root, observation, checkpoint)
    slot = root / ledger.SLOT
    receipt = slot / ledger.RECEIPT
    if attack == "symlink":
        receipt.rename(slot / "saved")
        receipt.symlink_to("saved")
        (slot / "saved").rename(root.parent / "saved")
    elif attack == "hardlink":
        os.link(receipt, root.parent / "saved")
    elif attack == "permissions":
        receipt.chmod(0o644)
    elif attack == "slot_copy":
        previous = root.parent / "previous"
        slot.rename(previous)
        slot.mkdir(mode=0o700)
        for name in (ledger.INTENT, ledger.RECEIPT):
            replacement = slot / name
            replacement.write_bytes((previous / name).read_bytes())
            replacement.chmod(0o600)
    else:
        read = ledger._read

        def swap(fd, name):
            raw, stamp = read(fd, name)
            if name == ledger.RECEIPT:
                receipt.rename(root.parent / "saved")
                receipt.write_bytes(raw)
                receipt.chmod(0o600)
            return raw, stamp

        monkeypatch.setattr(ledger, "_read", swap)
    assert (
        ledger.reconcile(root, observation, checkpoint=completed)["local_integrity"]
        == "UNKNOWN"
    )


def test_direct_execution_is_inert(ledger):
    assert not hasattr(ledger, "generate")
    with pytest.raises(ledger.Blocked, match="trusted_generation_unavailable"):
        importlib.import_module("final_recipe").generate()


def test_filesystem_unavailable_is_redacted(ledger, attempt, observation, monkeypatch):
    root, checkpoint = attempt
    completed = record(ledger, root, observation, checkpoint)

    def denied(*_args):
        raise PermissionError("private checkpoint location")

    monkeypatch.setattr(ledger, "_checkpoint", denied)
    report = ledger.reconcile(root, observation, checkpoint=completed)
    blocked(report)
    assert report["local_integrity"] == "UNKNOWN"
    assert "private" not in repr(report)


def test_slot_swap_before_intent(ledger, attempt, observation, monkeypatch):
    root, checkpoint = attempt
    sync = os.fsync

    def swap(fd):
        sync(fd)
        slot = root / ledger.SLOT
        slot.rename(root.parent / "original-slot")
        slot.mkdir(mode=0o700)

    monkeypatch.setattr(os, "fsync", swap)
    report = ledger.record_fixture(
        root, observation, generation=1, checkpoint=checkpoint
    )
    blocked(report)
    assert report["reason"] == "slot_changed"
    assert list((root / ledger.SLOT).iterdir()) == []
    assert list((root.parent / "original-slot").iterdir()) == []
