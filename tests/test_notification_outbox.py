"""Durability, replay and security tests; scripted fake delivery only."""

import json
import os
import socket
import subprocess
from dataclasses import asdict, replace

import pytest
from test_notifications import ack
from test_notifications import admitted as admitted
from test_notifications import event as event
from test_prepare import task as task
from test_publisher import completed as completed

from agent_platform import prepare, state
from agent_platform.notification_outbox import MAX_ENTRIES, Outbox
from agent_platform.notifications import (
    Kind,
    NotificationError,
    Preferences,
    Severity,
    format_event,
)
from agent_platform.telegram_fake import (
    FakeFault,
    FakeReply,
    FakeTelegram,
    Outcome,
    TelegramRequest,
)


@pytest.fixture
def box(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setattr(prepare, "HOME", home)
    policy = Preferences(
        enabled=True, chat_id=12345, repositories=(12,), severities=tuple(Severity)
    )
    outbox = Outbox(policy)
    outbox.initialize()
    return outbox


def success(box, event):
    return FakeTelegram(
        (
            ack(
                TelegramRequest(
                    box.preferences.chat_id, format_event(event, box.preferences)
                )
            ),
        )
    )


def test_default_disabled_touches_no_storage_or_transport(monkeypatch, tmp_path, event):
    monkeypatch.setattr(prepare, "HOME", tmp_path / "must-not-create")

    def forbidden(*a, **k):
        pytest.fail("disabled notifier accessed storage/network/process")

    monkeypatch.setattr(os, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    fake = FakeTelegram()
    box = Outbox()
    assert box.initialize().status == "disabled"
    assert box.enqueue(event, now=100).status == "disabled"
    assert box.attempt_once("not-even-validated", fake, now=100).status == "disabled"
    assert box.snapshot() == () and fake.requests == []
    assert not (tmp_path / "must-not-create").exists()


def test_durable_enqueue_delivery_restart_and_duplicate_suppression(box, event):
    queued = box.enqueue(event, now=100)
    assert queued.outcome == Outcome.PENDING and queued.mode == "offline_fake"
    assert state.load_checkpoint(box.path)["mode"] == "offline_fake"
    assert box.enqueue(event, now=100).status == "duplicate"
    fake = success(box, event)
    assert box.attempt_once(queued.key, fake, now=100).outcome == Outcome.DELIVERED
    restarted = Outbox(box.preferences)
    restarted.initialize()
    assert restarted.enqueue(event, now=101).outcome == Outcome.DELIVERED
    assert restarted.attempt_once(queued.key, fake, now=105).status == "duplicate"
    assert len(fake.requests) == 1
    assert restarted.snapshot()[0].attempts == 1
    assert len(box.path.read_bytes()) <= state.CHECKPOINT_LIMIT
    assert "chat_id" not in repr(asdict(restarted.snapshot()[0]))


def test_refreshed_receipt_does_not_create_duplicate_logical_event(box, event):
    original = box.enqueue(event, now=100)
    refreshed = replace(event, evidence_sha256="f" * 64, public_repository=True)
    assert refreshed.key == event.key
    assert box.enqueue(refreshed, now=100).key == original.key
    assert len(box.snapshot()) == 1


@pytest.mark.parametrize("fault", [FakeFault.TIMEOUT, FakeFault.ERROR])
def test_ambiguous_delivery_never_replayed(box, event, fault):
    queued = box.enqueue(event, now=100)
    fake = FakeTelegram((fault,))
    first = box.attempt_once(queued.key, fake, now=100)
    assert first.outcome == Outcome.UNKNOWN
    restarted = Outbox(box.preferences)
    assert (
        restarted.attempt_once(queued.key, success(box, event), now=1000).status
        == "reconciliation_required"
    )
    assert len(fake.requests) == 1


def test_durable_unknown_intent_precedes_fake_call_and_survives_crash(
    box, event, monkeypatch
):
    key = box.enqueue(event, now=100).key

    class Crash(BaseException):
        pass

    def crash(self, request):
        stored = state.load_checkpoint(box.path)["entries"][key]
        assert (
            stored["outcome"] == "unknown" and stored["category"] == "dispatch_intent"
        )
        raise Crash

    monkeypatch.setattr(FakeTelegram, "send", crash)
    with pytest.raises(Crash):
        box.attempt_once(key, FakeTelegram(), now=100)
    assert Outbox(box.preferences).snapshot()[0].outcome == Outcome.UNKNOWN
    assert (
        Outbox(box.preferences).attempt_once(key, FakeTelegram(), now=1000).status
        == "reconciliation_required"
    )


@pytest.mark.parametrize("point", ["intent_before", "intent_after", "outcome_before"])
def test_storage_failure_does_not_repeat_an_uncertain_send(
    box, event, monkeypatch, point
):
    key = box.enqueue(event, now=100).key
    original = state.write_checkpoint
    calls = []
    fake = success(box, event)

    def failing(path, data, **kwargs):
        entry = data["entries"][key]
        calls.append(entry["outcome"])
        if point == "intent_before" and entry["outcome"] == "unknown":
            raise OSError("secret storage detail")
        if point == "outcome_before" and entry["outcome"] == "delivered":
            raise OSError("secret storage detail")
        original(path, data, **kwargs)
        if point == "intent_after" and entry["outcome"] == "unknown":
            raise OSError("secret storage detail")

    monkeypatch.setattr(state, "write_checkpoint", failing)
    with pytest.raises(NotificationError, match="^notification_unavailable$"):
        box.attempt_once(key, fake, now=100)
    monkeypatch.setattr(state, "write_checkpoint", original)
    stored = Outbox(box.preferences).snapshot()[0]
    assert len(fake.requests) == (point == "outcome_before")
    assert stored.outcome == (
        Outcome.PENDING if point == "intent_before" else Outcome.UNKNOWN
    )
    if stored.outcome == Outcome.UNKNOWN:
        assert (
            box.attempt_once(key, FakeTelegram(), now=1000).status
            == "reconciliation_required"
        )


def test_explicit_definitely_not_sent_retries_are_bounded_no_loop(box, event):
    key = box.enqueue(event, now=100).key
    fake = FakeTelegram((FakeFault.NOT_SENT,) * 3)
    result = box.attempt_once(key, fake, now=100)
    assert result.outcome == Outcome.PENDING and result.next_attempt_at == 130
    assert len(fake.requests) == 1
    assert box.attempt_once(key, fake, now=129).status == "deferred"
    assert box.attempt_once(key, fake, now=130).next_attempt_at == 190
    exhausted = box.attempt_once(key, fake, now=190)
    assert exhausted.attempts == 3 and exhausted.next_attempt_at is None
    assert box.attempt_once(key, fake, now=1000).status == "retry_exhausted"
    assert len(fake.requests) == 3


def test_rate_limit_is_persisted_for_all_queue_entries(box, event):
    first = box.enqueue(event, now=100)
    other = replace(event, pr_number=8)
    second = box.enqueue(other, now=100)
    fake = FakeTelegram(
        (
            FakeReply(
                429,
                b'{"ok":false,"error_code":429,"parameters":{"retry_after":60},"description":"secret"}',
            ),
        )
    )
    assert box.attempt_once(first.key, fake, now=100).next_attempt_at == 160
    restarted = Outbox(box.preferences)
    assert restarted.attempt_once(second.key, fake, now=159).status == "deferred"
    assert len(fake.requests) == 1
    assert (
        restarted.attempt_once(second.key, success(box, other), now=160).outcome
        == Outcome.DELIVERED
    )
    assert "secret" not in box.path.read_text()


def test_permanent_rejection_is_not_retried(box, event):
    key = box.enqueue(event, now=100).key
    fake = FakeTelegram(
        (
            FakeReply(
                403,
                b'{"ok":false,"error_code":403,"description":"secret token detail"}',
            ),
        )
    )
    assert box.attempt_once(key, fake, now=100).outcome == Outcome.PENDING
    assert box.attempt_once(key, fake, now=1000).status == "retry_exhausted"
    assert len(fake.requests) == 1
    assert "secret" not in box.path.read_text()


def test_minimum_send_interval_and_clock_rollback(box, event):
    first = box.enqueue(event, now=100)
    other = replace(event, pr_number=8)
    second = box.enqueue(other, now=100)
    assert (
        box.attempt_once(first.key, success(box, event), now=100).outcome
        == Outcome.DELIVERED
    )
    fake = success(box, other)
    assert box.attempt_once(second.key, fake, now=104).status == "deferred"
    assert fake.requests == []
    assert box.attempt_once(second.key, fake, now=105).outcome == Outcome.DELIVERED
    with pytest.raises(NotificationError):
        box.enqueue(replace(event, pr_number=9), now=104)


def test_progress_enqueue_throttling_survives_restart(box, event):
    progress = replace(
        event, kind=Kind.PROGRESS, pr_number=None, generation=4, phase="RUNNING"
    )
    assert box.enqueue(progress, now=100).status == "queued"
    later = replace(progress, generation=7)
    assert Outbox(box.preferences).enqueue(later, now=159).status == "suppressed"
    assert box.enqueue(later, now=160).status == "queued"


def test_preferences_suppress_unapproved_repos_and_progress(
    tmp_path, monkeypatch, event
):
    monkeypatch.setattr(prepare, "HOME", tmp_path)
    policy = Preferences(enabled=True, chat_id=12345, repositories=(12,))
    box = Outbox(policy)
    box.initialize()
    assert box.enqueue(replace(event, repo_id=13), now=100).status == "suppressed"
    progress = replace(
        event, kind=Kind.PROGRESS, pr_number=None, generation=4, phase="RUNNING"
    )
    assert box.enqueue(progress, now=100).status == "suppressed"
    assert box.snapshot() == ()


def test_capacity_retains_dedup_tombstones_and_never_evicts(box, event):
    for i in range(MAX_ENTRIES):
        e = replace(event, pr_number=i + 1)
        key = box.enqueue(e, now=100 + i * 5).key
        box.attempt_once(key, success(box, e), now=100 + i * 5)
    before = box.path.read_bytes()
    assert len(box.snapshot()) == MAX_ENTRIES
    with pytest.raises(NotificationError):
        box.enqueue(replace(event, pr_number=999), now=1000)
    assert box.path.read_bytes() == before
    assert (
        box.enqueue(replace(event, pr_number=1), now=1000).outcome == Outcome.DELIVERED
    )


@pytest.mark.parametrize(
    "fault",
    [
        "queue_symlink",
        "queue_hardlink",
        "queue_mode",
        "dir_symlink",
        "dir_mode",
        "lock_symlink",
        "lock_hardlink",
        "lock_mode",
        "unknown_file",
        "temp",
        "corrupt",
        "duplicate_json",
        "huge",
        "changed_chat",
        "changed_policy",
        "event_tamper",
    ],
)
def test_unsafe_storage_and_schema_fail_closed(box, event, tmp_path, fault):
    key = box.enqueue(event, now=100).key
    if fault == "queue_symlink":
        box.path.rename(tmp_path / "original")
        box.path.symlink_to(tmp_path / "original")
    elif fault == "queue_hardlink":
        os.link(box.path, tmp_path / "alias")
    elif fault == "queue_mode":
        box.path.chmod(0o644)
    elif fault == "dir_symlink":
        box.directory.rename(tmp_path / "original")
        box.directory.symlink_to(tmp_path / "original", target_is_directory=True)
    elif fault == "dir_mode":
        box.directory.chmod(0o755)
    elif fault.startswith("lock"):
        lock = box.directory / "outbox.lock"
        if fault == "lock_symlink":
            lock.rename(tmp_path / "original")
            lock.symlink_to(tmp_path / "original")
        elif fault == "lock_hardlink":
            os.link(lock, tmp_path / "alias")
        else:
            lock.chmod(0o644)
    elif fault == "unknown_file":
        (box.directory / "auth.json").write_text("secret")
    elif fault == "temp":
        box.path.with_name(box.path.name + ".tmp-interrupted").write_text("secret")
    elif fault in {"corrupt", "duplicate_json", "huge"}:
        box.path.write_bytes(
            {
                "corrupt": b"{",
                "duplicate_json": b'{"version":1,"version":1}',
                "huge": b"x" * (state.CHECKPOINT_LIMIT + 1),
            }[fault]
        )
    elif fault == "changed_chat":
        box = Outbox(replace(box.preferences, chat_id=999))
    elif fault == "changed_policy":
        box = Outbox(replace(box.preferences, min_interval=10))
    else:
        data = json.loads(box.path.read_text())
        data["entries"][key]["event"]["pr_number"] = 999
        box.path.write_text(json.dumps(data))
    fake = success(box, event)
    with pytest.raises(NotificationError, match="^notification_unavailable$"):
        box.attempt_once(key, fake, now=100)
    assert fake.requests == []


@pytest.mark.parametrize("missing", ["queue", "lock"])
def test_reinitialize_cannot_silently_replace_lost_history_or_mutex(box, missing):
    path = box.path if missing == "queue" else box.directory / "outbox.lock"
    path.unlink()
    with pytest.raises(NotificationError):
        Outbox(box.preferences).initialize()


def test_contention_and_lock_replacement_fail_closed(box, event):
    other = Outbox(box.preferences)
    with box._locked():
        with pytest.raises(NotificationError):
            other.enqueue(event, now=100)
    assert box.snapshot() == ()


def test_only_scripted_fake_transport_is_accepted(box, event):
    key = box.enqueue(event, now=100).key

    class Arbitrary:
        def send(self, *args):
            pytest.fail("arbitrary transport called")

    class Subclass(FakeTelegram):
        def send(self, *args):
            pytest.fail("subclass called")

    for transport in (Arbitrary(), Subclass()):
        with pytest.raises(NotificationError):
            box.attempt_once(key, transport, now=100)


def test_no_network_processes_or_task_checkpoint_mutation(completed, monkeypatch):
    record = completed["checkpoint"].read_bytes()
    box = Outbox(Preferences(enabled=True, chat_id=12345, repositories=(12,)))
    from agent_platform import cli
    from agent_platform.notifications import checkpoint_event

    event = checkpoint_event(
        completed["admission"],
        prepare.source_snapshot(cli.inspect(completed["root"])),
        state.load_checkpoint(completed["checkpoint"]),
        kind=Kind.REVIEW_REQUESTED,
    )

    def forbidden(*args, **kwargs):
        pytest.fail("no processes or network")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    original = state.write_checkpoint

    def only_outbox(path, *args, **kwargs):
        assert path == box.path
        return original(path, *args, **kwargs)

    monkeypatch.setattr(state, "write_checkpoint", only_outbox)
    box.initialize()
    key = box.enqueue(event, now=100).key
    assert (
        box.attempt_once(key, success(box, event), now=100).outcome == Outcome.DELIVERED
    )
    assert completed["checkpoint"].read_bytes() == record


@pytest.mark.parametrize("point", ["file_fsync", "replace", "directory_fsync"])
def test_atomic_claim_failure_never_sends_or_replays(box, event, monkeypatch, point):
    key = box.enqueue(event, now=100).key
    original_fsync, original_replace, original_sync = (
        os.fsync,
        os.replace,
        state.sync_directory,
    )

    def fsync(fd):
        if point == "file_fsync":
            raise OSError("secret file sync error")
        return original_fsync(fd)

    def replace_file(a, b):
        if point == "replace":
            raise OSError("secret replace error")
        return original_replace(a, b)

    def directory_sync(path):
        if point == "directory_fsync":
            raise OSError("secret directory sync error")
        return original_sync(path)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "replace", replace_file)
    monkeypatch.setattr(state, "sync_directory", directory_sync)
    fake = success(box, event)
    with pytest.raises(NotificationError):
        box.attempt_once(key, fake, now=100)
    assert fake.requests == []
    monkeypatch.setattr(os, "fsync", original_fsync)
    monkeypatch.setattr(os, "replace", original_replace)
    monkeypatch.setattr(state, "sync_directory", original_sync)
    if point == "directory_fsync":
        assert (
            Outbox(box.preferences).attempt_once(key, fake, now=1000).status
            == "reconciliation_required"
        )
    else:
        with pytest.raises(NotificationError):
            Outbox(box.preferences).attempt_once(key, fake, now=1000)


def test_missing_mutex_never_recreated_even_by_failed_initialize(box, event):
    key = box.enqueue(event, now=100).key
    lock = box.directory / "outbox.lock"
    lock.unlink()
    with pytest.raises(NotificationError):
        Outbox(box.preferences).initialize()
    assert not lock.exists()
    with pytest.raises(NotificationError):
        Outbox(box.preferences).attempt_once(key, success(box, event), now=100)


def test_raw_transport_exception_is_persisted_only_as_uncertainty(
    box, event, monkeypatch
):
    key = box.enqueue(event, now=100).key

    def error(*args):
        raise TimeoutError("secret token /private/auth request-url")

    monkeypatch.setattr(FakeTelegram, "send", error)
    report = box.attempt_once(key, FakeTelegram(), now=100)
    assert report.outcome == Outcome.UNKNOWN
    assert "secret" not in repr(report) and "secret" not in box.path.read_text()


def test_schema_corruption_is_not_a_new_delivery_attempt(box, event):
    key = box.enqueue(event, now=100).key
    data = json.loads(box.path.read_text())
    data["entries"][key]["attempts"] = True
    box.path.write_text(json.dumps(data))
    with pytest.raises(NotificationError):
        box.attempt_once(key, success(box, event), now=100)
