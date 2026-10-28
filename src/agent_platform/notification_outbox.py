"""Separate private bounded notification queue; explicit fake attempts only."""

import fcntl
import os
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field

from agent_platform import prepare, publisher, state
from agent_platform.notifications import (
    Kind,
    NotificationError,
    NotificationEvent,
    Preferences,
    Result,
    Severity,
    format_event,
    need,
)
from agent_platform.telegram_fake import (
    Category,
    Delivery,
    FakeTelegram,
    Outcome,
    TelegramRequest,
)

MAX_ENTRIES = 16


@dataclass(frozen=True, slots=True)
class Report:
    status: str
    outcome: Outcome | None = None
    key: str | None = None
    attempts: int = 0
    next_attempt_at: int | None = None
    category: str | None = None
    mode: str = field(default="offline_fake", init=False)


def restore_event(data):
    need(
        type(data) is dict and set(data) == set(NotificationEvent.__dataclass_fields__)
    )
    value = dict(data)
    value["kind"] = Kind(value["kind"])
    if value["result"] is not None:
        value["result"] = Result(value["result"])
    return NotificationEvent(**value)


class Outbox:
    def __init__(self, preferences=None):
        self.preferences = Preferences() if preferences is None else preferences
        need(type(self.preferences) is Preferences)
        # A sibling of task checkpoints, not a child of their numeric repo store.
        self.directory = prepare.HOME / ".local/state/agent-platform-notifications"
        self.path = self.directory / "outbox.json"
        self._fd = None

    @contextmanager
    def _locked(self, *, create=False):
        fd = None
        try:
            need(self._fd is None)
            need(state.private_directory(self.directory, self.directory, create=create))
            recovery_present = False
            with os.scandir(self.directory) as listing:
                count = 0
                for item in listing:
                    count += 1
                    recovery_present |= item.name != "outbox.lock"
                    need(
                        count <= 20
                        and (
                            item.name in {"outbox.json", "outbox.lock"}
                            or item.name.startswith("outbox.json.tmp-")
                        )
                    )
            lock = self.directory / "outbox.lock"
            fresh = False
            try:
                state.private_file(lock.lstat())
                lock_exists = True
            except FileNotFoundError:
                lock_exists = False
            need(lock_exists or create and not recovery_present)
            if create:
                try:
                    fd = os.open(
                        lock,
                        os.O_RDWR
                        | os.O_CREAT
                        | os.O_EXCL
                        | os.O_NOFOLLOW
                        | os.O_NONBLOCK,
                        0o600,
                    )
                    fresh = True
                except FileExistsError:
                    fd = os.open(lock, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
            else:
                fd = os.open(lock, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
            state.private_file(os.fstat(fd))
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._fd = fd
            self._check_lock()
            yield fresh
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            RecursionError,
            state.PrepareError,
            publisher.PlanError,
        ):
            raise NotificationError() from None
        finally:
            if fd is not None:
                self._fd = None
                os.close(fd)

    def _check_lock(self):
        info = os.fstat(self._fd)
        state.private_file(info)
        path = (self.directory / "outbox.lock").lstat()
        state.private_file(path)
        need((info.st_dev, info.st_ino) == (path.st_dev, path.st_ino))

    def _binding(self):
        return publisher.digest(asdict(self.preferences))

    def _key(self, event):
        return publisher.digest(
            {"chat_id": self.preferences.chat_id, "event": event.key}
        )

    def _load(self):
        self._check_lock()
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            info = None
        data = state.load_checkpoint(self.path)
        if data is None:
            need(info is None)
            return None
        after = self.path.lstat()
        need(
            info is not None
            and (
                info.st_dev,
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
        )
        need(
            set(data)
            == {
                "version",
                "mode",
                "chat_id",
                "policy_sha256",
                "clock",
                "next_send_at",
                "next_progress_at",
                "entries",
            }
        )
        need(
            type(data["version"]) is int
            and data["version"] == 1
            and data["mode"] == "offline_fake"
            and type(data["chat_id"]) is int
            and data["chat_id"] == self.preferences.chat_id
            and data["policy_sha256"] == self._binding()
        )
        for key in ("clock", "next_send_at", "next_progress_at"):
            need(type(data[key]) is int and 0 <= data[key] < 2**63)
        entries = data["entries"]
        need(type(entries) is dict and len(entries) <= MAX_ENTRIES)
        for key, entry in entries.items():
            need(
                publisher.hex_digest(key)
                and type(entry) is dict
                and set(entry)
                == {
                    "event",
                    "event_sha256",
                    "outcome",
                    "category",
                    "attempts",
                    "next_at",
                }
            )
            event = restore_event(entry["event"])
            need(entry["event_sha256"] == publisher.digest(asdict(event)))
            need(
                key == self._key(event)
                and event.repo_id in self.preferences.repositories
                and event.severity in self.preferences.severities
            )
            attempts = entry["attempts"]
            need(
                type(attempts) is int and 0 <= attempts <= self.preferences.max_attempts
            )
            need(type(entry["next_at"]) is int and 0 <= entry["next_at"] < 2**63)
            outcome, category = entry["outcome"], entry["category"]
            if attempts == 0:
                need(
                    outcome == "pending"
                    and category == "queued"
                    and entry["next_at"] == 0
                )
            elif outcome == "delivered":
                need(category == Category.DELIVERED and entry["next_at"] == 0)
            elif outcome == "unknown":
                need(
                    category
                    in {
                        "dispatch_intent",
                        Category.UNCERTAIN,
                        Category.INVALID_RESPONSE,
                    }
                    and entry["next_at"] == 0
                )
            else:
                need(
                    outcome == "pending"
                    and category
                    in {Category.NOT_SENT, Category.RATE_LIMITED, Category.REJECTED}
                )
                need(
                    entry["next_at"] == 0
                    if category == Category.REJECTED
                    or attempts >= self.preferences.max_attempts
                    else entry["next_at"] > 0
                )
        return data

    def _save(self, data, previous):
        self._check_lock()
        state.write_checkpoint(self.path, data, previous=previous)
        self._check_lock()

    def initialize(self):
        if not self.preferences.enabled:
            return Report("disabled")
        with self._locked(create=True) as fresh:
            old = self._load()
            need((old is None) == fresh)
            if old is None:
                self._save(
                    {
                        "version": 1,
                        "mode": "offline_fake",
                        "chat_id": self.preferences.chat_id,
                        "policy_sha256": self._binding(),
                        "clock": 0,
                        "next_send_at": 0,
                        "next_progress_at": 0,
                        "entries": {},
                    },
                    None,
                )
        return Report("initialized")

    def _read_at(self, now):
        need(type(now) is int and 0 <= now < 2**63 - 86400)
        data = self._load()
        need(data is not None and now >= data["clock"])
        return data

    @staticmethod
    def _copy(data):
        return {**data, "entries": {k: dict(v) for k, v in data["entries"].items()}}

    @staticmethod
    def _report(status, key, entry):
        return Report(
            status,
            Outcome(entry["outcome"]),
            key,
            entry["attempts"],
            entry["next_at"] or None,
            entry["category"],
        )

    def enqueue(self, event, *, now):
        if not self.preferences.enabled:
            return Report("disabled")
        need(type(event) is NotificationEvent)
        if (
            event.repo_id not in self.preferences.repositories
            or event.severity not in self.preferences.severities
        ):
            return Report("suppressed")
        key = self._key(event)
        with self._locked():
            old = self._read_at(now)
            if key in old["entries"]:
                return self._report("duplicate", key, old["entries"][key])
            if event.severity == Severity.PROGRESS and now < old["next_progress_at"]:
                return Report("suppressed")
            need(len(old["entries"]) < MAX_ENTRIES)
            new = self._copy(old)
            entry = {
                "event": asdict(event),
                "event_sha256": publisher.digest(asdict(event)),
                "outcome": "pending",
                "category": "queued",
                "attempts": 0,
                "next_at": 0,
            }
            new["entries"][key] = entry
            new["clock"] = now
            if event.severity == Severity.PROGRESS:
                new["next_progress_at"] = now + self.preferences.progress_interval
            self._save(new, old)
            return self._report("queued", key, entry)

    def attempt_once(self, key, transport, *, now):
        if not self.preferences.enabled:
            return Report("disabled")
        # This milestone accepts only our token-free scripted fake, never HTTP.
        need(type(transport) is FakeTelegram and publisher.hex_digest(key))
        with self._locked():
            old = self._read_at(now)
            need(key in old["entries"])
            entry = old["entries"][key]
            if entry["outcome"] != "pending":
                return self._report(
                    "duplicate"
                    if entry["outcome"] == "delivered"
                    else "reconciliation_required",
                    key,
                    entry,
                )
            if (
                entry["attempts"] >= self.preferences.max_attempts
                or entry["category"] == Category.REJECTED
            ):
                return self._report("retry_exhausted", key, entry)
            due = max(entry["next_at"], old["next_send_at"])
            if now < due:
                return Report("deferred", Outcome.PENDING, key, entry["attempts"], due)
            event = restore_event(entry["event"])
            request = TelegramRequest(
                self.preferences.chat_id, format_event(event, self.preferences)
            )
            intent = self._copy(old)
            active = intent["entries"][key]
            active.update(
                outcome="unknown",
                category="dispatch_intent",
                attempts=entry["attempts"] + 1,
                next_at=0,
            )
            intent.update(clock=now, next_send_at=now + self.preferences.min_interval)
            self._save(intent, old)  # Durable uncertainty BEFORE even fake I/O.
            try:
                result = transport.send(request)
                need(type(result) is Delivery)
            except Exception:
                result = Delivery(Outcome.UNKNOWN, Category.UNCERTAIN)
            self._check_lock()
            finished = self._copy(intent)
            final = finished["entries"][key]
            final.update(outcome=result.outcome.value, category=result.category.value)
            if (
                result.outcome == Outcome.PENDING
                and result.category != Category.REJECTED
            ):
                if result.category == Category.RATE_LIMITED:
                    delay = result.retry_after
                    finished["next_send_at"] = max(
                        finished["next_send_at"], now + delay
                    )
                else:
                    delay = min(30 * 2 ** (final["attempts"] - 1), 300)
                if final["attempts"] < self.preferences.max_attempts:
                    final["next_at"] = now + delay
            self._save(finished, intent)
            return self._report("attempted", key, final)

    def snapshot(self):
        if not self.preferences.enabled:
            return ()
        with self._locked():
            data = self._load()
            need(data is not None)
            return tuple(
                self._report("stored", key, entry)
                for key, entry in sorted(data["entries"].items())
            )
