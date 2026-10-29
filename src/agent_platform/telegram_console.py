"""Offline Telegram prototype: strict parsing, replay journal, no action dispatcher."""

import json
import os
import re
from dataclasses import asdict, dataclass, field
from enum import StrEnum

from agent_platform import cli, issues, prepare, publisher, queue, recovery, state
from agent_platform import task_status as task_status

MAX_UPDATE_BYTES = 8192
MAX_ISSUE = 2**31 - 1
MAX_INTENTS = 16


class ConsoleError(Exception):
    def __init__(self):
        super().__init__("console_unavailable")


def need(value):
    if not value:
        raise ConsoleError()


def numeric(value):
    return type(value) is int and 0 < value < 2**52


def clock(value):
    return type(value) is int and 0 < value < 2**63 - 86400


def issue_number(value):
    return type(value) is int and 0 < value <= MAX_ISSUE


@dataclass(frozen=True, slots=True)
class Principal:
    sender: int
    chat: int

    def __post_init__(self):
        need(numeric(self.sender) and numeric(self.chat))


@dataclass(frozen=True, slots=True)
class Policy:
    repository_id: int
    repository: str
    bot_id: int
    principals: tuple[Principal, ...]
    status_issue: int | None = None
    max_age: int = 120
    enabled: bool = False

    def __post_init__(self):
        need(issues.positive_int(self.repository_id) and numeric(self.bot_id))
        need(type(self.repository) is str)
        need(
            cli.parse_origin("https://github.com/" + self.repository) == self.repository
        )
        need(type(self.principals) is tuple and 0 < len(self.principals) <= 8)
        need(
            all(
                type(p) is Principal and p.sender != self.bot_id
                for p in self.principals
            )
        )
        need(len(set(self.principals)) == len(self.principals))
        need(self.status_issue is None or issue_number(self.status_issue))
        need(type(self.max_age) is int and 1 <= self.max_age <= 300)
        need(type(self.enabled) is bool)

    @property
    def key(self):
        data = asdict(self)
        data["principals"] = [
            asdict(p) for p in sorted(self.principals, key=lambda p: (p.sender, p.chat))
        ]
        return publisher.digest(data)


@dataclass(frozen=True, slots=True)
class BotContext:
    """Trusted fake frontend assertion, never a field of untrusted Update JSON."""

    bot_id: int
    policy_sha256: str

    def __post_init__(self):
        need(numeric(self.bot_id) and publisher.hex_digest(self.policy_sha256))


class Command(StrEnum):
    HELP = "/help"
    STATUS = "/status"
    QUEUE = "/queue"
    ISSUE = "/issue"


class Operation(StrEnum):
    PAUSE = "pause"
    HOLD = "hold"
    RESUME = "resume"
    APPROVE = "approve"


@dataclass(frozen=True, slots=True)
class Update:
    identifier: int
    date: int
    principal: Principal
    digest: str
    command: Command | None = None
    issue: int | None = None
    callback_token: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class CurrentTask:
    reference: recovery.RecoveryReference
    head_sha: str

    def __post_init__(self):
        need(type(self.reference) is recovery.RecoveryReference)
        need(issue_number(self.reference.admission.issue))
        need(type(self.head_sha) is str and prepare.SHA.fullmatch(self.head_sha))


@dataclass(frozen=True, slots=True)
class CallbackIntent:
    """Trusted future-intent assertion; never action authority or issued by chat."""

    token: str = field(repr=False)
    principal: Principal
    bot_id: int
    operation: Operation
    task: CurrentTask
    issued_at: int
    expires_at: int

    def __post_init__(self):
        need(publisher.hex_digest(self.token))
        need(type(self.principal) is Principal and numeric(self.bot_id))
        need(type(self.operation) is Operation and type(self.task) is CurrentTask)
        need(clock(self.issued_at) and clock(self.expires_at))
        need(0 < self.expires_at - self.issued_at <= 300)


def callback_matches(update, intent, current, policy, now):
    """Pure dry-run comparison. True still grants NO execution/confirmation right."""
    return (
        type(update) is Update
        and type(intent) is CallbackIntent
        and type(current) is CurrentTask
        and type(policy) is Policy
        and policy.enabled
        and clock(now)
        and clock(update.date)
        and 0 <= now - update.date <= policy.max_age
        and update.callback_token == intent.token
        and update.principal == intent.principal
        and update.principal in policy.principals
        and intent.bot_id == policy.bot_id
        and intent.task == current
        and current.reference.admission.repo_id == policy.repository_id
        and current.reference.admission.repository == policy.repository
        and intent.issued_at <= now < intent.expires_at
    )


def _object(value, keys):
    need(type(value) is dict and set(value) == keys)


def _user(value, *, bot):
    _object(value, {"id", "is_bot"})
    need(numeric(value["id"]) and value["is_bot"] is bot)
    return value["id"]


def _chat(value):
    _object(value, {"id", "type"})
    need(numeric(value["id"]) and value["type"] == "private")
    return value["id"]


def parse(raw, policy, context, now):
    """Strict minimal synthetic Bot API subset; no normalization or prose parsing."""
    need(type(policy) is Policy and policy.enabled)
    need(type(context) is BotContext and context.bot_id == policy.bot_id)
    need(context.policy_sha256 == policy.key and clock(now))
    need(type(raw) is bytes and 0 < len(raw) <= MAX_UPDATE_BYTES)
    try:
        data = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=issues.unique_object,
            parse_constant=issues.invalid_constant,
        )
        need(
            type(data) is dict
            and set(data) in ({"update_id", "message"}, {"update_id", "callback_query"})
        )
        identifier = data["update_id"]
        need(type(identifier) is int and 0 < identifier < 2**31)
        token, command, number = None, None, None
        if "message" in data:
            message = data["message"]
            _object(message, {"message_id", "date", "from", "chat", "text"})
            sender = _user(message["from"], bot=False)
            text = message["text"]
            need(type(text) is str and len(text) <= 32)
            if text in ("/help", "/status", "/queue"):
                command = Command(text)
            else:
                match = re.fullmatch(r"/issue ([1-9][0-9]{0,9})", text)
                need(match is not None)
                number = int(match[1])
                need(issue_number(number))
                command = Command.ISSUE
        else:
            callback = data["callback_query"]
            _object(callback, {"id", "from", "message", "chat_instance", "data"})
            need(
                type(callback["id"]) is str
                and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", callback["id"])
            )
            need(
                type(callback["chat_instance"]) is str
                and re.fullmatch(r"[0-9]{1,32}", callback["chat_instance"])
            )
            sender = _user(callback["from"], bot=False)
            message = callback["message"]
            _object(message, {"message_id", "date", "from", "chat"})
            need(_user(message["from"], bot=True) == policy.bot_id)
            token = callback["data"]
            need(publisher.hex_digest(token))  # 64-byte opaque key; no command data.
        need(issues.positive_int(message["message_id"]))
        principal = Principal(sender, _chat(message["chat"]))
        need(principal in policy.principals)
        date = message["date"]
        need(clock(date) and 0 <= now - date <= policy.max_age)
        return Update(
            identifier, date, principal, publisher.digest(data), command, number, token
        )
    except (ValueError, TypeError, KeyError, RecursionError, issues.AdmissionError):
        raise ConsoleError() from None


@dataclass(frozen=True, slots=True)
class IssueView:
    issue: int
    phase: str | None

    def __post_init__(self):
        need(issue_number(self.issue))
        need(
            self.phase is None
            or type(self.phase) is str
            and self.phase in task_status.PHASES
        )


@dataclass(frozen=True, slots=True)
class QueueView:
    issue: int
    status: str

    def __post_init__(self):
        need(issue_number(self.issue))
        need(
            type(self.status) is str
            and self.status
            in {
                "waiting",
                "eligible_candidate",
                "blocked",
                "active",
                "under_review",
                "done",
                "unknown",
            }
        )


@dataclass(frozen=True, slots=True)
class Reports:
    """Trusted controller's safe projections; not a target/transport JSON format."""

    repository_id: int
    repository: str
    issues: tuple[IssueView, ...] = ()
    queue: tuple[QueueView, ...] | None = None

    def __post_init__(self):
        need(issues.positive_int(self.repository_id))
        need(
            type(self.repository) is str
            and cli.parse_origin("https://github.com/" + self.repository)
            == self.repository
        )
        need(type(self.issues) is tuple and len(self.issues) <= 8)
        need(all(type(v) is IssueView for v in self.issues))
        need(len({v.issue for v in self.issues}) == len(self.issues))
        if self.queue is not None:
            need(type(self.queue) is tuple and len(self.queue) <= queue.MAX_ENTRIES)
            need(all(type(v) is QueueView for v in self.queue))
            need(len({v.issue for v in self.queue}) == len(self.queue))


def collect_reports(root, policy, admissions=(), *, queue_snapshot=None):
    """Explicit trusted caller only; existing offline read-only abstractions."""
    need(type(policy) is Policy and type(admissions) is tuple and len(admissions) <= 8)
    views = []
    for admission in admissions:
        need(type(admission) is publisher.Admission)
        need(
            (admission.repo_id, admission.repository)
            == (policy.repository_id, policy.repository)
        )
        observed, _, details = task_status.inspect_local(root, admission.issue)
        phase = (
            observed["recorded_state"]
            if (
                observed["identity"] == "verified"
                and observed["checkpoint_validity"] == "valid"
                and details.get("admission") == asdict(admission)
            )
            else None
        )
        views.append(IssueView(admission.issue, phase))
    queued = None
    if queue_snapshot is not None:
        need(type(queue_snapshot) is queue.Snapshot)
        pin = queue_snapshot.policy.entries[0].admission
        need((pin.repo_id, pin.repository) == (policy.repository_id, policy.repository))
        report = queue.plan(root, queue_snapshot)
        if report["status"] == "advisory" and report["launch_allowed"] is False:
            queued = tuple(
                QueueView(r["issue"], r["status"]) for r in report["entries"]
            )
    return Reports(policy.repository_id, policy.repository, tuple(views), queued)


class Outcome(StrEnum):
    DISABLED = "disabled"
    REJECTED = "rejected"
    REPLAY = "replay"
    NEEDS_HUMAN = "needs_human"
    READ_ONLY = "read_only"
    UNAVAILABLE = "unavailable"
    DRY_RUN_ONLY = "dry_run_only"
    INITIALIZED = "initialized"


@dataclass(frozen=True, slots=True)
class Response:
    outcome: Outcome
    text: str
    mode: str = field(default="offline_fake", init=False)
    action_authorized: bool = field(default=False, init=False)
    launch_allowed: bool = field(default=False, init=False)
    resume_authorized: bool = field(default=False, init=False)

    def __post_init__(self):
        need(type(self.outcome) is Outcome and type(self.text) is str)
        need(len(self.text.encode()) <= 1024)


def _render(update, policy, reports):
    if update.command == Command.HELP:
        return Response(
            Outcome.READ_ONLY,
            "Commands: /help, /status, /queue, /issue N. "
            "Read-only; no action authority.",
        )
    if type(reports) is not Reports or (reports.repository_id, reports.repository) != (
        policy.repository_id,
        policy.repository,
    ):
        return Response(
            Outcome.UNAVAILABLE, "Trusted report unavailable; needs human review."
        )
    if update.command == Command.QUEUE:
        if reports.queue is None:
            return Response(Outcome.UNAVAILABLE, "Queue report unavailable.")
        text = "Recorded queue snapshot; advisory only; not live.\n"
        text += (
            "\n".join(f"Issue {v.issue}: {v.status}." for v in reports.queue)
            or "No entries in supplied snapshot."
        )
        return Response(Outcome.READ_ONLY, text)
    number = policy.status_issue if update.command == Command.STATUS else update.issue
    view = next((v for v in reports.issues if v.issue == number), None)
    if view is None or view.phase is None:
        return Response(
            Outcome.UNAVAILABLE, "Task status unavailable; needs human review."
        )
    return Response(
        Outcome.READ_ONLY,
        f"Issue {number}: recorded {view.phase}; live activity unknown. "
        "No launch or resume authority.",
    )


class Gateway:
    """One explicit offline request at a time. No token, transport or action hooks."""

    def __init__(self, policy, intents=()):
        need(type(policy) is Policy)
        need(type(intents) is tuple and len(intents) <= MAX_INTENTS)
        need(all(type(i) is CallbackIntent for i in intents))
        need(len({i.token for i in intents}) == len(intents))
        self.policy, self.intents = policy, intents
        self.intents_sha256 = publisher.digest(
            [asdict(i) for i in sorted(intents, key=lambda i: i.token)]
        )
        self.store = prepare.HOME / ".local/state/agent-platform-console"
        self.directory = self.store / str(policy.bot_id)
        self.path = self.directory / "replay.json"
        self.pending = self.directory / "pending.json"

    def _load(self, *, allow_pending=False):
        need(state.private_directory(self.directory, self.store, create=False))
        with os.scandir(self.directory) as listing:
            for count, entry in enumerate(listing, 1):
                need(count <= 4 and entry.name in {"replay.json", "pending.json"})
                need(allow_pending or entry.name != "pending.json")
        before = task_status.fingerprint(self.path.lstat())
        data = state.load_checkpoint(self.path)
        need(task_status.fingerprint(self.path.lstat()) == before)
        _object(
            data,
            {
                "version",
                "policy_sha256",
                "intents_sha256",
                "last_update_id",
                "last_digest",
                "clock",
                "generation",
                "used",
                "outcome",
            },
        )
        need(type(data["version"]) is int and data["version"] == 1)
        need(data["policy_sha256"] == self.policy.key)
        need(data["intents_sha256"] == self.intents_sha256)
        need(
            type(data["last_update_id"]) is int and 0 <= data["last_update_id"] < 2**31
        )
        need(publisher.hex_digest(data["last_digest"]) and clock(data["clock"]))
        need(issues.positive_int(data["generation"]))
        need(type(data["used"]) is list and len(data["used"]) <= MAX_INTENTS)
        need(all(publisher.hex_digest(k) for k in data["used"]))
        need(len(set(data["used"])) == len(data["used"]))
        need(
            type(data["outcome"]) is str
            and data["outcome"] in {v.value for v in Outcome}
        )
        return data, before

    def _save(self, data, previous, fd, lock):
        # Keep an independent durable intent across the cursor replacement.
        marker = {
            "policy_sha256": self.policy.key,
            "previous_sha256": publisher.digest(previous),
            "next_sha256": publisher.digest(data),
        }
        state.write_checkpoint(self.pending, marker)
        identity = task_status.fingerprint(self.pending.lstat())
        state.write_checkpoint(self.path, data, previous=previous)
        actual, _ = self._load(allow_pending=True)
        need(actual == data and self._lock_identity(fd) == lock)
        need(state.load_checkpoint(self.pending) == marker)
        need(task_status.fingerprint(self.pending.lstat()) == identity)
        # Remove only this transaction's verified marker, after durable cursor.
        self.pending.unlink()
        state.sync_directory(self.directory)

    def _lock_identity(self, fd):
        value = task_status.fingerprint(os.fstat(fd))
        need(
            task_status.fingerprint((state.LOCK_DIR / "prepare.lock").lstat()) == value
        )
        return value

    def initialize(self, context, *, last_update_id, now):
        if not self.policy.enabled:
            return Response(Outcome.DISABLED, "Offline console disabled.")
        try:
            need(
                type(context) is BotContext
                and context.bot_id == self.policy.bot_id
                and context.policy_sha256 == self.policy.key
            )
            need(
                clock(now)
                and type(last_update_id) is int
                and 0 <= last_update_id < 2**31
            )
            with state.host_lock(create=False) as fd:
                lock = self._lock_identity(fd)
                # Existing or partially created namespace is never reinitialized.
                state.no_symlinks(self.directory)
                need(not self.directory.exists())
                need(state.private_directory(self.store, self.store, create=True))
                self.directory.mkdir(mode=0o700)
                state.sync_directory(self.store)
                self._save(
                    {
                        "version": 1,
                        "policy_sha256": self.policy.key,
                        "intents_sha256": self.intents_sha256,
                        "last_update_id": last_update_id,
                        "last_digest": "0" * 64,
                        "clock": now,
                        "generation": 1,
                        "used": [],
                        "outcome": "initialized",
                    },
                    None,
                    fd,
                    lock,
                )
                need(self._lock_identity(fd) == lock)
                self._load()
            return Response(Outcome.INITIALIZED, "Offline replay evidence initialized.")
        except (
            ConsoleError,
            state.PrepareError,
            OSError,
            ValueError,
            TypeError,
            KeyError,
            issues.AdmissionError,
        ):
            return Response(
                Outcome.NEEDS_HUMAN, "Replay evidence unavailable; needs human review."
            )

    def handle(self, raw, context, *, now, reports=None, current=None):
        if not self.policy.enabled:
            return Response(Outcome.DISABLED, "Offline console disabled.")
        try:
            update = parse(raw, self.policy, context, now)
        except (ConsoleError, ValueError, TypeError):
            return Response(Outcome.REJECTED, "Request rejected.")
        try:
            with state.host_lock(create=False) as fd:
                lock = self._lock_identity(fd)
                previous, fingerprint = self._load()
                need(self._lock_identity(fd) == lock)
                need(now >= previous["clock"])
                if update.identifier <= previous["last_update_id"]:
                    return Response(
                        Outcome.REPLAY,
                        "Duplicate, conflicting or older update suppressed.",
                    )
                used = list(previous["used"])
                if update.callback_token is None:
                    result = _render(update, self.policy, reports)
                else:
                    result = Response(
                        Outcome.REJECTED,
                        "Protected callback rejected; no action authority.",
                    )
                    intent = next(
                        (i for i in self.intents if i.token == update.callback_token),
                        None,
                    )
                    if intent is not None and intent.principal == update.principal:
                        token_key = publisher.digest({"token": intent.token})
                        if token_key in used:
                            result = Response(
                                Outcome.REPLAY, "One-use callback already consumed."
                            )
                        else:
                            need(len(used) < MAX_INTENTS)
                            used.append(token_key)
                            if callback_matches(
                                update, intent, current, self.policy, now
                            ):
                                result = Response(
                                    Outcome.DRY_RUN_ONLY,
                                    "Dry-run proposal only. "
                                    "Protected actions remain disabled.",
                                )
                new = {
                    **previous,
                    "last_update_id": update.identifier,
                    "last_digest": update.digest,
                    "clock": now,
                    "generation": previous["generation"] + 1,
                    "used": used,
                    "outcome": result.outcome.value,
                }
                need(self._load() == (previous, fingerprint))
                need(self._lock_identity(fd) == lock)
                need(previous["generation"] < 2**63 - 1)
                self._save(new, previous, fd, lock)
                return result
        except (
            ConsoleError,
            state.PrepareError,
            OSError,
            ValueError,
            TypeError,
            KeyError,
            issues.AdmissionError,
        ):
            return Response(
                Outcome.NEEDS_HUMAN, "Replay evidence uncertain; needs human review."
            )


class FakeInbox:
    """Explicit bounded scripted deliveries only. No receive loop or HTTP client."""

    def __init__(self, updates, context):
        need(type(updates) is tuple and len(updates) <= 32)
        need(
            all(type(raw) is bytes and len(raw) <= MAX_UPDATE_BYTES for raw in updates)
        )
        need(type(context) is BotContext)
        self.updates, self.context = list(updates), context

    def deliver_one(self, gateway, *, now, reports=None, current=None):
        need(type(gateway) is Gateway and bool(self.updates))
        return gateway.handle(
            self.updates.pop(0), self.context, now=now, reports=reports, current=current
        )
