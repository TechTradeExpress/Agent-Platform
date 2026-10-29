"""Typed trusted notification facts and fixed presentation; no delivery hooks."""

from dataclasses import asdict, dataclass
from enum import StrEnum

from agent_platform import cli, codex, issues, prepare, publisher, state, task_status


class NotificationError(Exception):
    def __init__(self):
        super().__init__("notification_unavailable")


def need(value):
    if not value:
        raise NotificationError()


class Kind(StrEnum):
    ACCEPTED = "accepted"
    BLOCKED = "blocked"
    STARTED = "started"
    PROGRESS = "progress"
    PAUSED = "paused"
    FAILED = "failed"
    NEEDS_HUMAN = "needs_human"
    REVIEW_REQUESTED = "review_requested"
    DRAFT_PR_CREATED = "draft_pr_created"
    CI_RESULT = "ci_result"
    REVIEW_COMPLETED = "review_completed"
    READY = "ready_for_review"
    HUMAN_MERGED = "human_merged"


class Result(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    CANCELLED = "cancelled"
    CHANGES_REQUIRED = "changes_required"


class Severity(StrEnum):
    MILESTONE = "milestone"
    ERROR = "error"
    REVIEW = "review"
    PROGRESS = "progress"


LOCAL_KINDS = {
    "READY": (Kind.ACCEPTED,),
    "STARTING": (Kind.STARTED,),
    "RUNNING": (Kind.PROGRESS,),
    "PAUSED": (Kind.PAUSED, Kind.FAILED),
    "NEEDS_HUMAN": (Kind.NEEDS_HUMAN, Kind.BLOCKED),
    "COMPLETED": (Kind.PROGRESS, Kind.REVIEW_REQUESTED),
}
GITHUB_KINDS = {
    Kind.DRAFT_PR_CREATED,
    Kind.CI_RESULT,
    Kind.REVIEW_COMPLETED,
    Kind.READY,
    Kind.HUMAN_MERGED,
}


@dataclass(frozen=True, slots=True)
class NotificationEvent:
    kind: Kind
    repo_id: int
    repository: str
    issue: int
    sha: str
    evidence_sha256: str
    scope_sha256: str
    generation: int | None = None
    phase: str | None = None
    pr_number: int | None = None
    result: Result | None = None
    public_repository: bool = False

    def __post_init__(self):
        need(
            type(self.kind) is Kind
            and issues.positive_int(self.repo_id)
            and issues.positive_int(self.issue)
        )
        need(type(self.repository) is str)
        try:
            need(
                cli.parse_origin("https://github.com/" + self.repository)
                == self.repository
            )
        except cli.InspectionError:
            raise NotificationError() from None
        need(
            type(self.sha) is str
            and prepare.SHA.fullmatch(self.sha)
            and publisher.hex_digest(self.evidence_sha256)
            and publisher.hex_digest(self.scope_sha256)
            and type(self.public_repository) is bool
        )
        if self.kind in GITHUB_KINDS:
            need(
                issues.positive_int(self.pr_number)
                and self.generation is None
                and self.phase is None
            )
            if self.kind == Kind.CI_RESULT:
                need(
                    type(self.result) is Result
                    and self.result in {Result.PASS, Result.FAIL, Result.CANCELLED}
                )
            elif self.kind == Kind.REVIEW_COMPLETED:
                need(
                    type(self.result) is Result
                    and self.result in {Result.PASS, Result.CHANGES_REQUIRED}
                )
            else:
                need(self.result is None)
        else:
            need(
                type(self.phase) is str
                and self.phase in LOCAL_KINDS
                and self.kind in LOCAL_KINDS[self.phase]
                and issues.positive_int(self.generation)
                and self.pr_number is None
                and self.result is None
                and self.public_repository is False
            )

    @property
    def key(self):
        logical = asdict(self)
        # Receipt refresh/visibility changes do not create a new logical milestone.
        logical.pop("evidence_sha256")
        logical.pop("public_repository")
        return publisher.digest({"notification_schema": 1, **logical})

    @property
    def severity(self):
        if self.kind == Kind.PROGRESS:
            return Severity.PROGRESS
        if self.kind in {Kind.BLOCKED, Kind.PAUSED, Kind.FAILED, Kind.NEEDS_HUMAN} or (
            self.kind == Kind.CI_RESULT and self.result != Result.PASS
        ):
            return Severity.ERROR
        if self.kind in {Kind.REVIEW_REQUESTED, Kind.REVIEW_COMPLETED, Kind.READY}:
            return Severity.REVIEW
        return Severity.MILESTONE


def checkpoint_event(admission, source, record, *, kind=None):
    """Trusted controller supplies stable validated source/checkpoint snapshots."""
    need(type(admission) is publisher.Admission)
    try:
        task_status.validate_record(record, source, admission.issue, admission.repo_id)
        need(all(record[k] == v for k, v in asdict(admission).items()))
        allowed = LOCAL_KINDS[record["phase"]]
        kind = allowed[0] if kind is None else kind
        need(type(kind) is Kind and kind in allowed)
        return NotificationEvent(
            kind,
            admission.repo_id,
            admission.repository,
            admission.issue,
            admission.base_sha,
            publisher.digest(record),
            admission.scope_sha256,
            record["generation"],
            record["phase"],
        )
    except (
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        issues.AdmissionError,
        publisher.PlanError,
        state.PrepareError,
        codex.ProtocolError,
    ):
        raise NotificationError() from None


@dataclass(frozen=True, slots=True)
class GitHubEvidence:
    """Separately trusted collector assertion, not a GitHub/model JSON parser."""

    admission: publisher.Admission
    kind: Kind
    pr_number: int
    sha: str
    receipt_sha256: str
    result: Result | None = None
    public_repository: bool = False
    independent_review: bool = False
    human_merge: bool = False

    def __post_init__(self):
        need(
            type(self.admission) is publisher.Admission
            and type(self.kind) is Kind
            and self.kind in GITHUB_KINDS
        )
        need(type(self.independent_review) is bool and type(self.human_merge) is bool)
        need(self.independent_review == (self.kind == Kind.REVIEW_COMPLETED))
        need(self.human_merge == (self.kind == Kind.HUMAN_MERGED))
        self.event()

    def event(self):
        return NotificationEvent(
            self.kind,
            self.admission.repo_id,
            self.admission.repository,
            self.admission.issue,
            self.sha,
            self.receipt_sha256,
            self.admission.scope_sha256,
            pr_number=self.pr_number,
            result=self.result,
            public_repository=self.public_repository,
        )


@dataclass(frozen=True, slots=True)
class Preferences:
    enabled: bool = False
    chat_id: int | None = None
    repositories: tuple[int, ...] = ()
    severities: tuple[Severity, ...] = (
        Severity.MILESTONE,
        Severity.ERROR,
        Severity.REVIEW,
    )
    include_public_links: bool = False
    min_interval: int = 5
    progress_interval: int = 60
    max_attempts: int = 3

    def __post_init__(self):
        need(type(self.enabled) is bool and type(self.include_public_links) is bool)
        need(
            self.chat_id is None
            or type(self.chat_id) is int
            and 0 < self.chat_id < 2**52
        )
        need(
            type(self.repositories) is tuple
            and len(self.repositories) <= 32
            and all(issues.positive_int(n) for n in self.repositories)
            and len(set(self.repositories)) == len(self.repositories)
        )
        need(
            type(self.severities) is tuple
            and 0 < len(self.severities) <= 4
            and all(type(s) is Severity for s in self.severities)
            and len(set(self.severities)) == len(self.severities)
        )
        need(
            type(self.min_interval) is int
            and 1 <= self.min_interval <= 3600
            and type(self.progress_interval) is int
            and 30 <= self.progress_interval <= 86400
            and type(self.max_attempts) is int
            and 1 <= self.max_attempts <= 3
        )
        need(not self.enabled or self.chat_id is not None and bool(self.repositories))


LABELS = {
    Kind.ACCEPTED: "Task accepted in recorded local state.",
    Kind.BLOCKED: "Task blocked; operator attention required.",
    Kind.STARTED: "Task start intent recorded; live activity unverified.",
    Kind.PROGRESS: "Checkpoint progress recorded; live activity unverified.",
    Kind.PAUSED: "Task paused in recorded local state.",
    Kind.FAILED: "Task turn failed in recorded local state.",
    Kind.NEEDS_HUMAN: "Task requires human reconciliation.",
    Kind.REVIEW_REQUESTED: "Review requested for recorded completed task.",
    Kind.DRAFT_PR_CREATED: "Draft PR created, according to trusted GitHub evidence.",
    Kind.CI_RESULT: "CI result recorded by trusted GitHub evidence.",
    Kind.REVIEW_COMPLETED: "Independent review result recorded.",
    Kind.READY: "PR ready for review, according to trusted GitHub evidence.",
    Kind.HUMAN_MERGED: "PR human-merged, according to trusted GitHub evidence.",
}


@dataclass(frozen=True, slots=True)
class SafeNotification:
    event: NotificationEvent
    include_public_links: bool = False

    def __post_init__(self):
        need(
            type(self.event) is NotificationEvent
            and type(self.include_public_links) is bool
        )
        need(len(self.text.encode()) <= 768)

    @property
    def text(self):
        e = self.event
        lines = [
            "Agent Platform",
            f"Repository ID: {e.repo_id}; Issue: {e.issue}",
            LABELS[e.kind],
        ]
        if e.generation is not None:
            lines.append(f"Recorded checkpoint: {e.phase}; generation: {e.generation}")
        if e.pr_number is not None:
            lines.append(f"PR: {e.pr_number}")
        if e.result is not None:
            lines.append(f"Result: {e.result.value.upper()}")
        if self.include_public_links and e.public_repository:
            lines.append(f"https://github.com/{e.repository}/issues/{e.issue}")
            lines.append(f"https://github.com/{e.repository}/pull/{e.pr_number}")
        return "\n".join(lines)


def format_event(event, preferences=None):
    preferences = Preferences() if preferences is None else preferences
    need(type(event) is NotificationEvent and type(preferences) is Preferences)
    return SafeNotification(event, preferences.include_public_links)
