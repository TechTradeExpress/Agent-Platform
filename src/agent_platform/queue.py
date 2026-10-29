"""Bounded offline queue advice. No scheduler, authorization or GitHub writer."""

import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal, TypedDict

from agent_platform import (
    cli,
    codex,
    issues,
    prepare,
    publisher,
    recovery,
    state,
    task_status,
)

MAX_ENTRIES = 8
MAX_DEPENDENCIES = 8
MAX_LOCAL_FILES = 128

QueueStatus = Literal[
    "waiting",
    "eligible_candidate",
    "blocked",
    "active",
    "under_review",
    "done",
    "unknown",
]


class DependencyResult(TypedDict):
    issue: int
    status: QueueStatus


class Evaluation(TypedDict):
    issue: int
    status: QueueStatus
    reason: str
    priority: int
    dependencies: list[DependencyResult]


class QueueError(Exception):
    """Fixed diagnostic only; no input text crosses the output boundary."""


def require(value):
    if not value:
        raise QueueError("invalid_queue_evidence")


def sha(value):
    return type(value) is str and prepare.SHA.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class Dependency:
    repository: str
    issue: int

    def __post_init__(self):
        require(issues.positive_int(self.issue))
        require(type(self.repository) is str and len(self.repository) <= 200)
        require(
            cli.parse_origin("https://github.com/" + self.repository) == self.repository
        )


@dataclass(frozen=True, slots=True)
class Entry:
    """Operator-supplied pins/dependencies, never extracted from Issue prose."""

    admission: publisher.Admission
    dependencies: tuple[Dependency, ...] = ()
    priority: int = 100

    def __post_init__(self):
        require(type(self.admission) is publisher.Admission)
        require(type(self.dependencies) is tuple)
        require(len(self.dependencies) <= MAX_DEPENDENCIES)
        require(all(type(d) is Dependency for d in self.dependencies))
        require(type(self.priority) is int and 0 <= self.priority <= 100)
        require(len(set(self.dependencies)) == len(self.dependencies))


@dataclass(frozen=True, slots=True)
class Policy:
    entries: tuple[Entry, ...]

    def __post_init__(self):
        require(type(self.entries) is tuple and 0 < len(self.entries) <= MAX_ENTRIES)
        require(all(type(e) is Entry for e in self.entries))
        require(len({e.admission.issue for e in self.entries}) == len(self.entries))
        first = self.entries[0].admission
        require(
            all(
                (e.admission.repo_id, e.admission.repository, e.admission.base_sha)
                == (first.repo_id, first.repository, first.base_sha)
                for e in self.entries
            )
        )


@dataclass(frozen=True, slots=True)
class PullRequest:
    """Separately trusted stable GitHub receipt, NOT parsed from task files/text.

    The collector must verify native Issue linkage, both repository identities,
    base branch, full merge state, and stable re-reads of the exact reviewed HEAD.
    This offline type checks consistency, not authenticity of that collector.
    """

    admission: publisher.Admission
    number: int
    base_repository_id: int
    base_repository: str
    base_branch: str
    head_sha: str
    expected_head_sha: str
    state: Literal["open", "closed"]
    merged: bool
    merge_sha: str | None
    merged_at: str | None
    linked_issues: tuple[int, ...]
    default_branch_sha: str

    def __post_init__(self):
        require(type(self.admission) is publisher.Admission)
        require(issues.positive_int(self.number))
        require(issues.positive_int(self.base_repository_id))
        require(type(self.base_repository) is str and len(self.base_repository) <= 200)
        require(type(self.base_branch) is str and len(self.base_branch) <= 100)
        require(sha(self.head_sha) and sha(self.expected_head_sha))
        require(sha(self.default_branch_sha))
        require(type(self.state) is str and self.state in {"open", "closed"})
        require(type(self.merged) is bool)
        require(self.merge_sha is None or sha(self.merge_sha))
        require(
            type(self.linked_issues) is tuple and len(self.linked_issues) <= MAX_ENTRIES
        )
        require(all(issues.positive_int(n) for n in self.linked_issues))
        if self.merged_at is not None:
            issues.timestamp(self.merged_at)


@dataclass(frozen=True, slots=True)
class Observation:
    issue: int
    state: Literal["open", "closed"]
    scope_matches: bool
    admitted: bool
    is_issue: bool = True
    pin: publisher.Admission | None = None

    def __post_init__(self):
        require(issues.positive_int(self.issue))
        require(type(self.pin) is publisher.Admission and self.pin.issue == self.issue)
        require(type(self.state) is str and self.state in {"open", "closed"})
        require(
            type(self.scope_matches) is bool
            and type(self.admitted) is bool
            and type(self.is_issue) is bool
        )


@dataclass(frozen=True, slots=True)
class Snapshot:
    """Only capture() produces validated admission observations for this API.

    Like publisher receipts, this is an in-process trusted-controller boundary,
    not a signature, saved-file authority, or freshness promise about GitHub now.
    """

    policy: Policy
    observations: tuple[Observation, ...]
    pull_requests: tuple[PullRequest, ...]
    digest: str


def _repository(api, pin):
    repo_id, canonical = issues.identity(api, pin.repository)
    metadata, _ = api.get()
    branch, _ = api.get("/branches/main")
    require(type(metadata) is dict and type(branch) is dict)
    require(type(branch.get("commit")) is dict)
    require((repo_id, canonical) == (pin.repo_id, pin.repository))
    require(metadata.get("id") == repo_id and metadata.get("full_name") == canonical)
    require(metadata.get("default_branch") == "main" and branch.get("name") == "main")
    require(branch["commit"].get("sha") == pin.base_sha)


def capture(api, policy, actors, *, pull_requests=()):
    """Read a supplied bounded admission API twice; no client/network by default.

    Existing GitHub.get/pages limits and provenance checks apply unchanged.
    PR receipts are supplied separately by a trusted collector; this function
    does not add PR endpoints or retrieve/interpret Issue dependency prose.
    """
    require(type(policy) is Policy)
    require(type(actors) is tuple and 0 < len(actors) <= 16)
    require(all(type(a) is str and issues.LOGIN.fullmatch(a) for a in actors))
    require(type(pull_requests) is tuple and len(pull_requests) <= MAX_ENTRIES)
    require(all(type(p) is PullRequest for p in pull_requests))
    numbers = {e.admission.issue for e in policy.entries}
    require(all(p.admission.issue in numbers for p in pull_requests))
    require(len({p.admission.issue for p in pull_requests}) == len(pull_requests))
    pin = policy.entries[0].admission
    trusted = {a.casefold() for a in actors}

    def read():
        _repository(api, pin)
        observations, receipts = [], []
        for entry in sorted(policy.entries, key=lambda e: e.admission.issue):
            expected = entry.admission
            item, actor, reason, history = issues.validate_candidate(
                api, pin.repository, expected.issue, trusted
            )
            actual = publisher.Admission(
                **prepare.admission_record(
                    pin.repo_id, pin.repository, pin.base_sha, item, history
                )
            )
            scope_matches = all(
                getattr(actual, k) == getattr(expected, k)
                for k in ("issue_id", "scope_sha256", "scope_revision")
            )
            observations.append(
                Observation(
                    expected.issue,
                    item["state"],
                    scope_matches,
                    reason is None and actor is not None and actual == expected,
                    not item["pr"],
                    expected,
                )
            )
            # Retain all reread evidence only as a digest, never output raw prose.
            receipts.append(
                publisher.digest({"issue": item, "history": actual.admission_sha256})
            )
        _repository(api, pin)
        return tuple(observations), tuple(receipts)

    first = read()
    require(read() == first)
    digest = publisher.digest(
        {
            "policy": [
                {
                    **asdict(entry),
                    "dependencies": [
                        asdict(d)
                        for d in sorted(
                            entry.dependencies, key=lambda d: (d.repository, d.issue)
                        )
                    ],
                }
                for entry in sorted(policy.entries, key=lambda e: e.admission.issue)
            ],
            "receipts": first[1],
            "pull_requests": [
                asdict(p)
                for p in sorted(pull_requests, key=lambda p: p.admission.issue)
            ],
        }
    )
    return Snapshot(policy, first[0], pull_requests, digest)


def _inventory():
    """Scan only the existing nonsecret checkpoint namespace, across repositories."""
    store = prepare.HOME / ".local/state/agent-platform"
    if not state.private_directory(store, store, create=False):
        return ()
    found = []
    with os.scandir(store) as listing:
        parents = []
        for item in listing:
            require(len(parents) < MAX_LOCAL_FILES)
            require(bool(re.fullmatch(r"[1-9][0-9]{0,18}", item.name)))
            parents.append(item.name)
    for name in sorted(parents):
        parent = store / name
        require(state.private_directory(parent, store, create=False))
        with os.scandir(parent) as listing:
            for item in listing:
                require(len(found) < MAX_LOCAL_FILES)
                match = re.fullmatch(
                    r"issue-([1-9][0-9]{0,18})\.(json(?:\.tmp-[A-Za-z0-9_-]{1,128})?|execution-guard)",
                    item.name,
                )
                # Record guards/temporary writes too; shared status validates them.
                require(match is not None and issues.positive_int(int(match[1])))
                found.append(
                    (
                        int(name),
                        int(match[1]),
                        match[2],
                        task_status.fingerprint(item.stat(follow_symlinks=False)),
                    )
                )
    return tuple(sorted(found))


def _local(root, pin, lock_fd):
    state.no_symlinks(root)
    state.no_symlinks(root / ".git")
    require(root.resolve() == root)
    source = prepare.source_snapshot(cli.inspect(root))
    require(
        source["repository"] == pin.repository and source["base_sha"] == pin.base_sha
    )
    before = _inventory()
    if before:
        # Even COMPLETED is not exactly-once external-effects reconciliation.
        local = []
        tasks = sorted({(item[0], item[1]) for item in before})
        require(len(tasks) <= MAX_ENTRIES)
        for repo_id, number in tasks:
            if repo_id != pin.repo_id:
                return "unresolved_local_state", (), source, before
            report = task_status.empty_report(number)
            report["host_lock"] = "free"
            details = {}
            report, _ = task_status._observe(root, number, report, lock_fd, details)
            local.append(
                {
                    "issue": number,
                    "recorded_state": report["recorded_state"],
                    "recovery": recovery._classification(report, details),
                    "live_activity": "unknown",
                }
            )
        return "local_task_requires_human_review", tuple(local), source, before
    require(prepare.worktrees(root) == {str(root): (pin.base_sha, "refs/heads/main")})
    return "idle_snapshot_only", (), source, before


def _pr_status(root, entry, pr):
    pin = entry.admission
    if (
        pr.admission != pin
        or pr.base_repository_id != pin.repo_id
        or pr.base_repository != pin.repository
        or pr.base_branch != "main"
        or pr.default_branch_sha != pin.base_sha
        or pr.head_sha != pr.expected_head_sha
        or pr.linked_issues != (pin.issue,)
    ):
        return "unknown", "conflicting_pr_evidence"
    if pr.state == "open" and not pr.merged and pr.merge_sha is pr.merged_at is None:
        return "under_review", "open_pr_not_merged"
    if (
        pr.state != "closed"
        or not pr.merged
        or pr.merge_sha is None
        or pr.merged_at is None
    ):
        return "blocked", "merge_unverified"
    try:
        # Receipt must refer to a commit actually present on this exact main.
        kind = prepare.line(prepare.git(root, "cat-file", "-t", pr.merge_sha))
        require(kind == "commit")
        prepare.git(root, "merge-base", "--is-ancestor", pr.merge_sha, pin.base_sha)
    except (state.PrepareError, QueueError):
        return "unknown", "merge_ancestry_unverified"
    return "done", "verified_merged_dependency"


def _evaluate(root, snapshot, local) -> list[Evaluation]:
    entries = {e.admission.issue: e for e in snapshot.policy.entries}
    observations = {o.issue: o for o in snapshot.observations}
    require(set(entries) == set(observations))
    prs = {p.admission.issue: p for p in snapshot.pull_requests}
    results = {}
    visiting = set()

    def visit(number):
        if number in results:
            return results[number]
        if number in visiting:
            return "blocked", "dependency_cycle"
        visiting.add(number)
        entry, observed = entries[number], observations[number]
        status, reason = "waiting", "dependencies_pending"
        if observed.pin != entry.admission:
            status, reason = "unknown", "stale_observation_pin"
        elif not observed.is_issue:
            status, reason = "unknown", "not_an_issue"
        elif not observed.scope_matches:
            status, reason = "unknown", "stale_scope_or_issue_identity"
        elif number in prs:
            status, reason = _pr_status(root, entry, prs[number])
            if (observed.state == "open" and status == "done") or (
                observed.state == "closed" and status == "under_review"
            ):
                status, reason = "unknown", "contradictory_issue_pr_state"
        elif observed.state == "closed":
            status, reason = "blocked", "closed_without_verified_merge"
        elif not observed.admitted:
            status, reason = "blocked", "admission_unverified"
        else:
            dependencies = []
            for dep in sorted(
                entry.dependencies, key=lambda d: (d.repository, d.issue)
            ):
                if dep.repository != entry.admission.repository:
                    dependencies.append(("blocked", "cross_repository_dependency"))
                elif dep.issue == number:
                    dependencies.append(("blocked", "self_dependency"))
                elif dep.issue not in entries:
                    dependencies.append(("unknown", "missing_dependency"))
                else:
                    dependencies.append(visit(dep.issue))
            if any(s in {"blocked", "unknown"} for s, _ in dependencies):
                status, reason = (
                    "blocked",
                    next(r for s, r in dependencies if s in {"blocked", "unknown"}),
                )
            elif all(s == "done" for s, _ in dependencies):
                status, reason = "eligible_candidate", "admitted_dependencies_satisfied"
        visiting.remove(number)
        results[number] = status, reason
        return results[number]

    for number in sorted(entries):
        visit(number)
    active = {item["issue"] for item in local}
    # Stable topological display; unresolved cycles form a deterministic tail.
    remaining, order = set(entries), []

    def key(n):
        return entries[n].priority, n

    while remaining:
        ready = [
            n
            for n in remaining
            if not any(
                d.repository == entries[n].admission.repository and d.issue in remaining
                for d in entries[n].dependencies
            )
        ]
        if not ready:
            order.extend(sorted(remaining, key=key))
            break
        number = min(ready, key=key)
        order.append(number)
        remaining.remove(number)
    rows = []
    for number in order:
        status, reason = results[number]
        if number in active:
            status, reason = "active", "recorded_local_task_not_live_proof"
        rows.append(
            {
                "issue": number,
                "status": status,
                "reason": reason,
                "priority": entries[number].priority,
                "dependencies": [
                    {
                        "issue": dep.issue,
                        "status": results.get(dep.issue, ("unknown",))[0]
                        if dep.repository == entries[number].admission.repository
                        else "unknown",
                    }
                    for dep in sorted(
                        entries[number].dependencies,
                        key=lambda d: (d.repository, d.issue),
                    )
                ],
            }
        )
    return rows


def plan(cwd: Path, snapshot: Snapshot):
    """Bounded sanitized JSON; never nominates without one stable local host lock.

    Snapshot and policy are trusted in-process inputs, never deserialized from
    repository files. No snapshot is execution authority or a signed receipt.
    """
    result = {
        "schema_version": 1,
        "status": "blocked",
        "reason": "invalid_queue_evidence",
        "entries": [],
        "candidate_order": [],
        "next_candidate": None,
        "local_tasks": [],
        "live_activity": "unknown",
        "freshness": "unverified",
        "snapshot_sha256": None,
        "launch_allowed": False,
        "operator_authorization": "required",
        "runtime_isolation": "not_checked_subscription_blocked",
    }
    try:
        require(type(snapshot) is Snapshot and type(snapshot.policy) is Policy)
        require(publisher.hex_digest(snapshot.digest))
        require(type(snapshot.observations) is tuple)
        require(len(snapshot.observations) == len(snapshot.policy.entries))
        require(all(type(o) is Observation for o in snapshot.observations))
        require(
            len({o.issue for o in snapshot.observations}) == len(snapshot.observations)
        )
        require(type(snapshot.pull_requests) is tuple)
        require(len(snapshot.pull_requests) <= MAX_ENTRIES)
        require(all(type(p) is PullRequest for p in snapshot.pull_requests))
        require(
            len({p.admission.issue for p in snapshot.pull_requests})
            == len(snapshot.pull_requests)
        )
        pin = snapshot.policy.entries[0].admission
        with state.host_lock(create=False) as fd:
            lock_path = state.LOCK_DIR / "prepare.lock"
            lock_info = task_status.fingerprint(os.fstat(fd))
            require(task_status.fingerprint(lock_path.lstat()) == lock_info)
            reason, local, source, inventory = _local(cwd, pin, fd)
            trees = prepare.worktrees(cwd)
            rows = _evaluate(cwd, snapshot, local)
            require(prepare.worktrees(cwd) == trees)
            require(_inventory() == inventory)
            require(prepare.source_snapshot(cli.inspect(cwd)) == source)
            require(task_status.fingerprint(lock_path.lstat()) == lock_info)
            candidates = [
                r["issue"]
                for r in sorted(rows, key=lambda row: (row["priority"], row["issue"]))
                if r["status"] == "eligible_candidate"
            ]
            result.update(
                status="advisory",
                reason=reason,
                entries=rows,
                local_tasks=list(local),
                candidate_order=candidates,
                next_candidate=candidates[0]
                if candidates and reason == "idle_snapshot_only"
                else None,
                freshness="stable_snapshot_not_live",
                snapshot_sha256=snapshot.digest,
            )
    except state.PrepareError as exc:
        result["reason"] = (
            "lock_busy" if exc.code == 10 else "local_evidence_unverifiable"
        )
    except (OSError, cli.InspectionError):
        result["reason"] = "local_evidence_unavailable"
    except (
        QueueError,
        issues.AdmissionError,
        publisher.PlanError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        codex.ProtocolError,
    ):
        result["reason"] = "invalid_queue_evidence"
    require(len(publisher.encoded(result)) <= 16 * 1024)
    result["plan_sha256"] = publisher.digest(result)
    return result
