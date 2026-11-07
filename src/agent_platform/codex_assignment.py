"""AP-CA/1 trusted-caller offline assignment advice; no worker or writer adapter."""

import re
import time
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from . import github_evidence as evidence
from . import issues, publisher, queue
from . import review_comment as review

MAX_AGE = 300
CODING_PERMISSIONS = (
    ("contents", "write"),
    ("metadata", "read"),
    ("pull_requests", "write"),
)


def need(value):
    if not value:
        raise ValueError("assignment_blocked")


def agent(value):
    need(type(value) is str and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", value))


@dataclass(frozen=True, slots=True)
class CodexAssignment:
    """Operator-origin pins, never deserialized from Issue/model/target JSON.

    Admission owns repository/Issue/scope/base identity. Installation account is
    the target owner; App.owner separately means registration owner. No PR exists
    yet, so no fabricated PR/HEAD is placed in a TargetProject.
    """

    admission: publisher.Admission
    base_branch: str
    agent_id: str
    assignment_id: str
    authorization_sha256: str
    issued_at: int
    expires_at: int
    coding_app: review.AppIdentity
    installation: review.InstallationIdentity
    reviewer_app: review.AppIdentity
    runtime: str = "codex"
    schema_version: int = 1

    def __post_init__(self):
        need(type(self.schema_version) is int and self.schema_version == 1)
        need(type(self.admission) is publisher.Admission)
        replace(self.admission)
        agent(self.agent_id)
        need(self.runtime == "codex")
        need(publisher.hex_digest(self.assignment_id))
        need(publisher.hex_digest(self.authorization_sha256))
        need(type(self.issued_at) is type(self.expires_at) is int)
        need(0 <= self.issued_at < self.expires_at <= self.issued_at + MAX_AGE)
        need(type(self.base_branch) is str)
        need(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", self.base_branch))
        need(self.base_branch not in {"HEAD", "FETCH_HEAD", "ORIG_HEAD", "MERGE_HEAD"})
        need(type(self.coding_app) is type(self.reviewer_app) is review.AppIdentity)
        need(type(self.installation) is review.InstallationIdentity)
        replace(self.coding_app)
        replace(self.reviewer_app)
        replace(self.installation)
        need(self.installation.identifier == self.coding_app.installation_id)
        need(self.installation.account.login == self.admission.repository.split("/")[0])
        need(self.coding_app.app_id != self.reviewer_app.app_id)
        need(self.coding_app.slug.casefold() != self.reviewer_app.slug.casefold())
        need(self.coding_app.installation_id != self.reviewer_app.installation_id)
        need(self.coding_app.bot.identifier != self.reviewer_app.bot.identifier)
        need(
            self.coding_app.bot.login.casefold()
            != self.reviewer_app.bot.login.casefold()
        )

    @property
    def owner(self):
        return self.installation.account

    @property
    def owner_type(self):
        return self.installation.account_type

    @property
    def allowed_repository_ids(self):
        return (self.admission.repo_id,)

    @property
    def digest(self):
        return publisher.digest(asdict(self))

    def for_project(self, project):
        """Check a later #62 review context; never convert to runtime authority."""
        need(type(project) is evidence.TargetProject)
        replace(self)
        replace(project)
        need(project.admission == self.admission)
        need(project.base_branch == self.base_branch)
        need(project.owner == self.installation.account)
        need(project.owner_type == self.installation.account_type)
        need(project.author == self.coding_app.bot)
        need(project.reviewers == (self.reviewer_app.bot,))
        reviewer_installation = review.InstallationIdentity(
            self.reviewer_app.installation_id, project.owner, project.owner_type
        )
        need(
            project.publication_context_sha256
            == review.publication_context(
                self.reviewer_app, reviewer_installation, self.coding_app.bot
            )
        )
        return project


@dataclass(frozen=True, slots=True)
class RetainedIntent:
    """Nonsecret facts from a separately trusted complete controller ledger."""

    assignment_id: str
    assignment_sha256: str
    repo_id: int
    issue_id: int
    state: str
    recorded_at: int

    def __post_init__(self):
        need(publisher.hex_digest(self.assignment_id))
        need(publisher.hex_digest(self.assignment_sha256))
        need(issues.positive_int(self.repo_id) and issues.positive_int(self.issue_id))
        need(self.state in {"UNKNOWN", "RESERVED", "PREPARED", "FINISHED"})
        need(type(self.recorded_at) is int and self.recorded_at >= 0)


@dataclass(frozen=True, slots=True)
class Inventory:
    """Complete global view for one agent, not a model-selected subset/lease.

    External completeness and durable history remain trusted-controller duties.
    This advice API cannot create, reserve, release or reconstruct that ledger.
    """

    agent_id: str
    assignments: tuple[CodexAssignment, ...]
    retained: tuple[RetainedIntent, ...]
    epoch: str
    observed_at: int
    complete: bool

    def __post_init__(self):
        agent(self.agent_id)
        need(
            type(self.assignments) is tuple
            and 0 < len(self.assignments) <= queue.MAX_ENTRIES
        )
        need(
            type(self.retained) is tuple and len(self.retained) <= queue.MAX_LOCAL_FILES
        )
        need(publisher.hex_digest(self.epoch))
        need(type(self.observed_at) is int and self.observed_at >= 0)
        need(type(self.complete) is bool)
        for item in self.assignments:
            need(type(item) is CodexAssignment)
            replace(item)
            need(item.agent_id == self.agent_id)
        for item in self.retained:
            need(type(item) is RetainedIntent)
            replace(item)
        need(len({a.assignment_id for a in self.assignments}) == len(self.assignments))
        need(len({a.assignment_id for a in self.retained}) == len(self.retained))


@dataclass(frozen=True, slots=True)
class IdentitySnapshot:
    """Fabricated authoritative metadata in tests, NOT a live identity proof."""

    assignment_sha256: str
    observed_at: int
    facts: review.InstallationFacts
    provenance: str = "synthetic_identity"


def _identity(assignment, snapshot, now):
    need(type(snapshot) is IdentitySnapshot)
    need(snapshot.provenance == "synthetic_identity")
    need(snapshot.assignment_sha256 == assignment.digest)
    need(
        type(snapshot.observed_at) is int and 0 <= now - snapshot.observed_at <= MAX_AGE
    )
    facts = snapshot.facts
    need(type(facts) is review.InstallationFacts)
    need(type(facts.app) is review.AppIdentity)
    need(type(facts.installation) is review.InstallationIdentity)
    replace(facts.app)
    replace(facts.installation)
    need(facts.app == assignment.coding_app)
    need(facts.installation == assignment.installation)
    need(facts.repository_ids == assignment.allowed_repository_ids)
    need(facts.permissions == CODING_PERMISSIONS)
    need(facts.owner_type == assignment.coding_app.owner_type)
    need(
        facts.repository_selection == "selected" and facts.token_kind == "installation"
    )
    need(facts.project_sha256 is None)  # Pre-PR assignment, not a review receipt.
    need(type(facts.issued_at) is type(facts.expires_at) is int)
    need(0 <= facts.issued_at <= now < facts.expires_at <= facts.issued_at + 3600)


class _Reads(issues.GitHub):
    """Existing pagination over a fixed read-only, synthetic endpoint inventory."""

    def __init__(self, api, assignment):
        super().__init__(assignment.admission.repository)
        need(api is not None and api.provenance == "synthetic_assignment_snapshot")
        need(api.repository == assignment.admission.repository)
        need(api.repo_id == assignment.admission.repo_id)
        self.api = api
        self.issue = f"/issues/{assignment.admission.issue}"

    def get(self, suffix="", query=None):
        need(suffix in {"", "/branches/main", self.issue, self.issue + "/events"})
        if suffix.endswith("/events"):
            need(type(query) is dict and set(query) == {"page", "per_page"})
            need(type(query["page"]) is int and 1 <= query["page"] <= issues.MAX_PAGES)
            need(query["per_page"] == issues.PAGE_SIZE)
        else:
            need(query is None)
        need(self.requests < issues.MAX_REQUESTS and time.monotonic() < self.deadline)
        self.requests += 1
        result = self.api.get(suffix, query)
        need(time.monotonic() < self.deadline)
        need(len(publisher.encoded(result)) <= issues.OUTPUT_LIMIT)
        need(type(result) is tuple and len(result) == 2)
        return result


def _observed_context(reads, assignment):
    pin = assignment.admission
    metadata, link = reads.get()
    need(link is None and type(metadata) is dict)
    need(type(metadata.get("id")) is int and metadata["id"] == pin.repo_id)
    need(metadata.get("full_name") == pin.repository)
    need(metadata.get("default_branch") == assignment.base_branch)
    owner = metadata.get("owner")
    need(
        type(owner) is dict
        and owner.get("type") == assignment.installation.account_type
    )
    need(evidence._principal(owner) == assignment.installation.account)
    raw, link = reads.get(reads.issue)
    need(link is None and type(raw) is dict)
    # Assignment/assignee text is drift evidence only, not task selection.
    assignees = raw.get("assignees")
    need(type(assignees) is list and len(assignees) <= 16)
    seen = [evidence._principal(who) for who in assignees]
    need(len({who.identifier for who in seen}) == len(seen))
    need(len({who.login.casefold() for who in seen}) == len(seen))
    need(not seen or seen == [assignment.coding_app.bot])
    branch, link = reads.get("/branches/main")
    need(link is None and type(branch) is dict and branch.get("name") == "main")
    need(type(branch.get("commit")) is dict)
    need(branch["commit"].get("sha") == pin.base_sha)
    return publisher.digest({"repository": metadata, "issue": raw, "branch": branch})


def advise(
    root: Path,
    assignment,
    inventory,
    *,
    expected_agent,
    actors,
    identity=None,
    api=None,
    now,
):
    """Read-only eligibility advice. No reservation, preparation or launch effect.

    Capture/plan reuse secure admission and complete checkpoint/guard/worktree
    checks. Main-only inherited queue paths stay blocked for other branches.
    All supplied policy/history/identity callbacks belong to the trusted caller.
    """
    result = {
        "schema_version": 1,
        "status": "BLOCKED",
        "reason": "assignment_unavailable",
        "evidence": "VERIFIED_OFFLINE",
        "live_app_identity": "NOT_RUN",
        "live_activity": "unknown",
        "assignment_sha256": None,
        "inventory_sha256": None,
        "queue_plan_sha256": None,
        "reserved": False,
        "prepare_authorized": False,
        "launch_allowed": False,
        "resume_authorized": False,
        "publish_authorized": False,
        "runtime_exit_code": 13,
    }
    started = time.monotonic()
    try:
        need(type(assignment) is CodexAssignment and type(inventory) is Inventory)
        replace(assignment)
        replace(inventory)
        agent(expected_agent)
        need(type(now) is int and now >= 0)
        need(inventory.complete is True and inventory.agent_id == expected_agent)
        need(assignment.agent_id == expected_agent)
        need(0 <= now - inventory.observed_at <= MAX_AGE)
        need(
            inventory.assignments == (assignment,)
        )  # Conflicts never auto-prioritized.
        need(assignment.issued_at <= now < assignment.expires_at)
        need(issues.timestamp(assignment.admission.scope_revision).timestamp() <= now)
        need(assignment.base_branch == "main")  # No branch fallback/prepare expansion.
        for old in inventory.retained:
            need(old.recorded_at <= now)
            need(old.assignment_id != assignment.assignment_id)
            need(old.assignment_sha256 != assignment.digest)
            need(
                (old.repo_id, old.issue_id)
                != (assignment.admission.repo_id, assignment.admission.issue_id)
            )
            need(old.state == "FINISHED")  # Expiry never frees unresolved intent.
        inventory_digest = publisher.digest(asdict(inventory))
        if identity is None:
            result.update(
                status="IDENTITY_UNVERIFIED", reason="coding_identity_unverified"
            )
            return result
        _identity(assignment, identity, now)
        reads = _Reads(api, assignment)
        need(type(api.observed_at) is int and 0 <= now - api.observed_at <= MAX_AGE)
        before = _observed_context(reads, assignment)
        policy = queue.Policy((queue.Entry(assignment.admission),))
        captured = queue.capture(reads, policy, actors)
        need(
            all(
                o.admitted and o.scope_matches and o.is_issue
                for o in captured.observations
            )
        )
        planned = queue.plan(root, captured)
        need(
            planned["status"] == "advisory"
            and planned["reason"] == "idle_snapshot_only"
        )
        need(planned["candidate_order"] == [assignment.admission.issue])
        need(planned["next_candidate"] == assignment.admission.issue)
        need(_observed_context(reads, assignment) == before)
        current = now + int(time.monotonic() - started)
        need(current < assignment.expires_at)
        need(0 <= current - inventory.observed_at <= MAX_AGE)
        _identity(assignment, identity, current)
        need(type(api.observed_at) is int and 0 <= current - api.observed_at <= MAX_AGE)
        need(publisher.digest(asdict(inventory)) == inventory_digest)
        result.update(
            status="OFFLINE_ELIGIBLE_ADVICE",
            reason="single_assignment_snapshot",
            assignment_sha256=assignment.digest,
            inventory_sha256=inventory_digest,
            queue_plan_sha256=planned["plan_sha256"],
        )
    except Exception:
        # No raw Issue/model/transport/error text, identities, paths or secrets.
        pass
    return result
