"""Gate A: synthetic-only, human-authorized COMMENT policy. No live transport."""

import re
import time
from dataclasses import asdict, dataclass, replace
from enum import StrEnum

from agent_platform import github_evidence as evidence
from agent_platform import issues, publisher

MAX_BODY = 8192
MAX_AGE = 300
PERMISSIONS = (("metadata", "read"), ("pull_requests", "write"))


class PublicationError(Exception):
    def __init__(self):
        super().__init__("review_publication_blocked")


def need(value):
    if not value:
        raise PublicationError()


class Decision(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"


@dataclass(frozen=True, slots=True)
class AppIdentity:
    app_id: int
    slug: str
    installation_id: int
    owner: evidence.Principal
    bot: evidence.Principal
    owner_type: str = "Organization"

    def __post_init__(self):
        need(
            issues.positive_int(self.app_id)
            and issues.positive_int(self.installation_id)
        )
        need(
            type(self.owner) is evidence.Principal
            and type(self.bot) is evidence.Principal
        )
        need(self.owner_type in {"Organization", "User"})
        need(type(self.slug) is str and issues.LOGIN.fullmatch(self.slug))
        evidence.Principal(self.owner.identifier, self.owner.login)
        evidence.Principal(self.bot.identifier, self.bot.login)
        need(self.bot.login.casefold() == (self.slug + "[bot]").casefold())


@dataclass(frozen=True, slots=True)
class InstallationIdentity:
    identifier: int
    account: evidence.Principal
    account_type: str

    def __post_init__(self):
        need(issues.positive_int(self.identifier))
        need(type(self.account) is evidence.Principal)
        evidence.Principal(self.account.identifier, self.account.login)
        need(self.account_type in {"Organization", "User"})
        need(not self.account.login.endswith("[bot]"))


def publication_context(app, installation, author):
    """Nonsecret canonical binding, not an App/installation authentication proof."""
    need(type(app) is AppIdentity and type(installation) is InstallationIdentity)
    need(type(author) is evidence.Principal)
    return publisher.digest(
        {
            "app": asdict(app),
            "installation": asdict(installation),
            "author": asdict(author),
        }
    )


@dataclass(frozen=True, slots=True)
class Envelope:
    policy: evidence.Policy
    author: evidence.Principal
    app: AppIdentity
    decision: Decision
    summary: str
    installation: InstallationIdentity | None = None

    def __post_init__(self):
        need(type(self.policy) is evidence.Policy and self.policy.purpose == "reviewed")
        need(type(self.author) is evidence.Principal and type(self.app) is AppIdentity)
        replace(self.policy.admission)
        evidence.Principal(self.author.identifier, self.author.login)
        for who in self.policy.reviewers:
            evidence.Principal(who.identifier, who.login)
        for check in self.policy.checks:
            evidence.Check(check.app_id, check.app_slug, check.name)
        need(self.policy.reviewers == (self.app.bot,))
        if self.policy.project is None:
            # Explicit legacy Gate A profile: main, same-owner, no partially
            # migrated installation/project context may be silently inferred.
            need(self.installation is None and self.app.owner_type == "Organization")
            need(
                self.app.owner.login.casefold()
                == self.policy.admission.repository.split("/")[0].casefold()
            )
        else:
            need(type(self.installation) is InstallationIdentity)
            replace(self.installation)
            need(self.installation.identifier == self.app.installation_id)
            need(self.installation.account == self.policy.project.owner)
            need(self.installation.account_type == self.policy.project.owner_type)
            need(self.author == self.policy.project.author)
            need(
                self.policy.project.publication_context_sha256
                == publication_context(self.app, self.installation, self.author)
            )
        need(type(self.decision) is Decision)
        need(self.author.identifier != self.app.bot.identifier)
        need(self.author.login.casefold() != self.app.bot.login.casefold())
        need(type(self.summary) is str and 0 < len(self.summary) <= 4096)
        need(all(c == "\n" or 32 <= ord(c) <= 126 for c in self.summary))
        need(all(len(line) <= 1024 for line in self.summary.splitlines()))
        need(
            not re.search(
                r"agent-platform review|secret|token|authorization|bearer|private key|"
                r"gh[pousr]_|github_pat_|-----BEGIN|eyJ[A-Za-z0-9_-]+\.",
                self.summary,
                re.I,
            )
        )
        need(len(self.body.encode()) <= MAX_BODY)

    @property
    def body(self):
        context = publisher.digest(
            {
                "policy": asdict(self.policy),
                "author": asdict(self.author),
                "app": asdict(self.app),
                "installation": None
                if self.installation is None
                else asdict(self.installation),
            }
        )
        return (
            f"Agent-Platform review v1: {self.decision.value} {self.policy.head_sha}"
            f"\n\nRepository: {self.policy.admission.repository}"
            f"; PR: {self.policy.pull_request}"
            f"; Issue: #{self.policy.admission.issue}"
            f"\nBase: {self.policy.base_sha}; Merge: {self.policy.merge_sha}"
            f"\nReview context SHA-256: {context}\n\n{self.summary}"
        )

    @property
    def digest(self):
        return publisher.digest(asdict(self))

    @property
    def journal_scope(self):
        if self.policy.project is None:
            return None
        return publisher.digest(
            [self.policy.project.digest, asdict(self.app), asdict(self.installation)]
        )

    @property
    def key(self):
        # One retained operation per repository/PR. New HEAD cannot escape
        # an unknown previous write by choosing a new body or authorization ID.
        return publisher.digest(
            [
                self.policy.admission.repo_id,
                self.policy.pull_request,
            ]
        )


@dataclass(frozen=True, slots=True)
class ManualAuthorization:
    """Direct trusted human decision; never decoded from model/PR/Issue JSON."""

    envelope_sha256: str
    independent_review_sha256: str
    decision_id: str
    operator: evidence.Principal
    approved_at: int
    expires_at: int
    journal_epoch: str

    def __post_init__(self):
        need(
            all(
                publisher.hex_digest(v)
                for v in (
                    self.envelope_sha256,
                    self.independent_review_sha256,
                    self.decision_id,
                    self.journal_epoch,
                )
            )
        )
        need(type(self.operator) is evidence.Principal)
        evidence.Principal(self.operator.identifier, self.operator.login)
        need(not self.operator.login.endswith("[bot]"))
        need(type(self.approved_at) is type(self.expires_at) is int)
        need(0 <= self.approved_at < self.expires_at <= self.approved_at + MAX_AGE)


@dataclass(frozen=True, slots=True)
class InstallationFacts:
    """Synthetic credential-domain metadata only, NEVER a token or auth proof."""

    app: AppIdentity
    repository_ids: tuple[int, ...]
    permissions: tuple[tuple[str, str], ...]
    issued_at: int
    expires_at: int
    token_kind: str = "installation"
    owner_type: str = "Organization"
    repository_selection: str = "selected"
    installation: InstallationIdentity | None = None
    project_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class CommentRequest:
    repository: str
    pull_request: int
    commit_id: str
    body: str

    @property
    def endpoint(self):
        return f"/repos/{self.repository}/pulls/{self.pull_request}/reviews"

    @property
    def method(self):
        return "POST"

    @property
    def event(self):
        return "COMMENT"


@dataclass(frozen=True, slots=True)
class Intent:
    envelope_sha256: str
    authorization_sha256: str
    state: str
    review_id: int | None = None


@dataclass(frozen=True, slots=True)
class JournalFacts:
    epoch: str
    complete: bool
    scope_sha256: str | None = None
    guard_sha256: str | None = None


class _Reads:
    """Fixed read-only endpoint/query budget, no generic HTTP forwarding."""

    def __init__(self, api, envelope):
        self.api, self.policy = api, envelope.policy
        self.started, self.calls = time.monotonic(), 0
        pin, p = self.policy.admission, self.policy.pull_request
        self.singles = {
            "",
            f"/branches/{self.policy.base_branch}",
            f"/issues/{pin.issue}",
            f"/pulls/{p}",
            f"/commits/{self.policy.merge_sha}",
        }
        self.lists = {f"/issues/{pin.issue}/events", f"/pulls/{p}/reviews"}
        for sha in (self.policy.head_sha, self.policy.merge_sha):
            self.lists |= {f"/commits/{sha}/check-runs", f"/commits/{sha}/status"}

    def remaining(self):
        remaining = 60 - (time.monotonic() - self.started)
        need(remaining > 0 and self.calls < 128)
        return min(5, remaining)

    def _call(self, call):
        self.remaining()
        self.calls += 1
        result = call()
        need(time.monotonic() - self.started <= 60)
        need(len(publisher.encoded(result)) <= 2 * 1024 * 1024)
        return result

    def get(self, suffix="", query=None):
        need(suffix in self.singles | self.lists)
        if suffix in self.singles:
            need(query is None)
        else:
            need(type(query) is dict and set(query) == {"page", "per_page"})
            need(type(query["page"]) is int and 1 <= query["page"] <= issues.MAX_PAGES)
            need(query["per_page"] == issues.PAGE_SIZE)
        return self._call(lambda: self.api.get(suffix, query))

    def graph(self, connection, after=None):
        need(connection in {"links", "threads"})
        need(
            after is None
            or (type(after) is str and re.fullmatch(r"[A-Za-z0-9+/=_-]{1,256}", after))
        )
        return self._call(lambda: self.api.graph(connection, after))


def _identity(writer, env, now):
    started = time.monotonic()
    facts = writer.identity(timeout=5, limit=4096)
    now += int(time.monotonic() - started)
    need(
        type(facts) is InstallationFacts
        and type(facts.app) is AppIdentity
        and facts.app == env.app
    )
    need(facts.repository_ids == (env.policy.admission.repo_id,))
    need(facts.permissions == PERMISSIONS and facts.token_kind == "installation")
    need(
        facts.owner_type == env.app.owner_type
        and facts.repository_selection == "selected"
    )
    need(facts.installation == env.installation)
    need(
        facts.project_sha256
        == (None if env.policy.project is None else env.policy.project.digest)
    )
    need(type(facts.issued_at) is type(facts.expires_at) is int)
    need(0 <= facts.issued_at <= now < facts.expires_at <= facts.issued_at + 3600)
    return facts


def _existing(values, env, now):
    found = []
    for review in values:
        who = evidence._principal(review.get("user"))
        matches_id = who.identifier == env.app.bot.identifier
        matches_login = who.login.casefold() == env.app.bot.login.casefold()
        need(matches_id == matches_login)
        if matches_id:
            # Never replace a stale, conflicting, dismissed or different-body
            # review automatically, even if an older matching review exists.
            _verify(review, env, now)
            found.append(review["id"])
    need(len(found) <= 1)
    return found[0] if found else None


def _verify(value, env, now):
    need(type(value) is dict and issues.positive_int(value.get("id")))
    need(
        value.get("state") == "COMMENTED"
        and value.get("commit_id") == env.policy.head_sha
    )
    need(value.get("body") == env.body)
    need(
        value.get("pull_request_url")
        == f"https://api.github.com/repos/{env.policy.admission.repository}/pulls/{env.policy.pull_request}"
    )
    who = value.get("user")
    need(type(who) is dict and who.get("type") == "Bot")
    actual = evidence._principal(who)
    need(
        actual.identifier == env.app.bot.identifier
        and actual.login.casefold() == env.app.bot.login.casefold()
    )
    need(
        actual.identifier != env.author.identifier
        and actual.login.casefold() != env.author.login.casefold()
    )
    need(issues.timestamp(value.get("submitted_at")).timestamp() <= now)


def _snapshot(reads, env, now):
    first = evidence._read(reads, env.policy, now, _before_comment=True)
    need(evidence._read(reads, env.policy, now, _before_comment=True) == first)
    pr, reviews, _, _ = first
    author = evidence._principal(pr.get("user"))
    need(author == env.author and pr["draft"] is True)
    owner = pr["base"]["repo"].get("owner")
    expected_owner = (
        env.app.owner if env.installation is None else env.installation.account
    )
    expected_type = (
        env.app.owner_type
        if env.installation is None
        else env.installation.account_type
    )
    need(type(owner) is dict and owner.get("type") == expected_type)
    need(evidence._principal(owner) == expected_owner)
    return _existing(reviews, env, now)


def _result(status, reason, review_id=None):
    return {
        "schema_version": 1,
        "status": status,
        "reason": reason,
        "review_id": review_id,
        "evidence": "VERIFIED_OFFLINE",
        "live_app_identity": "NOT_RUN",
        "live_publication": "NOT_RUN",
        "launch_allowed": False,
        "resume_authorized": False,
        "publish_authorized": False,
        "runtime_exit_code": 13,
    }


def publish(
    envelope,
    authorization,
    *,
    reader=None,
    writer=None,
    journal=None,
    now,
    reconcile_only=False,
):
    """Synthetic Gate A transaction. No default live client or filesystem store.

    journal supplies atomic compare_and_swap, not task checkpoints. UNKNOWN is
    committed before the sole possible COMMENT attempt; it is never auto-retried.
    Reconciliation is read-only remotely and cannot send. All callbacks are TCB;
    Gate A provenance labels are not authentication or an OS/network boundary.
    """
    intent_started = False
    started = time.monotonic()

    def fresh():
        current = now + int(time.monotonic() - started)
        need(authorization.approved_at <= current)
        # Reconciliation cannot POST; expired grants remain immutable audit pins,
        # never permission for another attempt.
        need(reconcile_only or current < authorization.expires_at)
        return current

    try:
        need(type(envelope) is Envelope and type(authorization) is ManualAuthorization)
        need(type(now) is int and type(reconcile_only) is bool)
        # Frozen Python values are not an authentication or validation boundary.
        # Recheck canonical policy/payload constraints at every entry.
        replace(envelope.policy)
        replace(envelope.app)
        replace(envelope)
        replace(authorization)
        fresh()
        need(authorization.envelope_sha256 == envelope.digest)
        need(reader is not None and reader.provenance == "synthetic_snapshot")
        need(reader.policy == envelope.policy)
        need(writer is not None and writer.provenance == "synthetic_review_transport")
        need(journal is not None and journal.provenance == "synthetic_journal")
        grant_digest = publisher.digest(asdict(authorization))
        facts = journal.identity()
        need(type(facts) is JournalFacts and facts.complete is True)
        need(facts.epoch == authorization.journal_epoch)
        need(facts.scope_sha256 == envelope.journal_scope)
        need(
            facts.guard_sha256
            == (
                None
                if envelope.policy.project is None
                else envelope.policy.project.journal_guard_sha256
            )
        )
        previous = journal.read(envelope.key, epoch=authorization.journal_epoch)
        if previous is not None:
            need(type(previous) is Intent)
            need(
                previous.envelope_sha256 == envelope.digest
                and previous.authorization_sha256 == grant_digest
            )
            need(previous.state in {"UNKNOWN", "VERIFIED"})
            need(
                (previous.review_id is None)
                if previous.state == "UNKNOWN"
                else issues.positive_int(previous.review_id)
            )
            intent_started = True
            if previous.state == "UNKNOWN" and not reconcile_only:
                return _result("NEEDS_HUMAN", "reconciliation_required")
        elif reconcile_only:
            return _result("BLOCKED", "no_recorded_intent")
        identity = _identity(writer, envelope, fresh())
        reads = _Reads(reader, envelope)
        reads.started = started
        existing = _snapshot(reads, envelope, fresh())
        need(_identity(writer, envelope, fresh()) == identity)
        reads.remaining()
        fresh()
        if previous is not None and previous.state == "VERIFIED":
            need(existing == previous.review_id)
            return _result(
                "ALREADY_VERIFIED_SYNTHETIC", "exact_review_reverified", existing
            )
        if reconcile_only and existing is None:
            return _result("NEEDS_HUMAN", "remote_outcome_unconfirmed")
        if existing is not None:
            record = Intent(envelope.digest, grant_digest, "VERIFIED", existing)
            intent_started = True
            need(
                journal.compare_and_swap(
                    envelope.key, previous, record, epoch=authorization.journal_epoch
                )
            )
            return _result("RECONCILED_SYNTHETIC", "exact_review_reverified", existing)
        fresh()
        unknown = Intent(envelope.digest, grant_digest, "UNKNOWN")
        intent_started = True
        need(
            journal.compare_and_swap(
                envelope.key, None, unknown, epoch=authorization.journal_epoch
            )
        )
        request = CommentRequest(
            envelope.policy.admission.repository,
            envelope.policy.pull_request,
            envelope.policy.head_sha,
            envelope.body,
        )
        need(fresh() < identity.expires_at)
        response = writer.comment(request, timeout=reads.remaining(), limit=64 * 1024)
        need(len(publisher.encoded(response)) <= 64 * 1024)
        _verify(response, envelope, fresh())
        existing = _snapshot(reads, envelope, fresh())
        need(
            existing == response["id"]
            and _identity(writer, envelope, fresh()) == identity
        )
        reads.remaining()
        fresh()
        verified = Intent(envelope.digest, grant_digest, "VERIFIED", existing)
        need(
            journal.compare_and_swap(
                envelope.key, unknown, verified, epoch=authorization.journal_epoch
            )
        )
        return _result("PUBLISHED_SYNTHETIC", "comment_verified", existing)
    except Exception:
        # Unknown write/intent/store outcomes are retained, never retried. No
        # response, token, raw exception, body, login or stderr crosses output.
        return _result(
            "NEEDS_HUMAN" if intent_started else "BLOCKED",
            "publication_outcome_unknown"
            if intent_started
            else "review_publication_blocked",
        )
