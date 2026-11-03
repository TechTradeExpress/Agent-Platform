"""Trusted-caller, bounded read-only PR evidence. No CLI or publishing authority."""

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path

from agent_platform import cli, issues, prepare, publisher, queue, state, task_status
from agent_platform.process import CommandError, read_command

MAX_ITEMS = issues.PAGE_SIZE * issues.MAX_PAGES
MAX_AGE = 300


class EvidenceError(Exception):
    def __init__(self):
        super().__init__("github_evidence_unavailable")


def need(value):
    if not value:
        raise EvidenceError()


def sha(value):
    return type(value) is str and prepare.SHA.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class Principal:
    identifier: int
    login: str

    def __post_init__(self):
        need(issues.positive_int(self.identifier))
        need(
            type(self.login) is str
            and re.fullmatch(issues.LOGIN.pattern + r"(?:\[bot\])?", self.login)
        )


@dataclass(frozen=True, slots=True)
class Check:
    app_id: int
    app_slug: str
    name: str

    def __post_init__(self):
        need(issues.positive_int(self.app_id))
        need(type(self.app_slug) is str and issues.LOGIN.fullmatch(self.app_slug))
        need(
            type(self.name) is str
            and re.fullmatch(r"[A-Za-z0-9 _./-]{1,100}", self.name)
        )


@dataclass(frozen=True, slots=True)
class Policy:
    """Operator-held pins, never decoded from target files or model output."""

    admission: publisher.Admission
    pull_request: int
    head_sha: str
    base_sha: str
    purpose: str
    reviewers: tuple[Principal, ...] = ()
    checks: tuple[Check, ...] = ()
    merge_sha: str | None = None

    def __post_init__(self):
        need(type(self.admission) is publisher.Admission)
        need(
            issues.positive_int(self.pull_request)
            and sha(self.head_sha)
            and sha(self.base_sha)
        )
        need(type(self.purpose) is str and self.purpose in {"reviewed", "merged"})
        need(self.merge_sha is None or sha(self.merge_sha))
        for values, cls in [(self.reviewers, Principal), (self.checks, Check)]:
            need(type(values) is tuple and len(values) <= 8)
            need(
                all(type(v) is cls for v in values) and len(set(values)) == len(values)
            )
        need(len({p.identifier for p in self.reviewers}) == len(self.reviewers))
        need(len({p.login.casefold() for p in self.reviewers}) == len(self.reviewers))
        need(len({c.name for c in self.checks}) == len(self.checks))
        if self.purpose == "reviewed":
            need(self.reviewers and self.checks and sha(self.merge_sha))
            need(self.base_sha == self.admission.base_sha)
            need(self.merge_sha not in {self.head_sha, self.base_sha})


def _query(connection):
    fields = {
        "links": (
            "closingIssuesReferences(first:20, after:$after) { totalCount "
            "nodes { databaseId number state repository { databaseId "
            "nameWithOwner } } pageInfo { hasNextPage endCursor } }"
        ),
        "threads": (
            "reviewThreads(first:20, after:$after) { totalCount "
            "nodes { id isResolved } pageInfo { hasNextPage endCursor } }"
        ),
    }
    return (
        "query AgentPlatformEvidence($owner:String!,$name:String!,"
        "$number:Int!,$after:String) { "
        "repository(owner:$owner,name:$name) { databaseId nameWithOwner "
        "pullRequest(number:$number) { databaseId number headRefOid baseRefOid "
        + fields[connection]
        + " } } }"
    )


class GitHub(issues.GitHub):
    """Explicit opt-in trusted client. Only pinned REST GETs/two literal queries.

    Existing gh operator authentication is consumed only on explicit requests.
    No login, token creation, raw auth-store read or client is passed to a child.
    """

    provenance = "github_api_snapshot"

    def __init__(self, policy):
        need(type(policy) is Policy)
        super().__init__(policy.admission.repository)
        self.policy = policy
        n, p, h = policy.admission.issue, policy.pull_request, policy.head_sha
        self.singles = {"", "/branches/main", f"/issues/{n}", f"/pulls/{p}"}
        if policy.merge_sha is not None:
            self.singles.add(f"/commits/{policy.merge_sha}")
        self.lists = {
            f"/issues/{n}/events",
            f"/pulls/{p}/reviews",
            f"/commits/{h}/check-runs",
            f"/commits/{h}/status",
        }

        if policy.merge_sha is not None:
            self.lists |= {
                f"/commits/{policy.merge_sha}/check-runs",
                f"/commits/{policy.merge_sha}/status",
            }

    def get(self, suffix="", query=None):
        need(suffix in self.singles | self.lists)
        if suffix in self.singles:
            need(query is None)
        else:
            need(type(query) is dict and set(query) == {"page", "per_page"})
            need(type(query["page"]) is int and 1 <= query["page"] <= issues.MAX_PAGES)
            need(query["per_page"] == issues.PAGE_SIZE)
        return super().get(suffix, query)

    def graph(self, connection, after=None):
        need(connection in {"links", "threads"})
        need(
            after is None
            or (type(after) is str and re.fullmatch(r"[A-Za-z0-9+/=_-]{1,256}", after))
        )
        remaining = self.deadline - time.monotonic()
        need(remaining > 0 and self.requests < issues.MAX_REQUESTS)
        self.requests += 1
        owner, name = self.policy.admission.repository.split("/")
        args = [
            "gh",
            "api",
            "--hostname",
            "github.com",
            "--method",
            "POST",
            "graphql",
            "-f",
            "query=" + _query(connection),
            "-f",
            "owner=" + owner,
            "-f",
            "name=" + name,
            "-F",
            "number=" + str(self.policy.pull_request),
        ]
        if after is not None:
            args += ["-f", "after=" + after]
        env = {
            k: os.environ[k]
            for k in (
                "HOME",
                "XDG_CONFIG_HOME",
                "GH_CONFIG_DIR",
                "GH_TOKEN",
                "GITHUB_TOKEN",
            )
            if k in os.environ
        }
        env.update(
            PATH=os.defpath,
            LC_ALL="C",
            GH_PROMPT_DISABLED="1",
            GH_NO_UPDATE_NOTIFIER="1",
            GH_NO_EXTENSION_UPDATE_NOTIFIER="1",
        )
        raw = read_command(
            args,
            Path("/"),
            env,
            timeout=min(issues.REQUEST_TIMEOUT, remaining),
            limit=issues.OUTPUT_LIMIT,
        )
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=issues.unique_object,
            parse_constant=issues.invalid_constant,
        )
        need(
            type(value) is dict
            and set(value) <= {"data", "extensions"}
            and type(value.get("data")) is dict
        )
        return value["data"]


class _Lists:
    """Reuse strict REST Link parsing with counted object-envelope endpoints."""

    def __init__(self, api, pin, key=None):
        self.api, self.pin, self.key = api, pin, key
        self.prefix = "repos/" + pin.repository
        self.total = None

    def get(self, suffix, query):
        value, link = self.api.get(suffix, query)
        if self.key is not None:
            need(type(value) is dict and type(value.get("total_count")) is int)
            total = value["total_count"]
            need(0 <= total <= MAX_ITEMS and self.total in (None, total))
            self.total = total
            if self.key == "statuses":
                _repo(value.get("repository"), self.pin)
                need(value.get("sha") == suffix.split("/")[2])
                need(value.get("state") == ("success" if total else "pending"))
            value = value.get(self.key)
        return value, link

    def pages(self, suffix):
        values = issues.GitHub.pages(self, suffix)
        if self.total is not None:
            need(len(values) == self.total)
        need(all(type(v) is dict and issues.positive_int(v.get("id")) for v in values))
        need(len({v["id"] for v in values}) == len(values))
        return values


def _repo(value, pin, *, graph=False):
    need(type(value) is dict)
    identifier = value.get("databaseId" if graph else "id")
    need(issues.positive_int(identifier) and identifier == pin.repo_id)
    need(value.get("nameWithOwner" if graph else "full_name") == pin.repository)


def _principal(value):
    need(type(value) is dict)
    return Principal(value.get("id"), value.get("login"))


def _connection(api, policy, pr, connection):
    pin, after, result, total, cursors = policy.admission, None, [], None, set()
    field = "closingIssuesReferences" if connection == "links" else "reviewThreads"
    for _ in range(issues.MAX_PAGES):
        data = api.graph(connection, after)
        _repo(data.get("repository"), pin, graph=True)
        item = data["repository"].get("pullRequest")
        need(type(item) is dict)
        need(
            issues.positive_int(item.get("databaseId"))
            and issues.positive_int(item.get("number"))
        )
        need(
            (
                item.get("databaseId"),
                item.get("number"),
                item.get("headRefOid"),
                item.get("baseRefOid"),
            )
            == (pr["id"], policy.pull_request, policy.head_sha, policy.base_sha)
        )
        batch = item.get(field)
        need(type(batch) is dict and type(batch.get("nodes")) is list)
        count = batch.get("totalCount")
        need(type(count) is int and 0 <= count <= MAX_ITEMS and total in (None, count))
        total = count
        nodes, info = batch["nodes"], batch.get("pageInfo")
        need(len(nodes) <= issues.PAGE_SIZE and all(type(n) is dict for n in nodes))
        need(type(info) is dict and type(info.get("hasNextPage")) is bool)
        result.extend(nodes)
        if not info["hasNextPage"]:
            need(len(result) == total)
            key = "databaseId" if connection == "links" else "id"
            if connection == "links":
                need(
                    all(
                        issues.positive_int(n.get(key))
                        and issues.positive_int(n.get("number"))
                        for n in result
                    )
                )
            else:
                need(
                    all(
                        type(n.get(key)) is str and 0 < len(n[key]) <= 256
                        for n in result
                    )
                )
            need(len({n[key] for n in result}) == len(result))
            return result
        after = info.get("endCursor")
        need(
            len(nodes) == issues.PAGE_SIZE
            and type(after) is str
            and after not in cursors
        )
        need(re.fullmatch(r"[A-Za-z0-9+/=_-]{1,256}", after))
        cursors.add(after)
    raise EvidenceError()


def _review_candidates(values, policy, author, now):
    trusted = set(policy.reviewers)
    need(
        author not in trusted
        and all(
            p.identifier != author.identifier
            and p.login.casefold() != author.login.casefold()
            for p in trusted
        )
    )
    latest = {}
    for v in values:
        who = _principal(v.get("user"))
        need(
            type(v.get("state")) is str
            and v["state"]
            in {"COMMENTED", "APPROVED", "CHANGES_REQUESTED", "DISMISSED"}
        )
        need(sha(v.get("commit_id")))
        need(type(v.get("body")) is str and len(v["body"]) <= 65536)
        submitted = issues.timestamp(v.get("submitted_at"))
        need(submitted.timestamp() <= now)
        old = latest.get(who)
        if old is not None:
            need(submitted != issues.timestamp(old["submitted_at"]))
        if old is None or submitted > issues.timestamp(old["submitted_at"]):
            latest[who] = v
    need(all(v.get("state") != "CHANGES_REQUESTED" for v in latest.values()))
    return latest


def _review(values, policy, author, now):
    latest = _review_candidates(values, policy, author, now)
    trusted = set(policy.reviewers)
    selected = []
    for who, v in latest.items():
        if who not in trusted:
            continue
        need(v.get("commit_id") == policy.head_sha and v.get("state") == "COMMENTED")
        need(
            v["body"].splitlines()[0:1]
            == ["Agent-Platform review v1: PASS " + policy.head_sha]
        )
        selected.append((v["id"], publisher.digest(v["body"])))
    need(selected)
    return tuple(sorted(selected))


def _checks(api, policy, now, head):
    pin = policy.admission
    values = _Lists(api, pin, "check_runs").pages(f"/commits/{head}/check-runs")
    matched, facts = set(), []
    for v in values:
        need(
            v.get("head_sha") == head
            and v.get("status") == "completed"
            and v.get("conclusion") == "success"
        )
        need(
            v.get("url")
            == f"https://api.github.com/repos/{pin.repository}/check-runs/{v['id']}"
        )
        app = v.get("app")
        need(type(app) is dict)
        key = Check(app.get("id"), app.get("slug"), v.get("name"))
        need(issues.timestamp(v.get("completed_at")).timestamp() <= now)
        if key.name in {c.name for c in policy.checks}:
            need(key in policy.checks)
            matched.add(key)
        facts.append(
            (head, v["id"], key.app_id, key.app_slug, key.name, v["completed_at"])
        )
    need(matched == set(policy.checks))
    statuses = _Lists(api, pin, "statuses").pages(f"/commits/{head}/status")
    contexts = set()
    for v in statuses:
        need(type(v.get("context")) is str and v["context"] not in contexts)
        contexts.add(v["context"])
        need(v.get("state") == "success")
        need(
            v.get("url")
            == f"https://api.github.com/repos/{pin.repository}/statuses/{head}"
        )
    # Legacy statuses may veto but never replace pinned App check authority.
    return tuple(sorted(facts)), publisher.digest(statuses)


def _read(api, policy, now, *, _before_comment=False):
    # Internal prepublication facts are NOT a reviewed Receipt. collect() never
    # selects this branch and still requires _review() at the exact HEAD.
    if _before_comment:
        need(policy.purpose == "reviewed")
    pin = policy.admission
    metadata, _ = api.get()
    _repo(metadata, pin)
    need(metadata.get("default_branch") == "main")
    branch, _ = api.get("/branches/main")
    need(
        type(branch) is dict
        and branch.get("name") == "main"
        and type(branch.get("commit")) is dict
    )
    need(branch["commit"].get("sha") == pin.base_sha)
    raw, _ = api.get(f"/issues/{pin.issue}")
    issue = issues.issue_snapshot(raw, pin.issue, pin.repository)
    need(
        not issue["pr"]
        and issue["id"] == pin.issue_id
        and issue["updated_at"] == pin.scope_revision
    )
    need(issues.timestamp(issue["updated_at"]).timestamp() <= now)
    scope = {"title": issue["title"], "body": issue["body"]}
    # Preserve prepare.admission_record's existing scope encoding exactly.
    need(
        hashlib.sha256(json.dumps(scope, sort_keys=True).encode()).hexdigest()
        == pin.scope_sha256
    )
    need(not {"agent:working", "needs:human"} & set(issue["labels"]))
    history = _Lists(api, pin).pages(f"/issues/{pin.issue}/events")
    pr, _ = api.get(f"/pulls/{policy.pull_request}")
    need(
        type(pr) is dict
        and issues.positive_int(pr.get("id"))
        and pr.get("number") == policy.pull_request
    )
    need(
        pr.get("url")
        == f"https://api.github.com/repos/{pin.repository}/pulls/{policy.pull_request}"
    )
    for key, expected in [("head", policy.head_sha), ("base", policy.base_sha)]:
        side = pr.get(key)
        need(type(side) is dict and side.get("sha") == expected)
        _repo(side.get("repo"), pin)
    need(pr["base"].get("ref") == "main")
    need(issues.timestamp(pr.get("updated_at")).timestamp() <= now)
    author = _principal(pr.get("user"))
    need(type(pr.get("body")) is str and len(pr["body"]) <= 65536)
    body = pr["body"]
    need(len(re.findall(rf"(?m)^Closes #{pin.issue}[ \t]*$", body)) == 1)
    references = re.findall(
        r"(?i)\b(?:close[sd]?|fix(?:es|ed)?|resolve[sd]?)\s+((?:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)?#\d+|https://github\.com/\S+)",
        body,
    )
    need(references == [f"#{pin.issue}"])
    links = _connection(api, policy, pr, "links")
    need(len(links) == 1)
    _repo(links[0].get("repository"), pin, graph=True)
    need(
        (links[0].get("databaseId"), links[0].get("number"), links[0].get("state"))
        == (pin.issue_id, pin.issue, issue["state"].upper())
    )
    threads = _connection(api, policy, pr, "threads")
    need(all(t.get("isResolved") is True for t in threads))
    need(type(pr.get("merged")) is bool and type(pr.get("draft")) is bool)
    reviews, checks, statuses, merge, raw_reviews = (), (), None, None, ()
    if policy.purpose == "reviewed":
        need(
            pr.get("state") == issue["state"] == "open"
            and not pr["merged"]
            and pr.get("merged_at") is None
        )
        raw_reviews = _Lists(api, pin).pages(f"/pulls/{policy.pull_request}/reviews")
        if _before_comment:
            need(pr["draft"])
            _review_candidates(raw_reviews, policy, author, now)
            reviews = tuple(raw_reviews)
        else:
            reviews = _review(raw_reviews, policy, author, now)
        need(pr.get("merge_commit_sha") == policy.merge_sha)
        merge, _ = api.get(f"/commits/{policy.merge_sha}")
        need(type(merge) is dict and merge.get("sha") == policy.merge_sha)
        need(
            merge.get("url")
            == f"https://api.github.com/repos/{pin.repository}/commits/{policy.merge_sha}"
        )
        parents = merge.get("parents")
        need(type(parents) is list and all(type(p) is dict for p in parents))
        need([p.get("sha") for p in parents] == [policy.base_sha, policy.head_sha])
        head_checks, head_status = _checks(api, policy, now, policy.head_sha)
        merge_checks, merge_status = _checks(api, policy, now, policy.merge_sha)
        checks, statuses = head_checks + merge_checks, (head_status, merge_status)
        need(len({fact[1] for fact in checks}) == len(checks))
    else:
        need(pr.get("state") == issue["state"] == "closed" and pr["merged"])
        need(sha(pr.get("merge_commit_sha")))
        need(issues.timestamp(pr.get("merged_at")).timestamp() <= now)
    again, _ = api.get(f"/pulls/{policy.pull_request}")
    need(again == pr)
    again, _ = api.get(f"/issues/{pin.issue}")
    need(issues.issue_snapshot(again, pin.issue, pin.repository) == issue)
    need(_Lists(api, pin).pages(f"/issues/{pin.issue}/events") == history)
    again, _ = api.get()
    need(again == metadata)
    again, _ = api.get("/branches/main")
    need(again == branch)
    # Entire bounded facts are hashed for drift detection, never rendered as text.
    facts = publisher.digest(
        [
            metadata,
            branch,
            issue,
            history,
            pr,
            links,
            threads,
            reviews,
            checks,
            statuses,
            merge,
            raw_reviews,
        ]
    )
    return pr, reviews, checks, facts


@dataclass(frozen=True, slots=True)
class Receipt:
    policy: Policy
    observed_at: int
    api_provenance: str
    facts_sha256: str
    local_sha256: str
    reviews: tuple
    checks: tuple
    pull_request: queue.PullRequest

    def _fresh(self, now):
        need(type(now) is int and self.observed_at <= now <= self.observed_at + MAX_AGE)

    def queue_receipt(self, *, now):
        self._fresh(now)
        return self.pull_request

    def publisher_admission(self, *, now):
        self._fresh(now)
        need(self.policy.purpose == "reviewed")
        # This remains the separately trusted admission pin, not new launch
        # admission or synthetic local checkpoint/tree-bound TestEvidence.
        return self.policy.admission

    def diagnostic(self):
        return {
            "schema_version": 1,
            "status": "collected",
            "purpose": self.policy.purpose,
            "api_provenance": self.api_provenance,
            "freshness": "stable_snapshot_not_live",
            "admission": "separate_trusted_caller_pin_not_reauthenticated",
            "local_ancestry": "verified"
            if self.policy.purpose == "merged"
            else "not_claimed",
            "launch_allowed": False,
            "publish_authorized": False,
        }


def _local(root, pin):
    info = cli.inspect(root)
    source = prepare.source_snapshot(info)
    need(source["repository"] == pin.repository and source["base_sha"] == pin.base_sha)
    refs = prepare.git(root, "for-each-ref", "--format=%(refname) %(objectname)")
    return publisher.digest([source, refs.hex()])


def collect(root: Path, policy: Policy, *, api):
    """Two complete bounded reads, then local revalidation; no saved-file input.

    API authenticity is the trusted caller/transport boundary, not a dataclass.
    No caller can use this receipt to bypass existing queue/publisher checks.
    """
    try:
        need(type(policy) is Policy and isinstance(root, Path))
        need(root.is_absolute() and root.resolve(strict=True) == root)
        state.no_symlinks(root)
        need(
            api.policy == policy
            and api.provenance in {"github_api_snapshot", "synthetic_snapshot"}
        )
        started = time.monotonic()
        now = int(time.time())
        with state.host_lock(create=False) as fd:
            lock = task_status.fingerprint(os.fstat(fd))
            before = _local(root, policy.admission)
            first = _read(api, policy, now)
            need(_read(api, policy, now) == first)
            pr, reviews, checks, facts = first
            if policy.purpose == "merged":
                for commit in (policy.base_sha, pr["merge_commit_sha"]):
                    need(
                        prepare.line(prepare.git(root, "cat-file", "-t", commit))
                        == "commit"
                    )
                    prepare.git(
                        root,
                        "merge-base",
                        "--is-ancestor",
                        commit,
                        policy.admission.base_sha,
                    )
            need(_local(root, policy.admission) == before)
            need(
                task_status.fingerprint((state.LOCK_DIR / "prepare.lock").lstat())
                == lock
            )
            need(api.policy == policy)
            need(time.monotonic() - started <= issues.TOTAL_TIMEOUT)
        pin = policy.admission
        receipt = queue.PullRequest(
            pin,
            policy.pull_request,
            pin.repo_id,
            pin.repository,
            "main",
            policy.head_sha,
            policy.head_sha,
            pr["state"],
            pr["merged"],
            pr["merge_commit_sha"] if pr["merged"] else None,
            pr["merged_at"],
            (pin.issue,),
            pin.base_sha,
        )
        return Receipt(
            policy, now, api.provenance, facts, before, reviews, checks, receipt
        )
    except (
        EvidenceError,
        issues.AdmissionError,
        publisher.PlanError,
        queue.QueueError,
        state.PrepareError,
        cli.InspectionError,
        CommandError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        RecursionError,
    ):
        raise EvidenceError() from None
