"""Two fabricated downstream projects; no external repository or App access."""

import copy
import hashlib
import json
import socket
import subprocess
from dataclasses import replace

import pytest
from test_github_evidence import NOW, STAMP
from test_github_evidence import (
    fabricated_auth_environment as fabricated_auth_environment,
)
from test_issues import event, issue
from test_prepare import git, snapshot

from agent_platform import cli, native_codex, prepare, publisher, state, subscription
from agent_platform import github_evidence as evidence
from agent_platform import review_comment as comment


class Reader:
    provenance = "synthetic_snapshot"

    def __init__(self, policy, metadata, pr, raw_issue, check):
        self.policy, self.metadata, self.pr, self.issue = (
            policy,
            metadata,
            pr,
            raw_issue,
        )
        pin = policy.admission
        self.reviews, self.threads = [], []
        self.links = [
            {
                "databaseId": pin.issue_id,
                "number": pin.issue,
                "state": "OPEN",
                "repository": {
                    "databaseId": pin.repo_id,
                    "nameWithOwner": pin.repository,
                },
            }
        ]
        self.branch = {"name": policy.base_branch, "commit": {"sha": pin.base_sha}}
        self.parents = [{"sha": policy.base_sha}, {"sha": policy.head_sha}]
        self.checks = {}
        for offset, sha in enumerate((policy.head_sha, policy.merge_sha)):
            self.checks[sha] = {
                "total_count": 1,
                "check_runs": [
                    {
                        "id": 6000 + offset,
                        "name": check.name,
                        "head_sha": sha,
                        "app": {"id": check.app_id, "slug": check.app_slug},
                        "status": "completed",
                        "conclusion": "success",
                        "completed_at": STAMP,
                        "url": (
                            f"https://api.github.com/repos/{pin.repository}"
                            f"/check-runs/{6000 + offset}"
                        ),
                    }
                ],
            }
        self.calls, self.hook = [], None

    def get(self, suffix="", query=None):
        self.calls.append(suffix)
        if self.hook:
            self.hook(suffix)
        p = self.policy
        pin = p.admission
        if suffix == "":
            value = self.metadata
        elif suffix == f"/branches/{p.base_branch}":
            value = self.branch
        elif suffix == f"/issues/{pin.issue}":
            value = self.issue
        elif suffix == f"/issues/{pin.issue}/events":
            value = [event()]
        elif suffix == f"/pulls/{p.pull_request}":
            value = self.pr
        elif suffix == f"/pulls/{p.pull_request}/reviews":
            value = self.reviews
        elif suffix == f"/commits/{p.merge_sha}":
            value = {
                "sha": p.merge_sha,
                "url": f"https://api.github.com/repos/{pin.repository}/commits/{p.merge_sha}",
                "parents": self.parents,
            }
        elif suffix.endswith("/check-runs"):
            value = self.checks[suffix.split("/")[2]]
        elif suffix.endswith("/status"):
            value = {
                "sha": suffix.split("/")[2],
                "repository": self.metadata,
                "total_count": 0,
                "state": "pending",
                "statuses": [],
            }
        else:
            pytest.fail("unexpected endpoint")
        return copy.deepcopy(value), None

    def graph(self, connection, after=None):
        p = self.policy
        pin = p.admission
        nodes = self.links if connection == "links" else self.threads
        return copy.deepcopy(
            {
                "repository": {
                    "databaseId": pin.repo_id,
                    "nameWithOwner": pin.repository,
                    "pullRequest": {
                        "databaseId": self.pr["id"],
                        "number": p.pull_request,
                        "headRefOid": self.pr["head"]["sha"],
                        "baseRefOid": self.pr["base"]["sha"],
                        "closingIssuesReferences"
                        if connection == "links"
                        else "reviewThreads": {
                            "totalCount": len(nodes),
                            "nodes": nodes,
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        },
                    },
                }
            }
        )


class Journal:
    provenance = "synthetic_journal"

    def __init__(self, env, cells):
        self.env, self.cells = env, cells
        self.facts = comment.JournalFacts(
            "e" * 64, True, env.journal_scope, env.policy.project.journal_guard_sha256
        )

    def identity(self):
        return self.facts

    def read(self, key, *, epoch):
        assert key == self.env.key and epoch == self.facts.epoch
        return self.cells.get(key)

    def compare_and_swap(self, key, old, new, *, epoch):
        assert key == self.env.key and epoch == self.facts.epoch
        if self.cells.get(key) != old:
            return False
        self.cells[key] = new
        return True


class Writer:
    provenance = "synthetic_review_transport"

    def __init__(self, env, reader, journal):
        self.env, self.reader, self.journal = env, reader, journal
        self.calls, self.error, self.after = [], None, None
        self.facts = comment.InstallationFacts(
            env.app,
            (env.policy.admission.repo_id,),
            comment.PERMISSIONS,
            NOW - 1,
            NOW + 3000,
            owner_type=env.app.owner_type,
            installation=env.installation,
            project_sha256=env.policy.project.digest,
        )

    def identity(self, **kwargs):
        return self.facts

    def comment(self, request, **limits):
        env = self.env
        p = env.policy
        pin = p.admission
        assert (
            request.endpoint
            == f"/repos/{pin.repository}/pulls/{p.pull_request}/reviews"
        )
        assert request.event == "COMMENT" and request.commit_id == p.head_sha
        assert request.body == env.body
        assert self.journal.read(env.key, epoch="e" * 64).state == "UNKNOWN"
        self.calls.append(request)
        if self.error:
            raise self.error
        result = {
            "id": 9901,
            "user": {
                "id": env.app.bot.identifier,
                "login": env.app.bot.login,
                "type": "Bot",
            },
            "body": env.body,
            "commit_id": p.head_sha,
            "state": "COMMENTED",
            "submitted_at": STAMP,
            "pull_request_url": f"https://api.github.com/repos/{pin.repository}/pulls/{p.pull_request}",
        }
        self.reader.reviews.append(copy.deepcopy(result))
        if self.after:
            self.after()
        return result


@pytest.fixture
def projects(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "LOCK_DIR", tmp_path / "host-lock")
    monkeypatch.setattr(evidence.time, "time", lambda: NOW)
    with state.host_lock():
        pass  # Fixture-only initialization.
    cells = {}
    result = []
    for index, branch in enumerate(("main", "trunk"), 1):
        owner = evidence.Principal(index * 100, f"org-{index}")
        repo = f"{owner.login}/project-{index}"
        repo_id, issue_no, pr_no = index * 1000, index + 6, 101
        root = tmp_path / f"project-{index}"
        root.mkdir()
        git(root, "init", "-b", branch)
        (root / "tracked.txt").write_text(f"synthetic project {index}\n")
        git(root, "add", "tracked.txt")
        git(
            root,
            "-c",
            "user.name=Test",
            "-c",
            "user.email=t@example.invalid",
            "commit",
            "-m",
            "fixture",
        )
        git(root, "remote", "add", "origin", f"https://github.com/{repo}.git")
        base = git(root, "rev-parse", "HEAD")
        git(root, "update-ref", f"refs/remotes/origin/{branch}", base)
        raw = issue(issue_no)
        raw["id"] = index * 7000
        raw["url"] = f"https://api.github.com/repos/{repo}/issues/{issue_no}"
        raw["repository_url"] = f"https://api.github.com/repos/{repo}"
        scope = hashlib.sha256(
            json.dumps(
                {"title": raw["title"], "body": raw["body"]}, sort_keys=True
            ).encode()
        ).hexdigest()
        pin = publisher.Admission(
            repo_id,
            repo,
            issue_no,
            raw["id"],
            scope,
            raw["updated_at"],
            str(index) * 64,
            base,
        )
        head, merge = ("a" * 40, "b" * 40) if index == 1 else ("c" * 40, "d" * 40)
        check = evidence.Check(800 + index, "github-actions", "checks")
        bot = evidence.Principal(22, "reviewer[bot]")
        registration = evidence.Principal(999, "app-owner")
        app = comment.AppIdentity(88, "reviewer", 70 + index, registration, bot)
        installation = comment.InstallationIdentity(70 + index, owner, "Organization")
        author = evidence.Principal(30 + index, f"author-{index}")
        project = evidence.TargetProject(
            str(index) * 64,
            pin,
            owner,
            "Organization",
            branch,
            head,
            pr_no,
            (check,),
            str(root),
            str(index + 2) * 64,
            author,
            (bot,),
            comment.publication_context(app, installation, author),
        )
        policy = evidence.Policy(
            pin, pr_no, head, base, "reviewed", (bot,), (check,), merge, project
        )
        env = comment.Envelope(
            policy,
            author,
            app,
            comment.Decision.PASS,
            "Independent exact-revision review performed.",
            installation,
        )
        grant = comment.ManualAuthorization(
            env.digest,
            "a" * 64,
            str(index) * 64,
            evidence.Principal(50, "operator"),
            NOW,
            NOW + 300,
            "e" * 64,
        )
        metadata = {
            "id": repo_id,
            "full_name": repo,
            "default_branch": branch,
            "owner": {
                "id": owner.identifier,
                "login": owner.login,
                "type": "Organization",
            },
        }
        pr = {
            "id": index + 2000,
            "number": pr_no,
            "url": f"https://api.github.com/repos/{repo}/pulls/{pr_no}",
            "head": {"sha": head, "repo": metadata, "ref": "feature"},
            "base": {"sha": base, "repo": metadata, "ref": branch},
            "user": {"id": author.identifier, "login": author.login},
            "body": f"Closes #{issue_no}\n",
            "state": "open",
            "draft": True,
            "merged": False,
            "merged_at": None,
            "merge_commit_sha": merge,
            "updated_at": STAMP,
        }
        reader = Reader(policy, metadata, pr, raw, check)
        journal = Journal(env, cells)
        writer = Writer(env, reader, journal)
        result.append(
            dict(
                env=env,
                grant=grant,
                reader=reader,
                writer=writer,
                journal=journal,
                root=root,
                cells=cells,
            )
        )
    return result


def publish(case, **changes):
    args = dict(
        envelope=case["env"],
        authorization=case["grant"],
        reader=case["reader"],
        writer=case["writer"],
        journal=case["journal"],
        now=NOW,
    )
    args.update(changes)
    result = comment.publish(**args)
    assert result["live_publication"] == result["live_app_identity"] == "NOT_RUN"
    assert (
        result["launch_allowed"]
        is result["resume_authorized"]
        is result["publish_authorized"]
        is False
    )
    return result


@pytest.mark.parametrize("index", [0, 1])
def test_independent_downstream_projects_and_different_registration_owner(
    projects, index
):
    s = projects[index]
    env = s["env"]
    assert env.app.owner != env.installation.account == env.policy.project.owner
    before = snapshot(s["root"])
    assert publish(s)["status"] == "PUBLISHED_SYNTHETIC"
    receipt = evidence.collect(s["root"], env.policy, api=s["reader"])
    assert receipt.for_project(env.policy.project, now=NOW) is receipt
    assert receipt.pull_request is None
    for handoff in (receipt.queue_receipt, receipt.publisher_admission):
        with pytest.raises(evidence.EvidenceError):
            handoff(now=NOW)
    with pytest.raises(evidence.EvidenceError):
        receipt.for_project(projects[1 - index]["env"].policy.project, now=NOW)
    assert snapshot(s["root"]) == before
    assert f"/branches/{env.policy.base_branch}" in s["reader"].calls
    if index == 1:
        assert "/branches/main" not in s["reader"].calls
        with pytest.raises(state.PrepareError):
            prepare.source_snapshot(cli.inspect(s["root"]))


@pytest.mark.parametrize("field", ["authorization", "reader", "writer", "journal"])
def test_cross_project_dependencies_and_authorization_never_retarget(projects, field):
    a, b = projects
    changed = b["grant"] if field == "authorization" else b[field]
    assert publish(a, **{field: changed})["status"] == "BLOCKED"
    assert not a["writer"].calls and not b["writer"].calls


def test_identical_pr_numbers_have_isolated_intent_and_approval(projects):
    a, b = projects
    assert a["env"].policy.pull_request == b["env"].policy.pull_request
    assert a["env"].key != b["env"].key and a["env"].digest != b["env"].digest
    assert publish(a)["status"] == publish(b)["status"] == "PUBLISHED_SYNTHETIC"
    assert len(a["cells"]) == 2
    assert publish(a)["status"] == publish(b)["status"] == "ALREADY_VERIFIED_SYNTHETIC"


@pytest.mark.parametrize(
    "field",
    [
        "head",
        "base",
        "issue",
        "link",
        "owner",
        "check",
        "merge",
        "thread",
        "default",
        "fork",
    ],
)
def test_cross_project_observation_collisions_block(projects, field):
    a, b = projects
    r = a["reader"]
    other = b["reader"]
    if field in {"head", "base"}:
        r.pr[field] = copy.deepcopy(other.pr[field])
    elif field == "issue":
        r.issue = copy.deepcopy(other.issue)
    elif field == "link":
        r.links = copy.deepcopy(other.links)
    elif field == "owner":
        r.metadata["owner"] = copy.deepcopy(other.metadata["owner"])
    elif field == "check":
        r.checks[a["env"].policy.head_sha] = copy.deepcopy(
            other.checks[b["env"].policy.head_sha]
        )
    elif field == "merge":
        r.parents.reverse()
    elif field == "thread":
        r.threads = [{"id": "T", "isResolved": False}]
    elif field == "default":
        r.metadata["default_branch"] = "trunk"
    else:
        r.pr["head"]["repo"] = copy.deepcopy(other.metadata)
    assert publish(a)["status"] == "BLOCKED"
    assert not a["writer"].calls


@pytest.mark.parametrize(
    "field", ["app", "installation", "repository_ids", "project_sha256"]
)
def test_installation_metadata_cannot_cross_project(projects, field):
    a, b = projects
    a["writer"].facts = replace(
        a["writer"].facts, **{field: getattr(b["writer"].facts, field)}
    )
    assert publish(a)["status"] == "BLOCKED"
    assert not a["writer"].calls


def test_unknown_survives_installation_rotation_and_namespace_change(projects):
    s = projects[0]
    s["writer"].error = TimeoutError("fabricated unknown write")
    assert publish(s)["status"] == "NEEDS_HUMAN"
    old = s["env"]
    app = replace(old.app, installation_id=990)
    installation = replace(old.installation, identifier=990)
    project = replace(
        old.policy.project,
        publication_context_sha256=comment.publication_context(
            app, installation, old.author
        ),
    )
    policy = replace(old.policy, project=project)
    env = replace(old, app=app, installation=installation, policy=policy)
    s["reader"].policy = policy
    assert env.key == old.key and env.journal_scope != old.journal_scope
    grant = replace(s["grant"], envelope_sha256=env.digest)
    journal = Journal(env, s["cells"])
    writer = Writer(env, s["reader"], journal)
    assert (
        publish(s, envelope=env, authorization=grant, writer=writer, journal=journal)[
            "status"
        ]
        == "BLOCKED"
    )
    assert not writer.calls and len(s["writer"].calls) == 1
    assert s["cells"][old.key].state == "UNKNOWN"


def test_wrong_source_root_and_stale_source_branch_block(projects):
    a, b = projects
    assert publish(a)["status"] == "PUBLISHED_SYNTHETIC"
    with pytest.raises(evidence.EvidenceError):
        evidence.collect(b["root"], a["env"].policy, api=a["reader"])
    git(
        a["root"],
        "update-ref",
        "refs/remotes/origin/main",
        git(a["root"], "rev-parse", "HEAD^{tree}"),
    )
    with pytest.raises(evidence.EvidenceError):
        evidence.collect(a["root"], a["env"].policy, api=a["reader"])


@pytest.mark.parametrize(
    "branch",
    [
        "",
        "../main",
        "refs/heads/main",
        "release/v1",
        "x.lock",
        "a..b",
        "--main",
        "HEAD^{commit}",
    ],
)
def test_unapproved_ref_forms_cannot_select_endpoints(projects, branch):
    with pytest.raises(evidence.EvidenceError):
        replace(projects[0]["env"].policy.project, base_branch=branch)


def test_partial_migration_and_untrusted_project_are_not_inferred(projects):
    env = projects[0]["env"]
    with pytest.raises(comment.PublicationError):
        replace(env, installation=None)
    with pytest.raises(comment.PublicationError):
        replace(env, policy=replace(env.policy, project=None))
    with pytest.raises(evidence.EvidenceError):
        replace(env.policy, project={"repository": "model-selected"})
    with pytest.raises(evidence.EvidenceError):
        replace(env.policy, purpose="merged")


def test_head_drift_after_mock_post_preserves_unknown(projects):
    s = projects[1]
    s["writer"].after = lambda: s["reader"].pr["head"].update(sha="e" * 40)
    assert publish(s)["status"] == "NEEDS_HUMAN"
    assert publish(s)["reason"] == "reconciliation_required"
    assert len(s["writer"].calls) == 1


def test_project_comment_and_collection_never_use_network_or_state_writers(
    projects, monkeypatch
):
    def forbidden(*a, **kw):
        pytest.fail("forbidden external effect")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(state, "write_checkpoint", forbidden)
    assert publish(projects[1])["status"] == "PUBLISHED_SYNTHETIC"
    assert subscription.readiness()["launch_allowed"] is False
    with pytest.raises(state.PrepareError) as exc:
        native_codex.execute({}, 1, ["operator"])
    assert exc.value.code == 13


@pytest.mark.parametrize(
    "field,value",
    [
        ("identifier", 999),
        ("account", evidence.Principal(999, "org-1")),
        ("account", evidence.Principal(100, "other-org")),
        ("account_type", "User"),
    ],
)
def test_observed_installation_account_and_id_are_independently_pinned(
    projects, field, value
):
    s = projects[0]
    actual = replace(s["env"].installation, **{field: value})
    s["writer"].facts = replace(s["writer"].facts, installation=actual)
    assert publish(s)["status"] == "BLOCKED"
    assert not s["writer"].calls


@pytest.mark.parametrize(
    "field,value",
    [
        ("app_id", 999),
        ("owner", evidence.Principal(999, "changed-owner")),
        ("bot", evidence.Principal(999, "reviewer[bot]")),
        ("owner_type", "User"),
    ],
)
def test_registration_metadata_is_not_installation_account_metadata(
    projects, field, value
):
    s = projects[0]
    s["writer"].facts = replace(
        s["writer"].facts, app=replace(s["env"].app, **{field: value})
    )
    assert publish(s)["status"] == "BLOCKED"
    assert not s["writer"].calls


@pytest.mark.parametrize(
    "changes",
    [
        {"repository_ids": (1000, 2000)},
        {"repository_selection": "all"},
        {"permissions": comment.PERMISSIONS + (("contents", "write"),)},
        {"token_kind": "user"},
        {"expires_at": NOW},
    ],
)
def test_project_scope_is_never_broad_or_overprivileged(projects, changes):
    s = projects[1]
    s["writer"].facts = replace(s["writer"].facts, **changes)
    assert publish(s)["status"] == "BLOCKED"
    assert not s["writer"].calls


def test_approval_and_prior_pass_cannot_be_moved_between_number_collisions(projects):
    a, b = projects
    assert publish(a)["status"] == "PUBLISHED_SYNTHETIC"
    b["reader"].reviews = copy.deepcopy(a["reader"].reviews)
    assert publish(b)["status"] == "BLOCKED"
    assert not b["writer"].calls
    assert publish(b, authorization=a["grant"])["status"] == "BLOCKED"


def test_foreign_journal_intent_is_not_a_receipt_for_another_project(projects):
    a, b = projects
    a["writer"].error = TimeoutError()
    publish(a)
    old = a["cells"][a["env"].key]
    b["cells"][b["env"].key] = old  # Deliberately corrupt synthetic store mapping.
    assert publish(b)["status"] == "BLOCKED"
    assert not b["writer"].calls
    assert a["cells"][a["env"].key] == old


@pytest.mark.parametrize(
    "field,value",
    [
        ("scope_sha256", None),
        ("guard_sha256", None),
        ("scope_sha256", "f" * 64),
        ("guard_sha256", "f" * 64),
    ],
)
def test_partial_or_foreign_journal_namespace_blocks(projects, field, value):
    s = projects[0]
    s["journal"].facts = replace(s["journal"].facts, **{field: value})
    assert publish(s)["status"] == "BLOCKED"
    assert not s["writer"].calls


@pytest.mark.parametrize("phase", ["between_reads", "after_post"])
def test_project_head_drift_never_verifies_or_retries(projects, phase):
    s = projects[0]
    if phase == "between_reads":
        calls = []

        def drift(suffix):
            if suffix == f"/pulls/{s['env'].policy.pull_request}":
                calls.append(1)
                if len(calls) == 2:
                    s["reader"].pr["head"]["sha"] = "e" * 40

        s["reader"].hook = drift
    else:
        s["writer"].after = lambda: s["reader"].pr["head"].update(sha="e" * 40)
    assert publish(s)["status"] == (
        "BLOCKED" if phase == "between_reads" else "NEEDS_HUMAN"
    )
    assert len(s["writer"].calls) == (0 if phase == "between_reads" else 1)


@pytest.mark.parametrize("code", [401, 403, 429, 500])
def test_downstream_errors_do_not_authorize_retries(projects, code):
    s = projects[1]
    s["writer"].error = RuntimeError(f"fabricated HTTP {code}")
    assert publish(s)["status"] == "NEEDS_HUMAN"
    assert publish(s)["reason"] == "reconciliation_required"
    assert len(s["writer"].calls) == 1


@pytest.mark.parametrize("bad", [None, {}, True, 2])
def test_invalid_or_migrated_project_version_is_not_inferred(projects, bad):
    with pytest.raises(evidence.EvidenceError):
        replace(projects[0]["env"].policy.project, schema_version=bad)


@pytest.mark.parametrize(
    "key", ["include.path", "core.sparsecheckout", "filter.fake.clean"]
)
def test_project_read_only_source_retains_original_unsafe_config_rejections(
    projects, key
):
    s = projects[0]
    git(s["root"], "config", "--local", key, "inert-fixture")
    with pytest.raises(evidence.EvidenceError):
        evidence.collect(s["root"], s["env"].policy, api=s["reader"])


def test_explicit_project_owner_type_is_separate_from_registration_owner_type(projects):
    s = projects[1]
    old = s["env"]
    installation = replace(old.installation, account_type="User")
    project = replace(
        old.policy.project,
        owner_type="User",
        publication_context_sha256=comment.publication_context(
            old.app, installation, old.author
        ),
    )
    policy = replace(old.policy, project=project)
    env = replace(old, policy=policy, installation=installation)
    s["reader"].metadata["owner"]["type"] = "User"
    s["reader"].policy = policy
    journal = Journal(env, s["cells"])
    writer = Writer(env, s["reader"], journal)
    grant = replace(s["grant"], envelope_sha256=env.digest)
    assert env.app.owner_type == "Organization"
    assert (
        publish(s, envelope=env, authorization=grant, writer=writer, journal=journal)[
            "status"
        ]
        == "PUBLISHED_SYNTHETIC"
    )


def test_operator_approved_main_trunk_policies_are_not_runtime_authority(
    projects, monkeypatch
):
    def forbidden(*a, **kw):
        pytest.fail("runtime/prepare must stay disconnected")

    monkeypatch.setattr(prepare, "prepare", forbidden)
    for s in projects:
        assert publish(s)["status"] == "PUBLISHED_SYNTHETIC"
        receipt = evidence.collect(s["root"], s["env"].policy, api=s["reader"])
        with pytest.raises(evidence.EvidenceError):
            receipt.publisher_admission(now=NOW)


def test_wrong_project_root_is_rejected_before_git_inspection(projects, monkeypatch):
    a, b = projects

    def forbidden(*a, **kw):
        pytest.fail("foreign source root inspected")

    monkeypatch.setattr(cli, "inspect", forbidden)
    with pytest.raises(evidence.EvidenceError):
        evidence.collect(b["root"], a["env"].policy, api=a["reader"])
    assert not a["reader"].calls


@pytest.mark.parametrize("kind", ["issue", "link"])
def test_identical_issue_numbers_in_foreign_repository_are_not_equivalent(
    projects, kind
):
    a, b = projects
    pin = a["env"].policy.admission
    if kind == "issue":
        other = copy.deepcopy(b["reader"].issue)
        other["number"] = pin.issue
        other["url"] = (
            f"https://api.github.com/repos/{b['env'].policy.admission.repository}/issues/{pin.issue}"
        )
        a["reader"].issue = other
    else:
        a["reader"].links = copy.deepcopy(b["reader"].links)
        a["reader"].links[0]["number"] = pin.issue
    assert publish(a)["status"] == "BLOCKED"
    assert not a["writer"].calls


def test_cross_project_ci_app_with_otherwise_matching_sha_is_rejected(projects):
    a, b = projects
    head = a["env"].policy.head_sha
    a["reader"].checks[head]["check_runs"][0]["app"]["id"] = (
        b["env"].policy.checks[0].app_id
    )
    assert publish(a)["status"] == "BLOCKED"
    assert not a["writer"].calls


@pytest.mark.parametrize(
    "kind", ["branch", "missing_check", "author", "partial_connection"]
)
def test_project_preflight_does_not_skip_existing_strict_evidence_rules(projects, kind):
    s = projects[1]
    if kind == "branch":
        s["reader"].branch["name"] = "main"
    elif kind == "missing_check":
        s["reader"].checks[s["env"].policy.head_sha] = {
            "total_count": 0,
            "check_runs": [],
        }
    elif kind == "author":
        s["reader"].pr["user"] = {"id": 777, "login": "unapproved-author"}
    else:
        original = s["reader"].graph

        def partial(connection, after=None):
            result = original(connection, after)
            field = (
                "closingIssuesReferences" if connection == "links" else "reviewThreads"
            )
            result["repository"]["pullRequest"][field]["pageInfo"]["hasNextPage"] = True
            return result

        s["reader"].graph = partial
    assert publish(s)["status"] == "BLOCKED"
    assert not s["writer"].calls


def test_receipts_are_not_transferable_across_installation_or_author_context(projects):
    s = projects[0]
    env = s["env"]
    assert publish(s)["status"] == "PUBLISHED_SYNTHETIC"
    receipt = evidence.collect(s["root"], env.policy, api=s["reader"])
    rotated = replace(env.installation, identifier=999)
    app = replace(env.app, installation_id=999)
    rotated_project = replace(
        env.policy.project,
        publication_context_sha256=comment.publication_context(
            app, rotated, env.author
        ),
    )
    with pytest.raises(evidence.EvidenceError):
        receipt.for_project(rotated_project, now=NOW)
    changed_author = evidence.Principal(888, "new-author")
    changed_project = replace(
        env.policy.project,
        author=changed_author,
        publication_context_sha256=comment.publication_context(
            env.app, env.installation, changed_author
        ),
    )
    with pytest.raises(evidence.EvidenceError):
        receipt.for_project(changed_project, now=NOW)
    with pytest.raises(evidence.EvidenceError):
        replace(
            env.policy,
            project=replace(
                env.policy.project,
                reviewers=(evidence.Principal(333, "other-reviewer"),),
            ),
        )
