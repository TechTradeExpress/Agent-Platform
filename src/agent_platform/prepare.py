"""Explicit task preparation; no execution, automatic recovery or GitHub writes."""

import hashlib
import json
import os
import pwd
import re
from pathlib import Path

from agent_platform import issues, state
from agent_platform.cli import InspectionError, inspect, parse_origin
from agent_platform.process import CommandError, read_command
from agent_platform.state import PrepareError, check

HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)
SHA = re.compile(r"[0-9a-f]{40}")
GIT_OPTIONS = [
    "--no-replace-objects",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.untrackedCache=false",
    "-c",
    "submodule.recurse=false",
]


def git(root: Path, *args: str) -> bytes:
    env = {
        "PATH": os.defpath,
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_LAZY_FETCH": "1",
    }
    try:
        return read_command(
            ["git", *GIT_OPTIONS, *args], root, env, timeout=5, limit=256 * 1024
        )
    except CommandError:
        raise PrepareError(11, "git_query_failed") from None


def line(raw: bytes) -> str:
    try:
        value = raw.decode("utf-8").removesuffix("\n")
    except UnicodeError:
        raise PrepareError(11, "unsafe_git_value") from None
    check(bool(value) and all(c.isprintable() for c in value), 11, "unsafe_git_value")
    return value


def clean(root: Path) -> None:
    check(
        not git(
            root,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=all",
        ),
        11,
        "dirty_checkout",
    )


def source_snapshot(info: dict) -> dict:
    root = Path(info["root"])
    check(
        info["branch"] == "main" and not info["linked_worktree"],
        11,
        "source_must_be_primary_main",
    )
    state.no_symlinks(root / ".git")
    common = Path(
        line(git(root, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    )
    check(common == root / ".git" and common.is_dir(), 11, "ambiguous_common_directory")
    # Worktree config, includes and checkout filters can override safety settings
    # or execute commands during checkout. MVP.2a rejects these configurations.
    keys = git(root, "config", "--local", "--no-includes", "--name-only", "--list")
    try:
        config_keys = keys.decode("utf-8").lower().splitlines()
    except UnicodeError:
        raise PrepareError(11, "unsupported_git_configuration") from None
    for key in config_keys:
        check(
            not key.startswith(
                (
                    "include.",
                    "includeif.",
                    "filter.",
                    "extensions.",
                    "core.worktree",
                    "core.sparsecheckout",
                )
            )
            and not key.endswith((".promisor", ".partialclonefilter")),
            11,
            "unsupported_git_configuration",
        )
    for relative in ("objects/info/alternates", "info/grafts", "shallow", "commondir"):
        check(
            not (common / relative).exists() and not (common / relative).is_symlink(),
            11,
            "unsupported_git_layout",
        )
    for relative in (
        "config",
        "index",
        "HEAD",
        "packed-refs",
        "worktrees",
        "objects/pack",
        "refs/heads/agent",
        "logs/refs/heads/agent",
    ):
        state.no_symlinks(common / relative)
    origin = line(git(root, "remote", "get-url", "--all", "origin"))
    configured = line(git(root, "config", "--local", "--get-all", "remote.origin.url"))
    check(
        origin == configured and parse_origin(origin) == info["repository"],
        11,
        "ambiguous_origin",
    )
    stages = git(root, "ls-files", "--stage")
    check(
        not any(row.startswith(b"160000 ") for row in stages.splitlines()),
        11,
        "submodules_not_supported",
    )
    flags = git(root, "ls-files", "-v")
    check(
        all(row.startswith(b"H ") for row in flags.splitlines()),
        11,
        "unsupported_index_flags",
    )
    clean(root)
    revisions = [
        line(git(root, "rev-parse", "--verify", ref + "^{commit}"))
        for ref in ("HEAD", "refs/heads/main", "refs/remotes/origin/main")
    ]
    check(
        all(SHA.fullmatch(sha) for sha in revisions) and len(set(revisions)) == 1,
        11,
        "stale_or_diverged_refs",
    )
    return {
        "source_root": str(root),
        "common_dir": str(common),
        "repository": info["repository"],
        "base_sha": revisions[0],
    }


def approved(
    api: issues.GitHub, repository: str, number: int, actors: list[str]
) -> dict:
    repo_id, canonical = issues.identity(api, repository)
    metadata, _ = api.get()
    issues.require(
        isinstance(metadata, dict)
        and type(metadata.get("id")) is int
        and metadata["id"] == repo_id
    )
    issues.require(metadata.get("full_name") == canonical)
    check(metadata.get("default_branch") == "main", 11, "unsupported_default_branch")
    branch, _ = api.get("/branches/main")
    issues.require(isinstance(branch, dict) and isinstance(branch.get("commit"), dict))
    issues.require(branch.get("name") == "main")
    sha = branch["commit"].get("sha")
    issues.require(isinstance(sha, str) and SHA.fullmatch(sha) is not None)
    issue, actor, reason, history = issues.validate_candidate(
        api,
        canonical,
        number,
        {actor.casefold() for actor in actors},
    )
    check(reason is None and actor is not None, 9, "untrusted_issue")
    digest = hashlib.sha256(
        json.dumps(
            {"title": issue["title"], "body": issue["body"]},
            sort_keys=True,
        ).encode()
    ).hexdigest()
    history_digest = hashlib.sha256(
        json.dumps(history, default=str).encode()
    ).hexdigest()
    return {
        "repo_id": repo_id,
        "repository": canonical,
        "issue": number,
        "issue_id": issue["id"],
        "scope_sha256": digest,
        "scope_revision": issue["updated_at"],
        "admission_sha256": history_digest,
        "base_sha": sha,
    }


def worktrees(root: Path) -> dict:
    raw = git(root, "worktree", "list", "--porcelain", "-z")
    found = {}
    try:
        for entry in raw.rstrip(b"\0").split(b"\0\0"):
            rows = entry.split(b"\0")
            check(len(rows) == 3, 11, "unexpected_worktree")
            path, head, branch = rows
            check(
                path.startswith(b"worktree ")
                and head.startswith(b"HEAD ")
                and branch.startswith(b"branch "),
                11,
                "unexpected_worktree",
            )
            name = line(path[9:])
            check(name not in found, 11, "unexpected_worktree")
            found[name] = (line(head[5:]), line(branch[7:]))
    except UnicodeError:
        raise PrepareError(11, "unexpected_worktree") from None
    return found


def confirm(root: Path, record: dict) -> None:
    path = Path(record["worktree"])
    state.no_symlinks(path)
    check(path.is_dir() and path.resolve() == path, 12, "unconfirmed_worktree")
    check(
        path.stat().st_uid == os.getuid() and path.stat().st_mode & 0o777 == 0o700,
        12,
        "unconfirmed_worktree",
    )
    try:
        info = inspect(path)
    except InspectionError:
        raise PrepareError(12, "unconfirmed_worktree") from None
    check(
        info["root"] == str(path)
        and info["repository"].casefold() == record["repository"].casefold()
        and info["branch"] == record["branch"]
        and info["linked_worktree"],
        12,
        "unconfirmed_worktree",
    )
    common = line(git(path, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    check(common == record["common_dir"], 12, "unconfirmed_worktree")
    check(
        line(git(path, "rev-parse", "--verify", "HEAD^{commit}")) == record["base_sha"],
        12,
        "unconfirmed_worktree",
    )
    clean(path)
    expected = {
        str(root): (record["base_sha"], "refs/heads/main"),
        str(path): (record["base_sha"], "refs/heads/" + record["branch"]),
    }
    check(worktrees(root) == expected, 12, "unconfirmed_worktree")


def checkpoint_record(source: dict, admission: dict, path: Path) -> dict:
    return {
        **source,
        **admission,
        "version": 1,
        "branch": f"agent/issue-{admission['issue']}",
        "worktree": str(path),
        "phase": "NEEDS_HUMAN",
        "attempt": 1,
        "generation": 1,
        "last_intent": "CREATE_WORKTREE",
        "codex_thread_id": None,
    }


def validate_checkpoint(record: dict, expected: dict) -> None:
    phase = record.get("phase")
    check(phase in ("READY", "NEEDS_HUMAN"), 12, "invalid_checkpoint")
    desired = dict(expected)
    if phase == "READY":
        desired.update(phase="READY", generation=2, last_intent="CONFIRMED")
    check(record.keys() == desired.keys(), 12, "checkpoint_identity_mismatch")
    check(
        all(
            type(record[key]) is type(value) and record[key] == value
            for key, value in desired.items()
        ),
        12,
        "checkpoint_identity_mismatch",
    )
    check(phase == "READY", 12, "interrupted_transaction")


def prepare(info: dict, number: int, actors: list[str]) -> dict:
    check(
        actors and all(issues.LOGIN.fullmatch(actor) for actor in actors),
        9,
        "missing_trusted_actors",
    )
    source = source_snapshot(info)
    root = Path(source["source_root"])
    api = issues.GitHub(info["repository"])
    admission = approved(api, info["repository"], number, actors)
    check(admission["base_sha"] == source["base_sha"], 11, "github_base_mismatch")
    # Canonical spelling from GitHub, not a remote URL, is recorded.
    source["repository"] = admission["repository"]
    store = HOME / ".local/state/agent-platform"
    trees = HOME / ".local/share/agent-platform/worktrees"
    checkpoint = store / str(admission["repo_id"]) / f"issue-{number}.json"
    target = trees / str(admission["repo_id"]) / f"issue-{number}"
    check(
        not any(path.is_relative_to(root) for path in (store, trees, state.LOCK_DIR)),
        7,
        "private_paths_inside_target",
    )
    expected = checkpoint_record(source, admission, target)
    with state.host_lock():
        state.private_directory(checkpoint.parent, store, create=False)
        state.private_directory(target.parent, trees.parent, create=False)
        record = state.load_checkpoint(checkpoint)
        if record is not None:
            validate_checkpoint(record, expected)
            confirm(root, record)
        else:
            check(
                not target.exists() and not target.is_symlink(),
                11,
                "worktree_path_conflict",
            )
            for namespace in ("refs/heads", "logs/refs/heads"):
                path = Path(source["common_dir"]) / namespace / expected["branch"]
                state.no_symlinks(path)
                check(not path.exists(), 11, "branch_conflict")
            check(
                not git(
                    root,
                    "for-each-ref",
                    "--format=%(refname)",
                    "refs/heads/" + expected["branch"],
                ),
                11,
                "branch_conflict",
            )
            check(
                worktrees(root) == {str(root): (source["base_sha"], "refs/heads/main")},
                11,
                "unexpected_worktree",
            )
        # Revalidate exact scope, provenance, identity and refs under the host lock.
        fresh = approved(api, info["repository"], number, actors)
        check(fresh == admission, 9, "admission_changed")
        current = source_snapshot(inspect(root))
        current["repository"] = fresh["repository"]
        check(current == source, 11, "source_changed")
        if record is not None:
            confirm(root, record)
            return result(record, "already_prepared")
        state.private_directory(checkpoint.parent, store, create=True)
        state.private_directory(target.parent, trees.parent, create=True)
        # After this durable intent, *any* uncertainty requires human reconciliation.
        try:
            state.write_checkpoint(checkpoint, expected)
            target.mkdir(
                mode=0o700
            )  # Exclusive reservation; never reuse a pre-existing path.
            state.sync_directory(target.parent)
            git(
                root,
                "worktree",
                "add",
                "--no-track",
                "-b",
                expected["branch"],
                str(target),
                expected["base_sha"],
            )
            confirm(root, expected)
            ready = {
                **expected,
                "phase": "READY",
                "generation": 2,
                "last_intent": "CONFIRMED",
            }
            state.write_checkpoint(checkpoint, ready, previous=expected)
        except (OSError, PrepareError, CommandError):
            raise PrepareError(12, "interrupted_transaction") from None
        return result(ready, "prepared")


def result(record: dict, status: str) -> dict:
    return {
        "status": status,
        "state": "READY",
        "repository": record["repository"],
        "issue": record["issue"],
        "branch": record["branch"],
        "worktree": record["worktree"],
    }
