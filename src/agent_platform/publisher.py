"""Offline publish candidates; no credentials, writes or publishing authority."""

import hashlib
import json
import os
import re
import stat
import time
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Literal

from agent_platform import cli, codex, execution, issues, prepare, state
from agent_platform import runtime_manifest as static

MAX_FILES = 128
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_BYTES = 32 * 1024 * 1024
CHUNK = 65536
CHECKS = ("ruff", "pytest", "diff_check")
HEX = re.compile(r"[a-f0-9]{64}")


class PlanError(Exception):
    """Only fixed, bounded refusal codes cross the diagnostic boundary."""


def require(value, reason):
    if not value:
        raise PlanError(reason)


def encoded(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def hex_digest(value):
    return type(value) is str and HEX.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class Admission:
    """Trusted caller's result of prepare.approved, never parsed from task files."""

    repo_id: int
    repository: str
    issue: int
    issue_id: int
    scope_sha256: str
    scope_revision: str
    admission_sha256: str
    base_sha: str

    def __post_init__(self):
        require(
            all(
                issues.positive_int(n)
                for n in (self.repo_id, self.issue, self.issue_id)
            ),
            "invalid_admission",
        )
        require(
            type(self.repository) is str
            and cli.parse_origin("https://github.com/" + self.repository)
            == self.repository,
            "invalid_admission",
        )
        issues.timestamp(self.scope_revision)
        require(
            hex_digest(self.scope_sha256) and hex_digest(self.admission_sha256),
            "invalid_admission",
        )
        require(
            type(self.base_sha) is str and prepare.SHA.fullmatch(self.base_sha),
            "invalid_admission",
        )


@dataclass(frozen=True, slots=True)
class FileChange:
    path: str
    status: str
    base_blob: str | None
    index_blob: str | None
    base_mode: str | None
    index_mode: str | None
    worktree_mode: str | None
    bytes: int | None
    sha256: str | None

    def __post_init__(self):
        _safe_name(self.path)
        require(
            self.status in {" M", "M ", "MM", "A ", "AM", " D", "D ", "MD", "AD", "??"},
            "invalid_inventory",
        )
        require(
            all(
                v is None or type(v) is str and prepare.SHA.fullmatch(v)
                for v in (self.base_blob, self.index_blob)
            ),
            "invalid_inventory",
        )
        require(
            all(
                v is None or type(v) is str and v in {"100644", "100755"}
                for v in (self.base_mode, self.index_mode, self.worktree_mode)
            ),
            "invalid_inventory",
        )
        require(
            (self.bytes is None and self.sha256 is None)
            or (
                type(self.bytes) is int
                and 0 <= self.bytes <= MAX_FILE_BYTES
                and hex_digest(self.sha256)
            ),
            "invalid_inventory",
        )


@dataclass(frozen=True, slots=True)
class TestCheck:
    name: Literal["ruff", "pytest", "diff_check"]
    outcome: Literal["PASS"]
    artifact_sha256: str

    def __post_init__(self):
        require(
            type(self.name) is str
            and self.name in CHECKS
            and self.outcome == "PASS"
            and hex_digest(self.artifact_sha256),
            "invalid_test_evidence",
        )


@dataclass(frozen=True, slots=True)
class TestEvidence:
    """External trusted test receipts bound to exact checkpoint and file inventory."""

    checkpoint_sha256: str
    tree_sha256: str
    expected_changes: tuple[FileChange, ...]
    checks: tuple[TestCheck, ...]

    def __post_init__(self):
        require(
            hex_digest(self.checkpoint_sha256) and hex_digest(self.tree_sha256),
            "invalid_test_evidence",
        )
        require(
            type(self.expected_changes) is tuple
            and 0 < len(self.expected_changes) <= MAX_FILES
            and all(type(c) is FileChange for c in self.expected_changes),
            "invalid_test_evidence",
        )
        require(
            type(self.checks) is tuple
            and len(self.checks) == 3
            and all(type(c) is TestCheck for c in self.checks),
            "invalid_test_evidence",
        )


@dataclass(frozen=True, slots=True)
class PublishPlan:
    schema_version: Literal[1]
    admission: Admission
    source_root: str
    common_dir: str
    worktree: str
    branch: str
    checkpoint_generation: int
    checkpoint_sha256: str
    session_id: str
    execution_id: str
    refs_sha256: str
    changes: tuple[FileChange, ...]
    inventory_sha256: str
    tree_sha256: str
    evidence_sha256: str
    common_sha256: str
    idempotency_key: str
    terminal_state: Literal["COMPLETED"] = field(default="COMPLETED", init=False)
    execution_guard: Literal["ABSENT"] = field(default="ABSENT", init=False)
    base_branch: Literal["main"] = field(default="main", init=False)
    draft: Literal[True] = field(default=True, init=False)
    publish_authorized: Literal[False] = field(default=False, init=False)

    @property
    def title(self):
        return f"Issue #{self.admission.issue}: proposed changes"

    @property
    def body(self):
        return (
            f"Closes #{self.admission.issue}\n\n"
            "Offline candidate; publication is not authorized."
        )

    def diagnostic(self):
        # No local paths, filenames, Issue text, logs, remotes or model messages.
        return {
            "status": "INSPECTED_PUBLISH_CANDIDATE",
            "schema_version": 1,
            "repository": self.admission.repository,
            "repo_id": self.admission.repo_id,
            "issue": self.admission.issue,
            "base_sha": self.admission.base_sha,
            "changed_files": len(self.changes),
            "inventory_sha256": self.inventory_sha256,
            "idempotency_key": self.idempotency_key,
            "publish_authorized": False,
        }


def _fingerprint(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _safe_name(name):
    require(static.relative(name), "unsafe_path")
    require(
        all(
            not p.startswith("-")
            and p.casefold()
            not in {
                ".git",
                ".codex",
                ".ssh",
                ".aws",
                ".env",
                ".netrc",
                "auth.json",
                "credentials",
            }
            for p in name.split("/")
        ),
        "unsafe_path",
    )
    return name


def _rows(raw):
    require(not raw or raw.endswith(b"\0"), "ambiguous_git_status")
    return raw[:-1].split(b"\0") if raw else []


def _status(root):
    raw = prepare.git(
        root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignored=matching",
        "--ignore-submodules=none",
    )
    result = {}
    for row in _rows(raw):
        require(len(row) > 3 and row[2:3] == b" ", "ambiguous_git_status")
        code = row[:2].decode("ascii")
        require(
            code in {" M", "M ", "MM", "A ", "AM", " D", "D ", "MD", "AD", "??"},
            "ambiguous_git_status",
        )
        name = _safe_name(row[3:].decode("ascii"))
        require(name not in result, "ambiguous_git_status")
        result[name] = code
    require(len(result) <= MAX_FILES, "inventory_limit")
    return result


def _objects(root, *, index):
    raw = (
        prepare.git(root, "ls-files", "--stage", "-z")
        if index
        else prepare.git(root, "ls-tree", "-r", "-z", "--full-tree", "HEAD")
    )
    result = {}
    for row in _rows(raw):
        header, name = row.decode("ascii").split("\t")
        mode, value, stage = (
            header.split()
            if index
            else (header.split()[0], header.split()[2], header.split()[1])
        )
        require(
            mode in {"100644", "100755"} and prepare.SHA.fullmatch(value),
            "unsupported_index",
        )
        require(stage == ("0" if index else "blob"), "unsupported_index")
        name = _safe_name(name)
        require(name not in result, "unsupported_index")
        result[name] = (mode, value)
    return result


def _metadata(root):
    """Git control data stays outside the task tree; reject aliases and writers."""
    state.no_symlinks(root)
    static.mounts(root)
    info = root.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.getuid()
        and not info.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID),
        "unsafe_git_metadata",
    )
    private = not info.st_mode & 0o077
    result = {".": _fingerprint(info)}
    for name, info, _ in static.walk(root):
        require(
            info.st_uid == os.getuid()
            and not info.st_mode & (stat.S_ISUID | stat.S_ISGID),
            "unsafe_git_metadata",
        )
        require(private or not info.st_mode & 0o022, "unsafe_git_metadata")
        require(
            stat.S_ISDIR(info.st_mode)
            or stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1,
            "unsafe_git_metadata",
        )
        require(not str(name).endswith(".lock"), "git_writer_present")
        result[str(name)] = _fingerprint(info)
    return result


def _tree(root):
    """Bounded descriptor traversal, without filters, diff drivers or execution."""
    state.no_symlinks(root)
    static.mounts(root)
    files, fingerprints = {}, {".": _fingerprint(root.lstat())}
    total = 0
    deadline = time.monotonic() + 30
    for name, info, parent in static.walk(root):
        require(time.monotonic() < deadline, "inventory_limit")
        value = str(name)
        require(
            info.st_uid == os.getuid()
            and not info.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID),
            "unsafe_worktree",
        )
        require(
            stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), "unsafe_worktree"
        )
        fingerprints[value] = _fingerprint(info)
        if value != ".git":
            _safe_name(value)
        if stat.S_ISDIR(info.st_mode):
            continue
        require(info.st_nlink == 1, "unsafe_worktree")
        require(
            info.st_size <= (4096 if value == ".git" else MAX_FILE_BYTES),
            "inventory_limit",
        )
        total += info.st_size
        require(total <= MAX_BYTES, "inventory_limit")
        fd = os.open(
            name.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
        )
        try:
            require(
                _fingerprint(os.fstat(fd)) == _fingerprint(info), "worktree_changed"
            )
            sha = hashlib.sha256()
            blob = hashlib.sha1(
                f"blob {info.st_size}\0".encode(), usedforsecurity=False
            )
            count = 0
            while raw := os.read(fd, CHUNK):
                count += len(raw)
                require(
                    count <= info.st_size and time.monotonic() < deadline,
                    "worktree_changed",
                )
                sha.update(raw)
                blob.update(raw)
            require(
                count == info.st_size
                and _fingerprint(os.fstat(fd)) == _fingerprint(info),
                "worktree_changed",
            )
            require(
                _fingerprint(os.stat(name.name, dir_fd=parent, follow_symlinks=False))
                == _fingerprint(info),
                "worktree_changed",
            )
        finally:
            os.close(fd)
        if value != ".git":
            files[value] = (
                "100755" if info.st_mode & stat.S_IXUSR else "100644",
                blob.hexdigest(),
                info.st_size,
                sha.hexdigest(),
            )
    return files, fingerprints


def _inventory(root):
    before = _status(root)
    base, index = _objects(root, index=False), _objects(root, index=True)
    flags = prepare.git(root, "ls-files", "-v", "-z")
    require(all(row.startswith(b"H ") for row in _rows(flags)), "unsupported_index")
    files, metadata = _tree(root)
    result, derived = [], {}
    for name in sorted(base.keys() | index.keys() | files.keys()):
        old, staged, work = base.get(name), index.get(name), files.get(name)
        if old == staged and (work[:2] if work else None) == staged:
            continue
        if old is None and staged is None:
            code = "??"
        else:
            x = (
                " "
                if old == staged
                else "A"
                if old is None
                else "D"
                if staged is None
                else "M"
            )
            require(staged is not None or work is None, "ambiguous_git_status")
            y = (
                " "
                if (work[:2] if work else None) == staged
                else "D"
                if work is None
                else "M"
            )
            code = x + y
        derived[name] = code
        result.append(
            FileChange(
                name,
                code,
                old[1] if old else None,
                staged[1] if staged else None,
                old[0] if old else None,
                staged[0] if staged else None,
                work[0] if work else None,
                work[2] if work else None,
                work[3] if work else None,
            )
        )
    require(derived == before == _status(root), "ambiguous_git_status")
    require(index == _objects(root, index=True), "worktree_changed")
    require(0 < len(result) <= MAX_FILES, "empty_or_large_inventory")
    return tuple(result), metadata, digest(files)


def _completed(record, expected):
    require(
        type(record) is dict
        and record.keys() == expected.keys() | execution.EXTRA_KEYS,
        "invalid_checkpoint",
    )
    require(
        all(
            type(record[k]) is type(v) and record[k] == v
            for k, v in expected.items()
            if k not in execution.MUTABLE
        ),
        "checkpoint_identity_mismatch",
    )
    require(
        type(record["version"]) is int
        and record["version"] == 2
        and record["phase"] == "COMPLETED"
        and record["last_intent"] == "TURN_COMPLETED"
        and record["stop_reason"] == "completed",
        "task_not_completed",
    )
    require(
        type(record["attempt"]) is int
        and 1 <= record["attempt"] < 2**31
        and type(record["generation"]) is int
        and record["generation"] == 2 + 3 * record["attempt"],
        "invalid_checkpoint",
    )
    for key in ("codex_thread_id", "execution_id"):
        codex.session_id(record[key])
    require(record["codex_version"] == codex.VERSION, "invalid_checkpoint")
    require(
        all(
            hex_digest(record[k])
            for k in ("refs_sha256", "isolation_sha256", "runtime_sha256")
        ),
        "invalid_checkpoint",
    )
    usage = record["usage"]
    require(
        type(usage) is dict
        and set(usage) == {"input_tokens", "cached_input_tokens", "output_tokens"}
        and all(type(n) is int and 0 <= n < 2**63 for n in usage.values()),
        "invalid_checkpoint",
    )
    sessions = prepare.HOME / ".local/share/agent-platform/codex-sessions"
    home = (
        sessions
        / str(record["repo_id"])
        / f"issue-{record['issue']}"
        / record["execution_id"]
    )
    require(record["codex_home"] == str(home), "invalid_checkpoint")
    # Never open native session/auth files. Their recorded digest is lineage only.


def _evidence(evidence, checkpoint_digest, changes, tree_digest):
    require(
        type(evidence) is TestEvidence
        and type(evidence.expected_changes) is tuple
        and all(type(c) is FileChange for c in evidence.expected_changes),
        "invalid_test_evidence",
    )
    require(
        evidence.checkpoint_sha256 == checkpoint_digest
        and evidence.expected_changes == changes
        and evidence.tree_sha256 == tree_digest,
        "stale_test_evidence",
    )
    require(
        type(evidence.checks) is tuple
        and all(type(c) is TestCheck for c in evidence.checks),
        "invalid_test_evidence",
    )
    require(
        tuple(c.name for c in evidence.checks) == CHECKS
        and all(
            c.outcome == "PASS" and hex_digest(c.artifact_sha256)
            for c in evidence.checks
        ),
        "missing_test_evidence",
    )


def _no_guard(checkpoint):
    guard = checkpoint.with_suffix(".execution-guard")
    try:
        guard.lstat()
    except FileNotFoundError:
        return
    raise PlanError("execution_guard_present")


def plan(
    source_root: Path, admission: Admission, evidence: TestEvidence
) -> PublishPlan:
    """Trusted caller supplies admission/test receipts. No GitHub client is created."""
    require(type(admission) is Admission, "invalid_admission")
    require(isinstance(source_root, Path), "invalid_source")
    state.no_symlinks(source_root)
    source_info = source_root.lstat()
    require(
        source_info.st_uid == os.getuid() and not source_info.st_mode & 0o022,
        "unsafe_storage",
    )
    with state.host_lock(create=False) as lock_fd:
        lock_info = _fingerprint(os.fstat(lock_fd))
        lock_path = state.LOCK_DIR / "prepare.lock"
        require(_fingerprint(lock_path.lstat()) == lock_info, "lock_changed")
        metadata_before = _metadata(source_root / ".git")
        source = prepare.source_snapshot(cli.inspect(source_root))
        require(
            source["base_sha"] == admission.base_sha
            and source["repository"].casefold() == admission.repository.casefold(),
            "source_mismatch",
        )
        source["repository"] = admission.repository
        store = prepare.HOME / ".local/state/agent-platform"
        checkpoint = store / str(admission.repo_id) / f"issue-{admission.issue}.json"
        target = (
            prepare.HOME
            / ".local/share/agent-platform/worktrees"
            / str(admission.repo_id)
            / f"issue-{admission.issue}"
        )
        require(
            not target.is_relative_to(source_root)
            and not any(
                p.is_relative_to(source_root) or p.is_relative_to(target)
                for p in (store, state.LOCK_DIR)
            ),
            "unsafe_storage",
        )
        require(
            state.private_directory(checkpoint.parent, store, create=False),
            "checkpoint_required",
        )
        require(
            state.private_directory(target.parent, target.parents[2], create=False),
            "unsafe_storage",
        )
        _no_guard(checkpoint)
        checkpoint_info = _fingerprint(checkpoint.lstat())
        record = state.load_checkpoint(checkpoint)
        expected = prepare.checkpoint_record(source, asdict(admission), target)
        _completed(record, expected)
        prepare.confirm_identity(source_root, record)
        references = execution.refs(source_root)
        require(references == record["refs_sha256"], "unexpected_refs")
        checkpoint_digest = digest(record)
        changes, metadata, tree_digest = _inventory(target)
        _evidence(evidence, checkpoint_digest, changes, tree_digest)
        # No plan survives observed changes during inspection; no files are repaired.
        after, after_metadata, after_tree = _inventory(target)
        require(
            after == changes
            and after_metadata == metadata
            and after_tree == tree_digest,
            "worktree_changed",
        )
        require(state.load_checkpoint(checkpoint) == record, "checkpoint_changed")
        require(
            _fingerprint(checkpoint.lstat()) == checkpoint_info, "checkpoint_changed"
        )
        _no_guard(checkpoint)
        require(_fingerprint(lock_path.lstat()) == lock_info, "lock_changed")
        require(execution.refs(source_root) == references, "unexpected_refs")
        current = prepare.source_snapshot(cli.inspect(source_root))
        current["repository"] = admission.repository
        require(current == source, "source_mismatch")
        prepare.confirm_identity(source_root, record)
        payload = dict(
            schema_version=1,
            admission=admission,
            source_root=str(source_root),
            common_dir=record["common_dir"],
            worktree=str(target),
            branch=record["branch"],
            checkpoint_generation=record["generation"],
            checkpoint_sha256=checkpoint_digest,
            session_id=record["codex_thread_id"],
            execution_id=record["execution_id"],
            refs_sha256=references,
            changes=changes,
            inventory_sha256=digest([asdict(c) for c in changes]),
            evidence_sha256=digest(asdict(evidence)),
            tree_sha256=tree_digest,
        )
        require(
            _fingerprint(source_root.lstat()) == _fingerprint(source_info),
            "source_mismatch",
        )
        require(
            _metadata(source_root / ".git") == metadata_before, "git_metadata_changed"
        )
        payload["common_sha256"] = digest(metadata_before)
        candidate = PublishPlan(**payload, idempotency_key="")
        return replace(candidate, idempotency_key=digest(asdict(candidate)))


REFUSALS = frozenset(
    {
        "invalid_admission",
        "invalid_source",
        "invalid_inventory",
        "invalid_test_evidence",
        "unsafe_storage",
        "unsafe_git_metadata",
        "git_writer_present",
        "git_metadata_changed",
        "checkpoint_required",
        "source_mismatch",
        "execution_guard_present",
        "invalid_checkpoint",
        "task_not_completed",
        "checkpoint_identity_mismatch",
        "unexpected_refs",
        "lock_changed",
        "unsafe_path",
        "ambiguous_git_status",
        "inventory_limit",
        "unsupported_index",
        "unsafe_worktree",
        "worktree_changed",
        "empty_or_large_inventory",
        "stale_test_evidence",
        "missing_test_evidence",
        "checkpoint_changed",
    }
)


def diagnose(source_root, admission, evidence):
    """Bounded JSON-ready diagnostics, without raw errors or candidate file content."""
    try:
        return plan(source_root, admission, evidence).diagnostic()
    except PlanError as exc:
        reason = str(exc) if str(exc) in REFUSALS else "local_state_unavailable"
    except state.PrepareError as exc:
        reason = "lock_busy" if exc.code == 10 else "checkpoint_or_repository_invalid"
    except cli.InspectionError:
        reason = "invalid_source"
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        IndexError,
        RecursionError,
        codex.ProtocolError,
        static.InvalidRuntime,
    ):
        reason = "local_state_unavailable"
    return {"status": "BLOCKED", "reason": reason, "publish_authorized": False}
