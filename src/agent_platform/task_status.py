"""Read-only local checkpoint observations, never launch or live-process authority."""

import os
from pathlib import Path

from agent_platform import codex, execution, prepare, publisher, state
from agent_platform.state import check

PHASES = {"READY", "STARTING", "RUNNING", "PAUSED", "NEEDS_HUMAN", "COMPLETED"}


def validate_record(record, source, number, directory_id):
    """Use the existing checkpoint schema and lifecycle, without session-file reads."""
    check(type(record) is dict, 12, "invalid_checkpoint")
    fields = publisher.Admission.__dataclass_fields__
    admission = publisher.Admission(**{key: record[key] for key in fields})
    check(
        admission.issue == number and admission.repo_id == directory_id,
        12,
        "identity_mismatch",
    )
    check(
        admission.repository.casefold() == source["repository"].casefold()
        and admission.base_sha == source["base_sha"],
        12,
        "identity_mismatch",
    )
    source = {**source, "repository": admission.repository}
    target = (
        prepare.HOME
        / ".local/share/agent-platform/worktrees"
        / str(directory_id)
        / f"issue-{number}"
    )
    expected = prepare.checkpoint_record(
        source, {key: getattr(admission, key) for key in fields}, target
    )
    phase = record["phase"]
    check(type(phase) is str and phase in PHASES, 12, "invalid_checkpoint")
    if record["version"] == 1:
        if phase == "READY":
            prepare.validate_checkpoint(record, expected)
        else:
            check(
                phase == "NEEDS_HUMAN"
                and record.keys() == expected.keys()
                and all(
                    type(record[k]) is type(v) and record[k] == v
                    for k, v in expected.items()
                ),
                12,
                "invalid_checkpoint",
            )
        return target
    check(
        type(record["version"]) is int and record["version"] == 2,
        12,
        "invalid_checkpoint",
    )
    check(
        record.keys() == expected.keys() | execution.EXTRA_KEYS,
        12,
        "invalid_checkpoint",
    )
    check(
        all(
            type(record[k]) is type(v) and record[k] == v
            for k, v in expected.items()
            if k not in execution.MUTABLE
        ),
        12,
        "identity_mismatch",
    )
    codex.session_id(record["execution_id"])
    home = (
        prepare.HOME
        / ".local/share/agent-platform/codex-sessions"
        / str(directory_id)
        / f"issue-{number}"
        / record["execution_id"]
    )
    check(record["codex_home"] == str(home), 12, "invalid_checkpoint")
    if phase == "PAUSED":
        execution.validate_record(record, expected, resume=True)
        return target
    if phase == "COMPLETED":
        publisher._completed(record, expected)
        return target
    check(phase in {"STARTING", "RUNNING", "NEEDS_HUMAN"}, 12, "invalid_checkpoint")
    attempt, generation = record["attempt"], record["generation"]
    check(
        type(attempt) is int and 1 <= attempt < 2**31 and type(generation) is int,
        12,
        "invalid_checkpoint",
    )
    check(
        record["codex_version"] == codex.VERSION
        and all(
            publisher.hex_digest(record[k]) for k in ("refs_sha256", "isolation_sha256")
        ),
        12,
        "invalid_checkpoint",
    )
    check(
        record["usage"] is None and record["runtime_sha256"] is None,
        12,
        "invalid_checkpoint",
    )
    session = record["codex_thread_id"]
    if session is not None:
        codex.session_id(session)
    if phase == "STARTING":
        check(
            generation == 3 * attempt
            and record["last_intent"] == ("RUN" if attempt == 1 else "RESUME")
            and record["stop_reason"] is None,
            12,
            "invalid_checkpoint",
        )
        check(
            session is None if attempt == 1 else session is not None,
            12,
            "invalid_checkpoint",
        )
    elif phase == "RUNNING":
        check(
            session is not None
            and generation == 3 * attempt + 1
            and record["last_intent"] == "SESSION_RECORDED"
            and record["stop_reason"] is None,
            12,
            "invalid_checkpoint",
        )
    else:
        check(
            generation in (3 * attempt + 1, 3 * attempt + 2)
            and record["last_intent"] == "AMBIGUOUS_STOP"
            and record["stop_reason"] == "ambiguous",
            12,
            "invalid_checkpoint",
        )
        check(
            (
                generation == 3 * attempt + 1
                and (session is None if attempt == 1 else session is not None)
            )
            or (generation == 3 * attempt + 2 and session is not None),
            12,
            "invalid_checkpoint",
        )
    return target


def fingerprint(info):
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


def guard_snapshot(path, record):
    try:
        before = path.lstat()
    except FileNotFoundError:
        return "absent", None
    state.private_file(before)
    check(before.st_size == 37, 12, "invalid_guard")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        check(fingerprint(os.fstat(fd)) == fingerprint(before), 12, "guard_changed")
        raw = os.read(fd, 38)
        value = raw.decode("ascii")
        check(value.endswith("\n") and len(value) == 37, 12, "invalid_guard")
        identifier = codex.session_id(value[:-1])
        check(
            record["version"] == 1 or identifier == record["execution_id"],
            12,
            "invalid_guard",
        )
        check(
            fingerprint(os.fstat(fd))
            == fingerprint(before)
            == fingerprint(path.lstat()),
            12,
            "guard_changed",
        )
    finally:
        os.close(fd)
    return "present", fingerprint(before)


def empty_report(number):
    return {
        "schema_version": 1,
        "issue": number,
        "status": "unavailable",
        "reason": "local_state_unavailable",
        "recorded_state": None,
        "checkpoint_validity": "unknown",
        "generation": None,
        "execution_guard": "unknown",
        "host_lock": "unknown",
        "identity": "unverified",
        "session_id": None,
        "stop_reason": None,
        "usage": None,
        "live_activity": "unknown",
        "remote_admission": "not_checked",
        "launch_allowed": False,
    }


def find_checkpoint(root, repository, number):
    """Repo IDs are local admission evidence; never query GitHub to discover one."""
    store = prepare.HOME / ".local/state/agent-platform"
    if not state.private_directory(store, store, create=False):
        return None
    candidates = []
    with os.scandir(store) as listing:
        entries = []
        for item in listing:
            check(len(entries) < 128, 12, "state_limit")
            check(
                item.name.isascii()
                and item.name.isdecimal()
                and str(int(item.name)) == item.name,
                12,
                "ambiguous_store",
            )
            check(0 < int(item.name) < 2**63, 12, "ambiguous_store")
            entries.append(item.name)
    for name in sorted(entries):
        parent = store / name
        check(
            state.private_directory(parent, store, create=False), 12, "unsafe_storage"
        )
        checkpoint = parent / f"issue-{number}.json"
        try:
            before = fingerprint(checkpoint.lstat())
        except FileNotFoundError:
            before = None
        record = state.load_checkpoint(checkpoint)
        if record is None:
            check(before is None, 12, "checkpoint_changed")
            try:
                checkpoint.with_suffix(".execution-guard").lstat()
            except FileNotFoundError:
                continue
            raise state.PrepareError(12, "orphan_guard")
        check(
            before is not None and fingerprint(checkpoint.lstat()) == before,
            12,
            "checkpoint_changed",
        )
        check(type(record) is dict, 12, "invalid_checkpoint")
        # A matching source OR repo must not disappear through identity tampering.
        if (
            record.get("source_root") == str(root)
            or record.get("repository", "").casefold() == repository.casefold()
        ):
            candidates.append((checkpoint, record, before, int(name)))
    check(len(candidates) <= 1, 12, "ambiguous_store")
    return candidates[0] if candidates else None


def _observe(root, number, report, lock_fd):
    from agent_platform import cli

    state.no_symlinks(root)
    state.no_symlinks(root / ".git")
    lock = state.LOCK_DIR / "prepare.lock"
    lock_info = fingerprint(os.fstat(lock_fd))
    check(fingerprint(lock.lstat()) == lock_info, 12, "lock_changed")
    source = prepare.source_snapshot(cli.inspect(root))
    chosen = find_checkpoint(root, source["repository"], number)
    if chosen is None:
        report.update(
            status="missing", reason="checkpoint_missing", checkpoint_validity="missing"
        )
        return report, 12
    checkpoint, record, before, directory_id = chosen
    report["checkpoint_validity"] = "invalid"
    target = validate_record(record, source, number, directory_id)
    report.update(
        checkpoint_validity="valid",
        recorded_state=record["phase"],
        generation=record["generation"],
    )
    guard = checkpoint.with_suffix(".execution-guard")
    report["execution_guard"] = "invalid"
    guard_state, guard_info = guard_snapshot(guard, record)
    report["execution_guard"] = guard_state
    # Incomplete prepare intent can legitimately have no task worktree yet.
    identity_ok = True
    try:
        trees = prepare.HOME / ".local/share/agent-platform/worktrees"
        check(
            state.private_directory(target.parent, trees.parent, create=False),
            12,
            "unsafe_storage",
        )
        state.no_symlinks(target / ".git")
        prepare.confirm_identity(root, record)
    except (state.PrepareError, OSError):
        identity_ok = False
    if record["version"] == 2:
        check(execution.refs(root) == record["refs_sha256"], 12, "unexpected_refs")
    current = prepare.source_snapshot(cli.inspect(root))
    check(current == source, 12, "source_changed")
    check(
        state.load_checkpoint(checkpoint) == record
        and fingerprint(checkpoint.lstat()) == before,
        12,
        "checkpoint_changed",
    )
    check(
        guard_snapshot(guard, record) == (guard_state, guard_info), 12, "guard_changed"
    )
    check(fingerprint(lock.lstat()) == lock_info, 12, "lock_changed")
    if not identity_ok:
        report.update(
            status="blocked",
            reason="worktree_identity_unverified",
            identity="conflicting",
        )
        return report, 12
    report.update(
        identity="verified",
        session_id=record["codex_thread_id"],
        stop_reason=record.get("stop_reason"),
        usage=record.get("usage"),
    )
    if guard_state == "present" or record["phase"] in {
        "STARTING",
        "RUNNING",
        "NEEDS_HUMAN",
    }:
        report.update(status="blocked", reason="human_reconciliation_required")
        return report, 12
    report.update(status="recorded", reason="local_checkpoint_only")
    return report, 0


def diagnose(cwd, number):
    """Fixed JSON-ready schema; no remote admission, model or native session reads."""
    from agent_platform import cli, issues

    report = empty_report(number if issues.positive_int(number) else None)
    if not issues.positive_int(number):
        report.update(status="unavailable", reason="invalid_issue")
        return report, 2
    try:
        with state.host_lock(create=False) as fd:
            report["host_lock"] = "free"
            return _observe(Path.cwd() if cwd is None else cwd, number, report, fd)
    except state.PrepareError as exc:
        if report["host_lock"] == "unknown":
            report["host_lock"] = (
                "busy"
                if exc.code == 10
                else "missing"
                if exc.reason == "missing_lock"
                else "unavailable"
            )
            report.update(
                status="unavailable",
                reason="lock_busy" if exc.code == 10 else "lock_unavailable",
            )
            return report, 10 if exc.code == 10 else 12
        if exc.reason == "invalid_checkpoint":
            report["checkpoint_validity"] = "invalid"
        reason = "checkpoint_or_identity_invalid"
    except FileNotFoundError:
        if report["host_lock"] == "unknown":
            report.update(
                host_lock="missing", status="unavailable", reason="lock_unavailable"
            )
            return report, 12
        reason = "local_state_unavailable"
    except OSError:
        if report["host_lock"] == "unknown":
            report.update(
                host_lock="unavailable", status="unavailable", reason="lock_unavailable"
            )
            return report, 12
        reason = "local_state_unavailable"
    except cli.InspectionError:
        reason = "repository_unverified"
    except (
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        codex.ProtocolError,
        issues.AdmissionError,
        publisher.PlanError,
    ):
        reason = "local_state_unavailable"
    # Clear any earlier partial observations after a failed stable re-read.
    result = empty_report(number)
    result.update(
        status="ambiguous",
        reason=reason,
        host_lock=report["host_lock"],
        checkpoint_validity="invalid"
        if report["checkpoint_validity"] == "invalid"
        else "unverified",
    )
    if report["execution_guard"] == "invalid":
        result["execution_guard"] = "invalid"
    return result, 12
