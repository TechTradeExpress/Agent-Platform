"""Real SQLite/fsync; fabricated storage approval, no real App or power-loss proof."""

import json
import os
import sqlite3
import subprocess
import sys
from dataclasses import asdict, replace
from pathlib import Path

import pytest
from test_app_api_adapter import HTTP, Signer
from test_app_metadata import case as case

from agent_platform import app_api_adapter as api
from agent_platform import app_metadata as metadata
from agent_platform import custody_journal as journal
from agent_platform import publisher


@pytest.fixture
def store(tmp_path, monkeypatch, case):
    # Most CI/container temp FS profiles cannot establish persistent storage.
    # This fabricated profile tests protocol logic, NOT actual disk power loss.
    monkeypatch.setattr(journal, "_filesystem_type", lambda fd: 0xEF53)
    root = tmp_path / "store"
    root.mkdir(mode=0o700)
    namespace = journal.Namespace("a" * 64, case["pins"], case["observation"].source_id)
    identity, anchor = journal.provision(
        directory=root,
        namespace=namespace,
        store_id="e" * 64,
        storage_evidence_sha256="f" * 64,
    )
    return dict(root=root, identity=identity, anchor=anchor, case=case)


def open_store(store, **changes):
    return journal.SQLiteJournal(
        **(
            dict(
                directory=store["root"],
                identity=store["identity"],
                expected_anchor=store["anchor"],
            )
            | changes
        )
    )


def event(store, state="UNKNOWN", lease_id="1" * 64, binding="2" * 64):
    namespace = store["identity"].namespace
    return api.Event(
        lease_id,
        binding,
        namespace.source_id,
        namespace.pins.repo_id,
        namespace.pins.app.app_id,
        namespace.pins.installation.identifier,
        state,
        1794088800,
    )


def test_explicit_provision_open_append_confirm_and_restart(store):
    with open_store(store) as session:
        assert session.complete and session.snapshot() == ()
        for state in ("UNKNOWN", "ISSUED", "REVOKE_UNKNOWN", "REVOKED"):
            session.append(event(store, state))
        events = session.snapshot()
        anchor = session.anchor
        assert anchor.count == 4 and anchor != store["anchor"]
        assert session._connection.execute("PRAGMA synchronous").fetchone() == (3,)
        assert session._connection.execute("PRAGMA journal_mode").fetchone() == (
            "delete",
        )
    assert not session.complete
    with open_store(store, expected_anchor=anchor) as reopened:
        assert reopened.snapshot() == events
    with pytest.raises(journal.JournalError):
        open_store(
            store
        )  # Stale independently retained anchor, never silently accepted.


@pytest.mark.parametrize("last_state", ["UNKNOWN", "ISSUED", "REVOKE_UNKNOWN"])
def test_unknown_retained_on_restart_and_blocks_adapter_not_readonly_evidence(
    store, last_state
):
    states = ["UNKNOWN", "ISSUED", "REVOKE_UNKNOWN"]
    retained = tuple(
        event(store, value) for value in states[: states.index(last_state) + 1]
    )
    with open_store(store) as session:
        for value in retained:
            session.append(value)
        anchor = session.anchor
    with open_store(store, expected_anchor=anchor) as session:
        assert session.snapshot() == retained
        with pytest.raises(api.AdapterError):
            api.Adapter(
                pins=store["case"]["pins"],
                source_id=store["identity"].namespace.source_id,
                signer=Signer(),
                wire=object(),
                journal=session,
            )


def test_real_sqlite_integration_two_pass_observer_and_replay(store):
    case = store["case"]
    with open_store(store) as session:
        http = HTTP(case, object())

        # Fixed fake wire asserts journal's preceding durable UNKNOWN through snapshot.
        class View:
            @property
            def events(self):
                return session.snapshot()

        http.journal = View()
        adapter = api.Adapter(
            pins=case["pins"],
            source_id=case["observation"].source_id,
            signer=Signer(),
            wire=http,
            journal=session,
            clock=case["clock"],
        )
        result = metadata.observe(**(case | dict(custody=adapter, transport=adapter)))
        assert result.status == "METADATA_ONLY_BOT_ATTRIBUTION_UNVERIFIED"
        assert (
            result.app_attributed_bot_action == "NOT_OBSERVED"
            and result.runtime_exit_code == 13
        )
        assert not any(
            (
                result.reserved,
                result.prepare_authorized,
                result.launch_allowed,
                result.resume_authorized,
                result.publish_authorized,
            )
        )
        assert session.anchor.count == 8
        anchor = session.anchor
    with open_store(store, expected_anchor=anchor) as session:
        adapter = api.Adapter(
            pins=case["pins"],
            source_id=case["observation"].source_id,
            signer=Signer(),
            wire=http,
            journal=session,
            clock=case["clock"],
        )
        before = len(http.calls)
        assert (
            metadata.observe(**(case | dict(custody=adapter, transport=adapter))).status
            == "BLOCKED"
        )
        assert len(http.calls) == before
    assert b"fixture-only-opaque" not in (store["root"] / journal.NAME).read_bytes()


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "no_anchor",
        "wrong_anchor",
        "store",
        "namespace",
        "repo",
        "source",
        "inode",
    ],
)
def test_missing_or_wrong_independent_pins_fail_without_replacement(store, change):
    identity = store["identity"]
    args = {}
    if change == "missing":
        (store["root"] / journal.NAME).rename(store["root"] / "retained")
    elif change == "no_anchor":
        args["expected_anchor"] = None
    elif change == "wrong_anchor":
        args["expected_anchor"] = journal.Anchor(0, "0" * 64)
    elif change == "store":
        args["identity"] = replace(identity, store_id="0" * 64)
    elif change in {"namespace", "repo", "source"}:
        ns = identity.namespace
        if change == "namespace":
            ns = replace(ns, identifier="0" * 64)
        elif change == "source":
            ns = replace(ns, source_id="0" * 64)
        else:
            ns = replace(ns, pins=replace(ns.pins, repo_id=123))
        args["identity"] = replace(identity, namespace=ns)
    else:
        args["identity"] = replace(identity, database=(identity.database[0], 1))
    before = {p.name: p.read_bytes() for p in store["root"].iterdir()}
    with pytest.raises(journal.JournalError) as error:
        open_store(store, **args)
    assert (
        str(error.value) == "custody_journal_blocked"
        and error.value.__context__ is None
    )
    assert before == {p.name: p.read_bytes() for p in store["root"].iterdir()}


@pytest.mark.parametrize(
    "kind",
    [
        "db_mode",
        "dir_mode",
        "owner",
        "symlink",
        "hardlink",
        "rename",
        "directory_rename",
    ],
)
def test_unsafe_files_and_session_replacement_poison(store, monkeypatch, kind):
    session = open_store(store)
    path = store["root"] / journal.NAME
    if kind == "db_mode":
        path.chmod(0o644)
    elif kind == "dir_mode":
        store["root"].chmod(0o755)
    elif kind == "owner":
        original = os.fstat

        def other(fd):
            info = original(fd)
            if (info.st_dev, info.st_ino) == store["identity"].database:
                parts = list(info)
                parts[4] += 1
                return os.stat_result(parts)
            return info

        monkeypatch.setattr(os, "fstat", other)
    elif kind == "hardlink":
        os.link(path, store["root"].parent / "alias")
    elif kind == "directory_rename":
        store["root"].rename(store["root"].with_name("preserved"))
        store["root"].mkdir(mode=0o700)
    else:
        moved = store["root"] / "preserved"
        path.rename(moved)
        if kind == "symlink":
            path.symlink_to(moved)
        else:
            path.write_bytes(moved.read_bytes())
            path.chmod(0o600)
    with pytest.raises(journal.JournalError):
        session.snapshot()
    assert not session.complete
    session.close()


@pytest.mark.parametrize(
    "sql",
    [
        "CREATE TABLE secret(x)",
        "CREATE TRIGGER forged AFTER INSERT ON events BEGIN DELETE FROM events; END",
        "PRAGMA user_version=2",
        "PRAGMA application_id=1",
        "PRAGMA journal_mode=WAL",
    ],
)
def test_schema_trigger_version_and_wal_mode_rejected(store, sql):
    connection = sqlite3.connect(store["root"] / journal.NAME)
    connection.execute(sql)
    connection.commit()
    connection.close()
    with pytest.raises(journal.JournalError):
        open_store(store)


@pytest.mark.parametrize("sidecar", ["-journal", "-wal", "-shm", "-other"])
def test_preexisting_sidecar_is_preserved_not_automatically_recovered(store, sidecar):
    path = store["root"] / (journal.NAME + sidecar)
    path.write_bytes(b"secret retained evidence")
    path.chmod(0o600)
    with pytest.raises(journal.JournalError):
        open_store(store)
    assert path.read_bytes() == b"secret retained evidence"


@pytest.mark.parametrize(
    "change", ["dict", "invalid", "transition", "pin", "replay", "time"]
)
def test_exact_event_history_validation_before_sql_binding(store, change):
    session = open_store(store)
    value = event(store)
    if change == "dict":
        value = asdict(value)
    elif change == "invalid":
        object.__setattr__(value, "binding_sha256", "secret Authorization data")
    elif change == "transition":
        value = replace(value, state="REVOKED")
    elif change == "pin":
        value = replace(value, app_id=2)
    elif change == "time":
        session.append(value)
        value = replace(value, state="ISSUED", observed_at=value.observed_at - 1)
    else:
        for state in ("UNKNOWN", "REVOKE_UNKNOWN", "REVOKED"):
            session.append(event(store, state))
    before = (store["root"] / journal.NAME).read_bytes()
    with pytest.raises(journal.JournalError):
        session.append(value)
    assert not session.complete
    assert (store["root"] / journal.NAME).read_bytes() == before
    session.close()


@pytest.mark.parametrize("method", ["_commit", "_sync"])
def test_failure_before_or_after_commit_poison_and_old_anchor_cannot_hide_commit(
    store, monkeypatch, method
):
    session = open_store(store)
    original = session._commit

    def fail():
        if method == "_sync":
            raise OSError("secret fsync disk-full path")
        original()
        raise sqlite3.OperationalError("secret failure after COMMIT")

    monkeypatch.setattr(session, method, fail)
    with pytest.raises(journal.JournalError) as error:
        session.append(event(store))
    assert error.value.__context__ is None and not session.complete
    with pytest.raises(journal.JournalError):
        session.append(event(store))
    session.close()
    with pytest.raises(journal.JournalError):
        open_store(store)  # Durable UNKNOWN is present despite the failed return.
    expected = journal._anchor(store["identity"], (event(store),))
    with open_store(store, expected_anchor=expected) as reopened:
        assert reopened.snapshot() == (event(store),)


def test_capacity_has_no_eviction_or_compaction(store):
    with open_store(store) as session:
        for number in range(32):
            lease = publisher.digest({"lease": number})
            binding = publisher.digest({"binding": number})
            for state in ("UNKNOWN", "ISSUED", "REVOKE_UNKNOWN", "REVOKED"):
                session.append(event(store, state, lease, binding))
        assert session.anchor.count == 128
        before = session.snapshot()
        with pytest.raises(journal.JournalError):
            session.append(event(store))
        assert len(before) == 128 and not session.complete


def test_explicit_bootstrap_never_overwrites_or_initializes_missing_runtime(
    store, tmp_path
):
    identity = store["identity"]
    with pytest.raises(journal.JournalError):
        journal.provision(
            directory=store["root"],
            namespace=identity.namespace,
            store_id=identity.store_id,
            storage_evidence_sha256="f" * 64,
        )
    missing = tmp_path / "absent"
    with pytest.raises(journal.JournalError):
        open_store(store, directory=missing)
    assert not missing.exists()


def test_rollback_anchor_detection_has_explicit_external_limits(
    store,
):
    path = store["root"] / journal.NAME
    empty_bytes = path.read_bytes()
    with open_store(store) as session:
        session.append(event(store))
        current = session.anchor
    path.write_bytes(empty_bytes)  # Same inode, operator/storage attacker outside lock.
    with pytest.raises(journal.JournalError):
        open_store(store, expected_anchor=current)
    # Honest limit: restoring BOTH database and supplied old anchor is not detectable.
    with open_store(store) as session:
        assert (
            session.snapshot() == ()
        )  # Requires external continuity gate, not stronger claims.


def test_corrupt_truncated_and_oversize_store_never_repaired(store):
    path = store["root"] / journal.NAME
    path.write_bytes(b"secret corrupt SQLite")
    with pytest.raises(journal.JournalError):
        open_store(store)
    assert path.read_bytes() == b"secret corrupt SQLite"


def test_unsupported_filesystem_cannot_be_promoted_by_pin(store, monkeypatch):
    monkeypatch.setattr(
        journal,
        "_filesystem_type",
        lambda fd: (_ for _ in ()).throw(journal.JournalError()),
    )
    with pytest.raises(journal.JournalError):
        open_store(store)


def decode_pins(raw, raw_anchor):
    from agent_platform.github_evidence import Principal
    from agent_platform.review_comment import AppIdentity, InstallationIdentity

    raw = json.loads(raw)
    ns = raw["namespace"]
    pins = ns["pins"]
    app = pins["app"]
    app["owner"] = Principal(**app["owner"])
    app["bot"] = Principal(**app["bot"])
    install = pins["installation"]
    install["account"] = Principal(**install["account"])
    pins.pop("bot_profile_type")
    pins["app"], pins["installation"] = (
        AppIdentity(**app),
        InstallationIdentity(**install),
    )
    pins["permissions"] = tuple(tuple(p) for p in pins["permissions"])
    ns["pins"] = metadata.Pins(**pins)
    raw["namespace"] = journal.Namespace(**ns)
    raw["directory"], raw["database"] = tuple(raw["directory"]), tuple(raw["database"])
    return journal.StoreIdentity(**raw), journal.Anchor(**json.loads(raw_anchor))


CHILD = r"""
import json, os, socket, ssl, sys
from pathlib import Path
socket.socket = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("network forbidden"))
from agent_platform import custody_journal as j
from agent_platform.app_api_adapter import Event
from test_custody_journal import decode_pins
j._filesystem_type = lambda fd: 0xEF53  # Fabricated fixture, not host attestation.
identity, anchor = decode_pins(sys.argv[2], sys.argv[3])
try:
    session = j.SQLiteJournal(directory=Path(sys.argv[1]), identity=identity,
                              expected_anchor=anchor)
except j.JournalError:
    print("BLOCKED")
    sys.exit(8)
action = sys.argv[4]
if action == "before":
    session._commit = lambda: os._exit(21)
elif action == "after":
    commit = session._commit
    def die():
        commit()
        os._exit(22)
    session._commit = die
if action in {"before", "after", "append"}:
    ns = identity.namespace
    session.append(Event("1"*64,"2"*64,ns.source_id,ns.pins.repo_id,
                         ns.pins.app.app_id,ns.pins.installation.identifier,
                         "UNKNOWN",1794088800))
session.close()
print("CLOSED")
"""


def child(store, action):
    root = Path(__file__).resolve().parents[1]
    return subprocess.run(
        [
            sys.executable,
            "-c",
            CHILD,
            str(store["root"]),
            json.dumps(asdict(store["identity"])),
            json.dumps(asdict(store["anchor"])),
            action,
        ],
        env={
            "PYTHONPATH": str(root / "src") + ":" + str(root / "tests"),
            "PATH": "/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        cwd=root,
        capture_output=True,
        timeout=5,
        check=False,
    )


def test_exclusive_lock_blocks_other_process_and_releases_on_close(store):
    with open_store(store) as session:
        result = child(store, "open")
        assert result.returncode == 8 and result.stdout == b"BLOCKED\n"
        assert session.snapshot() == ()
    result = child(store, "open")
    assert result.returncode == 0 and result.stdout == b"CLOSED\n"


def test_second_session_same_process_cannot_drop_sqlite_locks(store):
    with open_store(store) as session:
        with pytest.raises(journal.JournalError):
            open_store(store)
        session.append(event(store))
        assert session.snapshot() == (event(store),)


def test_crash_before_commit_preserves_sidecar_and_blocks_automatic_recovery(store):
    result = child(store, "before")
    assert result.returncode == 21
    sidecar = store["root"] / (journal.NAME + "-journal")
    assert sidecar.exists()
    before = sidecar.read_bytes()
    with pytest.raises(journal.JournalError):
        open_store(store)
    assert sidecar.read_bytes() == before


def test_crash_after_commit_retains_unknown_and_rejects_old_anchor(store):
    result = child(store, "after")
    assert result.returncode == 22
    with pytest.raises(journal.JournalError):
        open_store(store)
    new_anchor = journal._anchor(store["identity"], (event(store),))
    with open_store(store, expected_anchor=new_anchor) as session:
        assert session.snapshot() == (event(store),)
        assert (
            session.complete
        )  # Complete history, NOT permission to create another token.
    store["anchor"] = new_anchor
    assert (
        child(store, "open").returncode == 0
    )  # Kernel released session lock on crash.


@pytest.mark.parametrize(
    "sql",
    [
        "PRAGMA synchronous=OFF",
        "PRAGMA query_only=ON",
        "PRAGMA trusted_schema=ON",
        "PRAGMA busy_timeout=1",
    ],
)
def test_changed_connection_safety_settings_poison_session(store, sql):
    with open_store(store) as session:
        session._connection.execute(sql)
        with pytest.raises(journal.JournalError):
            session.snapshot()
        assert not session.complete


@pytest.mark.parametrize("failure", ["full", "readonly", "lock", "fsync"])
def test_os_and_sqlite_faults_have_fixed_errors_no_retry(store, monkeypatch, failure):
    session = open_store(store)
    if failure == "full":
        pages = session._connection.execute("PRAGMA page_count").fetchone()[0]
        session._connection.execute(f"PRAGMA max_page_count={pages}")
        # Its altered cap itself is forbidden before any write.
    elif failure == "readonly":
        session._connection.execute("PRAGMA query_only=ON")
    elif failure == "lock":

        def busy():
            raise sqlite3.OperationalError("secret database is locked")

        monkeypatch.setattr(session, "_commit", busy)
    else:

        def no_sync(fd):
            raise OSError("secret ENOSPC fsync")

        monkeypatch.setattr(os, "fsync", no_sync)
    with pytest.raises(journal.JournalError) as caught:
        session.append(event(store))
    assert str(caught.value) == "custody_journal_blocked"
    assert caught.value.__context__ is None and not session.complete
    with pytest.raises(journal.JournalError):
        session.snapshot()
    session.close()


def test_unexpected_same_inode_file_changes_are_not_accepted_in_session(store):
    with open_store(store) as session:
        path = store["root"] / journal.NAME
        raw = path.read_bytes()
        before = path.stat()
        path.write_bytes(raw)
        # Deterministic observable metadata change, including coarse-time filesystems.
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 2_000_000_000))
        with pytest.raises(journal.JournalError):
            session.snapshot()
        assert not session.complete


def test_provision_failure_retains_partial_files_and_no_second_bootstrap(
    store, tmp_path, monkeypatch
):
    root = tmp_path / "partial"
    root.mkdir(mode=0o700)

    def fail(fd):
        raise OSError("secret failed fsync")

    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises(journal.JournalError) as caught:
        journal.provision(
            directory=root,
            namespace=store["identity"].namespace,
            store_id="c" * 64,
            storage_evidence_sha256="d" * 64,
        )
    assert caught.value.__context__ is None and (root / journal.NAME).exists()
    with pytest.raises(journal.JournalError):
        journal.provision(
            directory=root,
            namespace=store["identity"].namespace,
            store_id="c" * 64,
            storage_evidence_sha256="d" * 64,
        )


@pytest.mark.parametrize("failure", ["full", "permission"])
def test_insert_fault_prevents_token_post_and_poisoned_sqlite_cannot_retry(
    store, failure
):
    case = store["case"]
    with open_store(store) as session:
        real = session._connection

        class Fault:
            def __getattr__(self, key):
                return getattr(real, key)

            def execute(self, sql, *args):
                if sql.startswith("INSERT INTO events"):
                    if failure == "full":
                        raise sqlite3.OperationalError(
                            "secret database or disk is full"
                        )
                    raise PermissionError("secret write denied")
                return real.execute(sql, *args)

        session._connection = Fault()
        http = HTTP(case, object())
        adapter = api.Adapter(
            pins=case["pins"],
            source_id=case["observation"].source_id,
            signer=Signer(),
            wire=http,
            journal=session,
            clock=case["clock"],
        )
        result = metadata.observe(**(case | dict(custody=adapter, transport=adapter)))
        assert result.status == "BLOCKED" and not session.complete
        from agent_platform.app_api_wire import Operation

        assert Operation.ISSUE_TOKEN not in http.calls
        with pytest.raises(journal.JournalError):
            session.append(event(store))


@pytest.mark.parametrize("change", ["truncated", "oversize", "trailing"])
def test_bounded_database_shape_rejected_without_repair(store, change):
    path = store["root"] / journal.NAME
    original = path.read_bytes()
    value = (
        original[:100]
        if change == "truncated"
        else (
            b"x" * (journal.MAX_DB + 1)
            if change == "oversize"
            else original + b"secret"
        )
    )
    path.write_bytes(value)
    with pytest.raises(journal.JournalError):
        open_store(store)
    assert path.read_bytes() == value


@pytest.mark.parametrize(
    "kind,flags,result",
    [
        (0xEF53, 0, 0),
        (0x58465342, 0, 0),
        (0x794C7630, 0, 0),
        (0x01021994, 0, 0),
        (0x6969, 0, 0),
        (0xEF53, 1, 0),
        (0xEF53, 0, -1),
    ],
)
def test_statfs_profile_rejects_ephemeral_network_readonly_and_unknown(
    monkeypatch, kind, flags, result
):
    class Function:
        def __call__(self, fd, pointer):
            pointer._obj.kind, pointer._obj.flags = kind, flags
            return result

    class Lib:
        fstatfs = Function()

    monkeypatch.setattr(journal.ctypes, "CDLL", lambda *a, **kw: Lib())
    if kind in journal.FILESYSTEMS and not flags and result == 0:
        assert journal._filesystem_type(123) == kind
    else:
        with pytest.raises(journal.JournalError):
            journal._filesystem_type(123)
