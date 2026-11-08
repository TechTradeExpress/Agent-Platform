"""AP-AJ/1 explicit Linux SQLite custody store. No default path or activation."""

import ctypes
import fcntl
import hashlib
import json
import os
import sqlite3
import stat
import sys
import time
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from . import app_api_adapter as adapter
from . import app_metadata as metadata
from . import issues, publisher, state

NAME = "custody.sqlite3"
PAGE_SIZE = 4096
MAX_DB = 256 * 1024
MAX_PAYLOAD = 2048
APPLICATION_ID = 0x4150414A
FILESYSTEMS = {0xEF53, 0x58465342}  # Linux ext4 family / XFS; not host attestation.
SCHEMA = (
    "CREATE TABLE identity (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
    "version INTEGER NOT NULL, store_id TEXT NOT NULL, namespace TEXT NOT NULL) STRICT",
    "CREATE TABLE events (seq INTEGER PRIMARY KEY, payload TEXT NOT NULL) STRICT",
)


class JournalError(Exception):
    def __init__(self):
        super().__init__("custody_journal_blocked")


def need(value):
    if not value:
        raise JournalError()


def _identity(info):
    return info.st_dev, info.st_ino


@dataclass(frozen=True, slots=True)
class Namespace:
    identifier: str
    pins: metadata.Pins
    source_id: str
    schema_version: int = 1

    def __post_init__(self):
        need(type(self.schema_version) is int and self.schema_version == 1)
        need(
            publisher.hex_digest(self.identifier)
            and publisher.hex_digest(self.source_id)
        )
        need(type(self.pins) is metadata.Pins)
        replace(self.pins)

    @property
    def encoded(self):
        return publisher.encoded(asdict(self)).decode("ascii")


@dataclass(frozen=True, slots=True)
class StoreIdentity:
    namespace: Namespace
    store_id: str
    directory: tuple[int, int]
    database: tuple[int, int]
    filesystem_type: int
    storage_evidence_sha256: str

    def __post_init__(self):
        need(type(self.namespace) is Namespace)
        replace(self.namespace)
        need(publisher.hex_digest(self.store_id))
        need(publisher.hex_digest(self.storage_evidence_sha256))
        need(type(self.filesystem_type) is int and self.filesystem_type in FILESYSTEMS)
        for value in (self.directory, self.database):
            need(type(value) is tuple and len(value) == 2)
            need(all(type(x) is int and x >= 0 for x in value))


@dataclass(frozen=True, slots=True)
class Anchor:
    """Externally retained expected history, NOT self-authenticating attestation."""

    count: int
    digest: str

    def __post_init__(self):
        need(type(self.count) is int and 0 <= self.count <= adapter.MAX_EVENTS)
        need(publisher.hex_digest(self.digest))


def _anchor(identity, events):
    return Anchor(
        len(events),
        publisher.digest(
            {
                "store_id": identity.store_id,
                "namespace": asdict(identity.namespace),
                "events": [asdict(e) for e in events],
            }
        ),
    )


def _filesystem_type(fd):
    """Read Linux statfs, fail closed on unsupported ABI/filesystem/read-only FS."""
    need(sys.platform == "linux" and ctypes.sizeof(ctypes.c_long) == 8)

    class StatFS(ctypes.Structure):
        _fields_ = [
            ("kind", ctypes.c_long),
            ("bsize", ctypes.c_long),
            ("blocks", ctypes.c_ulong),
            ("bfree", ctypes.c_ulong),
            ("bavail", ctypes.c_ulong),
            ("files", ctypes.c_ulong),
            ("ffree", ctypes.c_ulong),
            ("fsid", ctypes.c_int * 2),
            ("namelen", ctypes.c_long),
            ("frsize", ctypes.c_long),
            ("flags", ctypes.c_long),
            ("spare", ctypes.c_long * 4),
        ]

    info = StatFS()
    libc = ctypes.CDLL(None, use_errno=True)
    libc.fstatfs.argtypes = [ctypes.c_int, ctypes.POINTER(StatFS)]
    libc.fstatfs.restype = ctypes.c_int
    need(libc.fstatfs(fd, ctypes.byref(info)) == 0)
    need(info.kind in FILESYSTEMS and not info.flags & 1)
    return info.kind


def _directory(path):
    need(type(path) is Path or isinstance(path, Path))
    need(path.is_absolute() and path == Path(os.path.normpath(path)))
    # Shared contributor storage checks; create=False never repairs/chmods paths.
    need(state.private_directory(path, path, create=False))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=fd,
            )
            os.close(fd)
            fd = next_fd
        info = os.fstat(fd)
        need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _files(directory_fd, *, transaction=False):
    names = set(os.listdir(directory_fd))
    need(names <= ({NAME, NAME + "-journal"} if transaction else {NAME}))
    for name in names:
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        state.private_file(info)
        need(info.st_size <= MAX_DB + PAGE_SIZE)


def _configure(connection, *, bootstrap=False):
    connection.enable_load_extension(False)
    for category, limit in (
        (sqlite3.SQLITE_LIMIT_LENGTH, 16384),
        (sqlite3.SQLITE_LIMIT_SQL_LENGTH, 16384),
        (sqlite3.SQLITE_LIMIT_COLUMN, 16),
        (sqlite3.SQLITE_LIMIT_ATTACHED, 0),
        (sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 16),
        (sqlite3.SQLITE_LIMIT_EXPR_DEPTH, 64),
        (sqlite3.SQLITE_LIMIT_TRIGGER_DEPTH, 0),
        (sqlite3.SQLITE_LIMIT_VDBE_OP, 10000),
    ):
        connection.setlimit(category, limit)
    connection.execute("PRAGMA busy_timeout=0")
    if bootstrap:
        need(connection.execute("PRAGMA journal_mode=DELETE").fetchone() == ("delete",))
        connection.execute("PRAGMA page_size=4096")
    else:
        need(connection.execute("PRAGMA journal_mode").fetchone() == ("delete",))
    connection.execute(
        "PRAGMA synchronous=EXTRA"
    )  # Connection-local; never accept a downgrade.
    connection.execute("PRAGMA trusted_schema=OFF")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA recursive_triggers=OFF")
    connection.execute("PRAGMA ignore_check_constraints=OFF")
    connection.execute("PRAGMA cell_size_check=ON")
    connection.execute("PRAGMA temp_store=MEMORY")
    connection.execute("PRAGMA mmap_size=0")
    connection.execute("PRAGMA cache_size=-256")
    connection.execute("PRAGMA max_page_count=64")


def _settings(connection):
    for sql, expected in (
        ("PRAGMA journal_mode", "delete"),
        ("PRAGMA synchronous", 3),
        ("PRAGMA busy_timeout", 0),
        ("PRAGMA trusted_schema", 0),
        ("PRAGMA foreign_keys", 1),
        ("PRAGMA recursive_triggers", 0),
        ("PRAGMA ignore_check_constraints", 0),
        ("PRAGMA cell_size_check", 1),
        ("PRAGMA temp_store", 2),
        ("PRAGMA mmap_size", 0),
        ("PRAGMA query_only", 0),
        ("PRAGMA page_size", PAGE_SIZE),
        ("PRAGMA max_page_count", MAX_DB // PAGE_SIZE),
        ("PRAGMA application_id", APPLICATION_ID),
        ("PRAGMA user_version", 1),
        ("PRAGMA freelist_count", 0),
    ):
        need(connection.execute(sql).fetchone() == (expected,))
    need(connection.execute("PRAGMA page_count").fetchone()[0] <= MAX_DB // PAGE_SIZE)


def _connect(directory_fd):
    # Only a trusted directory FD and fixed basename enter this URI; no caller flags.
    return sqlite3.connect(
        f"file:/proc/self/fd/{directory_fd}/{NAME}?mode=rw",
        uri=True,
        timeout=0,
        isolation_level=None,
    )


class _View:
    complete = True

    def __init__(self, events):
        self.events = events

    def snapshot(self):
        return self.events


def _validate(namespace, events):
    need(type(events) is tuple and len(events) <= adapter.MAX_EVENTS)
    for event in events:
        need(type(event) is adapter.Event)
        replace(event)
        need(event.repo_id == namespace.pins.repo_id)
        need(event.app_id == namespace.pins.app.app_id)
        need(event.installation_id == namespace.pins.installation.identifier)
        need(event.source_id == namespace.source_id)
    adapter._history(
        _View(events)
    )  # Same replay, transition, time and pin rules as AP-AL/1.


class SQLiteJournal:
    """Existing-store session, exclusive until close. No initialization fallback.

    identity and expected_anchor must come from the trusted operator/independent
    continuity boundary, not be learned automatically from this DB at startup.
    """

    def __init__(self, *, directory, identity, expected_anchor):
        self._connection = None
        self._directory_fd = self._database_fd = None
        self._poisoned = True
        self._pid = os.getpid()
        failed = False
        try:
            need(type(identity) is StoreIdentity and type(expected_anchor) is Anchor)
            replace(identity)
            replace(expected_anchor)
            self._path, self._identity = directory, identity
            self._directory_fd = _directory(directory)
            need(_identity(os.fstat(self._directory_fd)) == identity.directory)
            need(_filesystem_type(self._directory_fd) == identity.filesystem_type)
            fcntl.flock(self._directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            _files(self._directory_fd)  # No hot-journal recovery on open.
            self._database_fd = os.open(
                NAME,
                os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=self._directory_fd,
            )
            state.private_file(os.fstat(self._database_fd))
            need(_identity(os.fstat(self._database_fd)) == identity.database)
            self._check_files()
            self._connection = _connect(self._directory_fd)
            self._start()
            _configure(self._connection)
            events = self._read()
            need(_anchor(identity, events) == expected_anchor)
            self._events, self._anchor_value = events, expected_anchor
            self._evidence = self._fingerprint()
            self._poisoned = False
        except BaseException:
            failed = True
        if failed:
            self.close()
            raise JournalError()

    @property
    def complete(self):
        return (
            not self._poisoned
            and self._connection is not None
            and self._pid == os.getpid()
        )

    @property
    def anchor(self):
        need(self.complete)
        return self._anchor_value

    def _start(self):
        self._deadline = time.monotonic() + 1
        self._connection.set_progress_handler(
            lambda: int(time.monotonic() >= self._deadline), 100
        )

    def _fingerprint(self):
        info = os.fstat(self._database_fd)
        need(info.st_size <= MAX_DB)
        digest = hashlib.sha256()
        offset = 0
        while offset < info.st_size:
            raw = os.pread(self._database_fd, min(16384, info.st_size - offset), offset)
            need(raw)
            digest.update(raw)
            offset += len(raw)
        after = os.fstat(self._database_fd)
        before_pin = (info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        need(before_pin == (after.st_size, after.st_mtime_ns, after.st_ctime_ns))
        return (*before_pin, digest.hexdigest())

    def _check_files(self, *, transaction=False):
        need(os.getpid() == self._pid)
        fresh = _directory(self._path)
        try:
            need(_identity(os.fstat(fresh)) == self._identity.directory)
        finally:
            os.close(
                fresh
            )  # Directory, never a second DB FD that could drop SQLite's POSIX locks.
        need(_identity(os.fstat(self._directory_fd)) == self._identity.directory)
        need(_filesystem_type(self._directory_fd) == self._identity.filesystem_type)
        _files(self._directory_fd, transaction=transaction)
        db = os.fstat(self._database_fd)
        state.private_file(db)
        need(_identity(db) == self._identity.database)
        need(
            _identity(os.stat(NAME, dir_fd=self._directory_fd, follow_symlinks=False))
            == self._identity.database
        )
        need(PAGE_SIZE <= db.st_size <= MAX_DB and db.st_size % PAGE_SIZE == 0)
        need(os.pread(self._database_fd, 16, 0) == b"SQLite format 3\x00")

    def _read(self):
        self._check_files(transaction=self._connection.in_transaction)
        _settings(self._connection)
        schema = self._connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name LIMIT 5"
        ).fetchall()
        need(
            schema
            == [
                ("table", "events", "events", SCHEMA[1]),
                ("table", "identity", "identity", SCHEMA[0]),
            ]
        )
        need(self._connection.execute("PRAGMA quick_check(1)").fetchall() == [("ok",)])
        databases = self._connection.execute("PRAGMA database_list").fetchall()
        # quick_check may create SQLite's empty in-memory temp database.
        need(1 <= len(databases) <= 2 and databases[0][:2] == (0, "main"))
        need(len(databases) == 1 or databases[1] == (1, "temp", ""))
        need(_identity(os.stat(databases[0][2])) == self._identity.database)
        if not self._connection.in_transaction:
            pages = self._connection.execute("PRAGMA page_count").fetchone()[0]
            need(os.fstat(self._database_fd).st_size == pages * PAGE_SIZE)
        rows = self._connection.execute(
            "SELECT singleton,version,store_id,namespace FROM identity LIMIT 2"
        ).fetchall()
        need(
            rows == [(1, 1, self._identity.store_id, self._identity.namespace.encoded)]
        )
        rows = self._connection.execute(
            "SELECT seq,payload FROM events ORDER BY seq LIMIT 129"
        ).fetchall()
        need(len(rows) <= adapter.MAX_EVENTS)
        events = []
        for number, (seq, raw) in enumerate(rows, 1):
            need(type(seq) is int and seq == number and type(raw) is str)
            need(len(raw.encode("utf-8")) <= MAX_PAYLOAD)
            obj = json.loads(
                raw,
                object_pairs_hook=issues.unique_object,
                parse_constant=issues.invalid_constant,
            )
            need(type(obj) is dict)
            event = adapter.Event(**obj)
            need(publisher.encoded(asdict(event)).decode("ascii") == raw)
            events.append(event)
        result = tuple(events)
        _validate(self._identity.namespace, result)
        need(time.monotonic() < self._deadline)
        return result

    def snapshot(self):
        failed = False
        result = None
        try:
            need(self.complete)
            self._start()
            self._check_files()
            need(self._fingerprint() == self._evidence)
            result = self._read()
            need(
                result == self._events
                and _anchor(self._identity, result) == self._anchor_value
            )
            self._check_files()
            need(self._fingerprint() == self._evidence)
        except BaseException:
            failed = True
            self._poisoned = True
        if failed:
            raise JournalError()
        return result

    def _commit(self):
        self._connection.execute("COMMIT")

    def _sync(self):
        os.fsync(self._database_fd)
        os.fsync(self._directory_fd)

    def append(self, event):
        failed = False
        try:
            before = self.snapshot()
            need(len(before) < adapter.MAX_EVENTS)
            candidate = (*before, event)
            _validate(self._identity.namespace, candidate)
            raw = publisher.encoded(asdict(event)).decode("ascii")
            need(len(raw.encode()) <= MAX_PAYLOAD)
            self._start()
            self._connection.execute("BEGIN IMMEDIATE")
            need(self._read() == before)
            self._connection.execute(
                "INSERT INTO events(seq,payload) VALUES(?,?)", (len(candidate), raw)
            )
            self._check_files(transaction=True)
            need(self._read() == candidate)
            # A subsequent failure poisons; never retry or claim absence.
            self._commit()
            self._sync()
            self._check_files()
            need(self._read() == candidate)
            self._events, self._anchor_value = (
                candidate,
                _anchor(self._identity, candidate),
            )
            self._evidence = self._fingerprint()
        except BaseException:
            self._poisoned = True
            failed = True
        if failed:
            raise JournalError()

    def close(self):
        self._poisoned = True
        if os.getpid() != self._pid:
            # Never manipulate an inherited SQLite connection after fork.
            raise JournalError()
        failed = False
        if self._connection is not None:
            try:
                self._connection.close()
            except BaseException:
                failed = True
            self._connection = None
        for name in ("_database_fd", "_directory_fd"):
            fd = getattr(self, name)
            if fd is not None:
                try:
                    os.close(
                        fd
                    )  # Releasing the final description releases flock; never unlink.
                except OSError:
                    failed = True
                setattr(self, name, None)
        if failed:
            raise JournalError()

    def __enter__(self):
        need(self.complete)
        return self

    def __exit__(self, kind, value, traceback):
        self.close()


def provision(*, directory, namespace, store_id, storage_evidence_sha256):
    """Distinct explicit bootstrap on an existing EMPTY private directory only.

    Never called by open/import/retry. Retain partial files on failure; no repair.
    Returned pins/empty anchor must be independently retained by the operator.
    """
    directory_fd = database_fd = connection = None
    failed = False
    result = None
    try:
        need(type(namespace) is Namespace)
        replace(namespace)
        need(
            publisher.hex_digest(store_id)
            and publisher.hex_digest(storage_evidence_sha256)
        )
        directory_fd = _directory(directory)
        filesystem_type = _filesystem_type(directory_fd)
        fcntl.flock(directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        need(os.listdir(directory_fd) == [])
        database_fd = os.open(
            NAME,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=directory_fd,
        )
        state.private_file(os.fstat(database_fd))
        connection = _connect(directory_fd)
        _configure(connection, bootstrap=True)
        connection.execute("PRAGMA application_id=1095778634")
        connection.execute("PRAGMA user_version=1")
        connection.execute("BEGIN IMMEDIATE")
        for sql in SCHEMA:
            connection.execute(sql)
        connection.execute(
            "INSERT INTO identity VALUES(1,1,?,?)", (store_id, namespace.encoded)
        )
        connection.execute("COMMIT")
        os.fsync(database_fd)
        os.fsync(directory_fd)
        identity = StoreIdentity(
            namespace,
            store_id,
            _identity(os.fstat(directory_fd)),
            _identity(os.fstat(database_fd)),
            filesystem_type,
            storage_evidence_sha256,
        )
        _files(directory_fd)
        _settings(connection)
        result = identity, _anchor(identity, ())
    except Exception:
        failed = True
    finally:
        if connection is not None:
            try:
                connection.close()
            except BaseException:
                failed = True
        for fd in (database_fd, directory_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    failed = True
    if failed:
        raise JournalError()
    return result
