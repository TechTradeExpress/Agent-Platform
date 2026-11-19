"""Single-attempt offline ledger for the fixed PKG-17 release identity."""

import fcntl
import json
import os
import re
import stat
from contextlib import contextmanager
from pathlib import PosixPath
from typing import NamedTuple, Protocol

from final_recipe import (
    KEY,
    ROLES,
    Blocked,
    _directory,
    _hex,
    _relative,
    _stamp,
    encoded,
    need,
    sha,
)
from release_observation import BASELINE, RECIPE_PATHS, REPOSITORY, Observation

SCHEMA = "AP-PKG17-LEDGER/1"
SLOT = "release-attempt"
INTENT = "intent.json"
RECEIPT = "receipt.json"
LIMIT = 1024**2
FIXTURE = "UNVERIFIED_CALLER_FIXTURE"
HISTORICAL_CANONICAL_SHA256 = (
    "d85060334fcfa1284bd93eb04fa9a890d4e621d31725334f9c8a46743ac325fd"
)


class CustodyQuery(NamedTuple):
    release_key: str
    slot_sha256: str
    bundle_sha256: str
    generation: int
    prior_receipt_sha256: str | None
    challenge_sha256: str


class CustodyEvidence(NamedTuple):
    binding: CustodyQuery
    reviewed_operator_id: str
    protected_checkpoint: bytes
    operator_attestation: bytes


class ProtectedCustody(Protocol):
    """Future independently admitted custody. PKG-17 never calls this interface."""

    def attest(self, query: CustodyQuery) -> CustodyEvidence: ...


class FixtureCheckpoint(NamedTuple):
    release_key: str
    slot_sha256: str
    bundle_sha256: str
    generation: int
    receipt_sha256: str | None


def _report(reason, local="UNKNOWN", receipt=None):
    return {
        "schema": SCHEMA,
        "release_key": KEY,
        "status": "BLOCKED",
        "history": "UNKNOWN",
        "history_authenticated": False,
        "custody": "NOT_CONFIGURED",
        "operator_authority": "NOT_CONFIGURED",
        "input_provenance": FIXTURE,
        "local_integrity": local,
        "reason": reason,
        "fixture_receipt_sha256": receipt,
        "final_generation_allowed": False,
        "release_authorized": False,
        "publication_allowed": False,
        "installation_allowed": False,
    }


def _decode(raw):
    need(type(raw) is bytes and 0 < len(raw) <= LIMIT, "record_invalid")
    try:
        value = json.loads(raw)
        need(encoded(value) == raw, "record_invalid")
    except (ValueError, RecursionError):
        raise Blocked("record_invalid") from None
    return value


def _fields(value, names):
    need(type(value) is dict and set(value) == set(names.split()), "record_invalid")


def _number(value, limit=2**63 - 1):
    return type(value) is int and 0 < value <= limit


def _hashes(mapping, limit):
    return (
        type(mapping) is dict
        and 0 < len(mapping) <= limit
        and all(_relative(path) and _hex(digest) for path, digest in mapping.items())
    )


def _observation(observation):
    need(type(observation) is Observation, "observation_invalid")
    source, environment, archives = map(_decode, observation)
    _fields(
        source,
        "repository repository_identity commit tree parents epoch recipes "
        "source_inputs historical_source",
    )
    inputs = source["source_inputs"]
    recipes = source["recipes"]
    need(
        source["repository"] == REPOSITORY
        and source["repository_identity"] == "REPOSITORY_IDENTITY_NOT_ATTESTED"
        and _hex(source["commit"], 40)
        and _hex(source["tree"], 40)
        and _number(source["epoch"])
        and type(source["parents"]) is list
        and len(source["parents"]) <= 16
        and all(_hex(parent, 40) for parent in source["parents"])
        and _hashes(inputs, 4096)
        and _hashes(recipes, len(RECIPE_PATHS))
        and set(recipes) == set(RECIPE_PATHS)
        and all(inputs.get(name) == digest for name, digest in recipes.items()),
        "source_invalid",
    )
    historic = source["historical_source"]
    # PKG-16 hashes the pretty on-disk pin before observing any archives.
    need(
        type(historic) is dict
        and sha(encoded(historic)) == HISTORICAL_CANONICAL_SHA256,
        "historical_pin_invalid",
    )
    need(
        inputs.get("packaging/debian/pkg11-baseline.json") == BASELINE,
        "historical_pin_invalid",
    )
    _fields(archives, "control worker")
    for role in ROLES:
        entry = archives[role]
        _fields(entry, "archive_sha256 size")
        need(
            entry["archive_sha256"] == historic["roles"][role]["archive_sha256"]
            and _number(entry["size"], 16 * 1024**2),
            "historical_archive_invalid",
        )
    _fields(environment, "platform image_digest image_provenance tools packages_sha256")
    need(
        environment["platform"] == "debian-13/amd64"
        and environment["image_digest"] == "UNKNOWN"
        and environment["image_provenance"] == "IMAGE_PROVENANCE_UNKNOWN"
        and _hex(environment["packages_sha256"]),
        "environment_invalid",
    )
    _fields(environment["tools"], "python dpkg_deb xz git")
    for tool in environment["tools"].values():
        _fields(tool, "version sha256")
        version = tool["version"]
        need(
            _hex(tool["sha256"])
            and type(version) is str
            and re.fullmatch(r"[A-Za-z0-9 .()+:~_-]{1,160}", version),
            "environment_invalid",
        )
    return [sha(raw) for raw in observation]


def fixture_bundle_sha256(observation):
    """Bind the entire observed tuple. The artifact slots are reserved, empty."""
    return sha(
        encoded(
            {
                "schema": SCHEMA,
                "release_key": KEY,
                "observation": _observation(observation),
                "role_artifacts": dict.fromkeys(ROLES),
            }
        )
    )


def _identity(info):
    return info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode


def _private(info):
    need(
        stat.S_ISDIR(info.st_mode)
        and stat.S_IMODE(info.st_mode) == 0o700
        and info.st_uid == os.geteuid(),
        "directory_unsafe",
    )


@contextmanager
def _root(root, exclusive):
    need(type(root) is PosixPath, "path_invalid")
    need(
        root.is_absolute() and _relative(str(root)[1:]),
        "path_invalid",
    )
    fd = _directory(root)
    try:
        current = os.fstat(fd)
        _private(current)
        fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        _root_stable(root, fd)
        yield fd
    finally:
        os.close(fd)


def _root_stable(root, fd):
    reopened = _directory(root)
    try:
        need(_identity(os.fstat(reopened)) == _identity(os.fstat(fd)), "slot_changed")
        _private(os.fstat(fd))
    finally:
        os.close(reopened)


def _slot_digest(root, fd):
    return sha(encoded([str(root), SLOT, *_identity(os.fstat(fd))]))


def fixture_slot_sha256(root):
    """Capture a disposable slot binding for the modeled external checkpoint."""
    try:
        with _root(root, False) as fd:
            return _slot_digest(root, fd)
    except OSError:
        raise Blocked("ledger_unavailable") from None


def _checkpoint(value, slot, bundle, generation, receipt):
    need(type(value) is FixtureCheckpoint, "checkpoint_unavailable")
    need(
        type(value.generation) is int
        and type(value.release_key) is str
        and _hex(value.slot_sha256)
        and _hex(value.bundle_sha256)
        and (value.receipt_sha256 is None or _hex(value.receipt_sha256))
        and value == FixtureCheckpoint(KEY, slot, bundle, generation, receipt),
        "checkpoint_mismatch",
    )


@contextmanager
def _slot(root_fd):
    fd = os.open(SLOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
    try:
        _slot_stable(root_fd, fd)
        yield fd
    finally:
        os.close(fd)


def _slot_stable(root_fd, fd):
    info = os.fstat(fd)
    _private(info)
    need(
        info.st_dev == os.fstat(root_fd).st_dev
        and _identity(info)
        == _identity(os.stat(SLOT, dir_fd=root_fd, follow_symlinks=False)),
        "slot_changed",
    )


def _names(fd, allowed):
    # scandir avoids allocating names for a potentially hostile huge directory.
    with os.scandir(fd) as entries:
        for entry in entries:
            need(entry.name in allowed, "unexpected_entry")


def _write(fd, name, raw):
    out = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd
    )
    with os.fdopen(out, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
        written = _stamp(os.fstat(stream.fileno()))
        need(
            written == _stamp(os.stat(name, dir_fd=fd, follow_symlinks=False)),
            "record_changed",
        )
    os.fsync(fd)


def _read(fd, name):
    file_fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=fd)
    with os.fdopen(file_fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        need(
            stat.S_ISREG(info.st_mode)
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_nlink == 1
            and info.st_uid == os.geteuid()
            and info.st_dev == os.fstat(fd).st_dev
            and 0 < info.st_size <= LIMIT,
            "record_unsafe",
        )
        raw = stream.read(LIMIT + 1)
        stamp = _stamp(info)
        need(
            len(raw) == info.st_size and stamp == _stamp(os.fstat(stream.fileno())),
            "record_changed",
        )
        _record_stable(fd, name, stamp)
        return raw, stamp


def _record_stable(fd, name, stamp):
    need(
        stamp == _stamp(os.stat(name, dir_fd=fd, follow_symlinks=False)),
        "record_changed",
    )


def _intent(slot, bundle, fd):
    return {
        "schema": SCHEMA,
        "release_key": KEY,
        "slot_sha256": slot,
        "bundle_sha256": bundle,
        "provenance": FIXTURE,
        "directory_sha256": sha(encoded(_identity(os.fstat(fd)))),
        "generation": 1,
        "prior_receipt_sha256": None,
        "state": "UNKNOWN",
    }


def _receipt(intent):
    return {
        **intent,
        "state": "FIXTURE_RECORDED",
        "intent_sha256": sha(encoded(intent)),
    }


def _bound_records(root, root_fd, fd, expected):
    before = _stamp(os.fstat(fd))
    _names(fd, {INTENT, RECEIPT})
    intent, intent_stamp = _read(fd, INTENT)
    bound = _decode(intent)
    need(type(bound) is dict, "record_invalid")
    need(bound.get("bundle_sha256") == expected["bundle_sha256"], "bundle_conflict")
    need(intent == encoded(expected), "intent_mismatch")
    receipt, receipt_stamp = _read(fd, RECEIPT)
    need(receipt == encoded(_receipt(expected)), "receipt_mismatch")
    _record_stable(fd, INTENT, intent_stamp)
    _record_stable(fd, RECEIPT, receipt_stamp)
    need(before == _stamp(os.fstat(fd)), "slot_changed")
    _slot_stable(root_fd, fd)
    _root_stable(root, root_fd)
    _names(root_fd, {SLOT})
    return sha(receipt)


def record_fixture(root, observation, *, generation, checkpoint=None):
    """Exclusive one-shot proposal. Ambiguous effects are retained indefinitely."""
    try:
        need(type(generation) is int and generation == 1, "generation_invalid")
        bundle = fixture_bundle_sha256(observation)
        with _root(root, True) as fd:
            slot = _slot_digest(root, fd)
            _checkpoint(checkpoint, slot, bundle, 0, None)
            _names(fd, {SLOT})
            os.mkdir(SLOT, 0o700, dir_fd=fd)
            created = _identity(os.stat(SLOT, dir_fd=fd, follow_symlinks=False))
            os.fsync(fd)
            with _slot(fd) as record_fd:
                need(created == _identity(os.fstat(record_fd)), "slot_changed")
                intent = _intent(slot, bundle, record_fd)
                _root_stable(root, fd)
                _write(record_fd, INTENT, encoded(intent))
                _slot_stable(fd, record_fd)
                _root_stable(root, fd)
                _write(record_fd, RECEIPT, encoded(_receipt(intent)))
                receipt = _bound_records(root, fd, record_fd, intent)
        return _report("fixture_recorded", "LOCAL_FSYNC_COMPLETED", receipt)
    except Blocked as error:
        return _report(str(error))
    except FileExistsError:
        return _report("slot_already_exists")
    except OSError:
        return _report("ledger_unavailable_or_interrupted")


def reconcile(root, observation, *, checkpoint=None):
    """Read-only comparison with a modeled checkpoint. Never recover by writing."""
    try:
        bundle = fixture_bundle_sha256(observation)
        with _root(root, False) as fd:
            slot = _slot_digest(root, fd)
            _names(fd, {SLOT})
            with _slot(fd) as record_fd:
                receipt = _bound_records(
                    root, fd, record_fd, _intent(slot, bundle, record_fd)
                )
                _checkpoint(checkpoint, slot, bundle, 1, receipt)
        return _report("fixture_checkpoint_matches", "LOCAL_RECORDS_MATCH", receipt)
    except Blocked as error:
        return _report(str(error))
    except OSError:
        return _report("ledger_unavailable_or_incomplete")
