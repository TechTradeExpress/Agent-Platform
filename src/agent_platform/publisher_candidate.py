"""CP-03: pure, credential-free verification of fabricated Git candidates."""

import hashlib
import json
import re
from dataclasses import dataclass, field

VERSION = "AP-PC/1"
MAX_DESCRIPTOR = 16 * 1024
MAX_DATA = 1024 * 1024
MAX_OBJECT = 256 * 1024
MAX_PATHS = 128
SHA = re.compile(r"[0-9a-f]{40}")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
REF = re.compile(r"refs/heads/feature/issue-[1-9][0-9]*-[a-z0-9]+(?:-[a-z0-9]+)*")
CODES = frozenset(
    {
        "invalid_input",
        "limit_exceeded",
        "invalid_descriptor",
        "invalid_policy",
        "identity_mismatch",
        "unsupported_format",
        "invalid_operation",
        "invalid_ref",
        "invalid_object",
        "object_id_mismatch",
        "invalid_tree",
        "unsafe_path",
        "invalid_mode",
        "inventory_mismatch",
        "invalid_commit",
        "parent_mismatch",
        "remote_update_unverified",
    }
)


@dataclass(frozen=True, slots=True)
class GitObject:
    oid: str
    canonical: bytes  # uncompressed: <type> SP <decimal size> NUL <payload>


@dataclass(frozen=True, slots=True)
class Candidate:
    descriptor: bytes
    objects: tuple[GitObject, ...]
    version: str = VERSION


@dataclass(frozen=True, slots=True)
class Policy:
    """Caller pins; never deserialize from candidate/model/checkpoint data."""

    repo_id: int
    repository: str
    issue: int
    issue_id: int
    scope: str
    base_sha: str
    feature_ref: str
    paths: tuple[str, ...]
    operation: str = "create"
    expected_old: str = "ABSENT"
    executable_paths: tuple[str, ...] = ()
    version: str = VERSION


@dataclass(frozen=True, slots=True)
class Result:
    status: str
    code: str
    version: str = field(default=VERSION, init=False)
    publish_authorized: bool = field(default=False, init=False)


class _Blocked(Exception):
    pass


def _require(condition, code):
    if not condition:
        raise _Blocked(code)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "invalid_descriptor")
        result[key] = value
    return result


def _sha(value):
    return type(value) is str and SHA.fullmatch(value) is not None


def _path(name):
    # Flat ASCII profile also excludes NTFS/HFS aliases and Git control names.
    _require(type(name) is str and NAME.fullmatch(name), "unsafe_path")
    lower = name.casefold()
    _require(
        not name.endswith((".", " "))
        and ".." not in name
        and not lower.endswith(".lock")
        and "~" not in name
        and lower.split(".")[0]
        not in {
            "git",
            "con",
            "prn",
            "aux",
            "nul",
            *(f"com{i}" for i in range(10)),
            *(f"lpt{i}" for i in range(10)),
        },
        "unsafe_path",
    )


def verify(candidate: Candidate, policy: Policy) -> Result:
    """No I/O. Success describes bytes only, never admission or remote safety."""
    try:
        _verify(candidate, policy)
        return Result("VERIFIED_OFFLINE_FIXTURE", "verified")
    except _Blocked as exc:
        return Result("BLOCKED", str(exc))
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        return Result("BLOCKED", "invalid_input")


def _verify(c, p):
    _require(type(c) is Candidate and type(p) is Policy, "invalid_input")
    _require(c.version == p.version == VERSION, "unsupported_format")
    _require(type(c.descriptor) is bytes and type(c.objects) is tuple, "invalid_input")
    _require(
        len(c.descriptor) <= MAX_DESCRIPTOR and len(c.objects) <= 130, "limit_exceeded"
    )
    _require(
        all(type(o) is GitObject and type(o.canonical) is bytes for o in c.objects),
        "invalid_object",
    )
    _require(
        all(len(o.canonical) <= MAX_OBJECT for o in c.objects)
        and len(c.descriptor) + sum(len(o.canonical) for o in c.objects) <= MAX_DATA,
        "limit_exceeded",
    )
    d = json.loads(c.descriptor.decode("utf-8"), object_pairs_hook=_pairs)
    keys = {
        "version",
        "repo_id",
        "repository",
        "issue",
        "issue_id",
        "scope",
        "base_sha",
        "operation",
        "feature_ref",
        "expected_old",
        "commit",
        "tree",
        "object_format",
        "inventory",
    }
    _require(type(d) is dict and set(d) == keys, "invalid_descriptor")
    _require(
        d["version"] == VERSION and d["object_format"] == "sha1", "unsupported_format"
    )
    for key in ("repo_id", "issue", "issue_id"):
        _require(type(getattr(p, key)) is int and getattr(p, key) > 0, "invalid_policy")
        _require(type(d[key]) is int, "invalid_descriptor")
    _require(
        type(p.repository) is str
        and re.fullmatch(r"[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+", p.repository)
        and type(p.scope) is str
        and re.fullmatch(r"[a-f0-9]{64}", p.scope)
        and _sha(p.base_sha),
        "invalid_policy",
    )
    for key in ("repo_id", "repository", "issue", "issue_id", "scope", "base_sha"):
        _require(d[key] == getattr(p, key), "identity_mismatch")
    _require(
        type(p.feature_ref) is str
        and REF.fullmatch(p.feature_ref)
        and p.feature_ref.startswith(f"refs/heads/feature/issue-{p.issue}-")
        and len(p.feature_ref) <= 200
        and d["feature_ref"] == p.feature_ref,
        "invalid_ref",
    )
    _require(
        d["operation"] in ("create", "update")
        and d["operation"] == p.operation
        and d["expected_old"] == p.expected_old,
        "invalid_operation",
    )
    _require(
        (d["operation"] == "create" and d["expected_old"] == "ABSENT")
        or (d["operation"] == "update" and _sha(d["expected_old"])),
        "invalid_operation",
    )
    _require(
        type(p.paths) is tuple
        and type(p.executable_paths) is tuple
        and 0 < len(p.paths) <= MAX_PATHS,
        "invalid_policy",
    )
    for path in p.paths:
        _path(path)
    _require(
        len({s.casefold() for s in p.paths}) == len(p.paths)
        and set(p.executable_paths) <= set(p.paths),
        "invalid_policy",
    )
    inventory = d["inventory"]
    _require(
        type(inventory) is list and 0 < len(inventory) <= MAX_PATHS,
        "inventory_mismatch",
    )
    entries = []
    for entry in inventory:
        _require(
            type(entry) is dict and set(entry) == {"path", "mode", "oid"},
            "invalid_descriptor",
        )
        name, mode, oid = entry["path"], entry["mode"], entry["oid"]
        _path(name)
        _require(
            mode == "100644" or mode == "100755" and name in p.executable_paths,
            "invalid_mode",
        )
        _require(_sha(oid), "invalid_object")
        entries.append((name, mode, oid))
    names = [e[0] for e in entries]
    _require(len(set(s.casefold() for s in names)) == len(names), "unsafe_path")
    _require(names == sorted(p.paths), "inventory_mismatch")
    objects = {}
    for obj in c.objects:
        _require(_sha(obj.oid) and obj.oid not in objects, "invalid_object")
        header, sep, payload = obj.canonical.partition(b"\0")
        match = re.fullmatch(rb"(blob|tree|commit) (0|[1-9][0-9]*)", header)
        _require(sep and match and len(header) <= 32, "invalid_object")
        _require(int(match[2]) == len(payload), "invalid_object")
        _require(
            hashlib.sha1(obj.canonical).hexdigest() == obj.oid, "object_id_mismatch"
        )
        objects[obj.oid] = (match[1], payload)
    _require(_sha(d["tree"]) and _sha(d["commit"]), "invalid_object")
    expected = {d["tree"], d["commit"], *(e[2] for e in entries)}
    _require(set(objects) == expected, "inventory_mismatch")
    for _, _, oid in entries:
        _require(objects[oid][0] == b"blob", "invalid_tree")
    tree = b"".join(
        mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(oid)
        for name, mode, oid in entries
    )
    _require(objects[d["tree"]] == (b"tree", tree), "invalid_tree")
    kind, commit = objects[d["commit"]]
    _require(kind == b"commit", "invalid_commit")
    # Exactly four headers, no extensions, signatures, encoding or continuation.
    identity = rb"[A-Za-z][A-Za-z0-9 ._-]{0,63} <[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+>"
    pattern = (
        rb"tree ([0-9a-f]{40})\nparent ([0-9a-f]{40})\nauthor "
        + identity
        + rb" (0|[1-9][0-9]{0,11}) [+-][0-1][0-9][0-5][0-9]\ncommitter "
        + identity
        + rb" (0|[1-9][0-9]{0,11}) [+-][0-1][0-9][0-5][0-9]"
        + rb"\n\n[\x20-\x7e]{1,200}\n"
    )
    match = re.fullmatch(pattern, commit)
    _require(match is not None, "invalid_commit")
    _require(match[1].decode() == d["tree"], "invalid_commit")
    parent = p.base_sha if d["operation"] == "create" else d["expected_old"]
    _require(match[2].decode() == parent, "parent_mismatch")
    _require(d["operation"] != "update", "remote_update_unverified")
