"""Read-only release observations and a disposable operator intent prototype."""

import hashlib
import json
import os
import platform
import re
import socket
import stat
import struct
import tempfile
from pathlib import Path
from typing import NamedTuple

from final_recipe import (
    KEY,
    ROLES,
    Blocked,
    _directory,
    _files,
    _regular,
    _relative,
    _write_evidence,
    encoded,
    need,
    sha,
)

from agent_platform.process import CommandError, read_command

REPOSITORY = "TechTradeExpress/Agent-Platform"
RECIPE_PATHS = (
    "packaging/build_deb.py",
    "packaging/final_recipe.py",
    "packaging/debian_fixture_encoder.py",
)
BASELINE = "a34d89322d2578b5b251fdff9d03c10de8bede676d741d58d2d7bfba6d20cb06"
ENV = {
    "PATH": "/usr/bin:/bin",
    "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ALLOW_PROTOCOL": "",
}


def _read(argv, cwd, env=ENV):
    try:
        return read_command(argv, cwd, env, timeout=10, limit=16 * 1024**2)
    except CommandError:
        raise Blocked("observation_unavailable") from None


def _oid(kind, raw):
    return hashlib.sha1(kind + b" " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def _checkout(root):
    fd = _directory(root)
    os.close(fd)
    need(not (root / ".git").is_symlink(), "checkout_invalid")
    # Only canonical directory checkout or a Git linked worktree is accepted.
    admin = root / ".git"
    if admin.is_file():
        link = _regular(admin).decode()
        need(link.startswith("gitdir: ") and link.endswith("\n"), "checkout_invalid")
        admin = Path(link[8:-1])
        need(admin.is_absolute(), "checkout_invalid")
    fd = _directory(admin)
    os.close(fd)
    common = admin
    if (admin / "commondir").exists():
        pointer = _regular(admin / "commondir").decode().strip()
        common = Path(os.path.normpath(admin / pointer))
    if (admin / "gitdir").exists():
        need(
            _regular(admin / "gitdir").decode().strip() == str(root / ".git"),
            "checkout_invalid",
        )
    objects = common / "objects"
    fd = _directory(objects)
    os.close(fd)
    for name in ("alternates", "http-alternates"):
        need(not os.path.lexists(objects / "info" / name), "alternate_objects")
    return admin, common, objects


def _head(admin, common):
    raw = _regular(admin / "HEAD").decode().strip()
    if raw.startswith("ref: "):
        ref = raw[5:]
        need(ref.startswith("refs/heads/") and _relative(ref), "head_invalid")
        try:
            raw = _regular(common / ref).decode().strip()
        except FileNotFoundError:
            matches = [
                line.split()[0]
                for line in _regular(common / "packed-refs").decode().splitlines()
                if line.endswith(" " + ref)
            ]
            need(len(matches) == 1, "head_invalid")
            raw = matches[0]
    need(re.fullmatch("[0-9a-f]{40}", raw), "head_invalid")
    return raw


def _observed_files(root, blobs, modes):
    count = 0
    directory_count = 0

    def traversal_failed(_error):
        raise Blocked("checkout_traversal_unverified") from None

    for directory, dirs, names in os.walk(
        root, followlinks=False, onerror=traversal_failed
    ):
        directory_count += 1
        need(directory_count <= 1024, "checkout_limit")
        path = Path(directory)
        if path == root:
            if ".git" in dirs:
                dirs.remove(".git")
            if ".git" in names:
                names.remove(".git")
        for name in dirs:
            need(stat.S_ISDIR((path / name).lstat().st_mode), "checkout_invalid")
        for name in names:
            leaf = path / name
            rel = leaf.relative_to(root).as_posix()
            need(rel in blobs and _regular(leaf) == blobs[rel], "checkout_dirty")
            need(
                bool(leaf.lstat().st_mode & 0o111) == bool(modes[rel] & 0o111),
                "checkout_dirty",
            )
            count += 1
    need(count == len(blobs), "checkout_dirty")


def observe_source(root):
    """Observe actual bytes without executing reviewed source or its Git config."""
    root = Path(root)
    try:
        admin, common, objects = _checkout(root)
        commit = _head(admin, common)
        with tempfile.TemporaryDirectory(prefix="ap-release-reader-") as tmp:
            scratch = Path(tmp)
            _read(
                [
                    "/usr/bin/git",
                    "init",
                    "--bare",
                    "--template=",
                    "--object-format=sha1",
                    str(scratch),
                ],
                scratch,
            )
            env = ENV | {"GIT_OBJECT_DIRECTORY": str(objects)}

            def git(*args):
                return _read(
                    ["/usr/bin/git", "--no-replace-objects", *args], scratch, env
                )

            def headers(revision):
                raw = git("cat-file", "commit", revision)
                need(_oid(b"commit", raw) == revision, "commit_digest_mismatch")
                rows = raw.split(b"\n\n", 1)[0].decode().splitlines()
                return (
                    rows[0].split()[1],
                    [row.split()[1] for row in rows if row.startswith("parent ")],
                    int(
                        next(
                            row for row in rows if row.startswith("committer ")
                        ).rsplit(" ", 2)[1]
                    ),
                )

            tree, parents, epoch = headers(commit)

            tree_count = 0

            def verify_tree(oid, prefix="", depth=0):
                nonlocal tree_count
                tree_count += 1
                need(depth <= 32 and tree_count <= 1024, "tree_limit")
                need(re.fullmatch("[0-9a-f]{40}", oid), "tree_digest_mismatch")
                raw = git("cat-file", "tree", oid)
                need(_oid(b"tree", raw) == oid, "tree_digest_mismatch")
                while raw:
                    entry, _, raw = raw.partition(b"\0")
                    mode, name = entry.decode("ascii").split(" ", 1)
                    need(
                        len(raw) >= 20 and "/" not in name and _relative(name),
                        "tree_entry_invalid",
                    )
                    child, raw = raw[:20].hex(), raw[20:]
                    path = prefix + name
                    if mode == "40000":
                        yield from verify_tree(child, path + "/", depth + 1)
                    else:
                        need(mode in ("100644", "100755"), "tree_entry_invalid")
                        yield path, child, mode

            entries = {}
            for path, oid, mode in verify_tree(tree):
                need(len(entries) < 4096 and path not in entries, "tree_limit")
                entries[path] = oid, mode
            blobs, modes = _files(git("archive", "--format=tar", commit))
            need(set(blobs) == set(entries), "export_inventory_mismatch")
            for name, (oid, mode) in entries.items():
                need(
                    _oid(b"blob", blobs[name]) == oid
                    and bool(modes[name] & 0o111) == (mode == "100755"),
                    "export_digest_mismatch",
                )
            index = admin / "index"
            index_before = sha(_regular(index))
            indexed = _read(
                ["/usr/bin/git", "ls-files", "--stage", "-z"],
                scratch,
                env | {"GIT_INDEX_FILE": str(index)},
            )
            expected_index = {
                f"{mode} {oid} 0\t{name}".encode()
                for name, (oid, mode) in entries.items()
            }
            need(set(indexed.split(b"\0")[:-1]) == expected_index, "checkout_dirty")
            _observed_files(root, blobs, modes)
            need(sha(_regular(index)) == index_before, "index_changed")
            need(_head(admin, common) == commit, "head_changed")
            need(
                sha(blobs["packaging/debian/pkg11-baseline.json"]) == BASELINE,
                "historical_pin_changed",
            )
            historical = json.loads(blobs["packaging/debian/pkg11-baseline.json"])
            old_tree, _, old_epoch = headers(historical["source_commit"])
            need(
                (old_tree, old_epoch)
                == (historical["source_tree"], historical["source_date_epoch"]),
                "historical_source_mismatch",
            )
            old_files, _ = _files(
                git("archive", "--format=tar", historical["source_commit"])
            )
            need(
                sha(old_files["packaging/build_deb.py"]) == historical["recipe_sha256"],
                "historical_recipe_mismatch",
            )
            need(_head(admin, common) == commit, "head_changed")
        return {
            "repository": REPOSITORY,
            "repository_identity": "REPOSITORY_IDENTITY_NOT_ATTESTED",
            "commit": commit,
            "tree": tree,
            "parents": parents,
            "epoch": epoch,
            "recipes": {name: sha(blobs[name]) for name in RECIPE_PATHS},
            "source_inputs": {name: sha(raw) for name, raw in sorted(blobs.items())},
            "historical_source": historical,
        }
    except (OSError, ValueError, KeyError, IndexError, StopIteration):
        raise Blocked("source_observation_unverified") from None


def observe_environment():
    """Observe installed tools and package inventory. Image origin is unknown."""
    try:
        return _observe_environment()
    except (OSError, ValueError, IndexError, RuntimeError):
        raise Blocked("environment_unverified") from None


def _observe_environment():
    need(
        platform.machine() == "x86_64"
        and 'VERSION_ID="13"' in Path("/usr/lib/os-release").read_text(),
        "environment_unverified",
    )
    root = Path("/")
    commands = {
        "python": ["/usr/bin/python3", "--version"],
        "dpkg_deb": ["/usr/bin/dpkg-deb", "--version"],
        "xz": ["/usr/bin/xz", "--version"],
        "git": ["/usr/bin/git", "--version"],
    }
    inventory = _read(
        [
            "/usr/bin/dpkg-query",
            "-W",
            "-f=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n",
        ],
        root,
    )
    return {
        "platform": "debian-13/amd64",
        "image_digest": "UNKNOWN",
        "image_provenance": "IMAGE_PROVENANCE_UNKNOWN",
        "tools": {
            name: {
                "version": _read(argv, root).decode().splitlines()[0],
                "sha256": sha(_regular(Path(argv[0]).resolve())),
            }
            for name, argv in commands.items()
        },
        "packages_sha256": sha(b"\n".join(sorted(inventory.splitlines()))),
    }


def observe_historical_archives(directory, historical):
    """Match entire archive bytes to the independently pinned historical digest."""
    try:
        pin = _regular(Path(__file__).with_name("debian") / "pkg11-baseline.json")
        expected = json.loads(pin)
    except (OSError, ValueError):
        raise Blocked("historical_pin_unavailable") from None
    need(
        sha(pin) == BASELINE and historical == expected,
        "historical_pin_changed",
    )
    result = {}
    for role in ROLES:
        try:
            raw = _regular(Path(directory) / f"agent-platform-{role}_0.1.0-7_amd64.deb")
        except OSError:
            raise Blocked("historical_archive_unavailable") from None
        digest = sha(raw)
        need(
            digest == expected["roles"][role]["archive_sha256"],
            "historical_archive_mismatch",
        )
        result[role] = {"archive_sha256": digest, "size": len(raw)}
    return result


class Observation(NamedTuple):
    source: bytes
    environment: bytes
    historical_archives: bytes


def collect(source, historical_directory):
    """Collect and reobserve the complete tuple; no requested pins are accepted."""
    observed = observe_source(source)
    environment = observe_environment()
    archives = observe_historical_archives(
        historical_directory, observed["historical_source"]
    )
    need(environment == observe_environment(), "environment_changed")
    need(observed == observe_source(source), "source_changed")
    need(
        archives
        == observe_historical_archives(
            historical_directory, observed["historical_source"]
        ),
        "historical_archives_changed",
    )
    return Observation(encoded(observed), encoded(environment), encoded(archives))


def record_fixture_intent(
    peer, output, *, operator_uid, observer_uid, challenge, observation, now, expires
):
    """Receive a choice on a supervisor-owned connected Unix seqpacket socket.

    The kernel supplies peer identity. This fixture never produces authorization.
    Output is the supervisor's fixed one-shot slot for this review instance.
    """
    need(
        peer.family == socket.AF_UNIX and peer.type == socket.SOCK_SEQPACKET,
        "peer_transport_invalid",
    )
    try:
        pid, uid, gid = struct.unpack(
            "3i",
            peer.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            ),
        )
    except (OSError, struct.error):
        raise Blocked("peer_identity_unavailable") from None
    need(
        os.getuid() == observer_uid and uid == operator_uid and uid != observer_uid,
        "peer_identity_mismatch",
    )
    need(
        type(now) is int
        and type(expires) is int
        and 0 < expires - now <= 300
        and type(challenge) is str
        and re.fullmatch("[0-9a-f]{64}", challenge),
        "intent_expired_or_invalid",
    )
    need(type(observation) is Observation, "observation_invalid")
    need(
        all(type(value) is bytes and len(value) <= 1024**2 for value in observation),
        "observation_invalid",
    )
    binding = sha(
        encoded(
            {
                "release": KEY,
                "roles": ROLES,
                "challenge": challenge,
                "slot": str(output),
                "provenance": "UNVERIFIED_CALLER_FIXTURE",
                "observation": [sha(value) for value in observation],
                "expires": expires,
            }
        )
    )
    expected = ("OBSERVE " + binding).encode()
    try:
        peer.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        peer.settimeout(2)
        message, ancillary, flags, _ = peer.recvmsg(
            len(expected),
            socket.CMSG_SPACE(struct.calcsize("3i")),
            socket.MSG_CMSG_CLOEXEC,
        )
    except OSError:
        raise Blocked("operator_choice_unavailable") from None
    for level, kind, data in ancillary:
        if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
            for (fd,) in struct.iter_unpack("i", data):
                os.close(fd)
    need(
        not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
        and ancillary
        == [
            (
                socket.SOL_SOCKET,
                socket.SCM_CREDENTIALS,
                struct.pack("3i", pid, uid, gid),
            )
        ]
        and message == expected,
        "operator_choice_invalid",
    )
    record = {
        "schema": "AP-PKG164-INTENT/1",
        "status": "BLOCKED",
        "authority": "NOT_CONFIGURED",
        "fixture_peer_choice": "UNVERIFIED_CALLER_FIXTURE",
        "binding": binding,
        "release": KEY,
        "roles": ROLES,
        "final_generation_allowed": False,
        "release_authorized": False,
    }
    try:
        _write_evidence(
            Path(output),
            {"INTENT-REVIEW.json": encoded(record)},
            fixture_class="OPERATOR_BOUNDARY_FIXTURE",
        )
    except OSError:
        raise Blocked("intent_unknown_or_slot_exists") from None
    return record
