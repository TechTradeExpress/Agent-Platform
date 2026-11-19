"""PKG-13 separate final-profile recipe; real generation is unconditionally blocked.

Only rehearse() performs I/O: explicitly synthetic Git source and non-Debian
staging fixtures. No authorization loader, real final writer, vault or publisher.
"""

import hashlib
import io
import json
import os
import re
import stat
import tarfile
import tempfile
from pathlib import Path
from types import ModuleType
from typing import NamedTuple

VERSION = "0.1.0-8"
KEY = "TechTradeExpress/Agent-Platform/0.1.0-8/amd64"
ROLES = ("control", "worker")
MAGIC = b"AP-PKG13-SYNTHETIC-NOT-DEB/1\n"
MARKER = b"AP-PKG13-FABRICATED-SOURCE-ONLY/1\n"
LIMIT = 16 * 1024 * 1024  # Synthetic observation bound, not a runtime cap.
MAX_FILES = 512


class Blocked(Exception):
    """Fixed reason only; never source text, paths, stderr or credentials."""


class SourcePin(NamedTuple):
    commit: str
    tree: str
    epoch: int
    builder_sha256: str
    recipe_sha256: str
    inputs_sha256: str


class EnvironmentPin(NamedTuple):
    platform: str
    image_digest: str
    python: str
    dpkg_deb: str
    xz: str
    packages_sha256: str


class HistoricalPin(NamedTuple):
    version: str
    source_commit: str
    source_tree: str
    recipe_sha256: str
    control_archive_sha256: str
    worker_archive_sha256: str
    control_manifest_sha256: str
    worker_manifest_sha256: str


class HistoryPin(NamedTuple):
    # Synthetic caller assertion only, never independently authenticated history.
    state: str
    continuity_sha256: str
    bundle_sha256: str | None


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def need(ok, reason):
    if not ok:
        raise Blocked(reason)


def generate(*args, **kwargs):
    """No trusted generation-decision integration exists; refuse before I/O."""
    raise Blocked("trusted_generation_unavailable")


def refusal():
    return {
        "schema": "AP-PKG13-GENERATION/1",
        "status": "BLOCKED",
        "reason": "trusted_generation_unavailable",
        "release_key": KEY,
        "final_generation_allowed": False,
        "release_authorized": False,
        "publication_allowed": False,
        "installation_allowed": False,
    }


def _hex(value, size=64):
    return (
        type(value) is str
        and len(value) == size
        and re.fullmatch(f"[0-9a-f]{{{size}}}", value)
    )


def _relative(name):
    return (
        type(name) is str
        and 0 < len(name) <= 200
        and re.fullmatch(r"[A-Za-z0-9_./-]+", name)
        and all(p not in ("", ".", "..") for p in name.split("/"))
    )


def _directory(path):
    path = Path(path)
    need(path.is_absolute() and os.path.normpath(path) == str(path), "path_invalid")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
            info = os.fstat(fd)
            need(
                not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX, "unsafe_parent"
            )
        return fd
    except BaseException:
        os.close(fd)
        raise


def _stamp(info):
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


def _regular(path):
    parent = _directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            before = os.fstat(fd)
            need(
                stat.S_ISREG(before.st_mode)
                and before.st_nlink == 1
                and before.st_size <= LIMIT,
                "file_metadata_invalid",
            )
            data = bytearray()
            while len(data) <= LIMIT:
                chunk = os.read(fd, min(65536, LIMIT + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            after = os.fstat(fd)
            need(
                len(data) <= LIMIT
                and _stamp(before) == _stamp(after)
                and len(data) == before.st_size,
                "file_changed_or_limit",
            )
            return bytes(data)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _git(root, *args):
    # Existing bounded foreground reader, not a runner or credential client.
    from agent_platform.process import CommandError, read_command

    try:
        return read_command(
            [
                "git",
                "--no-replace-objects",
                "-c",
                "credential.helper=",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                *args,
            ],
            root,
            {
                "PATH": os.defpath,
                "LC_ALL": "C",
                "GIT_NO_LAZY_FETCH": "1",
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null",
            },
            timeout=10,
            limit=LIMIT,
        )
    except CommandError:
        raise Blocked("git_observation_unavailable") from None


def _stable(root, pin):
    need(
        _git(root, "rev-parse", "HEAD").decode().strip() == pin.commit,
        "source_head_moved",
    )
    need(
        not _git(root, "status", "--porcelain=v1", "--untracked-files=all"),
        "source_dirty",
    )


def _files(raw, epoch=None):
    need(len(raw) <= LIMIT, "archive_limit")
    result, modes, seen = {}, {}, set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as stream:
        for member in stream:
            name = member.name.removeprefix("./").rstrip("/")
            need(_relative(name) and name not in seen, "archive_path_invalid")
            seen.add(name)
            need(
                len(seen) <= MAX_FILES and (member.isdir() or member.isfile()),
                "archive_type_or_limit",
            )
            need(not member.mode & 0o7000, "archive_mode_invalid")
            if epoch is not None:
                need(
                    member.uid == member.gid == 0 and member.mtime == epoch,
                    "archive_metadata_mismatch",
                )
            if member.isfile():
                need(0 <= member.size <= LIMIT, "archive_limit")
                result[name] = stream.extractfile(member).read()
                modes[name] = member.mode
                need(sum(map(len, result.values())) <= LIMIT, "archive_limit")
    return result, modes


def _snapshot(root, pin):
    fd = _directory(root)
    os.close(fd)
    _stable(root, pin)
    need(
        _git(root, "rev-parse", "--verify", pin.commit + "^{commit}").decode().strip()
        == pin.commit,
        "source_commit_mismatch",
    )
    need(
        _git(root, "rev-parse", pin.commit + "^{tree}").decode().strip() == pin.tree,
        "source_tree_mismatch",
    )
    need(
        int(_git(root, "show", "-s", "--format=%ct", pin.commit)) == pin.epoch,
        "source_epoch_mismatch",
    )
    rows = _git(root, "ls-tree", "-rz", "--full-tree", pin.commit).split(b"\0")
    objects = {}
    for row in rows:
        if not row:
            continue
        metadata, name = row.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split()
        name = name.decode("ascii")
        need(
            _relative(name) and mode in ("100644", "100755") and kind == "blob",
            "source_object_invalid",
        )
        objects[name] = (mode, oid)
    files, modes = _files(_git(root, "archive", "--format=tar", pin.commit))
    need(set(files) == set(objects), "source_export_mismatch")
    for name, data in files.items():
        mode, oid = objects[name]
        need(
            hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            == oid,
            "source_blob_mismatch",
        )
        need(bool(modes[name] & 0o111) == (mode == "100755"), "source_mode_mismatch")
    need(files.get("PKG13_SYNTHETIC_SOURCE") == MARKER, "synthetic_source_required")
    hashes = {name: sha(data) for name, data in files.items()}
    need(sha(encoded(hashes)) == pin.inputs_sha256, "source_inputs_mismatch")
    for name, digest in (
        ("packaging/build_deb.py", pin.builder_sha256),
        ("packaging/final_recipe.py", pin.recipe_sha256),
    ):
        need(hashes.get(name) == digest, "source_recipe_mismatch")
        need(
            sha(_regular(Path(__file__).with_name(Path(name).name))) == digest,
            "observer_recipe_mismatch",
        )
    _stable(root, pin)
    return files, hashes


def _builder(pin):
    # Execute exactly the checked local tooling bytes, not export data or .pyc.
    path = Path(__file__).with_name("build_deb.py")
    data = _regular(path)
    need(sha(data) == pin.builder_sha256, "observer_recipe_mismatch")
    module = ModuleType("pkg13_staging")
    module.__file__ = str(path)
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module


def _fixture_writer(stage, artifact, epoch):
    """Canonical non-installable staging image; never ar/dpkg-deb or a .deb."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as stream:
        files = sorted(p for p in stage.rglob("*") if not p.is_dir())
        need(len(files) <= MAX_FILES, "stage_limit")
        for path in files:
            data = _regular(path)
            member = tarfile.TarInfo(str(path.relative_to(stage)))
            member.mode, member.size, member.mtime = (
                stat.S_IMODE(path.lstat().st_mode),
                len(data),
                epoch,
            )
            member.uid = member.gid = 0
            stream.addfile(member, io.BytesIO(data))
    data = MAGIC + raw.getvalue()
    need(len(data) <= LIMIT, "stage_limit")
    fd = os.open(artifact, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _payload_paths(role, builder, consumed):
    private = f"usr/lib/agent-platform-{role}/"
    doc = f"usr/share/doc/agent-platform-{role}/"
    names = {private + "agent_platform/" + n + ".py" for n in builder.MODULES[role]}
    names |= {
        private + "agent_platform-0.1.0.dist-info/" + n
        for n in ("METADATA", "INSTALLER", "entry_points.txt")
    }
    names |= {private + "migrate-example", f"etc/agent-platform-{role}/package.conf"}
    names |= {
        doc + n
        for n in (
            "copyright",
            "changelog.Debian.gz",
            "examples/schema-v1.json",
            "README.Debian",
            "build.json",
            "manifest.json",
        )
    }
    for command in builder.ENTRY_POINTS[role]:
        names |= {"usr/bin/" + command, "usr/share/man/man1/" + command + ".1.gz"}
    if role == "worker":
        names |= {
            "usr/lib/ap-worker-publisher/agent_platform/" + n + ".py"
            for n in builder.PUBLISHER_MODULES | {"__init__"}
        }
        names |= {
            "usr/libexec/" + n
            for n in (
                "ap-worker-publisher",
                "ap-worker-publisher-export",
                "ap-worker-publisher-operator",
                "ap-worker-publisher-signer",
            )
        }
        for unit in ("ap-worker-publisher", "ap-worker-publisher-signer"):
            names |= {
                "usr/lib/systemd/system/" + unit + ".service",
                "etc/apparmor.d/" + unit,
            }
        names |= {
            doc + "examples/" + n for n in ("job.example.json", "receipts.example.json")
        }
        names |= {
            doc + n
            for n in (
                "worker-doctor.md",
                "worker-pkg09-upgrade.md",
                "worker-pkg11-upgrade.md",
                "publisher-isolation-readiness.md",
                "worker-doctor.schema.json",
                "worker-pilot-checklist.md",
                "worker01-homelab-publisher.md",
                "worker-provisioning.md",
            )
        }
        names |= {
            private + "provisioning/" + n
            for n in (
                "provision.py",
                "worker_doctor.py",
                "codex_upstream.py",
                "codex-release-lock.json",
            )
        }
        names |= {
            private + n for n in consumed if n.startswith("provisioning/evidence/")
        }
    return names


def inspect_fixture(path, role, pin, environment, inputs, builder, *, baseline=None):
    try:
        return _inspect_fixture(path, role, pin, environment, inputs, builder, baseline)
    except Blocked:
        raise
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError):
        raise Blocked("fixture_unverified") from None


def _inspect_fixture(path, role, pin, environment, inputs, builder, baseline):
    need(type(baseline) is HistoricalPin, "historical_baseline_unverified")
    need(
        role in ROLES
        and path.name == f"agent-platform-{role}_{VERSION}_amd64.pkg13-fixture",
        "fixture_identity_invalid",
    )
    raw = _regular(path)
    need(raw.startswith(MAGIC), "noninstallable_fixture_required")
    files, modes = _files(raw[len(MAGIC) :], pin.epoch)
    doc = f"usr/share/doc/agent-platform-{role}/"
    build = json.loads(files[doc + "build.json"])
    need(
        build["package"] == "agent-platform-" + role
        and build["debian_version"] == VERSION,
        "role_mismatch",
    )
    need(
        build["build_kind"] == "final-unreleased"
        and build["ci_only"] is False
        and build["release_authorized"] is False,
        "artifact_class_invalid",
    )
    need(
        build["source_commit"] == pin.commit
        and build["source_tree"] == pin.tree
        and build["source_date_epoch"] == pin.epoch,
        "artifact_source_mismatch",
    )
    need(
        build["rehearsal"]
        == {
            "class": "SYNTHETIC_ONLY_NONINSTALLABLE",
            "recipes": {"builder": pin.builder_sha256, "final": pin.recipe_sha256},
            "source_inputs": inputs,
            "environment": environment._asdict(),
            "historical_baseline": baseline._asdict(),
        },
        "artifact_evidence_mismatch",
    )
    need(
        all(inputs.get(name) == value for name, value in build["inputs"].items()),
        "consumed_inputs_mismatch",
    )
    manifest_raw = files[doc + "manifest.json"]
    manifest = json.loads(manifest_raw)
    inventory = {item["path"].removeprefix("/"): item for item in manifest["files"]}
    payload = {
        name: value for name, value in files.items() if not name.startswith("DEBIAN/")
    }
    need(
        len(inventory) == len(manifest["files"]) and set(inventory) == set(payload),
        "manifest_inventory_mismatch",
    )
    need(
        set(payload) == _payload_paths(role, builder, build["inputs"]),
        "payload_closure_mismatch",
    )
    for name, item in inventory.items():
        need(
            (item["uid"], item["gid"]) == (0, 0) and modes[name] == item["mode"],
            "manifest_metadata_mismatch",
        )
        need(
            item["sha256"] is None
            if name == doc + "manifest.json"
            else sha(payload[name]) == item["sha256"],
            "manifest_digest_mismatch",
        )
        need(
            not payload[name].startswith(b"\x7fELF")
            and Path(name).name not in ("codex", "claude"),
            "vendor_binary_forbidden",
        )
    private = f"usr/lib/agent-platform-{role}/agent_platform/"
    need(
        {n for n in payload if n.startswith(private)}
        == {private + name + ".py" for name in builder.MODULES[role]},
        "role_closure_mismatch",
    )
    need(
        not any(
            Path(n).name
            in {
                name + ".py" for name in builder.SOURCE_ONLY - builder.PUBLISHER_MODULES
            }
            for n in payload
        ),
        "source_only_module_forbidden",
    )
    hooks = {n for n in files if n.startswith("DEBIAN/")}
    need(
        hooks
        == {"DEBIAN/control", "DEBIAN/conffiles", "DEBIAN/md5sums"}
        | ({"DEBIAN/preinst"} if role == "worker" else set()),
        "maintainer_scripts_invalid",
    )
    control = dict(
        line.split(": ", 1)
        for line in files["DEBIAN/control"].decode().splitlines()
        if line and not line.startswith(" ")
    )
    need(
        control["Package"] == build["package"]
        and control["Version"] == VERSION
        and control["Architecture"] == "amd64"
        and control["Conflicts"] == "agent-platform",
        "control_metadata_mismatch",
    )
    need(
        not {"Pre-Depends", "Replaces", "Breaks", "Provides"} & set(control),
        "control_metadata_mismatch",
    )
    for name in hooks:
        need(
            modes[name] == (0o755 if name == "DEBIAN/preinst" else 0o644),
            "control_mode_mismatch",
        )
    expected_sums = "".join(
        hashlib.md5(data).hexdigest() + "  " + name + "\n"
        for name, data in sorted(payload.items(), key=lambda pair: Path(pair[0]))
        if not name.startswith("etc/")
    ).encode()
    need(files["DEBIAN/md5sums"] == expected_sums, "control_md5_mismatch")
    need(
        control["Depends"]
        == (
            builder.P1_DEPENDENCIES if role == "worker" else builder.DEPENDENCIES[role]
        ),
        "dependencies_mismatch",
    )
    expected_conf = [f"/etc/agent-platform-{role}/package.conf"]
    if role == "worker":
        publisher = "usr/lib/ap-worker-publisher/agent_platform/"
        need(
            {n for n in payload if n.startswith(publisher)}
            == {
                publisher + n + ".py" for n in builder.PUBLISHER_MODULES | {"__init__"}
            },
            "publisher_closure_mismatch",
        )
        for unit in ("ap-worker-publisher", "ap-worker-publisher-signer"):
            expected_conf.append("/etc/apparmor.d/" + unit)
            unit_data = payload["usr/lib/systemd/system/" + unit + ".service"]
            need(
                b"[Install]" not in unit_data and b"Restart=no" in unit_data,
                "unit_activation_forbidden",
            )
    need(
        files["DEBIAN/conffiles"].decode().splitlines() == expected_conf,
        "conffiles_mismatch",
    )
    return {
        "package": build["package"],
        "archive_sha256": sha(raw),
        "size": len(raw),
        "manifest_sha256": sha(manifest_raw),
        "embedded_build_sha256": sha(files[doc + "build.json"]),
        "inputs": build["inputs"],
    }


def _write_evidence(output, files, *, fixture_class="SYNTHETIC_ONLY_NONINSTALLABLE"):
    parent = _directory(output.parent)
    fd = None
    try:
        need(_relative(output.name) and "/" not in output.name, "output_invalid")
        os.mkdir(output.name, 0o700, dir_fd=parent)  # Never adopt even an empty path.
        fd = os.open(
            output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
        )
        identity = os.fstat(fd)

        def put(name, data):
            need(_relative(name) and "/" not in name, "output_invalid")
            child = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=fd,
            )
            with os.fdopen(child, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
                info = os.fstat(handle.fileno())
                need(
                    stat.S_ISREG(info.st_mode)
                    and info.st_nlink == 1
                    and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == 0o600,
                    "output_file_changed",
                )
            os.fsync(fd)

        put(
            "INTENT.json",
            encoded(
                {
                    "class": fixture_class,
                    "state": "UNKNOWN",
                    "final_generation_allowed": False,
                }
            ),
        )
        for name, data in sorted(files.items()):
            put(name, data)
        current = os.stat(output.name, dir_fd=parent, follow_symlinks=False)
        need(
            (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino),
            "output_changed",
        )
        put(
            "COMPLETED.json",
            encoded(
                {
                    "class": fixture_class,
                    "files": {n: sha(v) for n, v in files.items()},
                    "release_authorized": False,
                }
            ),
        )
        os.fsync(parent)
        current = os.stat(output.name, dir_fd=parent, follow_symlinks=False)
        need(
            (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino),
            "output_changed",
        )
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def rehearse(
    source,
    output,
    *,
    pin,
    environment,
    history,
    observe_tools=None,
    baseline=None,
    observe_baseline=None,
):
    """Synthetic-only rehearsal. Caller facts/callbacks are NOT authorization.

    No real final archive backend or independently verified registry exists.
    Any failure leaves caller-owned output untouched or retained for reconciliation.
    """
    need(
        type(pin) is SourcePin
        and _hex(pin.commit, 40)
        and _hex(pin.tree, 40)
        and type(pin.epoch) is int
        and 0 <= pin.epoch <= 2**31 - 1
        and all(
            _hex(x) for x in (pin.builder_sha256, pin.recipe_sha256, pin.inputs_sha256)
        ),
        "source_pin_invalid",
    )
    need(
        type(environment) is EnvironmentPin
        and all(type(v) is str and len(v) <= 80 for v in environment)
        and environment.platform == "debian-13/amd64"
        and environment.image_digest.startswith("sha256:")
        and _hex(environment.image_digest[7:])
        and _hex(environment.packages_sha256)
        and all(
            re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+~][A-Za-z0-9.]+)?", v)
            for v in (environment.python, environment.dpkg_deb, environment.xz)
        ),
        "environment_invalid",
    )
    need(
        type(history) is HistoryPin
        and type(history.state) is str
        and history.state in ("EMPTY", "FROZEN")
        and _hex(history.continuity_sha256)
        and (
            history.bundle_sha256 is None
            if history.state == "EMPTY"
            else _hex(history.bundle_sha256)
        ),
        "history_unverified",
    )
    need(callable(observe_tools), "toolchain_unverified")
    try:
        observed = observe_tools()
    except Exception:
        raise Blocked("toolchain_unverified") from None
    need(
        type(observed) is EnvironmentPin and observed == environment,
        "toolchain_unverified",
    )
    need(
        type(baseline) is HistoricalPin
        and baseline.version == "0.1.0-7"
        and _hex(baseline.source_commit, 40)
        and _hex(baseline.source_tree, 40)
        and all(_hex(v) for v in baseline[3:]),
        "historical_baseline_unverified",
    )
    need(callable(observe_baseline), "historical_baseline_unverified")
    try:
        observed_baseline = observe_baseline()
    except Exception:
        raise Blocked("historical_baseline_unverified") from None
    need(
        type(observed_baseline) is HistoricalPin and observed_baseline == baseline,
        "historical_baseline_unverified",
    )
    source, output = Path(source), Path(output)
    try:
        files, inputs = _snapshot(source, pin)
        builder = _builder(pin)
        with tempfile.TemporaryDirectory(prefix="ap-pkg13-synthetic-") as temp:
            scratch = Path(temp)
            snapshot = scratch / "source"
            for name, data in files.items():
                path = snapshot / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            controls = builder.validate(snapshot, 8)
            rehearsal = {
                "class": "SYNTHETIC_ONLY_NONINSTALLABLE",
                "recipes": {"builder": pin.builder_sha256, "final": pin.recipe_sha256},
                "source_inputs": inputs,
                "environment": environment._asdict(),
                "historical_baseline": baseline._asdict(),
            }
            pairs = []
            for name in ("first", "second"):
                pairs.append(
                    builder._stage_archives(
                        snapshot,
                        scratch / name,
                        8,
                        pin.commit,
                        pin.epoch,
                        source_tree=pin.tree,
                        version=VERSION,
                        kind="final-unreleased",
                        ci_only=False,
                        controls=controls,
                        archive_writer=_fixture_writer,
                        rehearsal=rehearsal,
                        toolchain=environment._asdict(),
                    )
                )
            outputs, evidence = {}, {}
            for role in ROLES:
                first, second = (pair[role] for pair in pairs)
                need(_regular(first) == _regular(second), "rebuild_mismatch")
                record = inspect_fixture(
                    first, role, pin, environment, inputs, builder, baseline=baseline
                )
                provenance = _regular(
                    first.parent / ("agent-platform-" + role + ".provenance.json")
                )
                need(
                    provenance
                    == _regular(
                        second.parent / ("agent-platform-" + role + ".provenance.json")
                    ),
                    "provenance_rebuild_mismatch",
                )
                external = json.loads(provenance)
                staged, _ = _files(_regular(first)[len(MAGIC) :], pin.epoch)
                embedded = json.loads(
                    staged[f"usr/share/doc/agent-platform-{role}/build.json"]
                )
                need(
                    set(external)
                    == set(embedded)
                    | {
                        "artifact",
                        "sha256",
                        "size",
                        "manifest_sha256",
                        "dpkg_deb",
                        "python",
                        "xz",
                    }
                    and encoded({k: external[k] for k in embedded}) == encoded(embedded)
                    and external["artifact"] == first.name
                    and type(external["size"]) is int
                    and all(
                        external[k] == getattr(environment, k)
                        for k in ("python", "dpkg_deb", "xz")
                    ),
                    "external_provenance_mismatch",
                )
                need(
                    external["sha256"] == record["archive_sha256"]
                    and external["manifest_sha256"] == record["manifest_sha256"]
                    and external["size"] == record["size"]
                    and external["inputs"] == record["inputs"],
                    "external_provenance_mismatch",
                )
                evidence[role] = record | {"provenance_sha256": sha(provenance)}
                outputs[first.name] = _regular(first)
                outputs["agent-platform-" + role + ".provenance.json"] = provenance
            report = refusal() | {
                "schema": "AP-PKG13-REHEARSAL/1",
                "status": "SYNTHETIC_PASS",
                "reason": "noninstallable_rehearsal_only",
                "class": "SYNTHETIC_ONLY_NONINSTALLABLE",
                "source": pin._asdict(),
                "environment": environment._asdict(),
                "roles": evidence,
                "history_authenticated": False,
                "historical_baseline_authenticated": False,
                "historical_baseline": baseline._asdict(),
                "host": "HOST_NOT_RUN",
            }
            fingerprint = sha(encoded(report))
            if history.state == "FROZEN":
                need(history.bundle_sha256 == fingerprint, "final_version_conflict")
                raise Blocked("already_frozen_no_replay")
            _stable(source, pin)
            outputs["EVIDENCE.json"] = encoded(report | {"bundle_sha256": fingerprint})
            outputs["SHA256SUMS"] = "".join(
                sha(data) + "  " + name + "\n" for name, data in sorted(outputs.items())
            ).encode()
            _write_evidence(output, outputs)
            return report | {"bundle_sha256": fingerprint}
    except Blocked:
        raise
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, ImportError):
        raise Blocked("rehearsal_unverified") from None


def rehearse_debian(source, scratch, *, encoder_sha256, **observations):
    """Offline Debian encoding in caller-owned disposable scratch.

    The existing synthetic admission and two-pass staging run before encoding.
    Only test identities leave the encoder. This is separate from generate().
    """
    scratch = Path(scratch)
    try:
        recipe = Path(__file__).with_name("debian_fixture_encoder.py")
        data = _regular(recipe)
        need(
            _hex(encoder_sha256) and sha(data) == encoder_sha256, "encoder_pin_mismatch"
        )
        encoder = ModuleType("pkg162_encoder")
        exec(compile(data, str(recipe), "exec"), encoder.__dict__)
        fd = _directory(scratch)
        try:
            info = os.fstat(fd)
            need(
                info.st_uid == os.getuid() and not info.st_mode & 0o077,
                "private_scratch_required",
            )
            need(not os.listdir(fd), "scratch_not_empty")
        finally:
            os.close(fd)
        # A retained rehearsal (including UNKNOWN) blocks reuse of this path.
        staged = scratch / "staged"
        report = rehearse(source, staged, **observations)
        epoch = observations["pin"].epoch
        output = {}
        for role in ROLES:
            fixture = staged / f"agent-platform-{role}_{VERSION}_amd64.pkg13-fixture"
            raw = _regular(fixture)
            need(sha(raw) == report["roles"][role]["archive_sha256"], "staging_changed")
            files, modes = _files(raw[len(MAGIC) :], epoch)
            members = encoder.expected_members(files, role)
            archive = encoder.encode(members, modes, epoch)
            need(
                archive
                == encoder.encode(encoder.expected_members(files, role), modes, epoch),
                "encoder_rebuild_mismatch",
            )
            encoder.verify(archive, members, modes, epoch)
            package = f"ap-pkg162-fixture-{role}_{encoder.VERSION}_amd64.deb"
            output[package] = archive
        evidence = refusal() | {
            "schema": "AP-PKG162-ENCODING/1",
            "status": "SYNTHETIC_PASS",
            "class": "SYNTHETIC_ONLY_DEBIAN",
            "encoder_sha256": encoder_sha256,
            "staging_sha256": report["bundle_sha256"],
            "archives": {name: sha(raw) for name, raw in output.items()},
        }
        _write_evidence(
            scratch / "encoded",
            output | {"EVIDENCE.json": encoded(evidence)},
            fixture_class="SYNTHETIC_ONLY_DEBIAN",
        )
        return evidence
    except Blocked:
        raise
    except (OSError, EOFError, ValueError, KeyError, TypeError, tarfile.TarError):
        raise Blocked("debian_rehearsal_unverified") from None


if __name__ == "__main__":
    print(json.dumps(refusal(), sort_keys=True))
    raise SystemExit(13)
