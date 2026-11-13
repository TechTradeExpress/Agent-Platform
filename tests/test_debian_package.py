"""Build/inspect archives and migrate owned temporary examples; never install."""

import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = load("deb_builder", "packaging/build_deb.py")
migration = load("deb_example", "packaging/debian/migrate_example.py")


@pytest.fixture
def example(tmp_path):
    path = tmp_path / "example"
    path.mkdir(mode=0o700)
    (path / "EXAMPLE_ONLY").write_bytes(migration.MARKER)
    (path / "example.json").write_bytes(
        migration.encoded({"format": "AP-PKG-SYNTHETIC", "schema": 1, "label": "demo"})
    )
    for p in path.iterdir():
        p.chmod(0o600)
    return path


def snapshot(path):
    return {p.name: p.read_bytes() for p in path.iterdir()}


def test_real_deb_archives_metadata_permissions_contents_and_reproducibility(tmp_path):
    commit = "a" * 40  # Explicit fabricated provenance for this offline build test.
    first = builder.build(ROOT, tmp_path / "one", 2, commit, 1700000000)
    second = builder.build(ROOT, tmp_path / "two", 2, commit, 1700000000)
    baseline = builder.build(ROOT, tmp_path / "baseline", 1, commit, 1700000000)
    assert first.read_bytes() == second.read_bytes() != baseline.read_bytes()
    assert first.read_bytes().startswith(b"!<arch>\n")
    for pkg, version in [(first, "0.1.0-2"), (baseline, "0.1.0-1")]:
        field = subprocess.check_output(["dpkg-deb", "-f", str(pkg)], text=True)
        assert f"Version: {version}\n" in field
        assert "Architecture: amd64\n" in field
        assert f"Depends: {builder.DEPENDENCIES}\n" in field
        controls = subprocess.check_output(["dpkg-deb", "--ctrl-tarfile", str(pkg)])
        with tarfile.open(fileobj=io.BytesIO(controls)) as archive:
            names = {m.name.removeprefix("./") for m in archive}
            assert not names & {"preinst", "postinst", "prerm", "postrm", "triggers"}
            assert archive.extractfile("./conffiles").read() == (
                b"/etc/agent-platform/package.conf\n"
            )
        data = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(pkg)])
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            names = [m.name.removeprefix("./") for m in archive]
            assert "usr/bin/agent-platform" in names
            assert ("usr/lib/agent-platform/migrate-example" in names) == (
                version == "0.1.0-2"
            )
            assert not any(
                word in name
                for name in names
                for word in ("auth.json", "__pycache__", "/systemd/", ".venv", ".git/")
            )
            for member in archive:
                assert member.uid == member.gid == 0
                assert member.isfile() or member.isdir()
                assert member.mode in (0o644, 0o755)
            provenance = json.loads(
                archive.extractfile("./usr/share/doc/agent-platform/build.json").read()
            )
            assert not any(
                "publisher_handoff" in n or "publisher-handoff" in n for n in names
            )
            assert not any(
                "worker_publish" in n or "worker-publisher" in n for n in names
            )
            assert "src/agent_platform/publisher_handoff.py" not in provenance["inputs"]
            # Deployable modules must ship byte-for-byte in both profiles,
            # with source hashes, without changing admission or entry points.
            for source in (ROOT / "src/agent_platform").glob("*.py"):
                if source.name == "publisher_handoff.py" or source.name.startswith(
                    "worker_publish"
                ):
                    continue
                installed = "./usr/lib/agent-platform/agent_platform/" + source.name
                assert archive.extractfile(installed).read() == source.read_bytes()
                relative = str(source.relative_to(ROOT))
                assert (
                    provenance["inputs"][relative]
                    == hashlib.sha256(source.read_bytes()).hexdigest()
                )
            wrapper = archive.extractfile("./usr/bin/agent-platform").read()
            assert wrapper.startswith(b"#!/usr/bin/python3 -I\n")
            assert b"sys.dont_write_bytecode = True" in wrapper
            meta = archive.extractfile(
                "./usr/lib/agent-platform/agent_platform-0.1.0.dist-info/METADATA"
            ).read()
            assert b"Version: 0.1.0\n" in meta
            assert b"Requires-Dist: cryptography>=43.0.0,<51\n" in meta
            assert (
                provenance["inputs"]["uv.lock"]
                == hashlib.sha256((ROOT / "uv.lock").read_bytes()).hexdigest()
            )
    with pytest.raises(FileExistsError):
        builder.build(ROOT, tmp_path / "one", 2, commit, 1700000000)


@pytest.mark.parametrize("revision,commit", [(0, "a" * 40), (3, "a" * 40), (1, "bad")])
def test_bad_package_identity_fails_before_creating_output(tmp_path, revision, commit):
    output = tmp_path / "output"
    with pytest.raises(ValueError):
        builder.build(ROOT, output, revision, commit, 1700000000)
    assert not output.exists()


def test_migration_has_backup_intent_and_idempotent_verified_output(example):
    prior = (example / "example.json").read_bytes()
    assert migration.migrate(example) == "migrated"
    assert (example / "v1.backup").read_bytes() == prior
    assert json.loads((example / "example.json").read_bytes()) == {
        "format": "AP-PKG-SYNTHETIC",
        "schema": 2,
        "display_name": "demo",
    }
    after = snapshot(example)
    assert migration.migrate(example) == "already_migrated"
    assert snapshot(example) == after


@pytest.mark.parametrize(
    "raw",
    [
        b'{"format":"checkpoint","schema":1,"label":"demo"}',
        b'{"format":"AP-PKG-SYNTHETIC","schema":99}',
        b'{"format":"AP-PKG-SYNTHETIC","schema":true,"label":"demo"}',
        b'{"format":"AP-PKG-SYNTHETIC","schema":1,"schema":1,"label":"demo"}',
        b'{"format":"AP-PKG-SYNTHETIC","schema":1,"label":"demo","token":"fake"}',
        b"x" * 4097,
    ],
)
def test_migration_rejects_unsupported_data_without_writes(example, raw):
    (example / "example.json").write_bytes(raw)
    before = snapshot(example)
    with pytest.raises(ValueError):
        migration.migrate(example)
    assert snapshot(example) == before


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "mode", "extra", "backup"])
def test_migration_rejects_aliases_unsafe_modes_and_foreign_evidence(
    example, tmp_path, kind
):
    if kind == "symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(example, target_is_directory=True)
        with pytest.raises(OSError):
            migration.migrate(alias)
        return
    if kind == "hardlink":
        os.link(example / "example.json", tmp_path / "hardlink")
    elif kind == "mode":
        example.chmod(0o755)
    elif kind == "extra":
        (example / "checkpoint.json").write_text("UNKNOWN")
    else:
        (example / "v1.backup").write_text("foreign")
        (example / "v1.backup").chmod(0o600)
    before = snapshot(example)
    with pytest.raises(ValueError):
        migration.migrate(example)
    assert snapshot(example) == before


@pytest.mark.parametrize("phase", ["backup", "intent", "temporary", "renamed"])
def test_interruption_requires_exact_reconciliation_and_never_repeats_unknown(
    example, monkeypatch, phase
):
    original = migration.create

    def interrupt(fd, name, data):
        original(fd, name, data)
        if name == {
            "backup": "v1.backup",
            "intent": "migration.json",
            "temporary": "next.tmp",
        }.get(phase):
            raise OSError("fabricated interruption")

    monkeypatch.setattr(migration, "create", interrupt)
    if phase == "renamed":
        original_sync = migration.os.fsync
        calls = []

        def failed_sync(fd):
            calls.append(1)
            # .lock, backup, intent, temporary: each has file+directory fsync.
            if len(calls) == 9:
                raise OSError("fabricated post-rename fsync failure")
            return original_sync(fd)

        monkeypatch.setattr(migration.os, "fsync", failed_sync)
    with pytest.raises(OSError):
        migration.migrate(example)
    monkeypatch.undo()
    if phase == "temporary":
        before = snapshot(example)
        with pytest.raises(ValueError):
            migration.migrate(example)
        assert snapshot(example) == before  # retain uncertainty, no cleanup
    else:
        assert migration.migrate(example) in ("migrated", "already_migrated")
        assert migration.migrate(example) == "already_migrated"


def test_lifecycle_is_host_guarded_and_workflow_isolated_and_pinned():
    shell = (ROOT / "packaging/debian/lifecycle.sh").read_text()
    assert shell.index("test -f /.dockerenv") < shell.index("apt-get")
    assert "AP-PKG-CI-DISPOSABLE-v1" in shell
    workflow = (ROOT / ".github/workflows/debian-package.yml").read_text()
    assert "permissions:\n  contents: read" in workflow
    assert "persist-credentials: false" in workflow
    assert (
        "--network none" in workflow and "--security-opt no-new-privileges" in workflow
    )
    assert "--privileged" not in workflow and "/var/run/docker.sock:" not in workflow
    assert "--fail-on error" in workflow and "autopkgtest" in workflow
    assert "continue-on-error" not in workflow
    assert "if-no-files-found: error" in workflow
    pins = re.findall(r"uses: ([\w/-]+)@([0-9a-f]{40}) # (v[\d.]+)", workflow)
    assert {p[0] for p in pins} == {"actions/checkout", "actions/upload-artifact"}
    assert workflow.count("uses:") == len(pins)


def test_workflow_inputs_match_reviewed_public_provenance():
    pins = json.loads((ROOT / "docs/debian-package-inputs.json").read_text())
    workflow = (ROOT / ".github/workflows/debian-package.yml").read_text()
    action = pins["upload_action"]
    assert action["repository"] + "@" + action["commit"] in workflow
    assert "# " + action["version"] in workflow
    dockerfile = (ROOT / "packaging/debian/Dockerfile").read_text()
    assert "debian:trixie-slim@" + pins["image"]["manifest_digest"] in dockerfile
    assert pins["image"]["platform"] == "linux/amd64"


@pytest.mark.parametrize(
    "dependency", ["cryptography>=1", "unapproved", "cryptography>=51"]
)
def test_package_rejects_unreviewed_crypto_dependency(
    tmp_path, monkeypatch, dependency
):
    original = builder.checked_file

    def changed(path):
        raw = original(path)
        if path.name == "pyproject.toml":
            return raw.replace(b"cryptography>=43.0.0,<51", dependency.encode())
        return raw

    monkeypatch.setattr(builder, "checked_file", changed)
    with pytest.raises(ValueError, match="review_version_or_dependencies"):
        builder.build(ROOT, tmp_path / "rejected", 2, "a" * 40, 1700000000)
    assert not (tmp_path / "rejected").exists()
