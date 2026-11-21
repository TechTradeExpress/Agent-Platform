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


def payload(pkg):
    data = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(pkg)])
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        return {
            m.name.removeprefix("./"): (m, archive.extractfile(m).read())
            for m in archive
            if m.isfile()
        }


def test_real_role_archives_metadata_permissions_and_reproducibility(tmp_path):
    commit = "a" * 40  # Explicit fabricated provenance, offline staging API only.
    first = builder.build(ROOT, tmp_path / "one", 4, commit, 1700000000)
    second = builder.build(ROOT, tmp_path / "two", 4, commit, 1700000000)
    baseline = builder.build(ROOT, tmp_path / "baseline", 3, commit, 1700000000)
    inventories = {}
    for role in ("control", "worker"):
        assert first[role].read_bytes() == second[role].read_bytes()
        assert first[role].read_bytes() != baseline[role].read_bytes()
        for pkg, revision in [(first[role], 4), (baseline[role], 3)]:
            package = "agent-platform-" + role
            private = "usr/lib/" + package + "/"
            doc = "usr/share/doc/" + package + "/"
            field = subprocess.check_output(["dpkg-deb", "-f", str(pkg)], text=True)
            assert f"Package: {package}\n" in field
            assert f"Version: 0.1.0-{revision}\n" in field
            assert "Architecture: amd64\n" in field
            assert f"Depends: {builder.DEPENDENCIES[role]}\n" in field
            assert "Conflicts: agent-platform\n" in field
            assert not any(
                key + ":" in field
                for key in ("Replaces", "Provides", "Breaks", "Pre-Depends")
            )
            controls = subprocess.check_output(["dpkg-deb", "--ctrl-tarfile", str(pkg)])
            with tarfile.open(fileobj=io.BytesIO(controls)) as archive:
                assert {m.name.removeprefix("./") for m in archive if m.isfile()} == {
                    "control",
                    "conffiles",
                    "md5sums",
                }
                assert (
                    archive.extractfile("./conffiles").read()
                    == f"/etc/{package}/package.conf\n".encode()
                )
            files = payload(pkg)
            assert not any("control_plane_local_runner" in name for name in files)
            metadata = private + "agent_platform-0.1.0.dist-info/"
            expected = {
                private + "agent_platform/" + name + ".py"
                for name in builder.MODULES[role]
            }
            expected |= {
                metadata + name
                for name in ("METADATA", "INSTALLER", "entry_points.txt")
            }
            expected |= {
                doc + name
                for name in (
                    "copyright",
                    "changelog.Debian.gz",
                    "README.Debian",
                    "build.json",
                    "manifest.json",
                    "examples/schema-v1.json",
                )
            }
            expected |= {"usr/bin/" + command for command in builder.ENTRY_POINTS[role]}
            expected |= {
                "usr/share/man/man1/" + command + ".1.gz"
                for command in builder.ENTRY_POINTS[role]
            }
            expected.add(f"etc/{package}/package.conf")
            if revision == 4:
                expected.add(private + "migrate-example")
            assert files.keys() == expected
            assert all(
                m.uid == m.gid == 0 and m.mode in (0o644, 0o755)
                for m, _ in files.values()
            )
            manifest = json.loads(files[doc + "manifest.json"][1])
            assert {item["path"].lstrip("/") for item in manifest["files"]} == expected
            for item in manifest["files"]:
                member, data = files[item["path"].lstrip("/")]
                assert item["mode"] == member.mode
                if item["sha256"] is not None:
                    assert item["sha256"] == hashlib.sha256(data).hexdigest()
                else:
                    assert item["path"] == "/" + doc + "manifest.json"
            provenance = json.loads(files[doc + "build.json"][1])
            assert provenance["source_commit"] == commit
            # PUB-02 remains source-only until reviewed Worker P1 integration #111.
            for name in (
                "publisher_handoff",
                "worker_publisher",
                "worker_publish_artifact",
                "worker_publish_io",
                "worker_publish_signer",
                "worker_publish_export",
            ):
                assert not any(name in path for path in files)
                assert f"src/agent_platform/{name}.py" not in provenance["inputs"]
            assert not any("worker-publisher" in path for path in files)

            for name in builder.MODULES[role]:
                source = ROOT / "src/agent_platform" / (name + ".py")
                assert (
                    files[private + "agent_platform/" + name + ".py"][1]
                    == source.read_bytes()
                )
                assert (
                    provenance["inputs"][str(source.relative_to(ROOT))]
                    == hashlib.sha256(source.read_bytes()).hexdigest()
                )
            for command in builder.ENTRY_POINTS[role]:
                wrapper = files["usr/bin/" + command][1]
                assert wrapper.startswith(b"#!/usr/bin/python3 -I\n")
                assert b"sys.dont_write_bytecode = True" in wrapper
            if revision == 4:
                inventories[role] = expected
        assert not any("codex" in key for key in payload(first["worker"]))
    assert not inventories["control"] & inventories["worker"]
    with pytest.raises(FileExistsError):
        builder.build(ROOT, tmp_path / "one", 4, commit, 1700000000)


@pytest.mark.parametrize(
    "revision,commit", [(0, "a" * 40), (1, "a" * 40), (2, "a" * 40), (3, "bad")]
)
def test_bad_package_identity_fails_before_creating_output(tmp_path, revision, commit):
    output = tmp_path / "output"
    with pytest.raises(ValueError):
        builder.build(ROOT, output, revision, commit, 1700000000)
    assert not output.exists()


@pytest.mark.parametrize(
    "unknown_name", ["unreviewed.py", "worker_publish_unreviewed.py"]
)
def test_unknown_module_and_worker_authority_import_fail_closed(tmp_path, unknown_name):
    import shutil

    source = tmp_path / "source"
    shutil.copytree(ROOT / "src", source / "src")
    for name in ("pyproject.toml", "debian/control", "debian/changelog"):
        destination = source / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / name).read_bytes())
    unknown = source / "src/agent_platform" / unknown_name
    unknown.write_text("# not admitted\n")
    with pytest.raises(ValueError, match="review_module_classification"):
        builder.validate(source)
    unknown.unlink()  # Only newly created test-owned fixture.
    worker = source / "src/agent_platform/native_artifact.py"
    worker.write_text(worker.read_text() + "\nfrom agent_platform import app_signer\n")
    with pytest.raises(ValueError, match="review_role_import_closure_worker"):
        builder.validate(source)


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
    quality = (ROOT / "packaging/debian/quality.sh").read_text()
    assert "--fail-on error" in quality and "autopkgtest" in quality
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
    assert "debian:trixie-20261027@" + pins["image"]["manifest_digest"] in dockerfile
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
        builder.build(ROOT, tmp_path / "rejected", 4, "a" * 40, 1700000000)
    assert not (tmp_path / "rejected").exists()


@pytest.mark.parametrize("command", ["run", "resume", "doctor"])
def test_worker_inert_dispatcher_has_fixed_pre_io_refusal(tmp_path, command):
    poison = tmp_path / "agent_platform"
    poison.mkdir()
    (poison / "__init__.py").write_text('raise RuntimeError("foreign code loaded")\n')
    result = subprocess.run(
        [
            "/usr/bin/python3",
            "-I",
            str(ROOT / "packaging/debian/worker_inventory.py"),
            command,
            "--issue",
            "1",
        ],
        cwd=tmp_path,
        env={"PYTHONPATH": str(tmp_path), "PATH": "/nonexistent"},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 13
    report = json.loads(result.stdout)
    assert report["launch_allowed"] is report["resume_authorized"] is False
    assert report["subscription"] == "SUBSCRIPTION_ISOLATION_BLOCKED"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["agent_platform"]


@pytest.mark.parametrize(
    "args", [["codex", "install"], ["run", "--issue", "0"], ["run"], ["inspect"]]
)
def test_worker_rejects_unimplemented_or_invalid_commands(args):
    result = subprocess.run(
        [
            "/usr/bin/python3",
            "-I",
            str(ROOT / "packaging/debian/worker_inventory.py"),
            *args,
        ],
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 2


@pytest.mark.parametrize(
    "name",
    [
        "control_plane_local_runner",
        "harness_admission",
        "claude_adapter",
        "instruction_sources",
    ],
)
def test_source_only_contracts_in_closed_role_manifests(name):
    assert name in builder.SOURCE_ONLY
    assert all(name not in modules for modules in builder.MODULES.values())
    builder.validate(ROOT)


@pytest.mark.parametrize(
    "role,module", [("control", "cli"), ("worker", "native_artifact")]
)
@pytest.mark.parametrize(
    "name",
    [
        "control_plane_local_runner",
        "harness_admission",
        "claude_adapter",
        "instruction_sources",
    ],
)
def test_role_import_cannot_pull_source_only_contract(tmp_path, role, module, name):
    import shutil

    source = tmp_path / "source"
    shutil.copytree(ROOT / "src", source / "src")
    for relative_path in ("pyproject.toml", "debian/control", "debian/changelog"):
        target = source / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative_path).read_bytes())
    target = source / "src/agent_platform" / (module + ".py")
    target.write_text(target.read_text() + f"\nfrom agent_platform import {name}\n")
    with pytest.raises(ValueError, match="review_role_import_closure_" + role):
        builder.validate(source)


@pytest.mark.parametrize("revision", [3, 4, 5, 6, 8])
@pytest.mark.parametrize(
    "name",
    [
        "control_plane_local_runner",
        "harness_admission",
        "claude_adapter",
        "instruction_sources",
        "worker_publish_reconciliation",
    ],
)
def test_source_only_contract_excluded_from_every_role_phase_archive(
    tmp_path, revision, name
):
    artifacts = builder.build(
        ROOT,
        tmp_path / "packages",
        revision,
        "a" * 40,
        1700000000,
        source_tree="b" * 40 if revision == 8 else None,
        candidate=revision == 8,
    )
    assert name in builder.SOURCE_ONLY
    assert name not in builder.PUBLISHER_MODULES
    for role, artifact in artifacts.items():
        files = payload(artifact)
        assert not any(name in path for path in files)
        doc = "usr/share/doc/agent-platform-" + role + "/"
        manifest = json.loads(files[doc + "manifest.json"][1])
        provenance = json.loads(files[doc + "build.json"][1])
        assert name not in json.dumps(manifest, sort_keys=True)
        assert name not in json.dumps(provenance, sort_keys=True)
        assert provenance["modules"] == sorted(builder.MODULES[role])
        if role == "worker" and revision >= 5:
            assert provenance["publisher_modules"] == sorted(builder.PUBLISHER_MODULES)
        # Current revision records the exact source tree; old profiles never do
        if revision == 8:
            assert provenance["source_tree"] == "b" * 40
        else:
            assert "source_tree" not in provenance


@pytest.mark.parametrize(
    "name",
    [
        "control_plane_local_runner",
        "harness_admission",
        "claude_adapter",
        "instruction_sources",
    ],
)
def test_p1_publisher_import_cannot_pull_source_only_contract(tmp_path, name):
    import shutil

    source = tmp_path / "source"
    shutil.copytree(ROOT / "src", source / "src")
    for relative_path in ("pyproject.toml", "debian/control", "debian/changelog"):
        target = source / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative_path).read_bytes())
    target = source / "src/agent_platform/worker_publisher.py"
    target.write_text(target.read_text() + f"\nfrom agent_platform import {name}\n")
    with pytest.raises(ValueError, match="review_role_import_closure_publisher"):
        builder.validate(source, 5)
    with pytest.raises(ValueError, match="review_role_import_closure_publisher"):
        builder.validate(source, 6)
