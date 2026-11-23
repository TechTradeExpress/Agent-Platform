"""PKG-13 fabricated Git source and non-installable staging images only."""

import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    spec = importlib.util.spec_from_file_location("pkg13_test", ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def fixture(tmp_path):
    m = load("packaging/final_recipe.py")
    b = load("packaging/build_deb.py")
    root = tmp_path / "source"
    root.mkdir()
    text = b"# AP-PKG13 SYNTHETIC PAYLOAD ONLY\n"
    files = {"PKG13_SYNTHETIC_SOURCE": m.MARKER}
    for name in b.MODULES["control"] | b.MODULES["worker"] | b.SOURCE_ONLY:
        files["src/agent_platform/" + name + ".py"] = text
    files["pyproject.toml"] = (
        '[project]\nversion="0.1.0"\ndependencies='
        + json.dumps(b.PYTHON_DEPENDENCIES)
        + "\n[project.scripts]\n"
        + "".join(
            json.dumps(k) + "=" + json.dumps(v) + "\n"
            for k, v in b.DEVELOPER_SCRIPTS.items()
        )
    ).encode()
    controls = (ROOT / "debian/control").read_text().split("\n\n")
    for i in (1, 2):
        controls[i] = "\n".join(
            line
            if not line.startswith("Description:")
            else "Description: AP-PKG13 synthetic fixture only"
            for line in controls[i].splitlines()
        )
    files["debian/control"] = "\n\n".join(controls).encode()
    files["debian/changelog"] = "".join(
        f"agent-platform (0.1.0-{n}) trixie; urgency=low\n\n"
        "  * AP-PKG13 SYNTHETIC ONLY.\n\n"
        " -- Fixture <fixture@example.invalid>  Tue, 14 Nov 2023 00:00:00 +0000\n\n"
        for n in range(8, 0, -1)
    ).encode()
    # Trusted recipe code is input-only; every installed source/document/helper
    # payload is fabricated. Exported recipes are never imported/executed.
    for name in ("build_deb.py", "final_recipe.py"):
        files["packaging/" + name] = (ROOT / "packaging" / name).read_bytes()
    for name in (
        "uv.lock",
        "LICENSE",
        "debian/copyright",
        "docs/debian-role-package-architecture.md",
        "docs/codex-upstream-provisioning-decision.md",
        "docs/debian-package.md",
        "packaging/debian/migrate_example.py",
        "packaging/worker-provisioning/worker_cli.py",
        "packaging/worker-provisioning/provision.py",
        "packaging/worker-provisioning/worker_doctor.py",
    ):
        files[name] = text
    for name in (
        "ap-worker-publisher",
        "ap-worker-publisher-export",
        "ap-worker-publisher-operator",
        "ap-worker-publisher-signer",
        "ap-worker-publisher-recovery",
        "ap-worker-publisher-recovery-signer",
    ):
        files["packaging/worker-publisher/" + name] = (
            b"#!/bin/sh\n# AP-PKG13 SYNTHETIC ONLY\nexit 99\n"
        )
    for unit in (
        "ap-worker-publisher",
        "ap-worker-publisher-signer",
        "ap-worker-publisher-recovery",
        "ap-worker-publisher-recovery-signer",
    ):
        files["packaging/worker-publisher/" + unit + ".service"] = (
            b"[Unit]\nDescription=AP-PKG13 SYNTHETIC ONLY\n[Service]\n"
            b"Type=oneshot\nExecStart=/bin/false\nRestart=no\n"
        )
        files["packaging/worker-publisher/" + unit + ".apparmor"] = text
    for name in ("job.example.json", "receipts.example.json"):
        files["packaging/worker-publisher/" + name] = (
            b'{"class":"AP-PKG13-SYNTHETIC"}\n'
        )
    for name in (
        "worker-doctor.md",
        "worker-pkg09-upgrade.md",
        "worker-pkg11-upgrade.md",
        "publisher-isolation-readiness.md",
        "worker-doctor.schema.json",
        "worker-pilot-checklist.md",
        "worker01-homelab-publisher.md",
        "worker-provisioning.md",
    ):
        files["docs/" + name] = text
    files["packaging/worker-provisioning/preinst"] = (
        b"#!/bin/sh\n# AP-PKG13 SYNTHETIC ONLY\n# @OWNED_PATHS@\n"
        b"# @CLOSED_ROOT_ENTRIES@\nexit 99\n"
    )
    proof = m.encoded({"trusted_root_sha256": "a" * 64, "class": "AP-PKG13-SYNTHETIC"})
    lock = m.encoded(
        {
            "releases": [
                {
                    "version": "0.0.1",
                    "provenance": {
                        "evidence": "evidence/codex-0.0.1-provenance.json",
                        "evidence_sha256": m.sha(proof),
                    },
                }
            ]
        }
    )
    files["provisioning/codex-release-lock.json"] = lock
    files["provisioning/codex_upstream.py"] = (
        text + ("LOCK_SHA256=" + repr(m.sha(lock)) + "\n").encode()
    )
    files["provisioning/evidence/codex-0.0.1-provenance.json"] = proof
    files["provisioning/evidence/codex-0.0.1.sigstore"] = text
    files["provisioning/evidence/sigstore-trusted-root-" + "a" * 64 + ".json"] = (
        b'{"class":"AP-PKG13-SYNTHETIC"}\n'
    )
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    env = {
        "PATH": os.defpath,
        "LC_ALL": "C",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "Fixture",
        "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "Fixture",
        "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        "GIT_AUTHOR_DATE": "1700000000 +0000",
        "GIT_COMMITTER_DATE": "1700000000 +0000",
    }

    def git(*args):
        return (
            subprocess.check_output(
                [
                    "git",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "commit.gpgsign=false",
                    *args,
                ],
                cwd=root,
                env=env,
                stderr=subprocess.DEVNULL,
                timeout=15,
            )
            .decode()
            .strip()
        )

    git("init", "--initial-branch=main")
    git("add", "--", *sorted(files))
    git("commit", "-m", "fabricated PKG13 source")
    inputs = {name: m.sha(data) for name, data in files.items()}
    pin = m.SourcePin(
        git("rev-parse", "HEAD"),
        git("rev-parse", "HEAD^{tree}"),
        1700000000,
        inputs["packaging/build_deb.py"],
        inputs["packaging/final_recipe.py"],
        m.sha(m.encoded(inputs)),
    )
    environment = m.EnvironmentPin(
        "debian-13/amd64", "sha256:" + "5" * 64, "3.13.5", "1.22.22", "5.8.1", "6" * 64
    )
    history = m.HistoryPin("EMPTY", "7" * 64, None)
    return m, b, root, pin, environment, history, inputs, git


def _baseline(m):
    # Entirely fabricated historical observations, not installed -7 evidence.
    return m.HistoricalPin(
        "0.1.0-7", "a" * 40, "b" * 40, "c" * 64, "d" * 64, "e" * 64, "f" * 64, "0" * 64
    )


def run(fixture, output, **changes):
    m, _, root, pin, environment, history, _, _ = fixture
    args = dict(
        pin=pin,
        environment=environment,
        history=history,
        observe_tools=lambda: environment,
        baseline=_baseline(m),
        observe_baseline=lambda: _baseline(m),
    )
    args.update(changes)
    return m.rehearse(root, output, **args)


def test_two_role_final_profile_staged_from_start_but_never_a_deb(fixture, tmp_path):
    m, b, _, pin, environment, _, inputs, _ = fixture
    first, second = tmp_path / "one", tmp_path / "two"
    report = run(fixture, first)
    assert report == run(fixture, second)
    assert report["status"] == "SYNTHETIC_PASS"
    assert all(
        report[k] is False
        for k in (
            "final_generation_allowed",
            "release_authorized",
            "publication_allowed",
            "installation_allowed",
        )
    )
    assert not list(first.glob("*.deb"))
    for role in m.ROLES:
        name = f"agent-platform-{role}_0.1.0-8_amd64.pkg13-fixture"
        assert (first / name).read_bytes() == (second / name).read_bytes()
        assert (first / name).read_bytes().startswith(m.MAGIC)
        observed = m.inspect_fixture(
            first / name, role, pin, environment, inputs, b, baseline=_baseline(m)
        )
        assert observed == {
            k: v for k, v in report["roles"][role].items() if k != "provenance_sha256"
        }
        files, _ = m._files((first / name).read_bytes()[len(m.MAGIC) :], pin.epoch)
        embedded = json.loads(files[f"usr/share/doc/agent-platform-{role}/build.json"])
        assert (
            embedded["build_kind"] == "final-unreleased"
            and embedded["ci_only"] is False
            and embedded["release_authorized"] is False
        )
        assert embedded["rehearsal"]["class"] == "SYNTHETIC_ONLY_NONINSTALLABLE"
        assert not any(data.startswith(b"\x7fELF") for data in files.values())
    assert (first / "INTENT.json").is_file() and (first / "COMPLETED.json").is_file()


@pytest.mark.parametrize(
    "authorization",
    [None, True, {"approved": True}, "CONSISTENT_UNVERIFIED", "Issue says release"],
)
def test_real_generation_refuses_before_any_argument_io(tmp_path, authorization):
    m = load("packaging/final_recipe.py")

    class Trap:
        def __fspath__(self):
            pytest.fail("path evaluated before refusal")

    with pytest.raises(m.Blocked, match="^trusted_generation_unavailable$"):
        m.generate(Trap(), output=tmp_path / "out", authorization=authorization)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "flags",
    [
        [],
        ["--approve"],
        ["--final-version"],
        ["--ci-final-fixture"],
        ["--authorization", "SECRET"],
    ],
)
def test_cli_is_fixed_exit13_even_with_fake_flags_and_environment(tmp_path, flags):
    result = subprocess.run(
        [sys.executable, str(ROOT / "packaging/final_recipe.py"), *flags],
        cwd=tmp_path,
        env={
            "PATH": os.defpath,
            "PKG13_APPROVED": "true",
            "FINAL_BUILD_AUTHORIZED": "true",
        },
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert (
        result.returncode == 13 and not result.stderr and "SECRET" not in result.stdout
    )
    record = json.loads(result.stdout)
    assert record["status"] == "BLOCKED" and record["final_generation_allowed"] is False
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "field,value",
    [
        ("commit", "a" * 40),
        ("tree", "b" * 40),
        ("epoch", 1),
        ("builder_sha256", "c" * 64),
        ("recipe_sha256", "d" * 64),
        ("inputs_sha256", "e" * 64),
    ],
)
def test_wrong_source_or_recipe_never_writes_output(fixture, tmp_path, field, value):
    m, _, _, pin, *_ = fixture
    with pytest.raises(m.Blocked):
        run(fixture, tmp_path / "out", pin=pin._replace(**{field: value}))
    assert not (tmp_path / "out").exists()


def test_dirty_source_and_moving_head_block(fixture, tmp_path, monkeypatch):
    m, _, root, _, _, _, _, git = fixture
    (root / "untracked").write_text("preserved")
    with pytest.raises(m.Blocked, match="source_dirty"):
        run(fixture, tmp_path / "dirty")
    (root / "untracked").unlink()  # Only this test's own fabricated file.
    original = m._stable
    calls = []

    def moved(root, pin):
        calls.append(1)
        if len(calls) == 2:
            git("commit", "--allow-empty", "-m", "head moved")
        return original(root, pin)

    monkeypatch.setattr(m, "_stable", moved)
    with pytest.raises(m.Blocked, match="source_head_moved"):
        run(fixture, tmp_path / "moved")
    assert not (tmp_path / "dirty").exists() and not (tmp_path / "moved").exists()


@pytest.mark.parametrize(
    "state", ["missing", "UNKNOWN", "FROZEN", "bad_continuity", "empty_with_bundle"]
)
def test_unknown_or_incomplete_history_blocks_before_output(fixture, tmp_path, state):
    m, _, _, _, _, history, *_ = fixture
    if state == "missing":
        history = None
    elif state == "bad_continuity":
        history = history._replace(continuity_sha256="UNKNOWN")
    elif state == "empty_with_bundle":
        history = history._replace(bundle_sha256="a" * 64)
    else:
        history = history._replace(state=state)
    with pytest.raises(m.Blocked, match="history_unverified"):
        run(fixture, tmp_path / "out", history=history)
    assert not (tmp_path / "out").exists()


def test_frozen_same_bundle_is_no_replay_and_changed_bundle_is_conflict(
    fixture, tmp_path
):
    m, _, _, _, environment, history, *_ = fixture
    report = run(fixture, tmp_path / "first")
    frozen = history._replace(state="FROZEN", bundle_sha256=report["bundle_sha256"])
    with pytest.raises(m.Blocked, match="already_frozen_no_replay"):
        run(fixture, tmp_path / "same", history=frozen)
    changed = environment._replace(image_digest="sha256:" + "8" * 64)
    with pytest.raises(m.Blocked, match="final_version_conflict"):
        run(
            fixture,
            tmp_path / "changed",
            history=frozen,
            environment=changed,
            observe_tools=lambda: changed,
        )
    assert not (tmp_path / "same").exists() and not (tmp_path / "changed").exists()


@pytest.mark.parametrize("observer", [None, "missing", "wrong"])
def test_absent_or_mismatched_tools_never_become_synthetic_pass(
    fixture, tmp_path, observer
):
    m, *_ = fixture
    callback = (
        None if observer is None else lambda: None if observer == "missing" else "wrong"
    )
    with pytest.raises(m.Blocked, match="toolchain_unverified"):
        run(fixture, tmp_path / "out", observe_tools=callback)
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("kind", ["existing", "symlink", "hardlink"])
def test_output_never_replaces_any_prior_path(fixture, tmp_path, kind):
    m, *_ = fixture
    old = tmp_path / "old"
    old.write_bytes(b"prior release-related bytes")
    out = tmp_path / "out"
    if kind == "existing":
        out.mkdir()
        (out / "old").write_bytes(old.read_bytes())
    elif kind == "symlink":
        out.symlink_to(old)
    else:
        os.link(old, out)
    with pytest.raises(m.Blocked):
        run(fixture, out)
    assert old.read_bytes() == b"prior release-related bytes"
    if kind == "existing":
        assert (out / "old").read_bytes() == old.read_bytes()


def test_partial_output_is_retained_and_never_automatically_retried(
    fixture, tmp_path, monkeypatch
):
    m, *_ = fixture
    original = m.os.fsync
    calls = []

    def fail(fd):
        calls.append(1)
        if len(calls) == 3:
            raise OSError("synthetic uncertain write")
        return original(fd)

    original_writer = m._write_evidence

    def broken_writer(output, files):
        monkeypatch.setattr(m.os, "fsync", fail)
        return original_writer(output, files)

    monkeypatch.setattr(m, "_write_evidence", broken_writer)
    with pytest.raises(m.Blocked):
        run(fixture, tmp_path / "out")
    before = {p.name: p.read_bytes() for p in (tmp_path / "out").iterdir()}
    assert "INTENT.json" in before and "COMPLETED.json" not in before
    monkeypatch.setattr(m.os, "fsync", original)
    monkeypatch.setattr(m, "_write_evidence", original_writer)
    with pytest.raises(m.Blocked):
        run(fixture, tmp_path / "out")
    assert before == {p.name: p.read_bytes() for p in (tmp_path / "out").iterdir()}


def _mutate(m, path, change):
    files, modes = m._files(path.read_bytes()[len(m.MAGIC) :])
    change(files, modes)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for name, data in sorted(files.items()):
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = modes[name]
            member.uid = member.gid = 0
            member.mtime = 1700000000
            tf.addfile(member, io.BytesIO(data))
    path.write_bytes(m.MAGIC + raw.getvalue())


@pytest.mark.parametrize(
    "attack", ["payload", "manifest", "role", "ci", "script", "elf", "conffile", "unit"]
)
def test_integrity_inspection_rejects_tampering(fixture, tmp_path, attack):
    m, b, _, pin, environment, _, inputs, _ = fixture
    out = tmp_path / "out"
    run(fixture, out)
    artifact = out / "agent-platform-worker_0.1.0-8_amd64.pkg13-fixture"

    def change(files, modes):
        doc = "usr/share/doc/agent-platform-worker/"
        if attack == "payload":
            files["usr/bin/agent-platform-worker"] += b"tampered"
        elif attack == "manifest":
            files[doc + "manifest.json"] = b'{"files":[]}'
        elif attack in ("role", "ci"):
            record = json.loads(files[doc + "build.json"])
            record["package" if attack == "role" else "ci_only"] = (
                "agent-platform-control" if attack == "role" else True
            )
            files[doc + "build.json"] = m.encoded(record)
        elif attack == "script":
            files["DEBIAN/postinst"] = b"#!/bin/sh\nexit 99\n"
            modes["DEBIAN/postinst"] = 0o755
        elif attack == "elf":
            files["usr/bin/agent-platform-worker"] = b"\x7fELF synthetic"
        elif attack == "conffile":
            files["DEBIAN/conffiles"] += b"/etc/unreviewed\n"
        else:
            files["usr/lib/systemd/system/ap-worker-publisher.service"] += (
                b"\n[Install]\nWantedBy=multi-user.target\n"
            )

    _mutate(m, artifact, change)
    with pytest.raises(m.Blocked):
        m.inspect_fixture(
            artifact, "worker", pin, environment, inputs, b, baseline=_baseline(m)
        )


@pytest.mark.parametrize(
    "kind", ["renamed_ci", "symlink", "hardlink", "traversal", "tar_link"]
)
def test_alias_or_mislabelled_ci_or_archive_path_is_rejected(fixture, tmp_path, kind):
    m, b, _, pin, environment, _, inputs, _ = fixture
    out = tmp_path / "out"
    run(fixture, out)
    artifact = out / "agent-platform-control_0.1.0-8_amd64.pkg13-fixture"
    if kind == "renamed_ci":
        artifact.write_bytes(b"!<arch>\nFABRICATED_CI_ONLY_DEB")
    elif kind in ("symlink", "hardlink"):
        other = tmp_path / "other"
        artifact.rename(other)
        if kind == "symlink":
            artifact.symlink_to(other)
        else:
            os.link(other, artifact)
    else:
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as tf:
            item = tarfile.TarInfo("../escape" if kind == "traversal" else "alias")
            if kind == "tar_link":
                item.type = tarfile.LNKTYPE
                item.linkname = "/private/SECRET"
            else:
                item.size = 1
            tf.addfile(item, io.BytesIO(b"x"))
        artifact.write_bytes(m.MAGIC + raw.getvalue())
    with pytest.raises((m.Blocked, OSError)):
        m.inspect_fixture(
            artifact, "control", pin, environment, inputs, b, baseline=_baseline(m)
        )
    assert not (tmp_path / "escape").exists()


def test_final_shared_stager_cannot_use_real_debian_writer(fixture, tmp_path):
    _, b, root, pin, _, _, _, _ = fixture
    with pytest.raises(ValueError, match="final_generation_unavailable"):
        b._stage_archives(
            root,
            tmp_path / "out",
            8,
            pin.commit,
            pin.epoch,
            source_tree=pin.tree,
            version="0.1.0-8",
            kind="final-unreleased",
            ci_only=False,
            controls={},
            archive_writer=b._write_deb,
        )
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize(
    "kind",
    ["missing", "UNKNOWN", "changed_archive", "changed_recipe", "observer_missing"],
)
def test_historical_unknown_or_changed_artifact_never_becomes_evidence(
    fixture, tmp_path, kind
):
    m, *_ = fixture
    baseline = _baseline(m)
    if kind == "missing":
        baseline = None
    elif kind == "UNKNOWN":
        baseline = baseline._replace(worker_manifest_sha256="UNKNOWN")
    changes = dict(baseline=baseline, observe_baseline=lambda: _baseline(m))
    if kind == "changed_archive":
        changes["observe_baseline"] = lambda: _baseline(m)._replace(
            worker_archive_sha256="1" * 64
        )
    elif kind == "changed_recipe":
        changes["observe_baseline"] = lambda: _baseline(m)._replace(
            recipe_sha256="1" * 64
        )
    elif kind == "observer_missing":
        changes["observe_baseline"] = None
    with pytest.raises(m.Blocked, match="historical_baseline_unverified"):
        run(fixture, tmp_path / "out", **changes)
    assert not (tmp_path / "out").exists()


def test_rebuild_byte_drift_blocks_before_any_caller_output(
    fixture, tmp_path, monkeypatch
):
    m, *_ = fixture
    writer = m._fixture_writer
    calls = []

    def drift(stage, artifact, epoch):
        writer(stage, artifact, epoch)
        calls.append(1)
        if len(calls) == 3:
            artifact.write_bytes(artifact.read_bytes() + b"SYNTHETIC_DRIFT")

    monkeypatch.setattr(m, "_fixture_writer", drift)
    with pytest.raises(m.Blocked, match="rebuild_mismatch"):
        run(fixture, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_fabricated_export_never_executes_its_recipe(fixture, tmp_path):
    m, _, root, pin, _, _, _, git = fixture
    malicious = b"raise RuntimeError('untrusted export must not execute')\n"
    (root / "packaging/build_deb.py").write_bytes(malicious)
    git("add", "--", "packaging/build_deb.py")
    git("commit", "-m", "fabricated recipe")
    hashes = {
        name: m.sha(path.read_bytes())
        for path in root.rglob("*")
        if path.is_file() and ".git" not in path.parts
        for name in [str(path.relative_to(root))]
    }
    changed = pin._replace(
        commit=git("rev-parse", "HEAD"),
        tree=git("rev-parse", "HEAD^{tree}"),
        builder_sha256=m.sha(malicious),
        inputs_sha256=m.sha(m.encoded(hashes)),
    )
    with pytest.raises(m.Blocked, match="observer_recipe_mismatch"):
        run(fixture, tmp_path / "out", pin=changed)
    assert not (tmp_path / "out").exists()


def test_archive_bytes_must_match_observed_git_blob_objects(
    fixture, tmp_path, monkeypatch
):
    m, *_ = fixture
    original = m._git

    def forged(root, *args):
        raw = original(root, *args)
        if args[0] != "archive":
            return raw
        files, modes = m._files(raw)
        files["LICENSE"] += b"forged blob"
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as tf:
            for name, data in files.items():
                item = tarfile.TarInfo(name)
                item.size = len(data)
                item.mode = modes[name]
                tf.addfile(item, io.BytesIO(data))
        return stream.getvalue()

    monkeypatch.setattr(m, "_git", forged)
    with pytest.raises(m.Blocked, match="source_blob_mismatch"):
        run(fixture, tmp_path / "out")
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("case", ["source_alias", "output_parent_alias", "traversal"])
def test_source_and_output_ancestors_do_not_follow_aliases(fixture, tmp_path, case):
    m, _, root, pin, environment, history, *_ = fixture
    alias = tmp_path / "alias"
    alias.symlink_to(
        root if case == "source_alias" else tmp_path, target_is_directory=True
    )
    if case == "source_alias":
        with pytest.raises(m.Blocked):
            m.rehearse(
                alias,
                tmp_path / "out",
                pin=pin,
                environment=environment,
                history=history,
                observe_tools=lambda: environment,
                baseline=_baseline(m),
                observe_baseline=lambda: _baseline(m),
            )
    else:
        target = (
            alias / "out"
            if case == "output_parent_alias"
            else tmp_path / "nested/../out"
        )
        with pytest.raises(m.Blocked):
            run(fixture, target)
    assert not (tmp_path / "out").exists()


def test_frozen_identity_rejects_new_commit_with_same_tree(fixture, tmp_path):
    m, _, _, pin, _, history, _, git = fixture
    report = run(fixture, tmp_path / "first")
    git("commit", "--allow-empty", "-m", "different commit same tree")
    changed = pin._replace(commit=git("rev-parse", "HEAD"))
    assert git("rev-parse", "HEAD^{tree}") == pin.tree
    with pytest.raises(m.Blocked, match="final_version_conflict"):
        run(
            fixture,
            tmp_path / "changed",
            pin=changed,
            history=history._replace(
                state="FROZEN", bundle_sha256=report["bundle_sha256"]
            ),
        )
    assert not (tmp_path / "changed").exists()


def test_normal_final_flag_is_unchanged_and_not_an_escape_hatch(tmp_path):
    output = tmp_path / "out"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "packaging/build_deb.py"),
            "--source-commit",
            "c27d0ef9bb1a07f56bbaa1fce9811827636c054f",
            "--final-version",
            "--output",
            str(output),
        ],
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 2 and not output.exists()


@pytest.mark.parametrize("ci", [False, True])
def test_shared_staging_preserves_historical_bytes_except_pub03(fixture, tmp_path, ci):
    import hashlib
    from types import ModuleType

    _, current, source, *_ = fixture
    result = subprocess.run(
        [
            "git",
            "--no-replace-objects",
            "show",
            "c27d0ef9bb1a07f56bbaa1fce9811827636c054f:packaging/build_deb.py",
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=15,
    )
    if result.returncode:
        pytest.skip("pinned parent recipe object unavailable; no fetch in tests")
    data = result.stdout
    assert (
        hashlib.sha256(data).hexdigest()
        == "640f816f08d0fd4c645a73d6eabfca229d7251071314f8afb0011584de0dfda1"
    )
    parent = ModuleType("pkg13_pinned_parent_builder")
    parent.__file__ = str(ROOT / "packaging/build_deb.py")
    exec(compile(data, parent.__file__, "exec"), parent.__dict__)
    options = dict(source_tree="b" * 40, candidate=not ci, ci_final_fixture=ci)
    historical = tmp_path / "historical"
    shutil.copytree(source, historical, ignore=shutil.ignore_patterns(".git"))
    for module in (
        "worker_publish_operator",
        "worker_publish_reconciliation",
        "worker_publish_case",
        "worker_publish_observer",
        "worker_publish_generation",
        "worker_publish_pre_spend",
        "worker_publish_recovery_paths",
    ):
        (historical / f"src/agent_platform/{module}.py").unlink()
    before = parent.build(
        historical, tmp_path / "before", 8, "a" * 40, 1700000000, **options
    )
    after = current.build(
        source, tmp_path / "after", 8, "a" * 40, 1700000000, **options
    )
    assert before["control"].read_bytes() == after["control"].read_bytes()
    control = "agent-platform-control.provenance.json"
    assert (tmp_path / "before" / control).read_bytes() == (
        tmp_path / "after" / control
    ).read_bytes()

    def files(path):
        raw = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", path], timeout=10)
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            return {
                item.name.removeprefix("./"): (
                    item.mode,
                    archive.extractfile(item).read(),
                )
                for item in archive
                if item.isfile()
            }

    old, new = files(before["worker"]), files(after["worker"])
    doc = "usr/share/doc/agent-platform-worker/"
    assert set(new) - set(old) == {
        "usr/libexec/ap-worker-publisher-operator",
        "usr/lib/ap-worker-publisher/agent_platform/worker_publish_operator.py",
        "usr/lib/ap-worker-publisher/agent_platform/worker_publish_reconciliation.py",
        "usr/lib/ap-worker-publisher/agent_platform/worker_publish_case.py",
        "usr/lib/ap-worker-publisher/agent_platform/worker_publish_observer.py",
        doc + "worker01-homelab-publisher.md",
        "usr/lib/ap-worker-publisher/agent_platform/worker_publish_recovery_paths.py",
        "usr/libexec/ap-worker-publisher-recovery",
        "usr/libexec/ap-worker-publisher-recovery-signer",
        "usr/lib/systemd/system/ap-worker-publisher-recovery.service",
        "usr/lib/systemd/system/ap-worker-publisher-recovery-signer.service",
        "etc/apparmor.d/ap-worker-publisher-recovery",
        "etc/apparmor.d/ap-worker-publisher-recovery-signer",
    }
    assert not set(old) - set(new)
    assert {name for name in old if old[name] != new[name]} == {
        doc + "build.json",
        doc + "manifest.json",
    }
    assert new["usr/libexec/ap-worker-publisher-operator"][0] == 0o755


def test_unmarked_source_is_never_a_rehearsal_or_real_generation(fixture, tmp_path):
    m, _, root, pin, _, _, _, git = fixture
    (root / "PKG13_SYNTHETIC_SOURCE").unlink()
    git("add", "--", "PKG13_SYNTHETIC_SOURCE")
    git("commit", "-m", "remove synthetic marker")
    changed = pin._replace(
        commit=git("rev-parse", "HEAD"), tree=git("rev-parse", "HEAD^{tree}")
    )
    with pytest.raises(m.Blocked, match="synthetic_source_required"):
        run(fixture, tmp_path / "out", pin=changed)
    assert not (tmp_path / "out").exists()


def test_external_provenance_cannot_disagree_with_embedded_records(
    fixture, tmp_path, monkeypatch
):
    m, *_ = fixture
    original = m._builder

    def changed(pin):
        builder = original(pin)
        stage = builder._stage_archives

        def corrupt(*args, **kwargs):
            result = stage(*args, **kwargs)
            for role, artifact in result.items():
                path = artifact.parent / ("agent-platform-" + role + ".provenance.json")
                record = json.loads(path.read_text())
                record["source_tree"] = "0" * 40
                path.write_bytes(builder.encoded(record))
            return result

        builder._stage_archives = corrupt
        return builder

    monkeypatch.setattr(m, "_builder", changed)
    with pytest.raises(m.Blocked, match="external_provenance_mismatch"):
        run(fixture, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_real_synthetic_debian_archives(fixture, tmp_path):
    m, b, source, pin, environment, history, inputs, _ = fixture
    encoder_path = ROOT / "packaging/debian_fixture_encoder.py"
    encoder = load("packaging/debian_fixture_encoder.py")
    options = dict(
        encoder_sha256=m.sha(encoder_path.read_bytes()),
        pin=pin,
        environment=environment,
        history=history,
        observe_tools=lambda: environment,
        baseline=_baseline(m),
        observe_baseline=lambda: _baseline(m),
    )
    first, second = tmp_path / "deb-first", tmp_path / "deb-second"
    for directory in (first, second):
        directory.mkdir(mode=0o700)
    result = m.rehearse_debian(source, first, **options)
    assert not result["final_generation_allowed"]
    assert result == m.rehearse_debian(source, second, **options)
    for role in m.ROLES:
        name = f"ap-pkg162-fixture-{role}_{encoder.VERSION}_amd64.deb"
        archive = first / "encoded" / name
        assert archive.read_bytes() == (second / "encoded" / name).read_bytes()
        info = subprocess.check_output(["dpkg-deb", "--info", archive], timeout=10)
        listing = subprocess.check_output(
            ["dpkg-deb", "--contents", archive], timeout=10
        )
        assert f"Package: ap-pkg162-fixture-{role}".encode() in info
        assert f"/agent-platform-{role}/build.json".encode() in listing
        assert b"Version: 0.0.0-162" in info
        assert b"Architecture: amd64" in info
        assert b"Depends:" in info
        staged = (
            first / "staged" / f"agent-platform-{role}_{m.VERSION}_amd64.pkg13-fixture"
        )
        m.inspect_fixture(
            staged, role, pin, environment, inputs, b, baseline=_baseline(m)
        )
        files, modes = m._files(staged.read_bytes()[len(m.MAGIC) :], pin.epoch)
        expected = encoder.expected_members(files, role)
        raw = archive.read_bytes()
        with pytest.raises((ValueError, OSError, EOFError)):
            encoder.verify(raw[:-10], expected, modes, pin.epoch)
        for path, replacement in (
            ("DEBIAN/control", b"Package: wrong-role\n"),
            (
                f"usr/share/doc/agent-platform-{role}/build.json",
                b'{"ci_only":false,"release_authorized":true}',
            ),
        ):
            corrupt = encoder.encode(expected | {path: replacement}, modes, pin.epoch)
            with pytest.raises(ValueError, match="invalid_debian_payload"):
                encoder.verify(corrupt, expected, modes, pin.epoch)
        extra = encoder.encode(
            expected | {"extra": b"x"}, modes | {"extra": 0o644}, pin.epoch
        )
        with pytest.raises(ValueError, match="invalid_debian_payload"):
            encoder.verify(extra, expected, modes, pin.epoch)
    assert set(result["archives"]) == {
        p.name for p in (first / "encoded").glob("*.deb")
    }
    with pytest.raises(m.Blocked, match="scratch_not_empty"):
        m.rehearse_debian(source, first, **options)
    refused = tmp_path / "bad-encoder"
    refused.mkdir(mode=0o700)
    with pytest.raises(m.Blocked, match="encoder_pin_mismatch"):
        m.rehearse_debian(source, refused, **(options | {"encoder_sha256": "0" * 64}))
    assert not list(refused.iterdir())
    for override, reason in (
        (
            {"observe_tools": lambda: environment._replace(xz="0.0")},
            "toolchain_unverified",
        ),
        ({"observe_baseline": lambda: None}, "historical_baseline_unverified"),
        ({"history": history._replace(state="UNKNOWN")}, "history_unverified"),
        ({"pin": pin._replace(tree="0" * 40)}, "source_tree_mismatch"),
    ):
        with pytest.raises(m.Blocked, match=reason):
            m.rehearse_debian(source, refused, **(options | override))
        assert not list(refused.iterdir())
    alias = tmp_path / "deb-alias"
    alias.symlink_to(refused, target_is_directory=True)
    with pytest.raises(m.Blocked):
        m.rehearse_debian(source, alias, **options)
    assert not list(refused.iterdir())


def test_debian_ambiguous_write_preserves_intent_and_denies_retry(
    fixture, tmp_path, monkeypatch
):
    m, _, source, pin, environment, history, _, _ = fixture
    scratch = tmp_path / "interrupted-deb"
    scratch.mkdir(mode=0o700)
    options = dict(
        encoder_sha256=m.sha(
            (ROOT / "packaging/debian_fixture_encoder.py").read_bytes()
        ),
        pin=pin,
        environment=environment,
        history=history,
        observe_tools=lambda: environment,
        baseline=_baseline(m),
        observe_baseline=lambda: _baseline(m),
    )
    original = m._write_evidence

    def interrupted(path, files, **kwargs):
        if path.name != "encoded":
            return original(path, files, **kwargs)
        fsync = m.os.fsync

        def fail_after_archive(fd):
            if list(path.glob("*.deb")):
                raise OSError("synthetic write uncertainty")
            fsync(fd)

        with monkeypatch.context() as patch:
            patch.setattr(m.os, "fsync", fail_after_archive)
            return original(path, files, **kwargs)

    monkeypatch.setattr(m, "_write_evidence", interrupted)
    with pytest.raises(m.Blocked, match="debian_rehearsal_unverified"):
        m.rehearse_debian(source, scratch, **options)
    output = scratch / "encoded"
    assert json.loads((output / "INTENT.json").read_bytes())["state"] == "UNKNOWN"
    assert list(output.glob("*.deb"))
    assert not (output / "COMPLETED.json").exists()
    before = {path.name: path.read_bytes() for path in output.iterdir()}
    with pytest.raises(m.Blocked, match="scratch_not_empty"):
        m.rehearse_debian(source, scratch, **options)
    assert {path.name: path.read_bytes() for path in output.iterdir()} == before
