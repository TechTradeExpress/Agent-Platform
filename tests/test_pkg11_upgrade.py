"""PKG-11: actual archives and offline failure gates, never host installation."""

import importlib.util
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
OLD = "0fbc940ae94144f8cc29c9a0fd98afc704f58168"


def load(path):
    spec = importlib.util.spec_from_file_location("pkg11_test", ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("candidate", [False, True])
def test_current_recipe_never_emits_historical_7(tmp_path, candidate):
    builder = load("packaging/build_deb.py")
    assert builder.HISTORICAL_SOURCES == {7: OLD}
    with pytest.raises(
        ValueError, match="historical_revision_requires_original_recipe"
    ):
        builder.build(
            ROOT,
            tmp_path / "out",
            7,
            OLD,
            1794855509,
            source_tree="a" * 40,
            candidate=candidate,
        )
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("candidate,fixture", [(False, False), (True, True)])
def test_8_requires_either_candidate_or_explicit_ci_fixture(
    tmp_path, candidate, fixture
):
    builder = load("packaging/build_deb.py")
    with pytest.raises(ValueError, match="exact_current_version_requires_ci_fixture"):
        builder.build(
            ROOT,
            tmp_path / "out",
            8,
            "a" * 40,
            1700000000,
            source_tree="b" * 40,
            candidate=candidate,
            ci_final_fixture=fixture,
        )
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize(
    "flags",
    [
        ["--revision", "7"],
        ["--revision", "7", "--synthetic-fixture"],
        ["--revision", "7", "--ci-final-fixture"],
        ["--final-version"],
        ["--revision", "6", "--ci-final-fixture", "--synthetic-fixture"],
        ["--synthetic-fixture"],
    ],
)
def test_cli_refuses_historical_retag_and_release_mode_before_writes(tmp_path, flags):
    output = tmp_path / "out"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "packaging/build_deb.py"),
            "--source-commit",
            OLD,
            "--output",
            str(output),
            *flags,
        ],
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 2 and not output.exists()


@pytest.fixture(scope="module")
def historical(tmp_path_factory):
    # Archive identity needs the original gzip/dpkg/xz toolchain. Generic source
    # CI Python 3.12 is not the Debian 13 build environment; do not re-pin hashes.
    version = subprocess.check_output(
        ["/usr/bin/python3", "-c", "import sys; print(sys.version.split()[0])"],
        text=True,
        timeout=10,
    ).strip()
    dpkg = subprocess.check_output(["dpkg-deb", "--version"], text=True, timeout=10)
    xz = subprocess.check_output(["xz", "--version"], text=True, timeout=10)
    if version != "3.13.5" or "1.22.22" not in dpkg or "5.8.1" not in xz:
        pytest.skip("historical byte-identity needs original Debian 13 toolchain")
    module = load("packaging/debian/build_pkg11_baseline.py")
    output = tmp_path_factory.mktemp("pkg11-history")
    for folder in ("one", "two"):
        subprocess.run(
            [
                "/usr/bin/python3",
                str(ROOT / "packaging/debian/build_pkg11_baseline.py"),
                "--output",
                str(output / folder),
            ],
            check=True,
            capture_output=True,
            timeout=60,
        )
    return module, output


@pytest.fixture
def expected_record():
    module = load("packaging/debian/build_pkg11_baseline.py")
    pin = module.load_pin()
    # Fabricated record for negative checks only, never a successful attestation.
    record = {
        "schema": 2,
        "package": "agent-platform-worker",
        "source_commit": pin["source_commit"],
        "source_tree": pin["source_tree"],
        "source_date_epoch": pin["source_date_epoch"],
        "debian_version": pin["version"],
        "build_kind": "final-version-unreleased",
        "manifest_sha256": pin["roles"]["worker"]["manifest_sha256"],
        "sha256": pin["roles"]["worker"]["archive_sha256"],
    }
    return module, pin, record


def test_original_7_reproducible_and_matches_reported_hashes_not_live_install(
    historical,
):
    module, output = historical
    pin = module.load_pin()
    verification = json.loads((output / "one/baseline-verification.json").read_text())
    assert pin["source_commit"] == OLD
    assert verification["result"] == "RECONSTRUCTED_MATCHES_REPORTED_HASHES"
    assert verification["installed_artifact_verified"] is False
    assert verification["original_archive_access"] == "NOT_RUN"
    for role in ("control", "worker"):
        name = "agent-platform-" + role + "_0.1.0-7_amd64.deb"
        one, two = (output / folder / name for folder in ("one", "two"))
        assert one.read_bytes() == two.read_bytes()
        assert module.sha(one.read_bytes()) == pin["roles"][role]["archive_sha256"]
        record = json.loads(
            (
                output / "one" / ("agent-platform-" + role + ".provenance.json")
            ).read_text()
        )
        module.verify_archive(one, record, pin, role)
        assert record["inputs"]["packaging/build_deb.py"] == pin["recipe_sha256"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_commit", "a" * 40),
        ("source_tree", "a" * 40),
        ("source_date_epoch", 1),
        ("debian_version", "0.1.0-8"),
        ("manifest_sha256", "0" * 64),
        ("sha256", "0" * 64),
        ("build_kind", "candidate"),
        ("package", "agent-platform-control"),
    ],
)
def test_historical_record_drift_blocks(expected_record, tmp_path, field, value):
    module, pin, record = expected_record
    with pytest.raises(ValueError, match="historical_provenance_mismatch_STOP"):
        module.verify_archive(
            tmp_path / "absent.deb", record | {field: value}, pin, "worker"
        )


def test_historical_archive_corruption_blocks_without_removal(
    expected_record, tmp_path
):
    module, pin, record = expected_record
    archive = tmp_path / "corrupt.deb"
    archive.write_bytes(b"not a historical archive")
    with pytest.raises(ValueError, match="historical_provenance_mismatch_STOP"):
        module.verify_archive(archive, record, pin, "worker")
    assert archive.read_bytes() == b"not a historical archive"


def test_pin_drift_never_reaches_git_or_original_code(tmp_path, monkeypatch):
    module = load("packaging/debian/build_pkg11_baseline.py")
    pin = tmp_path / "pin.json"
    pin.write_text('{"source_commit":"untrusted"}')
    monkeypatch.setattr(module, "PIN", pin)
    monkeypatch.setattr(module, "git", lambda *args: pytest.fail("must not reach Git"))
    with pytest.raises(ValueError, match="historical_pin_mismatch_STOP"):
        module.build(tmp_path / "out")
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("part", ["tree", "epoch", "recipe", "missing_object"])
def test_missing_or_wrong_original_source_never_executes(tmp_path, monkeypatch, part):
    module = load("packaging/debian/build_pkg11_baseline.py")
    pin = module.load_pin()
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        member = tarfile.TarInfo("packaging/build_deb.py")
        data = b"raise RuntimeError('unreviewed code must not execute')\n"
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))

    def git(*args):
        if part == "missing_object":
            raise subprocess.CalledProcessError(128, ["git"])
        if args[0] == "archive":
            return stream.getvalue()
        if args[0] == "rev-parse":
            return ("a" * 40 if part == "tree" else pin["source_tree"]).encode()
        return str(1 if part == "epoch" else pin["source_date_epoch"]).encode()

    monkeypatch.setattr(module, "git", git)
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        module.build(tmp_path / "out")
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize(
    "version,kind,ci,release,tree,accepted",
    [
        ("0.1.0-8~git" + "a" * 40, "candidate", False, False, "b" * 40, True),
        ("0.1.0-8", "ci-final-fixture", True, False, "b" * 40, True),
        ("0.1.0-8", "final-version-unreleased", False, False, "b" * 40, False),
        ("0.1.0-8", "ci-final-fixture", False, False, "b" * 40, False),
        ("0.1.0-8~git" + "c" * 40, "candidate", False, False, "b" * 40, False),
        ("0.1.0-8~git" + "a" * 40, "candidate", False, True, "b" * 40, False),
        ("0.1.0-8", "ci-final-fixture", True, False, "bad", False),
        ("0.1.0-7", "final-version-unreleased", None, None, "b" * 40, True),
        ("0.1.0-7~git" + "a" * 40, "candidate", None, None, "b" * 40, True),
    ],
)
def test_doctor_preserves_7_and_binds_8_before_host_reads(
    monkeypatch,
    version,
    kind,
    ci,
    release,
    tree,
    accepted,
):
    module = load("packaging/worker-provisioning/worker_doctor.py")
    record = {
        "schema": 2,
        "package": "agent-platform-worker",
        "phase": "P1_INSTALL_INERT",
        "source_commit": "a" * 40,
        "source_tree": tree,
        "debian_version": version,
        "build_kind": kind,
        "ci_only": ci,
        "release_authorized": release,
    }
    monkeypatch.setattr(module, "read", lambda path: json.dumps(record).encode())

    class VersionAccepted(Exception):
        pass

    def query(*args):
        raise VersionAccepted

    monkeypatch.setattr(module, "query", query)
    with pytest.raises(VersionAccepted if accepted else module.Blocked):
        module.Observer().package()


def test_ci_current_source_cannot_generate_7_and_both_cases_are_required():
    workflow = (ROOT / ".github/workflows/debian-package.yml").read_text()
    assert "--final-version" not in workflow
    assert "--revision 7" not in workflow
    assert "build_pkg11_baseline.py --output /packages/historical-7" in workflow
    assert "0.1.0-8~git${source_sha}" in workflow
    assert "--ci-final-fixture --output /packages/pkg11-upgrade-test" in workflow
    part = workflow.split("      - name: PKG-11 real historical", 1)[1].split(
        "      - name:", 1
    )[0]
    assert "for journal_case in empty unknown" in part
    assert "if ! docker run" in part and 'test "$upgrade_failed" -eq 0' in part
    assert "pkg11-upgrade-$journal_case.json" in part
    assert "--network none" in part and "--privileged" not in workflow
    quality = (ROOT / "packaging/debian/quality.sh").read_text()
    assert "pkg11-lintian" in quality and "pkg11-autopkgtest" in quality
    assert "install /packages/historical-7" not in quality
    assert (
        "/packages/historical-7/*.deb > /evidence/historical-7-lintian.txt" in quality
    )


def test_upgrade_fixture_guards_before_commands_and_records_proof_limits(monkeypatch):
    module = load("packaging/debian/worker_upgrade_lifecycle.py")
    monkeypatch.setattr(module.os, "getuid", lambda: 2000)
    monkeypatch.setattr(
        module, "call", lambda *args, **kwargs: pytest.fail("host command")
    )
    with pytest.raises(AssertionError):
        module.main()
    code = (ROOT / "packaging/debian/worker_upgrade_lifecycle.py").read_text()
    assert '"effective_systemd_apparmor_bpf": "NOT_RUN"' in code
    assert '"installed_host_verified": False' in code
    assert '"claude"' in code and '"codex"' in code


def test_public_cli_exports_clean_exact_source_and_binds_real_git_identity(tmp_path):
    import os
    import shutil

    source = tmp_path / "source"
    source.mkdir()
    for directory in ("packaging", "debian", "docs", "src", "provisioning"):
        shutil.copytree(
            ROOT / directory,
            source / directory,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    for name in ("pyproject.toml", "uv.lock", "LICENSE"):
        shutil.copyfile(ROOT / name, source / name)
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
                ["git", "-c", "core.hooksPath=/dev/null", *args],
                cwd=source,
                env=env,
                stderr=subprocess.DEVNULL,
                timeout=15,
            )
            .decode()
            .strip()
        )

    git("init")
    git(
        "add",
        "--",
        "packaging",
        "provisioning",
        "debian",
        "docs",
        "src",
        "pyproject.toml",
        "uv.lock",
        "LICENSE",
    )
    git("-c", "commit.gpgsign=false", "commit", "-m", "synthetic source")
    commit, tree = git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")

    def build(commit, output, *flags):
        return subprocess.run(
            [
                sys.executable,
                str(source / "packaging/build_deb.py"),
                "--source-commit",
                commit,
                "--output",
                str(output),
                *flags,
            ],
            cwd=source,
            env=env,
            capture_output=True,
            timeout=60,
        )

    one, again, fixture = (tmp_path / name for name in ("one", "again", "ci"))
    assert build(commit, one).returncode == 0
    assert build(commit, again).returncode == 0
    assert build(commit, fixture, "--ci-final-fixture").returncode == 0
    for role in ("control", "worker"):
        name = "agent-platform-" + role
        candidate = name + "_0.1.0-8~git" + commit + "_amd64.deb"
        assert (one / candidate).read_bytes() == (again / candidate).read_bytes()
        record = json.loads((one / (name + ".provenance.json")).read_text())
        assert (
            record["source_commit"],
            record["source_tree"],
            record["source_date_epoch"],
        ) == (commit, tree, 1700000000)
        final = json.loads((fixture / (name + ".provenance.json")).read_text())
        assert final["build_kind"] == "ci-final-fixture"
        assert final["ci_only"] is True and final["release_authorized"] is False
        assert "CI_ONLY" in final["status"]
    # Different actual commit, same tree: candidates still have distinct versions.
    git(
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--allow-empty",
        "-m",
        "different source identity",
    )
    other = git("rev-parse", "HEAD")
    assert other != commit and git("rev-parse", "HEAD^{tree}") == tree
    second = tmp_path / "different-commit"
    assert build(other, second).returncode == 0
    assert set(p.name for p in second.glob("*.deb")) != set(
        p.name for p in one.glob("*.deb")
    )
    dirty = source / "untracked"
    dirty.write_text("must be preserved")
    rejected = tmp_path / "dirty-build"
    assert build(other, rejected).returncode == 2
    assert not rejected.exists() and dirty.read_text() == "must be preserved"
