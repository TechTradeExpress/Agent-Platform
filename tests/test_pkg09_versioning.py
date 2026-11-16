"""Version/provenance safety, real archives, no package installation or network."""

import gzip
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def files(path):
    raw = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(path)])
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        return {
            p.name.removeprefix("./"): archive.extractfile(p).read()
            for p in archive
            if p.isfile()
        }


@pytest.fixture(scope="module")
def candidates(tmp_path_factory):
    b = load("pkg09_builder", "packaging/build_deb.py")
    root = tmp_path_factory.mktemp("pkg09")
    params = dict(source_tree="b" * 40, candidate=True)
    one = b.build(ROOT, root / "one", 7, "a" * 40, 1700000000, **params)
    again = b.build(ROOT, root / "again", 7, "a" * 40, 1700000000, **params)
    other = b.build(ROOT, root / "other", 7, "c" * 40, 1700000000, **params)
    final = b.build(ROOT, root / "final", 7, "a" * 40, 1700000000, source_tree="b" * 40)
    return one, again, other, final


def test_unique_candidate_identity_ordering_repeatability_and_two_roles(candidates):
    one, again, other, final = candidates
    assert set(one) == {"control", "worker"}
    for role in one:
        assert one[role].read_bytes() == again[role].read_bytes()
        assert one[role].name != other[role].name
        version = "0.1.0-7~git" + "a" * 40
        assert (
            subprocess.check_output(
                ["dpkg-deb", "-f", str(one[role]), "Version"], text=True
            ).strip()
            == version
        )
        assert (
            subprocess.check_output(
                ["dpkg-deb", "-f", str(final[role]), "Version"], text=True
            ).strip()
            == "0.1.0-7"
        )
        for low, high in [("0.1.0-6", version), (version, "0.1.0-7")]:
            assert (
                subprocess.run(
                    ["dpkg", "--compare-versions", low, "lt", high]
                ).returncode
                == 0
            )
        payload = files(one[role])
        doc = "usr/share/doc/agent-platform-" + role + "/"
        record = json.loads(payload[doc + "build.json"])
        assert record["source_commit"] == "a" * 40 and record["source_tree"] == "b" * 40
        assert (
            record["build_kind"] == "candidate" and "NOT_RELEASED" in record["status"]
        )
        assert gzip.decompress(payload[doc + "changelog.Debian.gz"]).startswith(
            ("agent-platform (" + version + ")").encode()
        )
        assert not any(p.endswith(("/codex", "/claude")) for p in payload)
        assert not any(data.startswith(b"\x7fELF") for data in payload.values())


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["--source-commit", "HEAD"],
        ["--source-commit", "a" * 40, "--revision", "6"],
        ["--source-commit", "a" * 40, "--synthetic-fixture"],
        [
            "--source-commit",
            "a" * 40,
            "--revision",
            "6",
            "--synthetic-fixture",
            "--final-version",
        ],
    ],
)
def test_public_cli_refuses_ambiguous_or_colliding_inputs_before_writes(tmp_path, args):
    output = tmp_path / "out"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "packaging/build_deb.py"),
            "--output",
            str(output),
            *args,
        ],
        capture_output=True,
    )
    assert result.returncode == 2 and not output.exists()


def test_new_revision_requires_tree_before_writes(tmp_path):
    b = load("pkg09_missing_tree", "packaging/build_deb.py")
    with pytest.raises(ValueError, match="source_tree_required"):
        b.build(ROOT, tmp_path / "out", 7, "a" * 40, 1700000000)
    assert not (tmp_path / "out").exists()


def test_historical_fixture_is_pinned_to_original_recipe_and_installed_manifest():
    pin = json.loads((ROOT / "packaging/debian/worker-baseline.json").read_text())
    assert pin["source_commit"] == "938c5543757c4184635e08330115527f0108064a"
    assert pin["version"] == "0.1.0-6"
    assert (
        pin["worker_manifest_sha256"]
        == "80519eb56b98c4a5cd1ff222676dea2639c691f08fc318254d68b891d35152fa"
    )
    code = (ROOT / "packaging/debian/build_worker_baseline.py").read_text()
    assert "original.build(source, output, 6, commit" in code
    assert 'source / "packaging/build_deb.py"' in code
    assert (
        "historical_recipe_mismatch" in code
        and "historical_manifest_mismatch_STOP" in code
    )


def test_wrong_historical_source_is_refused_before_git_or_execution(
    tmp_path, monkeypatch
):
    m = load("pkg09_baseline", "packaging/debian/build_worker_baseline.py")
    pin = json.loads(m.PIN.read_text())
    pin["source_commit"] = "a" * 40
    path = tmp_path / "pin.json"
    path.write_text(json.dumps(pin))
    monkeypatch.setattr(m, "PIN", path)
    monkeypatch.setattr(m, "git", lambda *args: pytest.fail("untrusted Git read"))
    with pytest.raises(ValueError, match="historical_source_mismatch"):
        m.build(tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_doctor_accepts_only_bound_new_version_records(
    candidates, tmp_path, monkeypatch
):
    d = load("pkg09_doctor", "packaging/worker-provisioning/worker_doctor.py")
    raw = files(candidates[0]["worker"])[
        "usr/share/doc/agent-platform-worker/build.json"
    ]
    record = json.loads(raw)

    # Stop immediately after version validation; no host files, processes or data.
    class ReachedVersion(Exception):
        pass

    for change, accepted in [
        ({}, True),
        ({"source_tree": "bad"}, False),
        ({"debian_version": "0.1.0-6~git" + "a" * 40}, False),
        ({"source_commit": "c" * 40}, False),
        ({"build_kind": "final-version-unreleased"}, False),
    ]:
        changed = record | change
        monkeypatch.setattr(
            d,
            "read",
            lambda path, *args, changed=changed, **kwargs: json.dumps(
                changed if path.endswith("build.json") else {}
            ).encode(),
        )
        monkeypatch.setattr(
            d, "query", lambda *args: (_ for _ in ()).throw(ReachedVersion())
        )
        with pytest.raises(ReachedVersion if accepted else d.Blocked):
            d.Observer().package()


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", 1),
        ("phase", "P0"),
        ("source_commit", "c" * 40),
        ("source_date_epoch", 0),
        ("debian_version", "0.1.0-7"),
        ("manifest_sha256", "0" * 64),
    ],
)
def test_historical_identity_or_manifest_mismatch_is_stop(field, value):
    m = load("pkg09_verify_baseline", "packaging/debian/build_worker_baseline.py")
    pin = json.loads(m.PIN.read_text())
    record = {
        "schema": 2,
        "phase": "P1_INSTALL_INERT",
        "source_commit": pin["source_commit"],
        "source_date_epoch": pin["source_date_epoch"],
        "debian_version": pin["version"],
        "manifest_sha256": pin["worker_manifest_sha256"],
    }
    m.verify_record(record, pin)
    with pytest.raises(ValueError, match="historical_manifest_mismatch_STOP"):
        m.verify_record(record | {field: value}, pin)


def test_wrong_historical_recipe_never_executes(tmp_path, monkeypatch):
    m = load("pkg09_bad_recipe", "packaging/debian/build_worker_baseline.py")
    pin = json.loads(m.PIN.read_text())
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        info = tarfile.TarInfo("packaging/build_deb.py")
        data = b"raise RuntimeError('must not execute')\n"
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))

    def git(*args):
        if args[0] == "archive":
            return stream.getvalue()
        return (
            pin["source_tree"]
            if args[0] == "rev-parse"
            else str(pin["source_date_epoch"])
        ).encode()

    monkeypatch.setattr(m, "git", git)
    with pytest.raises(ValueError, match="historical_recipe_mismatch"):
        m.build(tmp_path / "out")
    assert not (tmp_path / "out").exists()
