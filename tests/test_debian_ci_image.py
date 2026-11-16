"""Offline pin-evidence and unchanged metadata policy; no image execution here."""

import importlib.util
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "docs/evidence/pkg05-debian-image-selection.json"


def load_doctor():
    spec = importlib.util.spec_from_file_location(
        "image_policy", ROOT / "packaging/worker-provisioning/worker_doctor.py"
    )
    doctor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(doctor)
    return doctor


def test_selected_pin_matches_reviewed_oci_and_identical_package_versions():
    data = json.loads(EVIDENCE.read_text())
    pins = json.loads((ROOT / "docs/debian-package-inputs.json").read_text())
    assert pins["image"] == data["selected"]
    assert data["selected"]["manifest_digest"] == (
        "sha256:e2914ec98e08b24b4cee3cefcb9f90dfb5519f8d215a2ccf0c9a49b10b6e43de"
    )
    assert data["platform"] == {"os": "linux", "architecture": "amd64"}
    assert data["same_installed_base_package_versions"] is True
    assert (
        data["installed_base_package_count"]
        == len(data["installed_base_package_versions"])
        == 78
    )
    assert data["installed_base_package_versions"]["dpkg"] == "1.22.22"
    assert data["same_apt_sources"] is True
    assert data["directory_differences"] == ["/usr/share/man/man1"]
    for value in data["directories_selected"].values():
        assert (value["uid"], value["gid"], value["type"]) == (0, 0, "directory")
        assert not int(value["mode"], 8) & 0o7022
        assert not value["pax_keys"]


def test_selected_directory_satisfies_unchanged_validator(monkeypatch):
    data = json.loads(EVIDENCE.read_text())["directories_selected"][
        "/usr/share/man/man1"
    ]
    doctor = load_doctor()
    # Explicit symbolic metadata; physical container validation is separate CI.
    value = SimpleNamespace(
        st_uid=data["uid"],
        st_gid=data["gid"],
        st_mode=stat.S_IFDIR | int(data["mode"], 8),
        st_nlink=1,
    )
    monkeypatch.setattr(os, "fstat", lambda _: value)
    monkeypatch.setattr(os, "listxattr", lambda _: [])
    assert doctor.meta(23, directory=True) is value


def test_actual_prior_image_metadata_still_reports_blocked(monkeypatch):
    data = json.loads(EVIDENCE.read_text())["directories_previous"][
        "/usr/share/man/man1"
    ]
    assert data["mode"] == "0775"
    doctor = load_doctor()
    value = SimpleNamespace(
        st_uid=data["uid"],
        st_gid=data["gid"],
        st_mode=stat.S_IFDIR | int(data["mode"], 8),
        st_nlink=1,
    )
    monkeypatch.setattr(os, "fstat", lambda _: value)
    monkeypatch.setattr(os, "listxattr", lambda _: [])

    class ObservedDirectoryOnly:
        artifacts = None

        def package(self):
            doctor.meta(23, directory=True)
            raise AssertionError("unsafe directory accepted")

        def __getattr__(self, _name):
            return lambda: ("NOT_RUN", "observation_denied")

    report = doctor.report(ObservedDirectoryOnly())
    assert report["checks"]["package"] == {
        "state": "BLOCKED",
        "reason": "unsafe_metadata",
    }
    assert report["launch_allowed"] is False


def test_ci_has_read_only_guards_and_independent_prior_image_case():
    dockerfile = (ROOT / "packaging/debian/Dockerfile").read_text()
    workflow = (ROOT / ".github/workflows/debian-package.yml").read_text()
    guard = (
        "test \"$(LC_ALL=C stat -c '%u:%g:%a:%F' /usr/share/man/man1)\" "
        '= "0:0:755:directory"'
    )
    assert dockerfile.count(guard) == 4  # Base, quality and both P1 images.
    negative = dockerfile.split("AS manpage-negative", 1)[1]
    assert "chmod" not in negative and "chown" not in negative
    assert "Prior slim manpage 0775 remains BLOCKED" in workflow
    assert "--target manpage-negative" in workflow
    assert "for p1_case in clean existing" in workflow
    assert 'test "$p1_failed" -eq 0' in workflow
    assert 'test -s "$RUNNER_TEMP/ap-evidence/codex-pkg05-lifecycle.json"' in workflow
    source = (ROOT / "packaging/debian/worker_manpage_negative.py").read_text()
    assert "doctor.meta(fd, directory=True)" in source
    assert '"status": "BLOCKED"' in source
    assert "doctor.stamp(before) == doctor.stamp(os.fstat(fd))" in source
    assert "chmod(" not in source and "chown(" not in source
