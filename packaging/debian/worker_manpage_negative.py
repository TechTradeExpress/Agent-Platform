"""Actual prior-image metadata rejection; disposable test, not product execution."""

import importlib.util
import json
import os
import platform
import stat
from pathlib import Path


def main():
    assert Path("/.dockerenv").exists() and os.getuid() == 0
    assert Path("/ap-package-ci-fixture").read_text() == "AP-PKG-CI-DISPOSABLE-v1\n"
    assert platform.machine() == "x86_64"
    assert not Path("/var/run/docker.sock").exists()
    assert "VERSION_CODENAME=trixie\n" in Path("/etc/os-release").read_text()
    spec = importlib.util.spec_from_file_location(
        "unchanged_doctor", "/source/packaging/worker-provisioning/worker_doctor.py"
    )
    doctor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(doctor)
    # Parent traversal uses the real unchanged checker too. No chmod/chown,
    # unsafe fixture construction or synthetic replacement of the validator.
    with doctor.directory("/usr/share/man") as parent:
        fd = os.open("man1", doctor.FLAGS | os.O_DIRECTORY, dir_fd=parent)
        try:
            before = os.fstat(fd)
            assert stat.S_ISDIR(before.st_mode)
            assert (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) == (
                0,
                0,
                0o775,
            )
            try:
                doctor.meta(fd, directory=True)
            except doctor.Blocked as error:
                assert str(error) == "unsafe_metadata"
            else:
                raise AssertionError("prior_group_writable_directory_was_accepted")
            assert doctor.stamp(before) == doctor.stamp(os.fstat(fd))
        finally:
            os.close(fd)
    result = {
        "schema": "AP-PKG-PRIOR-IMAGE-NEGATIVE/1",
        "case": "prior_slim_man1_0775",
        "check": "unchanged_doctor_directory_policy",
        "status": "BLOCKED",
        "reason": "unsafe_metadata",
        "expected_rejection_observed": True,
        "observed": {"uid": 0, "gid": 0, "mode": "0775", "type": "directory"},
        "runtime": "LIVE_NO_GO",
        "host": "HOST_NOT_RUN",
        "launch_allowed": False,
        "subscription": "SUBSCRIPTION_ISOLATION_BLOCKED",
        "gate_73": "BLOCKED",
    }
    Path("/evidence/prior-slim-manpage-negative.json").write_text(
        json.dumps(result, sort_keys=True) + "\n"
    )
    # Success means the expected refusal was observed, never product GO/exit 0.


if __name__ == "__main__":
    main()
