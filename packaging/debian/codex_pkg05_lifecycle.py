"""Separate synthetic PKG-03R lifecycle: disposable Debian container only."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path


def main():
    # All checks precede writes. No host root or Docker socket is acceptable.
    assert Path("/.dockerenv").exists() and os.getuid() == 0
    assert Path("/ap-package-ci-fixture").read_text() == "AP-PKG-CI-DISPOSABLE-v1\n"
    assert "VERSION_CODENAME=trixie\n" in Path("/etc/os-release").read_text()
    assert not Path("/var/run/docker.sock").exists()
    assert not Path("/opt/agent-platform-codex").exists()
    assert not Path("/usr/local/bin/codex").exists()
    assert not Path("/usr/bin/codex").exists()
    spec = importlib.util.spec_from_file_location(
        "fixture_helpers", "/source/tests/test_codex_upstream_provisioning.py"
    )
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    m = helper.module()
    m.check_platform()  # Actual Debian/architecture check; not monkeypatched.
    assert m.OWNER == 0 and m.BASE == "/opt/agent-platform-codex"
    # Copy only fixed public project inputs into this new disposable root-owned
    # tool directory. No host install, vendor executable, key or session read.
    trusted = Path("/opt/pkg05-test-tool")
    assert not trusted.exists()
    trusted.mkdir(mode=0o755)
    names = ["codex_upstream.py", "codex-release-lock.json"]
    source = Path("/source/provisioning")
    for name in names:
        (trusted / name).write_bytes((source / name).read_bytes())
    (trusted / "evidence").mkdir(mode=0o755)
    evidence_names = (
        "codex-0.166.0-provenance.json",
        "codex-0.166.0.sigstore",
        "sigstore-trusted-root-"
        "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66.json",
    )
    for name in evidence_names:
        path = source / "evidence" / name
        assert path.is_file() and not path.is_symlink()
        (trusted / "evidence" / path.name).write_bytes(path.read_bytes())
    m.__file__ = str(trusted / "codex_upstream.py")
    assert set(m.load_lock()) == {"0.166.0"}
    pins, paths = {}, {}
    for version in ("1.0.0", "2.0.0"):
        pin, data = helper.release(m, version)
        pins[version] = pin
        paths[version] = Path("/tmp") / (version + ".tar.gz")
        paths[version].write_bytes(data)
    # Fabricated trusted pins/ELFs only; production cannot select these pins.
    result = m.operate(pins, "1.0.0", archive=paths["1.0.0"], operator_path=m.BIN)
    assert result["outcome"] == "install"
    assert (
        m.operate(pins, "1.0.0", operator_path=m.BIN)["outcome"] == "already_installed"
    )
    with helper.http_fixture(paths["2.0.0"].read_bytes()) as connector:
        assert (
            m.operate(
                pins, "2.0.0", operator_path=m.BIN, upgrade=True, connector=connector
            )["version"]
            == "2.0.0"
        )
    assert (
        m.operate(pins, "1.0.0", operator_path=m.BIN, action="rollback")["version"]
        == "1.0.0"
    )
    binary = Path(m.BASE, "versions", m.key(pins["1.0.0"]), "codex")
    before = hashlib.sha256(binary.read_bytes()).hexdigest()
    binary.write_bytes(binary.read_bytes() + b"changed")
    try:
        m.operate(pins, "1.0.0", operator_path=m.BIN)
    except m.Blocked:
        pass
    else:
        raise AssertionError("tampered binary accepted")
    assert hashlib.sha256(binary.read_bytes()).hexdigest() != before
    assert not result["launch_allowed"]
    Path("/evidence/codex-pkg05-lifecycle.json").write_text(
        json.dumps(
            {
                "status": "PASS",
                "synthetic_only": True,
                "codex_executed": False,
                "offline_idempotence_upgrade_rollback": "PASS",
                "tampered_binary_refused_without_repair": "PASS",
                "real_hosts": "HOST_NOT_RUN",
                "runtime": "LIVE_NO_GO",
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
