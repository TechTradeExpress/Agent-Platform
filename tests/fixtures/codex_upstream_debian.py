"""Explicit disposable Debian 13 namespace proof using fabricated policy/ELFs only."""

import importlib.util
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    assert os.geteuid() == 0
    assert (
        Path("/ap-codex-provision-ci-fixture").read_text()
        == "AP-CODEX-PROVISION-CI-v1\n"
    )
    # Refuse an ordinary host root shell even if someone copied the marker.
    mapping = Path("/proc/self/uid_map").read_text().split()
    assert (
        len(mapping) == 3
        and mapping[0] == "0"
        and mapping[1] != "0"
        and mapping[2] == "1"
    )
    spec = importlib.util.spec_from_file_location(
        "fixture_helpers", ROOT / "tests/test_codex_upstream_provisioning.py"
    )
    helpers = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helpers)
    m = helpers.module()
    m.check_platform()  # Real distro/architecture/owner checks, not monkeypatched.
    assert m.OWNER == 0 and m.BASE == "/opt/agent-platform-codex"
    assert not Path(m.BASE).exists() and not Path(m.BIN, "codex").exists()
    trusted = Path("/trusted-tool/provisioning/codex_upstream.py")
    policy_spec = importlib.util.spec_from_file_location("trusted_provisioner", trusted)
    policy = importlib.util.module_from_spec(policy_spec)
    policy_spec.loader.exec_module(policy)
    assert set(policy.load_lock()) == {"0.166.0"}

    home = Path("/home/synthetic-operator")
    (home / ".codex").mkdir(parents=True)
    credential = home / ".codex/auth.json"
    credential.write_text("fabricated credential sentinel\n")
    (home / ".local/bin").mkdir(parents=True)
    personal = home / ".local/bin/codex"
    personal.write_text("fabricated external tool\n")
    before = (credential.read_bytes(), personal.read_bytes())
    pins, paths = {}, {}
    for version in ("1.0.0", "2.0.0"):
        pin, data = helpers.release(m, version)
        pins[version] = pin
        path = Path("/tmp") / (version + ".tar.gz")
        path.write_bytes(data)
        paths[version] = path
    # Policy is fabricated trusted test input, never loaded by production CLI.
    outcome = m.operate(pins, "1.0.0", archive=paths["1.0.0"], operator_path=m.BIN)
    assert outcome["outcome"] == "install" and outcome["launch_allowed"] is False
    assert (
        m.operate(pins, "1.0.0", operator_path=m.BIN)["outcome"] == "already_installed"
    )
    with helpers.http_fixture(paths["2.0.0"].read_bytes()) as connector:
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
    for file in Path(m.BASE, "versions").rglob("*"):
        assert file.stat().st_uid == file.stat().st_gid == 0
    assert before == (credential.read_bytes(), personal.read_bytes())
    # Unknown user PATH is detected by lstat; personal tool/credential untouched.
    try:
        m.operate(pins, "1.0.0", operator_path=str(personal.parent) + ":" + m.BIN)
    except m.Blocked as error:
        assert str(error) == "path_shadowing"
    else:
        raise AssertionError("shadowing accepted")

    # Explicit recovery after a fully verified version was published.
    def fail(phase):
        if phase == "pointer_staged":
            raise OSError("fabricated interruption")

    m.checkpoint = fail
    try:
        m.operate(
            pins, "2.0.0", archive=paths["2.0.0"], operator_path=m.BIN, upgrade=True
        )
    except OSError:
        pass
    else:
        raise AssertionError("missing interruption")
    m.checkpoint = lambda _: None
    assert (
        m.operate(pins, None, operator_path=m.BIN, action="recover")["version"]
        == "2.0.0"
    )
    report = {
        "status": "PASS",
        "fixture": "Debian 13 amd64 private user/mount/PID/net namespaces",
        "fixed_root_paths_and_owners": "PASS",
        "offline_and_controlled_http": "PASS",
        "idempotence_upgrade_rollback_recover": "PASS",
        "user_data_preserved": "PASS",
        "official_binary_installed": False,
        "codex_executed": False,
        "runtime": "LIVE_NO_GO",
    }
    Path("/evidence/fixed-root.json").write_text(json.dumps(report, indent=2) + "\n")
    print("SYNTHETIC_FIXED_ROOT_PROVISION_PASS")


if __name__ == "__main__":
    main()
