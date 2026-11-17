"""HAR-04 doctor harness observations; fabricated stores only, never a host or login."""

import json
import os
import subprocess
from pathlib import Path

import pytest
import test_claude_upstream_provisioning as helpers
from test_worker_doctor import GoodObservations, load

ROOT = Path(__file__).resolve().parents[1]
PASSWD = b"root:x:0:0::/root:/bin/sh\nagentdev:x:1001:1001::/home/agentdev:/bin/sh\n"


def selection(harness="codex", epoch=1):
    return (
        json.dumps(
            {
                "schema": "AP-HARNESS-LOCAL/1",
                "harness_id": harness,
                "selection_epoch": epoch,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()


@pytest.fixture(scope="module")
def keys():
    return helpers.signer.__wrapped__()


@pytest.fixture
def toolchain(tmp_path, monkeypatch, keys):
    e = helpers.env.__wrapped__(tmp_path, monkeypatch, keys)
    doctor = load()
    pins = {k: v for k, v in e.pins.items() if k in ("2.1.295", "2.1.296")}
    monkeypatch.setattr(doctor, "CLAUDE_BASE", e.m.BASE)
    monkeypatch.setattr(doctor, "CLAUDE_COMMAND_DIRS", (str(e.usrbin), str(e.localbin)))
    monkeypatch.setattr(doctor, "CLAUDE_PINS", pins)
    monkeypatch.setattr(doctor, "CLAUDE_OWNER", (os.getuid(), os.getgid()))
    monkeypatch.setattr(doctor, "directory", e.m.directory)
    original = doctor.meta
    monkeypatch.setattr(
        doctor,
        "meta",
        lambda fd, **kw: original(fd, uid=os.getuid(), gid=os.getgid(), **kw),
    )
    state = {"selection": None, "passwd": PASSWD}

    def fake_read(path, *_):
        if path == "/etc/passwd":
            return state["passwd"]
        if path == doctor.HARNESS_CONFIG:
            if state["selection"] is None:
                raise FileNotFoundError
            return state["selection"]
        pytest.fail("unexpected read " + path)

    monkeypatch.setattr(doctor, "read", fake_read)
    monkeypatch.setattr(doctor, "query", lambda *_: pytest.fail("tool"))
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_k: pytest.fail("process"))
    observer = doctor.Observer()
    observer.artifacts = {
        "worker_version": "0.1.0-6",
        "source_commit": "b" * 40,
        "manifest_sha256": "a" * 64,
    }
    e.doctor, e.observer, e.state, e.pins = doctor, observer, state, pins
    return e


def test_doctor_pins_equal_reviewed_lock_and_provisioner():
    doctor = load()
    lock = json.loads((ROOT / "provisioning/claude-release-lock.json").read_text())
    assert doctor.CLAUDE_PINS == {p["version"]: p for p in lock["releases"]}
    provisioner = helpers.module()
    assert provisioner.LOCK_SHA256 == provisioner.sha(
        (ROOT / "provisioning/claude-release-lock.json").read_bytes()
    )
    assert doctor.CLAUDE_BASE == provisioner.BASE != doctor.MANAGED_BASE
    assert doctor.CLAUDE_COMMAND_DIRS == provisioner.SYSTEM_COMMANDS


def test_doctor_verifies_exactly_the_provisioners_store_without_writes(toolchain):
    n = toolchain
    n.run()
    before = helpers.tree(n.tmp)
    assert n.observer.claude() == ("INSTALLED", "verified_managed_claude")
    pin = n.pins["2.1.295"]
    art = n.observer.artifacts
    assert art["claude_version"] == "2.1.295"
    assert art["claude_binary_sha256"] == pin["binary_sha256"]
    assert art["claude_manifest_sha256"] == pin["manifest_sha256"]
    assert art["claude_effective_path"].endswith("/claude")
    assert art["claude_release_pin_sha256"] == n.m.sha(n.m.encoded(pin))
    assert helpers.tree(n.tmp) == before


def test_missing_install_is_not_run_and_leaves_no_claims(toolchain):
    n = toolchain
    n.observer.artifacts["claude_version"] = "stale"
    assert n.observer.claude() == ("NOT_RUN", "claude_not_installed")
    assert not [k for k in n.observer.artifacts if k.startswith("claude_")]


def test_claude_requires_verified_package_first(toolchain):
    n = toolchain
    n.observer.artifacts = None
    with pytest.raises(n.doctor.Blocked, match="package_verification_required"):
        n.observer.claude()


@pytest.mark.parametrize(
    "defect,reason",
    [
        ("binary_flip", "claude_verification_failed"),
        ("binary_symlink", "unsafe_metadata|claude_verification_failed"),
        ("binary_hardlink", "unsafe_metadata"),
        ("binary_mode", "unsafe_metadata"),
        ("record", "claude_verification_failed"),
        ("extra_file", "claude_verification_failed"),
        ("version_dir_symlink", "unsafe_metadata|claude_verification_failed"),
        ("current_foreign", "claude_verification_failed"),
        ("current_missing", "claude_verification_failed"),
        ("unknown_version", "claude_verification_failed"),
        ("pending_transaction", "claude_verification_failed"),
        ("pending_next", "claude_verification_failed"),
        ("store_marker", "claude_verification_failed"),
        ("foreign_command", "foreign_claude_command"),
        ("foreign_command_link", "foreign_claude_command"),
    ],
)
def test_doctor_blocks_tampering_substitution_and_unknown_state(
    toolchain, defect, reason
):
    n = toolchain
    n.run()
    pin = n.pins["2.1.295"]
    folder = n.base / "versions" / (pin["version"] + "-" + pin["binary_sha256"])
    binary = folder / "claude"
    if defect == "binary_flip":
        data = bytearray(binary.read_bytes())
        data[300] ^= 1
        binary.write_bytes(bytes(data))
    elif defect == "binary_symlink":
        data = binary.read_bytes()
        binary.unlink()
        (n.tmp / "elsewhere").write_bytes(data)
        binary.symlink_to(n.tmp / "elsewhere")
    elif defect == "binary_hardlink":
        os.link(binary, n.tmp / "alias")
    elif defect == "binary_mode":
        binary.chmod(0o777)
    elif defect == "record":
        (folder / "record.json").write_bytes(b"{}\n")
    elif defect == "extra_file":
        (folder / "extra").write_bytes(b"x")
    elif defect == "version_dir_symlink":
        moved = n.tmp / "moved"
        folder.rename(moved)
        folder.symlink_to(moved)
    elif defect == "current_foreign":
        (n.base / "current").unlink()
        (n.base / "current").symlink_to("/opt/agent-platform-codex/current")
    elif defect == "current_missing":
        (n.base / "current").unlink()
    elif defect == "unknown_version":
        (n.base / "versions" / "9.9.9-x").mkdir()
    elif defect == "pending_transaction":
        (n.base / "transaction.json").write_bytes(b"{}\n")
    elif defect == "pending_next":
        (n.base / ".current.next").symlink_to("versions/x")
    elif defect == "store_marker":
        (n.base / "store.json").write_bytes(b"{}\n")
    elif defect == "foreign_command":
        (n.usrbin / "claude").write_bytes(b"personal")
    else:
        (n.localbin / "claude").symlink_to("/nonexistent")
    before = helpers.tree(n.base)
    with pytest.raises(n.doctor.Blocked, match=reason):
        n.observer.claude()
    assert n.observer._claude_identity is None
    assert not [k for k in n.observer.artifacts if k.startswith("claude_")]
    assert helpers.tree(n.base) == before


def test_unrecorded_version_in_store_is_unknown_not_accepted(toolchain):
    n = toolchain
    n.run()
    n.run("2.1.296", upgrade=True)
    n.monkeypatch.setattr(n.doctor, "CLAUDE_PINS", {"2.1.295": n.pins["2.1.295"]})
    with pytest.raises(n.doctor.Blocked, match="claude_verification_failed"):
        n.observer.claude()


def test_both_versions_retained_and_current_is_reported_exactly(toolchain):
    n = toolchain
    n.run()
    n.run("2.1.296", upgrade=True)
    assert n.observer.claude()[0] == "INSTALLED"
    assert n.observer.artifacts["claude_version"] == "2.1.296"
    n.run("2.1.295", action="rollback", path=None)
    n.observer.claude()
    assert n.observer.artifacts["claude_version"] == "2.1.295"


# ---- PATH, symlink and personal-install collisions: names only ----


def test_claude_path_requires_verified_identity_and_never_confirms(toolchain):
    n = toolchain
    with pytest.raises(n.doctor.Blocked, match="claude_verification_required"):
        n.observer.claude_path()
    n.run()
    n.observer.claude()
    n.monkeypatch.setenv("PATH", "/usr/local/bin:/usr/bin")
    n.monkeypatch.setattr(
        n.doctor.Observer, "exists_name", staticmethod(lambda _path: False)
    )
    assert n.observer.claude_path() == (
        "NOT_RUN",
        "coding_environment_scope_unverified",
    )


@pytest.mark.parametrize(
    "hit,reason",
    [
        ("/usr/local/bin/claude", "claude_path_collision"),
        ("/opt/other/claude", "claude_path_collision"),
        ("/home/agentdev/.local/bin/claude", "personal_claude_requires_exec_binding"),
    ],
)
def test_alternate_and_personal_claude_names_block_without_reading_them(
    toolchain, hit, reason
):
    n = toolchain
    n.run()
    n.observer.claude()
    n.monkeypatch.setenv("PATH", "/usr/local/bin:/opt/other:/usr/bin")
    seen = []

    def names_only(path):
        seen.append(path)
        return path == hit

    n.monkeypatch.setattr(n.doctor.Observer, "exists_name", staticmethod(names_only))
    with pytest.raises(n.doctor.Blocked, match=reason):
        n.observer.claude_path()
    assert all(p.endswith("/claude") for p in seen)


@pytest.mark.parametrize("path", ["", "relative:/usr/bin", "/a/../b", "/x:" * 40])
def test_invalid_caller_path_blocks(toolchain, path):
    n = toolchain
    n.run()
    n.observer.claude()
    n.monkeypatch.setenv("PATH", path)
    with pytest.raises(n.doctor.Blocked, match="path_invalid"):
        n.observer.claude_path()


def test_report_blocks_claude_when_personal_install_exists(toolchain):
    n = toolchain
    n.run()
    observed = GoodObservations()
    observed.claude = n.observer.claude
    observed.claude_path = lambda: ("BLOCKED", "personal_claude_requires_exec_binding")
    observed.artifacts = None
    n.observer.claude()
    report = n.doctor.report(observed)
    claude = report["harness"]["harnesses"]["claude_code"]
    assert claude == {
        "selected": False,
        "state": "BLOCKED",
        "reason": "personal_claude_requires_exec_binding",
    }


# ---- configured harness selection ----


@pytest.mark.parametrize("harness", ["codex", "claude_code"])
def test_valid_local_selection_is_recorded_not_authorized(toolchain, harness):
    n = toolchain
    n.state["selection"] = selection(harness, 7)
    assert n.observer.harness_selection() == (
        "CONFIGURED",
        "verified_harness_selection_record",
    )
    assert n.observer._selection[:2] == (harness, 7)
    assert n.observer.selection_unchanged() is True


def test_missing_selection_is_not_run_never_a_default(toolchain):
    n = toolchain
    assert n.observer.harness_selection() == ("NOT_RUN", "harness_selection_missing")
    assert n.observer._selection is None


def bad_selection_vectors():
    good = {"schema": "AP-HARNESS-LOCAL/1", "harness_id": "codex", "selection_epoch": 1}

    def enc(value):
        return (
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()

    return {
        "auto": enc(good | {"harness_id": "auto"}),
        "case_changed": enc(good | {"harness_id": "Codex"}),
        "alias": enc(good | {"harness_id": "claude"}),
        "model_name": enc(good | {"harness_id": "claude-sonnet-5-5"}),
        "dual_list": enc(good | {"harness_id": ["codex", "claude_code"]}),
        "dual_string": enc(good | {"harness_id": "codex,claude_code"}),
        "null_id": enc(good | {"harness_id": None}),
        "extra_field": enc(good | {"fallback": "claude_code"}),
        "missing_epoch": enc({k: v for k, v in good.items() if k != "selection_epoch"}),
        "epoch_zero": enc(good | {"selection_epoch": 0}),
        "epoch_negative": enc(good | {"selection_epoch": -1}),
        "epoch_bool": enc(good | {"selection_epoch": True}),
        "epoch_float": enc(good | {"selection_epoch": 1.0}),
        "epoch_overflow": enc(good | {"selection_epoch": 2**63}),
        "wrong_schema": enc(good | {"schema": "AP-HSEL/1"}),
        "not_canonical": json.dumps(good, indent=2).encode(),
        "no_newline": json.dumps(good, sort_keys=True, separators=(",", ":")).encode(),
        "duplicate_key": b'{"harness_id":"codex","harness_id":"claude_code",'
        b'"schema":"AP-HARNESS-LOCAL/1","selection_epoch":1}\n',
        "array": b'["codex"]\n',
        "invalid_json": b"{\n",
    }


@pytest.mark.parametrize("name", sorted(bad_selection_vectors()))
def test_invalid_or_dual_or_aliased_selection_blocks(toolchain, name):
    n = toolchain
    n.state["selection"] = bad_selection_vectors()[name]
    with pytest.raises((n.doctor.Blocked, ValueError)):
        n.observer.harness_selection()
    assert n.observer._selection is None


def test_selection_drift_between_reads_is_detected(toolchain):
    n = toolchain
    n.state["selection"] = selection("codex", 1)
    n.observer.harness_selection()
    assert n.observer.selection_unchanged() is True
    n.state["selection"] = selection("claude_code", 2)
    assert n.observer.selection_unchanged() is False
    n.state["selection"] = selection("codex", 2)
    assert n.observer.selection_unchanged() is False
    n.state["selection"] = None
    assert n.observer.selection_unchanged() is False


# ---- report-level harness semantics ----


def double(**changes):
    observed = GoodObservations()
    for name, value in changes.items():
        setattr(observed, name, value)
    return observed


def report_for(doctor, *, selected=None, codex="INSTALLED", claude="INSTALLED"):
    observed = GoodObservations()
    if codex != "INSTALLED":
        observed.codex = lambda: ("NOT_RUN", "object_missing")
    observed.claude = lambda: (
        (claude, "verified_managed_claude")
        if claude == "INSTALLED"
        else ("NOT_RUN", "claude_not_installed")
    )
    observed.claude_path = lambda: ("NOT_RUN", "coding_environment_scope_unverified")
    if selected is None:
        observed.harness_selection = lambda: ("NOT_RUN", "harness_selection_missing")
    else:
        observed._selection = (selected, 3, "c" * 64)
        observed.harness_selection = lambda: (
            "CONFIGURED",
            "verified_harness_selection_record",
        )
    observed.selection_unchanged = lambda: True
    observed.artifacts = None
    return doctor.report(observed)


def test_report_without_selection_selects_nothing_even_with_both_toolchains(doctor_):
    report = report_for(doctor_)
    harness = report["harness"]
    assert harness["configured"] is None and harness["selected_toolchain"] is None
    assert harness["selection_epoch"] is None and harness["selection_sha256"] is None
    assert not any(h["selected"] for h in harness["harnesses"].values())
    assert harness["alternate_toolchain_ignored"] is True
    assert harness["auto_selection"] == "NEVER" and harness["launch_allowed"] is False


@pytest.mark.parametrize("selected", ["codex", "claude_code"])
def test_both_toolchains_present_only_recorded_harness_is_selected(doctor_, selected):
    harness = report_for(doctor_, selected=selected)["harness"]
    assert harness["configured"] == selected
    assert [k for k, v in harness["harnesses"].items() if v["selected"]] == [selected]
    assert harness["selected_toolchain"] == "INSTALLED"
    assert harness["selection_epoch"] == 3 and harness["selection_sha256"] == "c" * 64
    assert harness["alternate_toolchain_ignored"] is True


def test_claude_binary_never_replaces_missing_selected_codex(doctor_):
    harness = report_for(doctor_, selected="codex", codex="NOT_RUN")["harness"]
    assert harness["configured"] == "codex"
    assert harness["selected_toolchain"] == "NOT_RUN"
    assert harness["harnesses"]["claude_code"]["selected"] is False
    assert harness["harnesses"]["claude_code"]["state"] == "INSTALLED"
    assert harness["alternate_toolchain_ignored"] is False


def test_codex_binary_never_replaces_missing_selected_claude(doctor_):
    harness = report_for(doctor_, selected="claude_code", claude="NOT_RUN")["harness"]
    assert harness["configured"] == "claude_code"
    assert harness["selected_toolchain"] == "NOT_RUN"
    assert harness["harnesses"]["codex"]["selected"] is False


@pytest.mark.parametrize("selected", [None, "codex", "claude_code"])
def test_installation_never_grants_readiness_or_launch(doctor_, selected):
    report = report_for(doctor_, selected=selected)
    text = json.dumps(report)
    assert report["status"] == "BLOCKED" and report["configuration"] == "BLOCKED"
    assert (
        report["launch_allowed"] is False
        and report["harness"]["launch_allowed"] is False
    )
    assert report["runtime"] == "LIVE_NO_GO" and report["gate_73"] == "BLOCKED"
    assert report["subscription"] == "SUBSCRIPTION_ISOLATION_BLOCKED"
    assert report["host_evidence"] == "HOST_NOT_RUN"
    assert "READY_FOR_SUPERVISED_PUBLISHING" not in text
    assert report["checks"]["execution_binding"] == {
        "state": "NOT_RUN",
        "reason": "trusted_absolute_exec_unobserved",
    }
    assert report["checks"]["claude_path"]["state"] in ("BLOCKED", "NOT_RUN")


def test_selection_changed_during_run_blocks_and_clears_selection(doctor_):
    observed = GoodObservations()
    observed._selection = ("claude_code", 3, "c" * 64)
    observed.harness_selection = lambda: (
        "CONFIGURED",
        "verified_harness_selection_record",
    )
    observed.selection_unchanged = lambda: False
    report = doctor_.report(observed)
    assert report["checks"]["harness_selection"] == {
        "state": "BLOCKED",
        "reason": "harness_selection_changed",
    }
    assert report["harness"]["configured"] is None
    assert not any(h["selected"] for h in report["harness"]["harnesses"].values())


def test_forged_internal_selection_without_configured_check_is_ignored(doctor_):
    observed = GoodObservations()
    observed._selection = ("claude_code", 3, "c" * 64)  # Check says NOT_RUN.
    observed.harness_selection = lambda: ("NOT_RUN", "harness_selection_missing")
    assert doctor_.report(observed)["harness"]["configured"] is None


@pytest.fixture
def doctor_(monkeypatch):
    module = load()

    def absent_network(*_args):
        raise FileNotFoundError

    monkeypatch.setattr(module, "network_read", absent_network)
    return module


def test_report_matches_closed_schema_including_harness_block(doctor_):
    schema = json.loads((ROOT / "docs/worker-doctor.schema.json").read_text())
    report = report_for(doctor_, selected="claude_code")
    assert set(report) == set(schema["properties"]) == set(schema["required"])
    assert set(report["checks"]) == set(schema["properties"]["checks"]["required"])
    block = schema["properties"]["harness"]
    assert set(report["harness"]) == set(block["required"]) == set(block["properties"])
    for name, item in report["harness"]["harnesses"].items():
        definition = block["properties"]["harnesses"]["properties"][name]
        assert set(item) == set(definition["required"])
        assert item["state"] in definition["properties"]["state"]["enum"]
        reasons = schema["$defs"]["check"]["properties"]["reason"]["enum"]
        assert definition["properties"]["reason"] == {
            "$ref": "#/$defs/check/properties/reason"
        }
        assert item["reason"] in reasons
    for name in ("claude", "harness_selection", "claude_path"):
        ref = schema["properties"]["checks"]["properties"][name]["$ref"]
        definition = schema["$defs"][ref.rsplit("/", 1)[1]]
        item = report["checks"][name]
        assert item["state"] in definition["properties"]["state"]["enum"]
        assert item["reason"] in definition["properties"]["reason"]["enum"]
    assert set(schema["properties"]["harness"]["required"]) <= set(report["harness"])


def test_every_doctor_reason_is_in_the_closed_schema():
    doctor = load()
    schema = json.loads((ROOT / "docs/worker-doctor.schema.json").read_text())
    enum = set(schema["$defs"]["check"]["properties"]["reason"]["enum"])
    assert doctor.REASONS <= enum
    new = {
        "verified_managed_claude", "claude_not_installed",
        "claude_verification_failed", "claude_verification_required",
        "foreign_claude_command", "claude_path_collision",
        "personal_claude_requires_exec_binding",
        "verified_harness_selection_record", "harness_selection_missing",
        "harness_selection_invalid", "harness_selection_changed",
    }  # fmt: skip
    assert new <= doctor.REASONS and new <= enum


def test_claude_observations_never_run_tools_or_touch_homes(toolchain, monkeypatch):
    n = toolchain
    n.run()
    n.state["selection"] = selection("claude_code", 1)
    opened = []
    real = os.open
    monkeypatch.setattr(
        os, "open", lambda p, *a, **k: opened.append(str(p)) or real(p, *a, **k)
    )
    n.monkeypatch.setattr(
        n.doctor.Observer, "exists_name", staticmethod(lambda _path: False)
    )
    n.monkeypatch.setenv("PATH", "/usr/local/bin:/usr/bin")
    n.observer.harness_selection()
    n.observer.claude()
    n.observer.claude_path()
    assert not any(".claude" in p or "/home/" in p or ".config" in p for p in opened)


def test_worker_cli_has_no_claude_provisioning_dispatch():
    spec_path = ROOT / "packaging/worker-provisioning/worker_cli.py"
    text = spec_path.read_text()
    assert "claude" not in text.lower()
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location("worker_cli_test", spec_path)
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    for argv in (
        ["claude", "install", "--approve"],
        ["harness", "select", "claude_code"],
    ):
        sys_argv = sys.argv
        sys.argv = ["agent-platform-worker", *argv]
        try:
            with pytest.raises(SystemExit) as raised:
                cli.main()
        finally:
            sys.argv = sys_argv
        assert raised.value.code == 2
