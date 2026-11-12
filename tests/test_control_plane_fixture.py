"""CP-06: synthetic reference-model evidence, never kernel/AppArmor attestation."""

import json
import os
from dataclasses import FrozenInstanceError, asdict, replace
from pathlib import Path

import pytest

from agent_platform import control_plane_fixture as cf


def config():
    return cf.Config(
        cf.Identity(
            "1" * 64,
            "2" * 64,
            "3" * 64,
            "4" * 64,
            tuple(cf.Fact(n, cf.Provenance.HOST_NOT_RUN) for n in cf.FACTS),
        )
    )


def step(case=cf.Case.PEER_VALID):
    return next(s for s in cf.scenarios(config()) if s.case == case)


def test_deterministic_closed_report_and_positive_negative_controls():
    c = config()
    report = cf.run(c, cf.scenarios(c))
    assert report.status == "VERIFIED_OFFLINE_FIXTURE"
    assert report.encode() == cf.run(c, cf.scenarios(c)).encode()
    raw = json.loads(report.encode())
    assert raw["live"] == "LIVE_NO_GO" and raw["gate_73"] == "BLOCKED"
    assert raw["launch_allowed"] is False
    assert len(report.encode()) <= 65536
    assert set(raw["host_matrix"].values()) == {"HOST_NOT_RUN"}
    assert set(raw) == {
        "version",
        "status",
        "code",
        "identity",
        "cases",
        "live",
        "launch_allowed",
        "gate_73",
        "host_matrix",
        "configuration",
        "configuration_sha256",
    }
    assert len(report.cases) == len(cf.Case)
    assert all(
        r.model_matches and r.host == cf.Disposition.HOST_NOT_RUN for r in report.cases
    )
    for r in report.cases:
        assert r.observed == (
            cf.Disposition.PASS if r.case in cf.POSITIVE else cf.Disposition.DENIED
        )
    with pytest.raises(FrozenInstanceError):
        report.live = "GO"


@pytest.mark.parametrize("case", list(cf.Case))
def test_every_fixed_case_has_expected_observation_and_reaped_model_children(case):
    adapter = cf.FakeAdapter()
    result = cf.run_case(config(), step(case), adapter)
    assert result.model_matches
    assert adapter.started == adapter.reaped == 1
    plan = adapter.plans[0]
    assert plan.argv == ("CP06_MODEL_ONLY", case.value)
    assert not plan.shell and not plan.env and not plan.pass_fds
    assert plan.executable is None and plan.close_fds
    assert plan.probe_ms <= 5000 and plan.case_ms <= 60000
    assert plan.output_bytes <= 65536


@pytest.mark.parametrize(
    "field,value",
    [
        ("elapsed_ms", 5001),
        ("elapsed_ms", 60001),
        ("cancelled", True),
        ("cleanup_complete", False),
    ],
)
def test_uncertain_cases_reap_and_do_not_pass(field, value):
    adapter = cf.FakeAdapter()
    s = replace(step(), **{field: value})
    r = cf.run_case(config(), s, adapter)
    assert r.observed == cf.Disposition.UNKNOWN and not r.model_matches
    assert adapter.started == adapter.reaped == 1 and len(adapter.plans) == 1
    steps = tuple(s if old.case == s.case else old for old in cf.scenarios(config()))
    assert cf.run(config(), steps).status == "BLOCKED"


def test_leaked_children_fail_without_retry_or_signalling_real_pids():
    adapter = cf.FakeAdapter()
    r = cf.run_case(config(), replace(step(), can_reap=False, children=4), adapter)
    assert r.observed == cf.Disposition.FAIL and r.code == "owned_children_unreaped"
    assert adapter.started == 4 and adapter.reaped == 0 and len(adapter.plans) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("leaked_env", 1),
        ("leaked_fds", 1),
        ("known_syscall", False),
    ],
)
def test_env_fd_leaks_and_unknown_syscall_fail_closed(field, value):
    s = replace(step(), stimulus=replace(step().stimulus, **{field: value}))
    r = cf.run_case(config(), s, cf.FakeAdapter())
    assert r.observed in {cf.Disposition.FAIL, cf.Disposition.UNSUPPORTED}
    assert not r.model_matches


@pytest.mark.parametrize(
    "field,value",
    [
        ("pid", True),
        ("uid", 0),
        ("gid", -1),
        ("groups", [10001]),
        ("groups", (True,)),
        ("lifetime", "private/path"),
        ("exists", 1),
    ],
)
def test_malformed_peer_evidence_never_starts_children(field, value):
    s = step()
    s = replace(
        s, stimulus=replace(s.stimulus, peer=replace(s.stimulus.peer, **{field: value}))
    )
    adapter = cf.FakeAdapter()
    assert cf.run_case(config(), s, adapter).observed == cf.Disposition.BLOCKED
    assert not adapter.started


@pytest.mark.parametrize(
    "field,value",
    [
        ("fixture_sha256", "f" * 64),
        ("collector_sha256", "f" * 64),
        ("provenance", cf.Provenance.OPERATOR_REPORTED),
        ("provenance", cf.Provenance.INDEPENDENT_RETAINED),
        ("stdout", b"x" * 65537),
        ("stderr", b"x" * 65537),
        ("stderr", "raw error"),
        ("children", 5),
        ("children", True),
        ("elapsed_ms", True),
        ("complete", False),
        ("case", "injected; command"),
        ("stimulus", {"command": "arbitrary"}),
    ],
)
def test_invalid_or_unbounded_evidence_is_blocked(field, value):
    adapter = cf.FakeAdapter()
    r = cf.run_case(config(), replace(step(), **{field: value}), adapter)
    assert r.observed == cf.Disposition.BLOCKED
    assert not adapter.started


def test_combined_output_budget():
    adapter = cf.FakeAdapter()
    r = cf.run_case(
        config(), replace(step(), stdout=b"x" * 32769, stderr=b"y" * 32768), adapter
    )
    assert r.observed == cf.Disposition.BLOCKED and not adapter.started


@pytest.mark.parametrize(
    "field,value",
    [
        ("probe_ms", 5001),
        ("case_ms", 60001),
        ("output_bytes", 65537),
        ("probe_ms", 0),
        ("probe_ms", True),
        ("case_ms", 1),
        ("version", "unknown"),
    ],
)
def test_config_limits_cannot_be_widened(field, value):
    c = replace(config(), **{field: value})
    report = cf.run(c, cf.scenarios(config()))
    assert report.status == "BLOCKED" and report.identity is None
    assert json.loads(report.encode())["code"] == "invalid_evidence"


def test_missing_duplicate_and_unknown_cases_do_not_disappear():
    c = config()
    steps = cf.scenarios(c)
    for invalid in (
        steps[:-1],
        steps + (steps[0],),
        steps[::-1],
        list(steps),
        steps[:-1] + (steps[0],),
        (None,) * len(steps),
    ):
        assert cf.run(c, invalid).status == "BLOCKED"


def test_provenance_remains_operator_reported_not_independent_host_proof():
    c = config()
    fact = cf.Fact("kernel", cf.Provenance.OPERATOR_REPORTED, "a" * 64)
    c = replace(c, identity=replace(c.identity, facts=(fact, *c.identity.facts[1:])))
    report = cf.run(c, cf.scenarios(c))
    assert report.identity.facts[0].provenance == cf.Provenance.OPERATOR_REPORTED
    assert set(json.loads(report.encode())["host_matrix"].values()) == {"HOST_NOT_RUN"}
    fact = replace(fact, provenance=cf.Provenance.INDEPENDENT_RETAINED)
    c = replace(c, identity=replace(c.identity, facts=(fact, *c.identity.facts[1:])))
    assert cf.run(c, cf.scenarios(config())).status == "BLOCKED"


def test_report_redacts_fake_markers_private_paths_and_arbitrary_stderr():
    c = config()
    raw = b"fabricated-only marker /private/fixture env:FAKE_KEY random stderr"
    steps = tuple(replace(s, stdout=raw, stderr=raw) for s in cf.scenarios(c))
    encoded = cf.run(c, steps).encode()
    for fragment in (b"marker", b"/private", b"FAKE_KEY", b"stderr"):
        assert fragment not in encoded
    with pytest.raises(cf.FixtureError):
        replace(cf.run(c, steps), code=raw.decode()).encode()


def test_pure_harness_never_accesses_credentials_network_or_subprocesses(monkeypatch):
    import builtins
    import socket
    import subprocess

    c = config()
    steps = cf.scenarios(c)

    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected host I/O")

    with monkeypatch.context() as patch:
        for module, name in (
            (builtins, "open"),
            (os, "open"),
            (os, "system"),
            (os, "getenv"),
            (os, "kill"),
            (socket, "socket"),
            (subprocess, "Popen"),
        ):
            patch.setattr(module, name, forbidden)
        assert cf.run(c, steps).status == "VERIFIED_OFFLINE_FIXTURE"


def test_no_executable_adapter_or_cli_surface():
    assert not hasattr(cf, "main") and not hasattr(cf, "run_host")
    with pytest.raises(TypeError):
        cf.FakeAdapter(lambda: None)
    assert cf.run_case(config(), step(), object()).observed == cf.Disposition.BLOCKED


def test_disposable_lifecycle_owns_only_unique_created_objects(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sentinel = tmp_path / "preexisting"
    sentinel.write_bytes(os.urandom(16))
    content = sentinel.read_bytes()
    a, b = cf.DisposableFixture.create(), cf.DisposableFixture.create()
    assert a._name != b._name and len(list(tmp_path.iterdir())) == 3
    assert (tmp_path / a._name).stat().st_mode & 0o777 == 0o700
    assert (tmp_path / a._name / "marker").stat().st_mode & 0o777 == 0o600
    with pytest.raises(FrozenInstanceError):
        a._marker_pin.uid = 0
    assert a.cleanup() and b.cleanup() and not a.cleanup()
    assert list(tmp_path.iterdir()) == [sentinel] and sentinel.read_bytes() == content


@pytest.mark.parametrize(
    "mutation",
    ["extra", "symlink", "hardlink", "marker_bytes", "owner_mode", "directory_replace"],
)
def test_cleanup_refuses_drift_without_deleting_preexisting_or_unknown_data(
    tmp_path, monkeypatch, mutation
):
    monkeypatch.chdir(tmp_path)
    fixture = cf.DisposableFixture.create()
    directory = tmp_path / fixture._name
    marker = directory / "marker"
    sentinel = tmp_path / "sentinel"
    sentinel.write_bytes(os.urandom(32))
    before = sentinel.read_bytes()
    if mutation == "extra":
        (directory / "unexpected").write_text("inert")
    elif mutation == "symlink":
        marker.unlink()
        marker.symlink_to(sentinel)
    elif mutation == "hardlink":
        os.link(marker, tmp_path / "alias")
    elif mutation == "marker_bytes":
        marker.write_bytes(os.urandom(32))
    elif mutation == "owner_mode":
        directory.chmod(0o755)
    else:
        directory.rename(tmp_path / "preserved")
        directory.mkdir()
        (directory / "marker").write_bytes(os.urandom(32))
    assert not fixture.cleanup() and not fixture.cleanup()
    assert directory.exists() and sentinel.read_bytes() == before


def test_no_caller_path_cleanup_or_recursive_delete(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(TypeError):
        cf.DisposableFixture.create(tmp_path)
    tmp_path.chmod(0o777)
    with pytest.raises(cf.FixtureError, match="fixture_creation_uncertain"):
        cf.DisposableFixture.create()
    assert not list(tmp_path.iterdir())


def test_creation_partial_failure_retains_evidence_and_closes_fds(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    original_open = os.open
    fds = []

    def fail_marker(path, *args, **kwargs):
        if path == "marker":
            raise OSError("private error")
        fd = original_open(path, *args, **kwargs)
        fds.append(fd)
        return fd

    monkeypatch.setattr(os, "open", fail_marker)
    with pytest.raises(cf.FixtureError, match="^fixture_creation_uncertain$"):
        cf.DisposableFixture.create()
    assert len(list(tmp_path.iterdir())) == 1
    for fd in fds:
        with pytest.raises(OSError):
            os.fstat(fd)


def test_noninstallable_candidates_match_documentation_and_cp01_contract():
    candidates = cf.policy_candidates()
    path = Path(__file__).parents[1] / "docs/control-plane-policy-candidates.json"
    assert json.loads(path.read_text()) == json.loads(
        json.dumps(
            {
                "version": cf.VERSION,
                "status": "DESIGN_ONLY",
                "installable": False,
                "candidates": [asdict(c) for c in candidates],
            }
        )
    )
    assert cf.assess_policies(candidates).code == "host_mechanisms_unverified"
    forbidden = {
        "ExecStart",
        "ExecStartPre",
        "ExecStopPost",
        "WantedBy",
        "Install",
        "LoadCredential",
        "StateDirectory",
        "ConfigurationDirectory",
    }
    for candidate in candidates:
        assert not candidate.installable and candidate.attachment is None
        directives = dict(candidate.directives)
        assert not forbidden & directives.keys()
        assert directives["User"] == directives["Group"] == candidate.principal.value
        assert directives["SupplementaryGroups"] == "" and directives["UMask"] == "0077"
        assert directives["IPAddressDeny"] == "any" and directives["LimitCORE"] == "0"
        assert (
            directives["CapabilityBoundingSet"]
            == directives["AmbientCapabilities"]
            == ""
        )
        assert "gate_73" in candidate.unresolved
        if candidate.principal == cf.Role.SIGNER:
            assert candidate.writable_assets == ()
        if candidate.principal != cf.Role.CUSTODY:
            assert directives["RestrictAddressFamilies"] == "AF_UNIX"
    # Documentation is not a runnable unit/profile or package installation input.
    assert path.suffix == ".json"
    assert not list(path.parent.glob("agent-platform*.service"))


@pytest.mark.parametrize("change", ["unknown", "missing", "widen", "profile"])
def test_unknown_or_widened_candidate_policy_never_passes(change):
    candidates = cf.policy_candidates()
    p = candidates[0]
    if change == "unknown":
        p = replace(p, directives=(*p.directives, ("UnknownDirective", "yes")))
    elif change == "missing":
        p = replace(p, unresolved=())
    elif change == "widen":
        p = replace(
            p,
            directives=tuple(
                (k, "any") if k == "RestrictAddressFamilies" else (k, v)
                for k, v in p.directives
            ),
        )
    else:
        p = replace(p, apparmor_requirements=())
    result = cf.assess_policies((p, *candidates[1:]))
    assert result.status == "BLOCKED" and result.live == "LIVE_NO_GO"
    assert result.code == "invalid_or_unknown_candidate" and not result.installable


@pytest.mark.parametrize(
    "field", ["source_sha256", "policy_sha256", "fixture_sha256", "collector_sha256"]
)
def test_complete_configuration_binding_rejects_relabelled_evidence(field):
    c = config()
    steps = cf.scenarios(c)
    changed = replace(c, identity=replace(c.identity, **{field: "f" * 64}))
    assert cf.configuration_digest(c) != cf.configuration_digest(changed)
    assert cf.run(changed, steps).status == "BLOCKED"
    report = cf.run(changed, cf.scenarios(changed))
    raw = json.loads(report.encode())
    assert raw["configuration_sha256"] == cf.configuration_digest(changed)
    assert raw["configuration"]["probe_ms"] == 5000


def test_configuration_budget_is_bound_to_evidence():
    c = replace(config(), probe_ms=1000)
    assert cf.run(c, cf.scenarios(config())).status == "BLOCKED"
    assert cf.run(c, cf.scenarios(c)).status == "VERIFIED_OFFLINE_FIXTURE"


def test_invalid_report_cannot_smuggle_configuration_into_redacted_output():
    report = cf.Report("BLOCKED", "invalid_evidence", None, (), {"private": "bad"})
    with pytest.raises(cf.FixtureError):
        report.encode()


def test_suite_stops_after_uncertainty_and_retains_unexecuted_cases(monkeypatch):
    original = cf.FakeAdapter.execute
    calls = []

    def record(self, plan, step):
        calls.append(step.case)
        return original(self, plan, step)

    monkeypatch.setattr(cf.FakeAdapter, "execute", record)
    c = config()
    steps = cf.scenarios(c)
    steps = (replace(steps[0], elapsed_ms=5001), *steps[1:])
    report = cf.run(c, steps)
    assert calls == [cf.Case.OWN_READ]
    assert report.status == "BLOCKED"
    assert report.cases[0].observed == cf.Disposition.UNKNOWN
    assert all(
        r.observed == cf.Disposition.HOST_NOT_RUN and r.code == "after_stop"
        for r in report.cases[1:]
    )
    assert json.loads(report.encode())["status"] == "BLOCKED"


def test_full_suite_rejects_wrong_uid_case_replaced_by_wrong_gid_stimulus():
    c = config()
    steps = cf.scenarios(c)
    gid_stimulus = next(s.stimulus for s in steps if s.case == cf.Case.WRONG_GID)
    changed = tuple(
        replace(s, stimulus=gid_stimulus) if s.case == cf.Case.WRONG_UID else s
        for s in steps
    )
    variant = next(s for s in changed if s.case == cf.Case.WRONG_UID)
    # Ad-hoc variants are allowed, but this denial did not exercise WRONG_UID.
    assert variant.stimulus.peer.uid == cf.MODEL_PEER.uid
    assert variant.stimulus.peer.gid != cf.MODEL_PEER.gid
    assert cf.run_case(c, variant, cf.FakeAdapter()).observed == cf.Disposition.DENIED
    assert cf.run(c, changed).status == "BLOCKED"


@pytest.mark.parametrize("case", [cf.Case.OWN_READ, cf.Case.WRONG_UID])
def test_zero_children_never_proves_case_execution(case):
    c = config()
    s = replace(step(case), children=0)
    adapter = cf.FakeAdapter()
    r = cf.run_case(c, s, adapter)
    assert r.observed == cf.Disposition.BLOCKED and not r.model_matches
    assert not adapter.started and not adapter.plans
    steps = tuple(s if old.case == case else old for old in cf.scenarios(c))
    assert cf.run(c, steps).status == "BLOCKED"


@pytest.mark.parametrize(
    "code",
    [
        "invalid_evidence",
        "owned_children_unreaped",
        "cleanup_incomplete",
        "cancelled",
        "deadline",
        "model_mismatch",
        "after_stop",
    ],
)
def test_report_rejects_failure_code_on_successful_disposition(code):
    c = config()
    report = cf.run(c, cf.scenarios(c))
    first = replace(report.cases[0], code=code)
    report = replace(report, cases=(first, *report.cases[1:]))
    with pytest.raises(cf.FixtureError):
        report.encode()


@pytest.mark.parametrize(
    "field,value",
    [
        ("live", "LIVE_GO"),
        ("gate_73", "PASS"),
        ("launch_allowed", True),
        ("launch_allowed", 0),
        ("version", "AP-CF/unknown"),
    ],
)
@pytest.mark.parametrize("blocked", [False, True])
def test_serialization_rechecks_security_fields_even_on_frozen_objects(
    field, value, blocked
):
    c = config()
    report = cf.run(c, () if blocked else cf.scenarios(c))
    object.__setattr__(report, field, value)
    with pytest.raises(cf.FixtureError):
        report.encode()


def test_report_rejects_mutated_case_host_disposition():
    c = config()
    report = cf.run(c, cf.scenarios(c))
    object.__setattr__(report.cases[0], "host", cf.Disposition.PASS)
    with pytest.raises(cf.FixtureError):
        report.encode()


def test_report_rejects_resumed_results_after_stop():
    c = config()
    steps = cf.scenarios(c)
    good = cf.run(c, steps)
    stopped = cf.run(c, (replace(steps[0], elapsed_ms=5001), *steps[1:]))
    # Every row after the first failure must remain after_stop, not a later PASS.
    resumed = replace(stopped, cases=(stopped.cases[0], *good.cases[1:]))
    with pytest.raises(cf.FixtureError):
        resumed.encode()


def test_execution_must_account_for_started_and_reaped_children(monkeypatch):
    # A return value alone must not fabricate completed execution.
    monkeypatch.setattr(cf.FakeAdapter, "execute", lambda *a: True)
    result = cf.run_case(config(), step(), cf.FakeAdapter())
    assert not result.model_matches and result.observed == cf.Disposition.FAIL


@pytest.mark.parametrize(
    "field,value",
    [
        ("elapsed_ms", 5001),
        ("cleanup_complete", False),
        ("cancelled", True),
        ("complete", False),
        ("children", 0),
        ("can_reap", False),
    ],
)
def test_valid_failure_report_encodes_closed_dispositions_and_stop_suffix(field, value):
    c = config()
    steps = cf.scenarios(c)
    report = cf.run(c, (replace(steps[0], **{field: value}), *steps[1:]))
    assert report.status == "BLOCKED"
    assert report.cases[0].code != "after_stop"
    assert all(r.code == "after_stop" for r in report.cases[1:])
    assert json.loads(report.encode())["status"] == "BLOCKED"


@pytest.mark.parametrize(
    "field,value",
    [
        ("code", "invalid_evidence"),
        ("code", "owned_children_unreaped"),
        ("code", "model_match"),
        ("code", "model_mismatch"),
        ("observed", cf.Disposition.FAIL),
        ("model_matches", True),
    ],
)
def test_report_rejects_inconsistent_first_failure(field, value):
    c = config()
    steps = cf.scenarios(c)
    report = cf.run(c, (replace(steps[0], elapsed_ms=5001), *steps[1:]))
    first = replace(report.cases[0], **{field: value})
    with pytest.raises(cf.FixtureError):
        replace(report, cases=(first, *report.cases[1:])).encode()


def test_after_stop_cannot_appear_before_failure_or_be_replaced_by_second_failure():
    c = config()
    steps = cf.scenarios(c)
    report = cf.run(c, (replace(steps[0], elapsed_ms=5001), *steps[1:]))
    uncaused = replace(
        report.cases[0], observed=cf.Disposition.HOST_NOT_RUN, code="after_stop"
    )
    with pytest.raises(cf.FixtureError):
        replace(report, cases=(uncaused, *report.cases[1:])).encode()
    second_failure = replace(
        report.cases[1], observed=cf.Disposition.UNKNOWN, code="deadline"
    )
    with pytest.raises(cf.FixtureError):
        replace(
            report, cases=(report.cases[0], second_failure, *report.cases[2:])
        ).encode()


@pytest.mark.parametrize(
    "fault", ["started", "reaped", "plans", "boolean_counter", "non_boolean_return"]
)
def test_partial_execution_accounting_never_produces_model_pass(monkeypatch, fault):
    original = cf.FakeAdapter.execute

    def incomplete(self, plan, step):
        original(self, plan, step)
        if fault == "started":
            self.started += 1
        elif fault == "reaped":
            self.reaped -= 1
        elif fault == "plans":
            self.plans.clear()
        elif fault == "boolean_counter":
            self.started = True
        else:
            return 1
        return True

    monkeypatch.setattr(cf.FakeAdapter, "execute", incomplete)
    result = cf.run_case(config(), step(), cf.FakeAdapter())
    assert result.observed == cf.Disposition.FAIL
    assert result.code == "execution_incomplete" and not result.model_matches


def test_complete_multi_child_variant_is_still_bounded_and_accounted():
    adapter = cf.FakeAdapter()
    r = cf.run_case(config(), replace(step(), children=4), adapter)
    assert r.model_matches and adapter.started == adapter.reaped == 4


def test_canonical_comparison_validates_nested_types_before_equality():
    class UntrustedPeer:
        def __eq__(self, other):
            pytest.fail("invalid nested object must not participate in comparison")

    c = config()
    steps = cf.scenarios(c)
    malformed = replace(
        steps[0], stimulus=replace(steps[0].stimulus, peer=UntrustedPeer())
    )
    assert cf.run(c, (malformed, *steps[1:])).status == "BLOCKED"
