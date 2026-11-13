"""Fabricated PUB-01 artifacts/authority/CAS/history only; never real GitHub."""

import ast
import base64
import hashlib
import json
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest
from test_publisher_candidate import fixture, obj

from agent_platform import draft_publisher as dp
from agent_platform import publisher_candidate as pc
from agent_platform import publisher_handoff as ph


def wire(candidate, *, pr_number=7):
    d = json.loads(candidate.descriptor)
    return json.dumps(
        {
            "version": ph.VERSION,
            "pr_number": pr_number,
            "parent": d["expected_old"],
            "descriptor": base64.b64encode(candidate.descriptor).decode(),
            "objects": [
                {"oid": o.oid, "data": base64.b64encode(o.canonical).decode()}
                for o in candidate.objects
            ],
        },
        sort_keys=True,
    ).encode()


def pin(data, policy):
    return replace(policy, artifact_sha256=hashlib.sha256(data).hexdigest())


class Crash(BaseException):
    pass


class Ports:
    """Explicit in-memory simulation, NOT durable storage or an isolation proof."""

    def __init__(self, candidate, policy):
        self.candidate, self.policy = candidate, policy
        self.tip = policy.publication.candidate.expected_old
        self.prior_tip = self.tip  # prior publication's retained exact tip
        self.guards = set()
        self.pending = None
        self.intents, self.results, self.effects = [], [], []
        self.objects = {}
        self.allowed = self.durable = self.confirm = True
        self.claimed = False
        self.transform = lambda value: value
        self.ancestors = ()
        self.fail = None
        self.race = False
        self.on_unknown = lambda: None

    def validate(self, request):
        return self.allowed

    def claim(self, request):
        p = request.policy.publication.candidate
        keys = {
            (p.repo_id, "issue", p.issue_id),
            (p.repo_id, "ref", p.feature_ref),
            (p.repo_id, "pr", request.policy.pr_number),
        }
        if keys & self.guards or request.parent != self.prior_tip:
            return False
        self.guards |= keys
        self.claimed = True
        if self.fail == "claim":
            raise TimeoutError("FAKE_PRIVATE_DO_NOT_PRINT")
        return True

    def unknown(self, intent):
        assert self.claimed and self.pending is None
        assert intent.sequence == len(self.results) + 1
        assert intent.request_digest == self.request_digest
        self.intents.append(intent)
        self.pending = intent
        self.on_unknown()
        return self.durable

    def confirmed(self, intent, digest):
        assert self.pending == intent
        if self.confirm:
            self.results.append((intent, digest))
            self.pending = None
        return self.confirm

    def observe(self, request):
        pub, p = request.policy.publication, request.policy.publication.candidate
        snapshot = ph.Snapshot(
            dp.Observation(
                p.repository,
                p.repo_id,
                pub.owner_id,
                p.issue,
                p.issue_id,
                p.scope,
                True,
                pub.app_id,
                pub.installation_id,
                pub.bot_id,
                pub.bot_login,
                dp.PERMISSIONS,
                (p.repo_id,),
                "main",
                p.base_sha,
                p.feature_ref,
                self.tip,
                (request.policy.pr_number,),
                True,
                True,
                True,
                pub.app_owner_id,
                pub.owner_id,
                "selected",
                True,
                (),
            ),
            dp.PullRequest(
                request.policy.pr_number,
                p.repo_id,
                p.repo_id,
                p.repo_id,
                p.feature_ref[11:],
                self.tip,
                "main",
                p.base_sha,
                pub.bot_id,
                pub.bot_login,
                pub.app_id,
                True,
                True,
                request.policy.title,
                request.policy.body,
                (p.issue_id,),
            ),
            self.ancestors,
            True,
            True,
            True,
        )
        return self.transform(snapshot)

    def effect(self, name):
        assert self.pending is not None and self.pending.operation == name
        assert self.durable
        self.effects.append(name)
        if self.fail == name:
            raise TimeoutError("FAKE_PRIVATE_DO_NOT_PRINT")
        if self.fail == "crash:" + name:
            raise Crash

    def create_object(self, request, value):
        self.effect("create_object")
        self.objects[value.oid] = value
        return value.oid

    def read_object(self, request, oid):
        return self.objects[oid]

    def compare_exchange(self, request):
        self.effect("compare_exchange")
        if self.race:
            self.tip = "f" * 40  # another writer wins after the last GET
        if self.tip != request.parent:
            raise ValueError("compare failed")
        # Actual single-parent bytes were validated against this parent by CP-03.
        self.tip = request.commit
        return self.tip


def setup(candidate=None, cp=None):
    if candidate is None:
        candidate, cp = fixture(operation="update")
    data = wire(candidate)
    pub = dp.Policy(cp, 10, 20, 30, 40, "fixture[bot]", "c" * 64, 200, 50)
    policy = ph.Policy(
        pub,
        7,
        hashlib.sha256(data).hexdigest(),
        "Issue fixture",
        f"Closes #{cp.issue}\n",
    )
    ports = Ports(candidate, policy)
    request = ph.intake(data, policy, now=100)
    ports.request_digest = None if request is None else request.digest
    return data, policy, ports


def run(data, policy, ports):
    result = ph.update_fixture(
        data, policy, now=100, admission=ports, journal=ports, api=ports
    )
    encoded = result.encode()
    assert b"FAKE_PRIVATE" not in encoded and len(encoded) < 1024
    assert result.live == "LIVE_NO_GO" and result.host == "HOST_NOT_RUN"
    assert result.gate_73 == "BLOCKED" and result.live_authorized is False
    assert result.encode() == encoded
    return result


def test_end_to_end_exact_commit_and_replay():
    data, policy, ports = setup()
    request = ph.intake(data, policy, now=100)
    assert pc.verify(request.candidate, policy.publication.candidate).code == (
        "remote_update_unverified"
    )  # CP-03 gate unchanged
    result = run(data, policy, ports)
    assert result == ph.Result("UPDATED_OFFLINE_FIXTURE", "verified_draft_update", 4)
    assert ports.tip == request.commit
    assert [i.sequence for i in ports.intents] == [1, 2, 3, 4]
    assert ports.effects == ["create_object"] * 3 + ["compare_exchange"]
    assert len(ports.results) == 4 and ports.pending is None
    assert {o.oid: o for o in request.candidate.objects} == ports.objects
    assert run(data, policy, ports).status == "UNKNOWN_NEEDS_HUMAN"
    assert len(ports.effects) == 4
    with pytest.raises(FrozenInstanceError):
        result.live_authorized = True
    assert "c" * 64 not in repr(request) + repr(policy) + repr(result)


def test_old_tip_has_independently_read_exact_base_ancestry():
    c, cp = fixture(operation="update")
    original_commit = c.objects[-1]
    cp = replace(cp, expected_old=original_commit.oid)
    descendant = obj(
        "commit",
        original_commit.canonical.split(b"\0", 1)[1].replace(
            b"parent " + b"a" * 40, b"parent " + original_commit.oid.encode()
        ),
    )
    descriptor = json.loads(c.descriptor) | {
        "expected_old": cp.expected_old,
        "commit": descendant.oid,
    }
    c = replace(
        c,
        descriptor=json.dumps(descriptor).encode(),
        objects=c.objects[:-1] + (descendant,),
    )
    data, policy, ports = setup(c, cp)
    ports.ancestors = (original_commit,)
    assert run(data, policy, ports).status == "UPDATED_OFFLINE_FIXTURE"


@pytest.mark.parametrize(
    "value",
    [
        None,
        "{}",
        Path("/never/read/worker"),
        b"",
        b"{}",
        b"[]",
        b"null",
        b"{",
        b"PACK",
        b"# v2 git bundle\n",
        b"x" * (ph.MAX_ARTIFACT + 1),
    ],
)
def test_no_paths_bundles_execution_or_unbounded_intake(value):
    _, policy, ports = setup()
    assert run(value, policy, ports).status == "BLOCKED"
    assert not ports.claimed and not ports.effects


@pytest.mark.parametrize(
    "key,value",
    [
        ("version", "unknown"),
        ("pr_number", True),
        ("pr_number", 8),
        ("parent", "f" * 40),
        ("descriptor", "!!!!"),
        ("objects", []),
        ("command", "git push"),
        ("url", "https://evil.invalid"),
        ("token", "FAKE_PRIVATE"),
        ("path", "/worker/.git"),
        ("symlink", "/etc/shadow"),
        ("nlink", 2),
        ("force", True),
        ("operation", "merge"),
        ("method", "PATCH"),
    ],
)
def test_untrusted_envelope_is_closed_even_if_digest_is_repinned(key, value):
    data, policy, ports = setup()
    data = json.dumps(json.loads(data) | {key: value}).encode()
    assert run(data, pin(data, policy), ports).status == "BLOCKED"
    assert not ports.claimed


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: d.replace(
            b'"version": "AP-PH/1"', b'"version":"AP-PH/1","version":"AP-PH/1"'
        ),
        lambda d: d[:-1],
        lambda d: b"\xff" + d,
        lambda d: d.decode().encode("utf-16"),
    ],
)
def test_duplicate_truncated_and_non_utf8_artifact(mutation):
    data, policy, ports = setup()
    data = mutation(data)
    assert run(data, pin(data, policy), ports).status == "BLOCKED"


@pytest.mark.parametrize(
    "change",
    [
        {"repo_id": 2},
        {"repository": "other/repo"},
        {"issue": 92},
        {"issue_id": 101},
        {"scope": "f" * 64},
        {"base_sha": "f" * 40},
        {"feature_ref": "refs/heads/main"},
        {"feature_ref": "refs/tags/release"},
        {"feature_ref": "refs/heads/feature/issue-91-../../main"},
        {"expected_old": "f" * 40},
        {"operation": "create"},
        {"commit": "f" * 40},
        {"tree": "f" * 40},
        {"force": False},
        {"remote_verified": True},
    ],
)
def test_candidate_identity_ref_hash_and_authority_cannot_be_changed(change):
    c, cp = fixture(operation="update")
    c = replace(c, descriptor=json.dumps(json.loads(c.descriptor) | change).encode())
    data, policy, ports = setup(c, cp)
    assert run(data, policy, ports).status == "BLOCKED" and not ports.claimed


@pytest.mark.parametrize(
    "names,mode",
    [
        (("../outside",), "100644"),
        (("dir/file",), "100644"),
        ((".git",), "100644"),
        (("file.lock",), "100644"),
        (("A", "a"), "100644"),
        (("link",), "120000"),
        (("module",), "160000"),
        (("executable",), "100755"),
    ],
)
def test_links_aliases_nested_trees_and_unapproved_executables_block(names, mode):
    c, cp = fixture(names=names, mode=mode, operation="update")
    assert run(*setup(c, cp)).status == "BLOCKED"


@pytest.mark.parametrize(
    "extra", [b"parent " + b"a" * 40 + b"\n", b"gpgsig fake\n", b"encoding UTF-8\n"]
)
def test_unsupported_commit_complexity_is_not_transformed(extra):
    c, cp = fixture(operation="update", extra=extra)
    assert run(*setup(c, cp)).status == "BLOCKED"


@pytest.mark.parametrize(
    "field,value",
    [
        ("app_id", 11),
        ("bot_id", 41),
        ("installation_id", 21),
        ("app_owner_id", 51),
        ("repo_id", 2),
        ("owner_id", 31),
        ("installation_account_id", 31),
        ("repository", "other/repo"),
        ("issue_open", False),
        ("issue_id", 101),
        ("issue", 92),
        ("scope", "f" * 64),
        ("base_sha", "f" * 40),
        ("base_branch", "release"),
        ("feature_sha", "f" * 40),
        ("feature_ref", "refs/heads/main"),
        ("prs", (7, 8)),
        ("complete", False),
        ("app_attribution_verified", False),
        ("governance_verified", False),
        ("installation_active", False),
        ("repository_selection", "all"),
        ("repositories", (1, 2)),
        ("permissions", dp.PERMISSIONS + (("issues", "write"),)),
        ("events", ("push",)),
        ("repo_id", True),
    ],
)
def test_independent_observation_drift_retains_claim_without_writes(field, value):
    data, policy, ports = setup()
    ports.transform = lambda s: replace(s, remote=replace(s.remote, **{field: value}))
    assert run(data, policy, ports).status == "UNKNOWN_NEEDS_HUMAN"
    assert ports.claimed and not ports.effects
    ports.transform = lambda s: s
    assert run(data, policy, ports).status == "UNKNOWN_NEEDS_HUMAN"
    assert not ports.effects


@pytest.mark.parametrize(
    "field,value",
    [
        ("number", 8),
        ("draft", False),
        ("open", False),
        ("head_repo_id", 2),
        ("base_repo_id", 2),
        ("head_ref", "main"),
        ("head_sha", "f" * 40),
        ("base_sha", "f" * 40),
        ("author_id", 41),
        ("author_login", "other[bot]"),
        ("app_id", 11),
        ("linked_issue_ids", (100, 101)),
        ("title", "changed"),
        ("body", "Closes #92"),
    ],
)
def test_exact_same_repo_open_draft_and_native_issue_link_required(field, value):
    data, policy, ports = setup()
    ports.transform = lambda s: replace(s, pr=replace(s.pr, **{field: value}))
    assert run(data, policy, ports).status == "UNKNOWN_NEEDS_HUMAN"
    assert not ports.effects


@pytest.mark.parametrize(
    "field",
    ["publisher_isolation_verified", "app_merge_denied", "atomic_compare_verified"],
)
@pytest.mark.parametrize("value", [False, None, 1])
def test_missing_safety_evidence_does_not_authorize_even_simulated_effect(field, value):
    data, policy, ports = setup()
    ports.transform = lambda s: replace(s, **{field: value})
    assert run(data, policy, ports).status == "UNKNOWN_NEEDS_HUMAN"
    assert not ports.effects
    assert ph.live_readiness().status == "BLOCKED"


@pytest.mark.parametrize("point", ["claim", "create_object", "compare_exchange"])
def test_ambiguous_failure_is_unknown_and_not_replayed(point):
    data, policy, ports = setup()
    ports.fail = point
    result = run(data, policy, ports)
    assert result.status == "UNKNOWN_NEEDS_HUMAN"
    count = len(ports.effects)
    ports.fail = None
    assert run(data, policy, ports).status == "UNKNOWN_NEEDS_HUMAN"
    assert len(ports.effects) == count


@pytest.mark.parametrize("point", ["create_object", "compare_exchange"])
def test_crash_keeps_unknown_and_stable_guards(point):
    data, policy, ports = setup()
    ports.fail = "crash:" + point
    with pytest.raises(Crash):
        run(data, policy, ports)
    assert ports.pending is not None
    ports.fail = None
    assert run(data, policy, ports).status == "UNKNOWN_NEEDS_HUMAN"


@pytest.mark.parametrize("field", ["durable", "confirm", "allowed"])
def test_missing_admission_or_journal_confirmation_stops(field):
    data, policy, ports = setup()
    setattr(ports, field, False)
    result = run(data, policy, ports)
    assert result.status == ("BLOCKED" if field == "allowed" else "UNKNOWN_NEEDS_HUMAN")
    assert not ports.effects if field != "confirm" else len(ports.effects) == 1


def test_revocation_after_unknown_prevents_dispatch():
    data, policy, ports = setup()
    ports.on_unknown = lambda: setattr(ports, "allowed", False)
    assert run(data, policy, ports).status == "UNKNOWN_NEEDS_HUMAN"
    assert ports.pending is not None and not ports.effects


def test_head_race_after_read_is_atomically_rejected_not_unconditional_patch():
    data, policy, ports = setup()
    ports.race = True
    assert run(data, policy, ports).status == "UNKNOWN_NEEDS_HUMAN"
    assert ports.tip == "f" * 40 and ports.pending.operation == "compare_exchange"
    count = len(ports.effects)
    assert run(data, policy, ports).status == "UNKNOWN_NEEDS_HUMAN"
    assert len(ports.effects) == count


def test_lost_or_conflicting_prior_publication_history_blocks():
    data, policy, ports = setup()
    ports.prior_tip = None
    assert run(data, policy, ports).status == "UNKNOWN_NEEDS_HUMAN"
    assert not ports.effects


def test_rotation_cannot_escape_repo_task_ref_pr_guard():
    data, policy, ports = setup()
    ports.fail = "create_object"
    assert run(data, policy, ports).status == "UNKNOWN_NEEDS_HUMAN"
    rotated = replace(
        policy,
        publication=replace(
            policy.publication, app_id=11, installation_id=21, authorization="d" * 64
        ),
    )
    assert run(data, rotated, ports).status == "UNKNOWN_NEEDS_HUMAN"
    assert len(ports.effects) == 1


@pytest.mark.parametrize(
    "ancestors",
    [
        None,
        (),
        (pc.GitObject("f" * 40, b"tag 0\0"),),
        (pc.GitObject("f" * 40, b"commit 0\0"),) * 33,
    ],
)
def test_missing_or_unsafe_independent_ancestry_refuses(ancestors):
    c, cp = fixture(operation="update")
    cp = replace(cp, base_sha="f" * 40)
    c = replace(
        c,
        descriptor=json.dumps(
            json.loads(c.descriptor) | {"base_sha": cp.base_sha}
        ).encode(),
    )
    data, policy, ports = setup(c, cp)
    ports.ancestors = ancestors
    assert run(data, policy, ports).status == "UNKNOWN_NEEDS_HUMAN"
    assert not ports.effects


def test_post_cas_pr_drift_stops_without_success_or_rollback():
    data, policy, ports = setup()
    ports.transform = lambda s: (
        replace(s, pr=replace(s.pr, draft=False))
        if (ports.tip != policy.publication.candidate.expected_old)
        else s
    )
    result = run(data, policy, ports)
    assert result.status == "UNKNOWN_NEEDS_HUMAN" and result.completed_writes == 3
    assert ports.pending.operation == "compare_exchange"


def test_readback_mismatch_stops_before_ref_effect():
    data, policy, ports = setup()
    ports.read_object = lambda *args: pc.GitObject("f" * 40, b"FAKE_PRIVATE")
    assert run(data, policy, ports).status == "UNKNOWN_NEEDS_HUMAN"
    assert ports.effects == ["create_object"]


@pytest.mark.parametrize("times", [[0, 0, 6], [0, 0, -1], [0, 60]])
def test_late_or_reversed_clock_refuses_before_claim(monkeypatch, times):
    monkeypatch.setattr(ph, "monotonic", iter(times).__next__)
    data, policy, ports = setup()
    assert run(data, policy, ports).status == "BLOCKED"
    assert not ports.claimed and not ports.effects


@pytest.mark.parametrize(
    "change",
    [
        {"expires": 100},
        {"expires": 401},
        {"expires": True},
        {"authorization": "model PASS"},
    ],
)
def test_expired_or_forged_policy_is_not_authority(change):
    data, policy, ports = setup()
    policy = replace(policy, publication=replace(policy.publication, **change))
    assert run(data, policy, ports).status == "BLOCKED"


def test_new_module_has_no_filesystem_process_network_or_credential_imports():
    source = Path(ph.__file__).read_text()
    tree = ast.parse(source)
    imports = {
        node.names[0].name for node in ast.walk(tree) if isinstance(node, ast.Import)
    }
    assert imports == {"base64", "hashlib", "json", "re"}
    functions = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
    assert not functions & {"main", "run", "serve", "load_credentials"}
    assert set(ph.FixtureAPI.__dict__) & {"create_object", "compare_exchange"} == {
        "create_object",
        "compare_exchange",
    }
    for name in (
        "merge",
        "approve",
        "ready",
        "close_issue",
        "delete",
        "force_push",
        "patch",
        "request",
        "execute",
        "create_draft",
    ):
        assert name not in ph.FixtureAPI.__dict__
    assert ph.live_readiness().encode() == ph.live_readiness().encode()


@pytest.mark.parametrize(
    "kind",
    [
        "descriptor",
        "object",
        "count",
        "extra",
        "tag",
        "bad_hash",
        "bad_header",
        "duplicate",
        "base64",
    ],
)
def test_bounded_object_container_and_canonical_bytes(kind):
    data, policy, ports = setup()
    raw = json.loads(data)
    if kind == "descriptor":
        raw["descriptor"] = base64.b64encode(b"x" * (pc.MAX_DESCRIPTOR + 1)).decode()
    elif kind == "object":
        raw["objects"][0]["data"] = base64.b64encode(
            b"x" * (pc.MAX_OBJECT + 1)
        ).decode()
    elif kind == "count":
        raw["objects"] *= 44
    elif kind == "extra":
        raw["objects"][0]["path"] = "/private/do-not-open"
    elif kind == "duplicate":
        raw["objects"].append(raw["objects"][0])
    elif kind == "bad_hash":
        raw["objects"][0]["oid"] = "f" * 40
    elif kind == "base64":
        raw["objects"][0]["data"] += "\n"
    else:
        raw["objects"][0]["data"] = base64.b64encode(
            b"tag 0\0" if kind == "tag" else b"blob 09\0incomplete"
        ).decode()
    data = json.dumps(raw).encode()
    assert run(data, pin(data, policy), ports).status == "BLOCKED"
    assert not ports.effects and not ports.claimed


def test_malicious_blob_bytes_are_only_data_without_worktree_or_io(monkeypatch, capsys):
    import builtins
    import os
    import socket
    import subprocess

    c, cp = fixture(operation="update")
    blob = obj("blob", b"FAKE_PRIVATE; git push; $(evil); import os; /etc/shadow\n")
    old_blob, old_tree, old_commit = c.objects
    tree = obj(
        "tree",
        old_tree.canonical.split(b"\0", 1)[1].replace(
            bytes.fromhex(old_blob.oid), bytes.fromhex(blob.oid)
        ),
    )
    commit = obj(
        "commit",
        old_commit.canonical.split(b"\0", 1)[1].replace(
            old_tree.oid.encode(), tree.oid.encode()
        ),
    )
    d = json.loads(c.descriptor) | {"tree": tree.oid, "commit": commit.oid}
    d["inventory"][0]["oid"] = blob.oid
    c = pc.Candidate(json.dumps(d).encode(), (commit, blob, tree))
    data, policy, ports = setup(c, cp)

    def forbidden(*args, **kwargs):
        pytest.fail("unexpected I/O")

    with monkeypatch.context() as m:
        for owner, name in (
            (builtins, "open"),
            (os, "open"),
            (socket, "socket"),
            (subprocess, "Popen"),
            (Path, "open"),
        ):
            m.setattr(owner, name, forbidden)
        result = run(data, policy, ports)
    assert result.status == "UPDATED_OFFLINE_FIXTURE"
    assert ports.objects[blob.oid].canonical == blob.canonical
    assert b"FAKE_PRIVATE" not in result.encode()
    assert capsys.readouterr() == ("", "")


def test_no_fspath_or_arbitrary_object_protocol_is_evaluated():
    class Hostile:
        def __fspath__(self):
            pytest.fail("path traversal")

        def __bytes__(self):
            pytest.fail("arbitrary conversion")

    _, policy, ports = setup()
    assert run(Hostile(), policy, ports).status == "BLOCKED"
    assert not ports.claimed


def test_static_requirements_are_inert_and_live_schema_is_unverified():
    root = Path(__file__).resolve().parents[1]
    raw = json.loads(
        (root / "docs/publisher-handoff-policy-candidates.json").read_bytes()
    )
    assert set(raw) == {
        "version",
        "status",
        "installable",
        "host",
        "live",
        "systemd_requirements",
        "apparmor_requirements",
        "cas_research",
    }
    assert raw["version"] == ph.VERSION and raw["status"] == "DESIGN_ONLY"
    assert raw["installable"] is False
    assert raw["live"] == "LIVE_NO_GO" and raw["host"] == "HOST_NOT_RUN"
    assert set(raw["systemd_requirements"]) == {
        "principal",
        "credential_custody",
        "filesystem",
        "process",
        "resources",
        "privileges",
        "network",
        "activation",
    }
    assert set(raw["apparmor_requirements"]) == {
        "attachment",
        "deny",
        "positive_controls",
        "negative_controls",
    }
    research = raw["cas_research"]
    assert research["semantics_verified"] is False
    assert research["permissions_verified"] is False
    assert research["official_schema_sha256"] is None
    assert research["live_disposition"] == "BLOCKED"
    assert research["retrieval_status"] == "RETRIEVED_PUBLIC_DOCS"
    assert research["reference_urls"] == [
        "https://docs.github.com/en/graphql/reference/git#updaterefs",
        "https://docs.github.com/en/graphql/reference/git#refupdate",
        "https://docs.github.com/en/rest/git/refs#update-a-reference",
    ]
    assert research["documentation_semantics_confirmed"] is True
    assert [(s["bytes"], s["sha256"]) for s in research["sources"]] == [
        (292354, "c002899a9a9b6bbf768e3d99ae16851c76f6aa5da9c631f35e8e27b62f05c2e5"),
        (346513, "cbb59d21990457059e3757b69dac64265ceb63f66fec06ee130fffa6872193c1"),
    ]
    # Requirement strings, never loadable unit/profile files or executable commands.
    data = json.dumps(raw)
    for syntax in ("[Service]", "ExecStart=", "profile ap-", "BEGIN PRIVATE KEY"):
        assert syntax not in data


@pytest.mark.parametrize(
    "field,value",
    [
        ("live", "GO"),
        ("host", "HOST_PASS"),
        ("gate_73", "PASS"),
        ("live_authorized", True),
        ("completed_writes", True),
        ("status", "PUBLISHED"),
        ("code", "/private/FAKE_PRIVATE"),
    ],
)
def test_results_refuse_forged_safety_constants(field, value):
    result = ph.live_readiness()
    object.__setattr__(result, field, value)
    with pytest.raises(Exception, match="^handoff_blocked$"):
        result.encode()


@pytest.mark.parametrize("point", ["create_object", "compare_exchange"])
def test_effect_applied_but_reply_lost_never_retries(point):
    data, policy, ports = setup()
    original = getattr(ports, point)

    def lost(*args):
        original(*args)
        raise TimeoutError("FAKE_PRIVATE reply lost after effect")

    setattr(ports, point, lost)
    result = run(data, policy, ports)
    assert result.status == "UNKNOWN_NEEDS_HUMAN" and ports.pending is not None
    if point == "compare_exchange":
        assert ports.tip == ph.intake(data, policy, now=100).commit
        assert result.completed_writes == 3
    else:
        assert len(ports.objects) == 1 and result.completed_writes == 0
    before = tuple(ports.effects)
    assert run(data, policy, ports).status == "UNKNOWN_NEEDS_HUMAN"
    assert tuple(ports.effects) == before


def test_physical_symlink_and_hardlink_paths_are_not_intake(tmp_path):
    data, policy, ports = setup()
    original = tmp_path / "fixture"
    original.write_bytes(data)
    symlink = tmp_path / "symlink"
    symlink.symlink_to(original)
    hardlink = tmp_path / "hardlink"
    hardlink.hardlink_to(original)
    before = original.stat()
    for path in (original, symlink, hardlink):
        assert run(path, policy, ports).status == "BLOCKED"
    assert original.stat() == before
    assert original.read_bytes() == data
    assert symlink.is_symlink() and hardlink.stat().st_nlink == 2
    assert not ports.claimed and not ports.effects


@pytest.mark.parametrize("field", ["expected_old", "base_sha"])
def test_zero_oid_absence_or_delete_semantics_are_not_existing_ref_updates(field):
    c, cp = fixture(operation="update")
    cp = replace(cp, **{field: "0" * 40})
    d = json.loads(c.descriptor) | {field: "0" * 40}
    if field == "expected_old":
        commit = obj(
            "commit",
            c.objects[-1]
            .canonical.split(b"\0", 1)[1]
            .replace(b"parent " + b"a" * 40, b"parent " + b"0" * 40),
        )
        c = replace(c, objects=c.objects[:-1] + (commit,))
        d["commit"] = commit.oid
    c = replace(c, descriptor=json.dumps(d).encode())
    assert pc.verify(c, cp).code == "remote_update_unverified"
    data, policy, ports = setup(c, cp)
    assert run(data, policy, ports).status == "BLOCKED"
    assert not ports.claimed and not ports.effects
