"""Fabricated CP-05 transaction ports; no network or credentials."""

from dataclasses import FrozenInstanceError, replace

import pytest
from test_publisher_candidate import change, fixture

from agent_platform import draft_publisher as dp


class Crash(BaseException):
    pass


class Ports:
    def __init__(self, candidate, policy):
        self.candidate, self.policy = candidate, policy
        self.wire_calls = []
        self.claimed = False
        self.claim_history = []
        self.intents = []
        self.results = []
        self.calls = []
        self.objects = {}
        self.ref = None
        self.prs = ()
        self.allowed = self.durable = self.confirm = True
        self.mutate = self.pr_mutate = lambda v: v
        self.fail = None

    def validate(self, r):
        return self.allowed

    def claim(self, *pins):
        if self.claimed:
            return False
        self.claimed = True
        self.claim_history.append(pins)
        return True

    def unknown(self, intent):
        self.intents.append(intent)
        return self.durable

    def confirmed(self, intent, digest):
        self.results.append((intent, digest))
        return self.confirm

    def observe(self, r):
        p, c = r.policy, r.policy.candidate
        return self.mutate(
            dp.Observation(
                c.repository,
                c.repo_id,
                p.owner_id,
                c.issue,
                c.issue_id,
                c.scope,
                True,
                p.app_id,
                p.installation_id,
                p.bot_id,
                p.bot_login,
                dp.PERMISSIONS,
                (c.repo_id,),
                "main",
                c.base_sha,
                c.feature_ref,
                self.ref,
                self.prs,
                True,
                True,
                True,
                p.app_owner_id,
                p.owner_id,
                "selected",
                True,
                (),
            )
        )

    def effect(self, name):
        assert self.durable
        assert len(self.intents) == len(self.calls) + 1
        assert self.intents[-1].operation == name
        self.calls.append(name)
        if self.fail == name:
            raise TimeoutError("secret remote response")
        if self.fail == "crash:" + name:
            raise Crash

    def wire(self, operation, method, path, *, pr_number=None, **metadata):
        route = dp.Route(operation, method, path, **metadata)
        assert dp.route_allowed(
            self.candidate, self.policy, route, now=100, pr_number=pr_number
        )
        self.wire_calls.append(route)

    def create_object(self, r, obj):
        kind = obj.canonical.split(b" ", 1)[0].decode()
        op = {
            "blob": dp.RouteOperation.CREATE_BLOB,
            "tree": dp.RouteOperation.CREATE_TREE,
            "commit": dp.RouteOperation.CREATE_COMMIT,
        }[kind]
        self.wire(op, "POST", f"/repos/{r.policy.candidate.repository}/git/{kind}s")
        self.effect("create_object")
        self.objects[obj.oid] = obj
        return obj.oid

    def read_object(self, r, oid):
        kind = self.objects[oid].canonical.split(b" ", 1)[0].decode()
        self.wire(
            dp.RouteOperation.READ_OBJECT,
            "GET",
            f"/repos/{r.policy.candidate.repository}/git/{kind}s/{oid}",
        )
        return self.objects[oid]

    def create_ref(self, r):
        self.wire(
            dp.RouteOperation.CREATE_REF,
            "POST",
            f"/repos/{r.policy.candidate.repository}/git/refs",
            ref=r.policy.candidate.feature_ref,
            sha=r.commit,
        )
        self.effect("create_ref")
        assert self.ref is None
        self.ref = r.commit
        return self.ref

    def create_draft(self, r):
        self.wire(
            dp.RouteOperation.CREATE_DRAFT,
            "POST",
            f"/repos/{r.policy.candidate.repository}/pulls",
            ref=r.policy.candidate.feature_ref,
            sha=r.commit,
            draft=True,
        )
        self.effect("create_draft")
        assert self.prs == ()
        self.prs = (7,)
        return 7

    def read_pr(self, r, number):
        self.wire(
            dp.RouteOperation.READ_PR,
            "GET",
            f"/repos/{r.policy.candidate.repository}/pulls/{number}",
            pr_number=number,
        )
        p, c = r.policy, r.policy.candidate
        return self.pr_mutate(
            dp.PullRequest(
                number,
                c.repo_id,
                c.repo_id,
                c.repo_id,
                c.feature_ref.removeprefix("refs/heads/"),
                r.commit,
                "main",
                c.base_sha,
                p.bot_id,
                p.bot_login,
                p.app_id,
                True,
                True,
                r.title,
                r.body,
                (c.issue_id,),
            )
        )


def setup():
    c, cp = fixture()
    p = dp.Policy(cp, 10, 20, 30, 40, "fixture[bot]", "c" * 64, 200, 50)
    return c, p, Ports(c, p)


def run(c, p, ports):
    return dp.publish(c, p, now=100, admission=ports, journal=ports, api=ports)


def test_complete_transaction_and_replay():
    args = setup()
    result = run(*args)
    assert result == dp.Result("PUBLISHED_OFFLINE_FIXTURE", "verified_draft", 5, 7)
    assert not result.live_authorized
    ports = args[-1]
    assert [i.sequence for i in ports.intents] == [1, 2, 3, 4, 5]
    assert len(ports.results) == 5
    assert ports.calls == ["create_object"] * 3 + ["create_ref", "create_draft"]
    assert run(*args).status == "UNKNOWN_NEEDS_HUMAN"
    assert len(ports.calls) == 5
    with pytest.raises(FrozenInstanceError):
        result.pr_number = 9


@pytest.mark.parametrize(
    "field,value",
    [
        ("repo_id", 9),
        ("repository", "evil/repo"),
        ("issue", 2),
        ("issue_id", 8),
        ("base_sha", "c" * 40),
        ("commit", "d" * 40),
        ("tree", "e" * 40),
        ("feature_ref", "refs/heads/main"),
        ("operation", "update"),
    ],
)
def test_candidate_mismatch(field, value):
    c, p, ports = setup()
    assert run(change(c, **{field: value}), p, ports).status == "BLOCKED"
    assert not ports.calls and not ports.claimed


@pytest.mark.parametrize("name", ["../x", "a/b", ".git", "con.txt"])
def test_unsafe_paths(name):
    c, cp = fixture((name,))
    _, p, ports = setup()
    assert run(c, replace(p, candidate=cp), ports).status == "BLOCKED"
    assert not ports.calls


@pytest.mark.parametrize(
    "field,value",
    [
        ("repo_id", 2),
        ("repo_id", True),
        ("owner_id", 8),
        ("issue_id", 3),
        ("issue_open", False),
        ("app_id", 8),
        ("installation_id", 8),
        ("bot_id", 8),
        ("bot_login", "other[bot]"),
        ("repositories", (1, 2)),
        ("permissions", (*dp.PERMISSIONS, ("issues", "write"))),
        ("base_sha", "c" * 40),
        ("base_branch", "other"),
        ("feature_sha", "c" * 40),
        ("prs", (7,)),
        ("prs", (7, 7)),
        ("complete", False),
        ("app_attribution_verified", False),
        ("governance_verified", False),
        ("app_owner_id", 99),
        ("installation_account_id", 99),
        ("repository_selection", "all"),
        ("installation_active", False),
        ("events", ("push",)),
    ],
)
def test_remote_preconditions(field, value):
    args = setup()
    args[-1].mutate = lambda o: replace(o, **{field: value})
    assert run(*args).status == "UNKNOWN_NEEDS_HUMAN"
    assert not args[-1].calls


def test_admission_separate():
    c, p, ports = setup()
    assert dp.validate(c, p, 100) is not None
    ports.allowed = False
    assert run(c, p, ports).status == "BLOCKED"
    assert not ports.claimed


@pytest.mark.parametrize(
    "field,value",
    [
        ("expires", 100),
        ("expires", 401),
        ("app_id", True),
        ("authorization", "model PASS"),
        ("version", "AP-DP/2"),
        ("bot_login", "bad\nlogin"),
    ],
)
def test_invalid_policy(field, value):
    c, p, ports = setup()
    assert run(c, replace(p, **{field: value}), ports).status == "BLOCKED"


@pytest.mark.parametrize("operation", ["create_object", "create_ref", "create_draft"])
@pytest.mark.parametrize("crash", [False, True])
def test_timeout_crash_no_retry(operation, crash):
    args = setup()
    ports = args[-1]
    ports.fail = ("crash:" if crash else "") + operation
    if crash:
        with pytest.raises(Crash):
            run(*args)
    else:
        assert run(*args).status == "UNKNOWN_NEEDS_HUMAN"
    count = len(ports.calls)
    ports.fail = None
    assert run(*args).status == "UNKNOWN_NEEDS_HUMAN"
    assert len(ports.calls) == count


@pytest.mark.parametrize("flag", ["durable", "confirm"])
def test_durable_confirmation_required(flag):
    args = setup()
    setattr(args[-1], flag, False)
    assert run(*args).status == "UNKNOWN_NEEDS_HUMAN"
    assert len(args[-1].calls) == (0 if flag == "durable" else 1)


@pytest.mark.parametrize(
    "field,value",
    [
        ("author_id", 99),
        ("author_login", "other"),
        ("app_id", 99),
        ("head_sha", "f" * 40),
        ("base_sha", "f" * 40),
        ("head_repo_id", 2),
        ("base_repo_id", 2),
        ("draft", False),
        ("open", False),
        ("body", "Closes #2\n"),
        ("linked_issue_ids", ()),
        ("linked_issue_ids", (100, 101)),
        ("number", 8),
    ],
)
def test_independent_pr_verification(field, value):
    args = setup()
    args[-1].pr_mutate = lambda pr: replace(pr, **{field: value})
    result = run(*args)
    assert result.status == "UNKNOWN_NEEDS_HUMAN"
    assert result.pr_number is None
    assert len(args[-1].results) == 4


@pytest.mark.parametrize("field,value", [("base_sha", "f" * 40), ("feature_sha", None)])
def test_ref_drift(field, value):
    args = setup()
    ports = args[-1]
    ports.mutate = lambda o: replace(o, **{field: value}) if ports.ref else o
    assert run(*args).status == "UNKNOWN_NEEDS_HUMAN"
    assert "create_draft" not in ports.calls


@pytest.mark.parametrize(
    "method", ["create_object", "read_object", "create_ref", "create_draft"]
)
def test_mismatched_api_response(method):
    args = setup()
    setattr(args[-1], method, lambda *a: "invalid")
    assert run(*args).status == "UNKNOWN_NEEDS_HUMAN"


def test_deadline(monkeypatch):
    args = setup()
    clock = [0]
    monkeypatch.setattr(dp, "monotonic", lambda: clock[0])
    original = args[-1].create_object

    def late(*a):
        value = original(*a)
        clock[0] += 6
        return value

    args[-1].create_object = late
    assert run(*args).status == "UNKNOWN_NEEDS_HUMAN"
    assert len(args[-1].calls) == 1


def test_surface():
    assert {n for n in dp.API.__dict__ if not n.startswith("_")} == {
        "observe",
        "create_object",
        "read_object",
        "create_ref",
        "create_draft",
        "read_pr",
    }
    for forbidden in (
        "merge",
        "approve",
        "delete",
        "update",
        "request",
        "post",
        "comment",
        "ready",
    ):
        assert not hasattr(dp.API, forbidden)


def test_app_rotation_retains_replay_guard():
    c, p, ports = setup()
    assert run(c, p, ports).pr_number == 7
    assert run(c, replace(p, app_id=999), ports).status == "UNKNOWN_NEEDS_HUMAN"
    assert len(ports.calls) == 5


def test_immutable_machine_rejects_out_of_order_transitions():
    state = dp.State()
    intent = dp.Intent("a" * 64, 1, "create_ref", "b" * 64)
    with pytest.raises(dp._Stop):
        state.begin(intent)
    active = state.claiming().admitted()
    pending = active.begin(intent)
    assert state.phase == "VALIDATED" and pending.phase == "UNKNOWN"
    with pytest.raises(FrozenInstanceError):
        pending.phase = "ACTIVE"
    with pytest.raises(dp._Stop):
        pending.begin(intent)
    with pytest.raises(dp._Stop):
        pending.confirmed(replace(intent, sequence=2))
    assert pending.confirmed(intent).completed_writes == 1


def test_timeout_after_remote_effect_and_journal_crashes():
    args = setup()
    ports = args[-1]
    original = ports.create_ref

    def lost_response(r):
        original(r)
        raise TimeoutError("secret")

    ports.create_ref = lost_response
    assert run(*args).status == "UNKNOWN_NEEDS_HUMAN"
    assert ports.ref is not None and ports.prs == ()
    assert run(*args).status == "UNKNOWN_NEEDS_HUMAN"
    assert ports.calls.count("create_ref") == 1

    for name in ("claim", "unknown", "confirmed"):
        args = setup()
        ports = args[-1]
        original = getattr(ports, name)

        def crash(*a, original=original):
            original(*a)
            raise Crash

        setattr(ports, name, crash)
        with pytest.raises(Crash):
            run(*args)
        setattr(ports, name, original)
        count = len(ports.calls)
        assert run(*args).status == "UNKNOWN_NEEDS_HUMAN"
        assert len(ports.calls) == count


def test_admission_revoked_during_upload():
    args = setup()
    ports = args[-1]
    original = ports.create_object

    def revoke(*a):
        value = original(*a)
        ports.allowed = False
        return value

    ports.create_object = revoke
    assert run(*args).status == "UNKNOWN_NEEDS_HUMAN"
    assert len(ports.calls) == 1


def test_strict_nested_identity_types():
    args = setup()
    args[-1].mutate = lambda o: replace(o, repositories=(True,))
    assert run(*args).status == "UNKNOWN_NEEDS_HUMAN"


def test_candidate_limits_and_malformed_tree():
    c, p, ports = setup()
    assert (
        run(replace(c, descriptor=b"x" * (16 * 1024 + 1)), p, ports).status == "BLOCKED"
    )
    tree = replace(c.objects[1], canonical=c.objects[1].canonical + b"bad")
    assert (
        run(replace(c, objects=(c.objects[0], tree, c.objects[2])), p, ports).status
        == "BLOCKED"
    )
    assert not ports.claimed


def test_total_deadline_and_redacted_exception(monkeypatch):
    args = setup()
    clock = [0]
    monkeypatch.setattr(dp, "monotonic", lambda: clock[0])
    ports = args[-1]
    original = ports.observe

    def slow(r):
        clock[0] += 4
        return original(r)

    ports.observe = slow
    # Individually timely calls must still obey the overall deadline.
    ports.validate = lambda r: clock.__setitem__(0, clock[0] + 4) or True
    result = run(*args)
    assert result.status == "UNKNOWN_NEEDS_HUMAN"
    assert "create_draft" not in ports.calls
    args = setup()
    args[-1].fail = "create_draft"
    assert "secret" not in repr(run(*args))


def test_no_io_or_process_execution(monkeypatch):
    import builtins
    import os
    import socket
    import subprocess

    args = setup()

    def forbidden(*a, **kw):
        raise AssertionError("I/O forbidden")

    with monkeypatch.context() as patch:
        for module, name in (
            (builtins, "open"),
            (os, "open"),
            (os, "system"),
            (socket, "socket"),
            (subprocess, "Popen"),
        ):
            patch.setattr(module, name, forbidden)
        assert run(*args).status == "PUBLISHED_OFFLINE_FIXTURE"


@pytest.mark.parametrize("failure", ["exception", "mismatch", "revoked"])
def test_first_observation_after_claim_requires_reconciliation(failure):
    c, p, ports = setup()
    original_observe = ports.observe
    if failure == "exception":

        def unavailable(r):
            raise TimeoutError("untrusted secret")

        ports.observe = unavailable
    elif failure == "mismatch":
        ports.mutate = lambda o: replace(o, issue_open=False)
    else:
        original_claim = ports.claim

        def revoke(*pins):
            result = original_claim(*pins)
            ports.allowed = False
            return result

        ports.claim = revoke
    result = run(c, p, ports)
    assert result == dp.Result("UNKNOWN_NEEDS_HUMAN", "reconciliation_required")
    assert ports.claimed and len(ports.claim_history) == 1
    history = tuple(ports.claim_history)
    assert not ports.calls and not ports.intents and not ports.results
    # Restoring observations/authority cannot erase or automatically reuse claim.
    ports.allowed = True
    ports.mutate = lambda o: o
    ports.observe = original_observe
    assert run(c, p, ports).status == "UNKNOWN_NEEDS_HUMAN"
    assert tuple(ports.claim_history) == history and ports.claimed
    assert not ports.calls and not ports.intents and not ports.results
    assert not hasattr(dp.Journal, "reset") and not hasattr(dp.Journal, "delete")


@pytest.mark.parametrize("failure", ["candidate", "admission"])
def test_preclaim_refusal_leaves_no_claim_history(failure):
    c, p, ports = setup()
    if failure == "candidate":
        c = change(c, issue=999)
    else:
        ports.allowed = False
    assert run(c, p, ports).status == "BLOCKED"
    assert not ports.claimed and ports.claim_history == []
    assert ports.calls == ports.intents == ports.results == ports.wire_calls == []


def test_claim_reconciliation_state_survives_zero_confirmed_writes():
    state = dp.State().claiming().admitted()
    assert state.completed_writes == 0 and state.uncertain
    assert not dp.State().uncertain


def test_synthetic_routes_cover_end_to_end_without_live_semantics():
    c, p, ports = setup()
    assert run(c, p, ports).pr_number == 7
    writes = [route for route in ports.wire_calls if route.method == "POST"]
    assert [r.operation for r in writes] == [
        dp.RouteOperation.CREATE_BLOB,
        dp.RouteOperation.CREATE_TREE,
        dp.RouteOperation.CREATE_COMMIT,
        dp.RouteOperation.CREATE_REF,
        dp.RouteOperation.CREATE_DRAFT,
    ]
    assert writes[-2].path == "/repos/example/target/git/refs"
    assert writes[-2].ref == p.candidate.feature_ref
    assert writes[-1].path == "/repos/example/target/pulls" and writes[-1].draft is True
    assert all(not r.semantics_verified for r in ports.wire_calls)
    routes = dp.allowed_routes(c, p, now=100, pr_number=7)
    assert {r.operation for r in routes} == set(dp.RouteOperation)
    assert all(dp.route_allowed(c, p, r, now=100, pr_number=7) for r in routes)
    assert [
        r.query[-1] for r in routes if r.operation == dp.RouteOperation.LIST_PRS
    ] == [
        ("page", "1"),
        ("page", "2"),
        ("page", "3"),
    ]
    with pytest.raises(FrozenInstanceError):
        writes[-1].method = "PATCH"


@pytest.mark.parametrize(
    "field,value",
    [
        ("method", "PATCH"),
        ("method", "PUT"),
        ("method", "DELETE"),
        ("method", "OPTIONS"),
        ("method", "post"),
        ("method", "UNKNOWN"),
        ("origin", "http://api.github.com"),
        ("origin", "https://evil.invalid"),
        ("origin", "https://api.github.com.evil.invalid"),
        ("origin", "https://api.github.com@evil.invalid"),
        ("path", "https://api.github.com/repos/example/target/git/refs"),
        ("path", "/repos/other/target/git/refs"),
        ("path", "/repos/example/target"),
        ("path", "/repos/example/target/pulls/7/merge"),
        ("path", "/repos/example/target/pulls/7/reviews"),
        ("path", "/repos/example/target/branches/main/protection"),
        ("path", "/repos/example/target/git/refs/heads/main"),
        ("path", "/repos/example/target/git/refs/heads/feature/issue-91-test"),
        ("path", "/repos/example/target/git/../refs"),
        ("path", "/repos/example/target/git/refs?force=true"),
        ("ref", "refs/heads/main"),
        ("ref", "refs/tags/v1"),
        ("sha", "f" * 40),
        ("force", True),
        ("force", False),
        ("operation", "create_ref"),
        ("query", (("force", "true"),)),
    ],
)
def test_route_contract_denies_unapproved_methods_paths_and_metadata(field, value):
    c, p, _ = setup()
    route = next(
        r
        for r in dp.allowed_routes(c, p, now=100)
        if r.operation == dp.RouteOperation.CREATE_REF
    )
    assert not dp.route_allowed(c, p, replace(route, **{field: value}), now=100)


def test_route_contract_denies_arbitrary_pr_object_query_and_payload():
    c, p, _ = setup()
    routes = dp.allowed_routes(c, p, now=100, pr_number=7)
    for r in routes:
        assert not dp.route_allowed(
            c, p, replace(r, path=r.path + "/extra"), now=100, pr_number=7
        )
    read = next(r for r in routes if r.operation == dp.RouteOperation.READ_PR)
    assert not dp.route_allowed(c, p, read, now=100)
    assert not dp.route_allowed(
        c, p, replace(read, path=read.path[:-1] + "8"), now=100, pr_number=7
    )
    obj = next(r for r in routes if r.operation == dp.RouteOperation.READ_OBJECT)
    assert not dp.route_allowed(
        c, p, replace(obj, path=obj.path[:-40] + "f" * 40), now=100
    )
    draft = next(r for r in routes if r.operation == dp.RouteOperation.CREATE_DRAFT)
    assert not dp.route_allowed(c, p, replace(draft, draft=False), now=100)
    page = next(r for r in routes if r.operation == dp.RouteOperation.LIST_PRS)
    assert not dp.route_allowed(c, p, replace(page, query=(("page", "4"),)), now=100)
    with pytest.raises(TypeError):
        dp.Route(
            dp.RouteOperation.CREATE_DRAFT, "POST", draft.path, body={"merge": True}
        )
    for forbidden in ("MERGE", "APPROVE", "DELETE", "UPDATE", "SETTINGS"):
        assert not hasattr(dp.RouteOperation, forbidden)
    assert dp.allowed_routes(c, p, now=200) == ()
    assert dp.allowed_routes(c, p, now=100, pr_number=True) == ()
    assert not dp.route_allowed(c, p, {"method": "POST"}, now=100)


@pytest.mark.parametrize("repository", ["example/..", "example/.", "example/a..b"])
def test_route_root_rejects_traversal_even_in_matching_policy(repository):
    c, p, _ = setup()
    c = change(c, repository=repository)
    p = replace(p, candidate=replace(p.candidate, repository=repository))
    assert dp.allowed_routes(c, p, now=100) == ()
