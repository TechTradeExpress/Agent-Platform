"""Fabricated CP-05 transaction ports; no network or credentials."""

from dataclasses import FrozenInstanceError, replace

import pytest
from test_publisher_candidate import change, fixture

from agent_platform import draft_publisher as dp


class Crash(BaseException):
    pass


class Ports:
    def __init__(self):
        self.claimed = False
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

    def create_object(self, r, obj):
        self.effect("create_object")
        self.objects[obj.oid] = obj
        return obj.oid

    def read_object(self, r, oid):
        return self.objects[oid]

    def create_ref(self, r):
        self.effect("create_ref")
        assert self.ref is None
        self.ref = r.commit
        return self.ref

    def create_draft(self, r):
        self.effect("create_draft")
        assert self.prs == ()
        self.prs = (7,)
        return 7

    def read_pr(self, r, number):
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
    return c, dp.Policy(cp, 10, 20, 30, 40, "fixture[bot]", "c" * 64, 200, 50), Ports()


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
    assert run(*args).status == "BLOCKED"
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
    assert run(*args).status == "BLOCKED"


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
