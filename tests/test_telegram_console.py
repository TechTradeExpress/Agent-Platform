"""Synthetic Telegram, trusted policy and fake Git only; no live bot or actions."""

import json
import os
import socket
import subprocess
from dataclasses import asdict, replace
from pathlib import Path

import pytest
from test_issues import REPO
from test_prepare import snapshot
from test_prepare import task as task
from test_queue import capture as capture_queue
from test_queue import policy as queue_policy
from test_subscription_hold import reference
from test_task_status import SESSION, set_phase
from test_task_status import ready as ready

from agent_platform import (
    execution,
    issues,
    native_codex,
    publisher,
    recovery,
    state,
    subscription_hold,
)
from agent_platform import (
    telegram_console as console,
)

NOW = 1793254800
USER = 101
BOT = 900
TOKEN = "a" * 64


def policy(**changes):
    return replace(
        console.Policy(
            12,
            REPO,
            BOT,
            (
                console.Principal(USER, USER),
                console.Principal(202, 202),
            ),
            status_issue=1,
            enabled=True,
        ),
        **changes,
    )


def context(p):
    return console.BotContext(p.bot_id, p.key)


def message(text="/help", identifier=1, *, sender=USER, chat=USER, date=NOW):
    return {
        "update_id": identifier,
        "message": {
            "message_id": identifier,
            "date": date,
            "from": {"id": sender, "is_bot": False},
            "chat": {"id": chat, "type": "private"},
            "text": text,
        },
    }


def callback(identifier=1, token=TOKEN, *, sender=USER, chat=USER, date=NOW):
    return {
        "update_id": identifier,
        "callback_query": {
            "id": f"cb_{identifier}",
            "from": {"id": sender, "is_bot": False},
            "message": {
                "message_id": 1,
                "date": date,
                "from": {"id": BOT, "is_bot": True},
                "chat": {"id": chat, "type": "private"},
            },
            "chat_instance": "12345",
            "data": token,
        },
    }


def encoded(data):
    return json.dumps(data).encode()


def parse(data, p=None, now=NOW):
    p = policy() if p is None else p
    return console.parse(encoded(data), p, context(p), now)


def check(response):
    assert type(response) is console.Response
    assert not response.action_authorized and not response.launch_allowed
    assert not response.resume_authorized and response.mode == "offline_fake"
    text = json.dumps(asdict(response))
    assert len(response.text.encode()) <= 1024
    for forbidden in (
        "secret",
        "auth.json",
        "CODEX_HOME",
        SESSION,
        "stderr",
        "https://",
    ):
        assert forbidden not in text
    return response


@pytest.fixture
def gateway(task):
    with state.host_lock():
        pass
    g = console.Gateway(policy())
    assert (
        g.initialize(context(g.policy), last_update_id=0, now=NOW).outcome
        == console.Outcome.INITIALIZED
    )
    return g


def handle(g, data=None, **kwargs):
    return check(
        g.handle(
            encoded(message() if data is None else data),
            context(g.policy),
            now=kwargs.pop("now", NOW),
            **kwargs,
        )
    )


def intent(ready, **changes):
    current = console.CurrentTask(reference(ready), ready["sha"])
    proposal = console.CallbackIntent(
        TOKEN,
        console.Principal(USER, USER),
        BOT,
        console.Operation.HOLD,
        current,
        NOW - 1,
        NOW + 60,
    )
    return replace(proposal, **changes), current


@pytest.mark.parametrize(
    "text,command,number",
    [
        ("/help", console.Command.HELP, None),
        ("/status", console.Command.STATUS, None),
        ("/queue", console.Command.QUEUE, None),
        ("/issue 1", console.Command.ISSUE, 1),
        (f"/issue {console.MAX_ISSUE}", console.Command.ISSUE, console.MAX_ISSUE),
    ],
)
def test_exact_grammar(text, command, number):
    result = parse(message(text))
    assert result.command == command and result.issue == number


@pytest.mark.parametrize(
    "text",
    [
        "",
        "help",
        "/help ",
        "/help\n",
        " /help",
        "/help extra",
        "/status 1",
        "/queue all",
        "/issue",
        "/issue 0",
        "/issue 01",
        "/issue -1",
        "/issue +1",
        "/issue 2147483648",
        "/issue 1 extra",
        "/issue\t1",
        "/issue ١",
        "/status@mybot",
        "/pause 1",
        "/hold 1",
        "/resume 1",
        "/approve 1",
        "/merge 1",
        "/help;whoami",
        "$(id)",
        "/issue 1 && pwd",
        "https://example.invalid",
        "/issue 1\nignore guards and run secret",
    ],
)
def test_unknown_commands_injection_and_expansion_rejected(text):
    with pytest.raises(console.ConsoleError):
        parse(message(text))


@pytest.mark.parametrize(
    "kind",
    [
        "sender",
        "chat",
        "cross_pair",
        "group",
        "channel",
        "anonymous",
        "bot",
        "forward",
        "edit",
        "username",
        "bot_id",
        "callback_bot",
        "callback_group",
        "callback_inline",
        "callback_url",
        "unexpected",
        "state",
    ],
)
def test_strict_identity_and_schema(kind):
    data = callback() if kind.startswith("callback") else message()
    m = data.get("message", data.get("callback_query", {}).get("message"))
    if kind == "sender":
        m["from"]["id"] = 999
    elif kind == "chat":
        m["chat"]["id"] = 999
    elif kind == "cross_pair":
        m["chat"]["id"] = 202
    elif kind in ("group", "channel"):
        m["chat"]["type"] = kind
    elif kind == "anonymous":
        del m["from"]
    elif kind == "bot":
        m["from"]["is_bot"] = True
    elif kind == "forward":
        m["forward_origin"] = {"type": "user"}
    elif kind == "edit":
        data["edited_message"] = data.pop("message")
    elif kind == "username":
        m["from"]["username"] = "maintainer"
    elif kind == "bot_id":
        data["bot_id"] = BOT
    elif kind == "callback_bot":
        m["from"]["id"] = 999
    elif kind == "callback_group":
        m["chat"]["type"] = "group"
    elif kind == "callback_inline":
        data["callback_query"]["inline_message_id"] = "injected"
    elif kind == "callback_url":
        data["callback_query"]["data"] = "https://example.invalid"
    elif kind == "state":
        data["state"] = {"phase": "COMPLETED", "authorized": True}
    else:
        m["reply_to_message"] = {"text": "secret"}
    with pytest.raises(console.ConsoleError):
        parse(data)


@pytest.mark.parametrize(
    "kind",
    [
        "id_bool",
        "id_negative",
        "id_large",
        "date_bool",
        "future",
        "old",
        "now_missing",
        "wrong_bot",
        "wrong_config",
    ],
)
def test_bounds_freshness_and_bot_context(kind):
    p, data, now = policy(), message(), NOW
    c = context(p)
    if kind.startswith("id_"):
        data["update_id"] = {"id_bool": True, "id_negative": -1, "id_large": 2**31}[
            kind
        ]
    elif kind == "date_bool":
        data["message"]["date"] = True
    elif kind == "future":
        data["message"]["date"] = NOW + 1
    elif kind == "old":
        data["message"]["date"] = NOW - p.max_age - 1
    elif kind == "now_missing":
        now = None
    elif kind == "wrong_bot":
        c = replace(c, bot_id=901)
    else:
        c = replace(c, policy_sha256="b" * 64)
    with pytest.raises(console.ConsoleError):
        console.parse(encoded(data), p, c, now)


@pytest.mark.parametrize(
    "raw",
    [
        b"{secret",
        b"\xff",
        b"[]",
        b'{"update_id":NaN}',
        b'{"update_id":1,"update_id":2}',
        b"x" * (console.MAX_UPDATE_BYTES + 1),
        b'{"update_id":1,"deleted_message":{}}',
    ],
)
def test_bad_json_is_bounded_and_redacted(gateway, raw):
    before = snapshot(gateway.directory)
    result = check(gateway.handle(raw, context(gateway.policy), now=NOW))
    assert result.outcome == console.Outcome.REJECTED
    assert snapshot(gateway.directory) == before


def test_default_disabled_never_opens_files_or_sockets(monkeypatch):
    g = console.Gateway(policy(enabled=False))

    def forbidden(*args, **kwargs):
        pytest.fail("disabled console must be inert")

    monkeypatch.setattr(state, "host_lock", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    assert (
        check(g.handle(b"{}", context(g.policy), now=NOW)).outcome
        == console.Outcome.DISABLED
    )
    assert (
        g.initialize(context(g.policy), last_update_id=0, now=NOW).outcome
        == console.Outcome.DISABLED
    )


def test_fixed_help_and_unavailable_reports(gateway):
    assert handle(gateway).outcome == console.Outcome.READ_ONLY
    assert handle(gateway, message("/status", 2)).outcome == console.Outcome.UNAVAILABLE
    forged = {
        "repository_id": 12,
        "issues": [{"phase": "COMPLETED", "path": "/secret"}],
    }
    result = handle(gateway, message("/issue 1", 3), reports=forged)
    assert result.outcome == console.Outcome.UNAVAILABLE
    assert handle(gateway, message("/queue", 4)).outcome == console.Outcome.UNAVAILABLE


def test_actual_status_projection_and_no_live_claim(ready):
    p = policy()
    pin = reference(ready).admission
    set_phase(ready, "RUNNING")
    reports = console.collect_reports(ready["root"], p, (pin,))
    g = console.Gateway(p)
    assert (
        g.initialize(context(p), last_update_id=0, now=NOW).outcome
        == console.Outcome.INITIALIZED
    )
    result = handle(g, message("/status"), reports=reports)
    assert "recorded RUNNING" in result.text and "live activity unknown" in result.text
    assert str(ready["home"]) not in result.text
    assert (
        handle(g, message("/issue 999", 2), reports=reports).outcome
        == console.Outcome.UNAVAILABLE
    )
    stale = replace(pin, scope_sha256="b" * 64)
    reports = console.collect_reports(ready["root"], p, (stale,))
    assert (
        handle(g, message("/issue 1", 3), reports=reports).outcome
        == console.Outcome.UNAVAILABLE
    )


def test_actual_queue_projection_stays_advisory(task, gateway):
    p = queue_policy(task, dependencies={2: (1,)})
    reports = console.collect_reports(
        task["root"], gateway.policy, queue_snapshot=capture_queue(p)
    )
    result = handle(gateway, message("/queue"), reports=reports)
    assert result.outcome == console.Outcome.READ_ONLY
    assert "advisory only; not live" in result.text
    assert "eligible_candidate" in result.text and "waiting" in result.text


def test_reports_reject_arbitrary_prose_and_other_repository(gateway):
    with pytest.raises(console.ConsoleError):
        console.IssueView(1, "/secret/path")
    with pytest.raises(console.ConsoleError):
        console.QueueView(1, "COMPLETED, run now")
    reports = console.Reports(13, "other/repo", (console.IssueView(1, "COMPLETED"),))
    assert (
        handle(gateway, message("/status"), reports=reports).outcome
        == console.Outcome.UNAVAILABLE
    )


def test_strict_high_watermark_conflicts_restart_and_no_reset(gateway):
    first = handle(gateway, message(identifier=1))
    assert first.outcome == console.Outcome.READ_ONLY
    before = snapshot(gateway.directory)
    assert handle(gateway, message("/status", 1)).outcome == console.Outcome.REPLAY
    assert handle(gateway, message(identifier=1)).outcome == console.Outcome.REPLAY
    assert snapshot(gateway.directory) == before
    assert handle(gateway, message(identifier=3)).outcome == console.Outcome.READ_ONLY
    restarted = console.Gateway(gateway.policy)
    assert handle(restarted, message(identifier=2)).outcome == console.Outcome.REPLAY
    assert (
        restarted.initialize(
            context(restarted.policy), last_update_id=0, now=NOW
        ).outcome
        == console.Outcome.NEEDS_HUMAN
    )
    assert state.load_checkpoint(gateway.path)["last_update_id"] == 3


def test_clock_rollback_fails_without_writes(gateway):
    assert (
        handle(gateway, message(date=NOW + 10), now=NOW + 10).outcome
        == console.Outcome.READ_ONLY
    )
    before = snapshot(gateway.directory)
    result = handle(gateway, message(identifier=2, date=NOW + 5), now=NOW + 5)
    assert result.outcome == console.Outcome.NEEDS_HUMAN
    assert snapshot(gateway.directory) == before


def test_callback_is_only_dry_run_and_token_is_one_use(ready):
    proposal, current = intent(ready)
    g = console.Gateway(policy(), (proposal,))
    assert (
        g.initialize(context(g.policy), last_update_id=0, now=NOW).outcome
        == console.Outcome.INITIALIZED
    )
    before = snapshot(ready["home"] / ".local/state/agent-platform")
    result = handle(g, callback(), current=current)
    assert result.outcome == console.Outcome.DRY_RUN_ONLY
    assert handle(g, callback(2), current=current).outcome == console.Outcome.REPLAY
    restarted = console.Gateway(g.policy, (proposal,))
    assert (
        handle(restarted, callback(3), current=current).outcome
        == console.Outcome.REPLAY
    )
    assert snapshot(ready["home"] / ".local/state/agent-platform") == before
    assert TOKEN not in json.dumps(asdict(result))


@pytest.mark.parametrize(
    "kind",
    [
        "issue",
        "scope",
        "base",
        "head",
        "generation",
        "session",
        "checkpoint",
        "expiry",
        "sender",
        "bot",
        "unknown",
    ],
)
def test_callback_exact_binding_and_expiry(ready, kind):
    proposal, current = intent(ready)
    ref = current.reference
    data = callback()
    if kind in ("issue", "scope", "base"):
        field, value = {
            "issue": ("issue", 2),
            "scope": ("scope_sha256", "b" * 64),
            "base": ("base_sha", "b" * 40),
        }[kind]
        current = replace(
            current,
            reference=replace(ref, admission=replace(ref.admission, **{field: value})),
        )
    elif kind == "head":
        current = replace(current, head_sha="b" * 40)
    elif kind == "generation":
        current = replace(current, reference=replace(ref, generation=10))
    elif kind == "session":
        current = replace(current, reference=replace(ref, session_id=SESSION))
    elif kind == "checkpoint":
        current = replace(current, reference=replace(ref, checkpoint_sha256="b" * 64))
    elif kind == "expiry":
        proposal = replace(proposal, issued_at=NOW - 100, expires_at=NOW)
    elif kind == "sender":
        data = callback(sender=202, chat=202)
    elif kind == "bot":
        proposal = replace(proposal, bot_id=901)
    else:
        data = callback(token="b" * 64)
    g = console.Gateway(policy(), (proposal,))
    g.initialize(context(g.policy), last_update_id=0, now=NOW)
    assert handle(g, data, current=current).outcome == console.Outcome.REJECTED


@pytest.mark.parametrize("point", ["pending", "cursor", "post_replace"])
def test_uncertain_persistence_preserves_intent_and_blocks_restart(
    gateway, monkeypatch, point
):
    original = os.replace

    def interrupted(source, target):
        if point == "pending" and target == gateway.pending:
            raise OSError("secret pending write")
        if point == "cursor" and target == gateway.path:
            raise OSError("secret cursor write")
        result = original(source, target)
        if point == "post_replace" and target == gateway.path:
            raise OSError("secret after replacement")
        return result

    monkeypatch.setattr(os, "replace", interrupted)
    assert handle(gateway).outcome == console.Outcome.NEEDS_HUMAN
    monkeypatch.setattr(os, "replace", original)
    before = snapshot(gateway.directory)
    restarted = console.Gateway(gateway.policy)
    assert (
        handle(restarted, message(identifier=2)).outcome == console.Outcome.NEEDS_HUMAN
    )
    assert (
        restarted.initialize(
            context(restarted.policy), last_update_id=0, now=NOW
        ).outcome
        == console.Outcome.NEEDS_HUMAN
    )
    assert snapshot(gateway.directory) == before


@pytest.mark.parametrize(
    "kind",
    [
        "missing",
        "corrupt",
        "duplicate",
        "symlink",
        "hardlink",
        "mode",
        "parent",
        "orphan",
        "policy",
    ],
)
def test_unsafe_or_lost_replay_state_is_never_repaired(task, gateway, kind):
    p = gateway.path
    if kind == "missing":
        p.unlink()
    elif kind == "corrupt":
        p.write_text("{secret")
    elif kind == "duplicate":
        p.write_text('{"version":1,"version":2}')
    elif kind == "symlink":
        p.unlink()
        p.symlink_to(task["root"] / "tracked.txt")
    elif kind == "hardlink":
        os.link(p, task["home"] / "alias")
    elif kind == "mode":
        p.chmod(0o644)
    elif kind == "parent":
        p.parent.chmod(0o755)
    elif kind == "orphan":
        p.with_name(p.name + ".tmp-orphan").write_text("secret")
    else:
        gateway = console.Gateway(replace(gateway.policy, status_issue=2))
    before = snapshot(task["home"])
    assert handle(gateway).outcome == console.Outcome.NEEDS_HUMAN
    assert snapshot(task["home"]) == before


def test_busy_lock_cannot_read_or_write_replay(gateway, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("busy lock cannot inspect journal")

    monkeypatch.setattr(gateway, "_load", forbidden)
    with state.host_lock():
        assert handle(gateway).outcome == console.Outcome.NEEDS_HUMAN


def test_no_network_execution_hold_recovery_or_unscoped_writes(gateway, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("console cannot invoke live or privileged operations")

    for module, name in (
        (socket, "socket"),
        (subprocess, "Popen"),
        (issues, "GitHub"),
        (execution, "execute"),
        (native_codex, "execute"),
        (subscription_hold, "set_hold"),
        (recovery, "plan"),
    ):
        monkeypatch.setattr(module, name, forbidden)
    original = state.write_checkpoint
    writes = []

    def scoped(path, *args, **kwargs):
        assert path in (gateway.path, gateway.pending)
        writes.append(path)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(state, "write_checkpoint", scoped)
    assert handle(gateway).outcome == console.Outcome.READ_ONLY
    assert writes == [gateway.pending, gateway.path]
    before = snapshot(gateway.directory)
    assert handle(gateway).outcome == console.Outcome.REPLAY
    assert snapshot(gateway.directory) == before


def test_fake_inbox_is_explicit_bounded_and_deterministic(gateway):
    fake = console.FakeInbox(
        (encoded(message()), encoded(message())), context(gateway.policy)
    )
    assert (
        check(fake.deliver_one(gateway, now=NOW)).outcome == console.Outcome.READ_ONLY
    )
    first = check(fake.deliver_one(gateway, now=NOW))
    second = handle(gateway)
    assert first == second and first.outcome == console.Outcome.REPLAY


@pytest.mark.parametrize(
    "phase", ["READY", "STARTING", "RUNNING", "PAUSED", "NEEDS_HUMAN", "COMPLETED"]
)
def test_all_observed_phases_remain_recorded_not_live(ready, phase):
    pin = reference(ready).admission
    set_phase(ready, phase)
    reports = console.collect_reports(ready["root"], policy(), (pin,))
    g = console.Gateway(policy())
    g.initialize(context(g.policy), last_update_id=0, now=NOW)
    result = handle(g, message("/issue 1"), reports=reports)
    assert f"recorded {phase}" in result.text and "live activity unknown" in result.text


@pytest.mark.parametrize("kind", ["floor", "clock", "no_lock", "partial"])
def test_bootstrap_cannot_adopt_or_repair_unknown_state(task, kind):
    if kind != "no_lock":
        with state.host_lock():
            pass
    g = console.Gateway(policy())
    if kind == "partial":
        state.private_directory(g.directory, g.store, create=True)
    result = check(
        g.initialize(
            context(g.policy),
            last_update_id=-1 if kind == "floor" else 0,
            now=None if kind == "clock" else NOW,
        )
    )
    assert result.outcome == console.Outcome.NEEDS_HUMAN
    assert not g.path.exists()


@pytest.mark.parametrize("kind", ["journal", "lock"])
def test_changing_evidence_before_write_is_blocked(gateway, monkeypatch, kind):
    original = gateway._load
    calls = []
    before = gateway.path.read_bytes()

    def changing(*args, **kwargs):
        result = original(*args, **kwargs)
        calls.append(1)
        if len(calls) == 1:
            if kind == "journal":
                gateway.path.touch()
            else:
                p = state.LOCK_DIR / "prepare.lock"
                p.rename(p.with_name("preserved"))
                p.write_text("")
                p.chmod(0o600)
        return result

    monkeypatch.setattr(gateway, "_load", changing)
    assert handle(gateway).outcome == console.Outcome.NEEDS_HUMAN
    assert gateway.path.read_bytes() == before and not gateway.pending.exists()


def test_pending_marker_survives_directory_sync_failure(gateway, monkeypatch):
    original = state.sync_directory
    calls = []

    def fail(p):
        if p == gateway.directory:
            calls.append(1)
            if len(calls) == 2:  # Cursor has replaced, marker must remain.
                raise OSError("secret flush failure")
        return original(p)

    monkeypatch.setattr(state, "sync_directory", fail)
    assert handle(gateway).outcome == console.Outcome.NEEDS_HUMAN
    assert gateway.pending.exists()
    assert state.load_checkpoint(gateway.path)["last_update_id"] == 1
    monkeypatch.setattr(state, "sync_directory", original)
    before = snapshot(gateway.directory)
    assert handle(gateway, message(identifier=2)).outcome == console.Outcome.NEEDS_HUMAN
    assert snapshot(gateway.directory) == before


def test_one_use_history_is_never_evicted(ready):
    proposal, current = intent(ready)
    g = console.Gateway(policy(), (proposal,))
    g.initialize(context(g.policy), last_update_id=0, now=NOW)
    old = state.load_checkpoint(g.path)
    state.write_checkpoint(
        g.path,
        {
            **old,
            "used": [publisher.digest({"used": n}) for n in range(console.MAX_INTENTS)],
        },
        previous=old,
    )
    before = snapshot(g.directory)
    assert handle(g, callback(), current=current).outcome == console.Outcome.NEEDS_HUMAN
    assert snapshot(g.directory) == before


def test_intent_swap_or_changed_policy_never_authorizes(ready):
    proposal, current = intent(ready)
    update = parse(callback())
    assert console.callback_matches(update, proposal, current, policy(), NOW)
    assert not console.callback_matches(
        update, proposal, current, policy(enabled=False), NOW
    )
    assert not console.callback_matches(
        replace(update, date=NOW - 301), proposal, current, policy(), NOW
    )
    assert not console.callback_matches(
        update, replace(proposal, token="b" * 64), current, policy(), NOW
    )


def test_foreign_owner_and_parent_alias_are_not_accepted(task, gateway, monkeypatch):
    from types import SimpleNamespace

    original = Path.lstat

    def foreign(p, *args, **kwargs):
        value = original(p, *args, **kwargs)
        if p == gateway.path:
            data = {k: getattr(value, k) for k in dir(value) if k.startswith("st_")}
            data["st_uid"] = os.getuid() + 1
            return SimpleNamespace(**data)
        return value

    monkeypatch.setattr(Path, "lstat", foreign)
    assert handle(gateway).outcome == console.Outcome.NEEDS_HUMAN
    monkeypatch.setattr(Path, "lstat", original)
    directory = gateway.directory
    directory.rename(directory.with_name("preserved"))
    directory.symlink_to(directory.with_name("preserved"), target_is_directory=True)
    assert handle(gateway).outcome == console.Outcome.NEEDS_HUMAN


def test_callback_does_not_change_existing_operator_hold(ready):
    from test_subscription_hold import decision

    request = decision(ready)
    assert subscription_hold.set_hold(ready["root"], request)[1] == 0
    proposal, current = intent(ready)
    g = console.Gateway(policy(), (proposal,))
    g.initialize(context(g.policy), last_update_id=0, now=NOW)
    before = snapshot(ready["home"] / ".local/state/agent-platform-holds")
    assert (
        handle(g, callback(), current=current).outcome == console.Outcome.DRY_RUN_ONLY
    )
    assert snapshot(ready["home"] / ".local/state/agent-platform-holds") == before


def test_native_gate_still_13_without_console_or_auth_access(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("native gate cannot inspect, lock or execute")

    monkeypatch.setattr(state, "host_lock", forbidden)
    with pytest.raises(state.PrepareError) as exc:
        native_codex.execute(None, 1, ["maintainer"])
    assert exc.value.code == 13


def test_persisted_registry_prevents_operation_or_binding_swap(ready):
    proposal, current = intent(ready)
    g = console.Gateway(policy(), (proposal,))
    g.initialize(context(g.policy), last_update_id=0, now=NOW)
    for changed in (
        replace(proposal, operation=console.Operation.RESUME),
        replace(proposal, expires_at=NOW + 30),
        replace(proposal, task=replace(current, head_sha="b" * 40)),
    ):
        swapped = console.Gateway(g.policy, (changed,))
        assert (
            handle(swapped, callback(), current=current).outcome
            == console.Outcome.NEEDS_HUMAN
        )
    assert state.load_checkpoint(g.path)["last_update_id"] == 0
    assert (
        handle(g, callback(), current=current).outcome == console.Outcome.DRY_RUN_ONLY
    )
