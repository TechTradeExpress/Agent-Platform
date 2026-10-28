"""Trusted synthetic facts and scripted Bot API replies, never real Telegram."""

import json
from dataclasses import FrozenInstanceError, asdict, replace

import pytest
from test_prepare import task as task
from test_publisher import completed as completed

from agent_platform import cli, prepare, publisher, state
from agent_platform.notifications import (
    GitHubEvidence,
    Kind,
    NotificationError,
    NotificationEvent,
    Preferences,
    Result,
    SafeNotification,
    checkpoint_event,
    format_event,
)
from agent_platform.telegram_fake import (
    Category,
    Delivery,
    FakeFault,
    FakeReply,
    FakeTelegram,
    Outcome,
    TelegramRequest,
    classify,
)


@pytest.fixture
def admitted():
    return publisher.Admission(
        12,
        "example/target",
        1,
        101,
        "a" * 64,
        "2026-10-27T12:00:00Z",
        "b" * 64,
        "c" * 40,
    )


@pytest.fixture
def event(admitted):
    return GitHubEvidence(
        admitted, Kind.DRAFT_PR_CREATED, 7, "d" * 40, "e" * 64
    ).event()


def ack(request, *, chat=None, private="private", text=None):
    return FakeReply(
        200,
        json.dumps(
            {
                "ok": True,
                "result": {
                    "message_id": 123,
                    "chat": {
                        "id": request.chat_id if chat is None else chat,
                        "type": private,
                    },
                    "text": request.notification.text if text is None else text,
                },
            }
        ).encode(),
    )


def test_checkpoint_events_reuse_real_validators(completed):
    record = state.load_checkpoint(completed["checkpoint"])
    source = prepare.source_snapshot(cli.inspect(completed["root"]))
    admission = completed["admission"]
    event = checkpoint_event(admission, source, record)
    assert event.kind == Kind.PROGRESS and event.phase == "COMPLETED"
    assert event.generation == 5 and event.evidence_sha256 == publisher.digest(record)
    assert (
        checkpoint_event(admission, source, record, kind=Kind.REVIEW_REQUESTED).kind
        == Kind.REVIEW_REQUESTED
    )
    with pytest.raises(NotificationError):
        checkpoint_event(admission, source, record, kind=Kind.HUMAN_MERGED)
    record["phase"] = "RUNNING"
    record["generation"] = 4
    record["last_intent"] = "SESSION_RECORDED"
    record.update(stop_reason=None, usage=None, runtime_sha256=None)
    event = checkpoint_event(admission, source, record)
    text = format_event(event).text
    assert "Recorded checkpoint: RUNNING" in text and "live activity unverified" in text
    record["issue"] = 2
    with pytest.raises(NotificationError):
        checkpoint_event(admission, source, record)


@pytest.mark.parametrize("kind", list(Kind))
def test_entire_typed_vocabulary_has_fixed_bounded_format(admitted, kind):
    if kind in {
        Kind.DRAFT_PR_CREATED,
        Kind.CI_RESULT,
        Kind.REVIEW_COMPLETED,
        Kind.READY,
        Kind.HUMAN_MERGED,
    }:
        result = (
            Result.PASS if kind in {Kind.CI_RESULT, Kind.REVIEW_COMPLETED} else None
        )
        event = GitHubEvidence(
            admitted,
            kind,
            7,
            "d" * 40,
            "e" * 64,
            result,
            independent_review=kind == Kind.REVIEW_COMPLETED,
            human_merge=kind == Kind.HUMAN_MERGED,
        ).event()
    else:
        phases = {
            Kind.ACCEPTED: "READY",
            Kind.BLOCKED: "NEEDS_HUMAN",
            Kind.STARTED: "STARTING",
            Kind.PROGRESS: "RUNNING",
            Kind.PAUSED: "PAUSED",
            Kind.FAILED: "PAUSED",
            Kind.NEEDS_HUMAN: "NEEDS_HUMAN",
            Kind.REVIEW_REQUESTED: "COMPLETED",
        }
        event = NotificationEvent(
            kind,
            12,
            "example/target",
            1,
            "c" * 40,
            "a" * 64,
            admitted.scope_sha256,
            5,
            phases[kind],
        )
    a = format_event(event)
    assert a == format_event(event)
    assert 0 < len(a.text.encode()) <= 768
    assert "example/target" not in a.text and "https:" not in a.text
    assert event.sha not in a.text and event.scope_sha256 not in a.text
    assert "Repository ID: 12; Issue: 1" in a.text
    assert "<" not in a.text and "[" not in a.text
    assert len(event.key) == 64
    with pytest.raises(FrozenInstanceError):
        event.kind = Kind.ACCEPTED
    with pytest.raises(FrozenInstanceError):
        a.include_public_links = True


def test_public_links_require_both_receipt_and_operator_opt_in(event):
    enabled = Preferences(include_public_links=True)
    assert "https:" not in format_event(event, enabled).text
    public = replace(event, public_repository=True)
    assert "https:" not in format_event(public).text
    text = format_event(public, enabled).text
    assert "https://github.com/example/target/issues/1" in text
    assert "https://github.com/example/target/pull/7" in text


@pytest.mark.parametrize(
    "changes",
    [
        {"repository": "evil.invalid/a"},
        {"repository": "https://evil.invalid/a"},
        {"repository": "user/token?x"},
        {"repository": "user/<b>secret</b>"},
        {"issue": True},
        {"pr_number": -1},
        {"sha": "/secret/path"},
        {"evidence_sha256": "raw secret"},
        {"kind": "human_merged"},
        {"result": "PASS"},
        {"public_repository": "true"},
        {"generation": 2},
    ],
)
def test_raw_or_malicious_fields_are_not_trusted_events(event, changes):
    with pytest.raises(NotificationError):
        replace(event, **changes)


def test_untrusted_message_or_issue_data_cannot_select_notification(event):
    for raw in [
        "<b>secret</b>",
        {"kind": "human_merged", "text": "secret", "url": "https://evil.invalid"},
    ]:
        with pytest.raises(NotificationError):
            format_event(raw)
    with pytest.raises(TypeError):
        NotificationEvent(**{**asdict(event), "text": "secret"})
    with pytest.raises(TypeError):
        SafeNotification(event, text="secret")


@pytest.mark.parametrize(
    "kind,flags", [(Kind.REVIEW_COMPLETED, {}), (Kind.HUMAN_MERGED, {})]
)
def test_privileged_github_claims_need_explicit_trusted_receipt(admitted, kind, flags):
    with pytest.raises(NotificationError):
        GitHubEvidence(
            admitted,
            kind,
            7,
            "a" * 40,
            "b" * 64,
            Result.PASS if kind == Kind.REVIEW_COMPLETED else None,
            **flags,
        )


@pytest.mark.parametrize(
    "values",
    [
        {"enabled": True},
        {"enabled": "true"},
        {"chat_id": "@somebody"},
        {"chat_id": -100},
        {"chat_id": True},
        {"chat_id": 2**52},
        {"repositories": [12]},
        {"repositories": (12, 12)},
        {"severities": ("error",)},
        {"min_interval": 0},
        {"progress_interval": 1},
        {"max_attempts": 4},
    ],
)
def test_invalid_operator_preferences_refused(values):
    with pytest.raises(NotificationError):
        Preferences(**values)


def test_bot_request_exact_contract_and_no_token(event):
    request = TelegramRequest(12345, format_event(event))
    assert request.origin == "https://api.telegram.org"
    assert (
        request.method == "sendMessage"
        and request.timeout == 5
        and request.redirects is False
    )
    data = json.loads(request.body)
    assert data == {
        "chat_id": 12345,
        "text": format_event(event).text,
        "link_preview_options": {"is_disabled": True},
        "protect_content": True,
        "allow_paid_broadcast": False,
    }
    assert "parse_mode" not in data and "entities" not in data
    assert "token" not in repr(request).lower()
    for name in ["origin", "method", "timeout", "redirects"]:
        with pytest.raises(ValueError):
            replace(request, **{name: "https://evil.invalid"})


def test_exact_private_chat_ack_and_payload_binding(event):
    request = TelegramRequest(12345, format_event(event))
    assert classify(ack(request), request).outcome == Outcome.DELIVERED
    for reply in [
        ack(request, chat=12346),
        ack(request, chat=True),
        ack(request, private="group"),
        ack(request, text="secret other message"),
    ]:
        assert classify(reply, request).outcome == Outcome.UNKNOWN


@pytest.mark.parametrize(
    "reply,expected",
    [
        (FakeFault.TIMEOUT, Outcome.UNKNOWN),
        (FakeFault.ERROR, Outcome.UNKNOWN),
        (FakeFault.NOT_SENT, Outcome.PENDING),
        (FakeReply(302, b'{"ok":false}'), Outcome.UNKNOWN),
        (
            FakeReply(500, b'{"ok":false,"error_code":500,"description":"secret"}'),
            Outcome.UNKNOWN,
        ),
        (
            FakeReply(403, b'{"ok":false,"error_code":403,"description":"secret"}'),
            Outcome.PENDING,
        ),
        (
            FakeReply(
                429, b'{"ok":false,"error_code":429,"parameters":{"retry_after":30}}'
            ),
            Outcome.PENDING,
        ),
    ],
)
def test_error_classification_without_raw_diagnostics(event, reply, expected):
    result = classify(reply, TelegramRequest(12345, format_event(event)))
    assert result.outcome == expected and "secret" not in repr(result)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"<html>secret</html>",
        b"\xff",
        b"[]",
        b"{",
        b'{"ok":true,"ok":false}',
        b'{"ok":NaN}',
        b'{"ok":"true"}',
        b'{"ok":true,"result":{}}',
        b'{"ok":false,"error_code":429,"parameters":{"retry_after":true}}',
        b'{"ok":false,"error_code":429,"parameters":{"retry_after":0}}',
        b'{"ok":false,"error_code":429,"parameters":{"retry_after":86401}}',
        b'{"ok":false,"error_code":429,"parameters":{"retry_after":1,"migrate_to_chat_id":99}}',
        b"x" * 8193,
    ],
)
def test_malformed_response_is_unknown(event, raw):
    reply = FakeReply(429 if b"429" in raw else 200, raw)
    result = classify(reply, TelegramRequest(12345, format_event(event)))
    assert result.outcome == Outcome.UNKNOWN
    assert result.category == Category.INVALID_RESPONSE
    assert "secret" not in repr(result)


def test_fake_transport_is_bounded_and_not_a_callback(event):
    with pytest.raises(NotificationError):
        FakeTelegram(lambda: pytest.fail("no callbacks"))
    fake = FakeTelegram()
    request = TelegramRequest(12345, format_event(event))
    for _ in range(32):
        assert fake.send(request).category == Category.NOT_SENT
    with pytest.raises(NotificationError):
        fake.send(request)
    assert len(fake.requests) == 32
    with pytest.raises(NotificationError):
        Delivery(Outcome.DELIVERED, Category.UNCERTAIN)


def test_logical_identity_ignores_receipt_refresh_but_binds_scope_and_result(event):
    assert event.key == replace(event, evidence_sha256="f" * 64).key
    assert event.key != replace(event, scope_sha256="f" * 64).key
    assert event.key != replace(event, sha="f" * 40).key
    assert event.key != replace(event, pr_number=8).key
    ci = replace(event, kind=Kind.CI_RESULT, result=Result.PASS)
    assert ci.key != replace(ci, result=Result.FAIL).key


def test_impossible_success_with_error_fields_is_unknown(event):
    request = TelegramRequest(12345, format_event(event))
    data = json.loads(ack(request).body)
    data["error_code"] = 429
    assert (
        classify(FakeReply(200, json.dumps(data).encode()), request).outcome
        == Outcome.UNKNOWN
    )
