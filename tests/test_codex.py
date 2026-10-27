import json

import pytest

from agent_platform import codex

SESSION = "0199a213-81c0-7800-8aa1-bbab2a035a53"


def accept(parser, data):
    parser.accept(json.dumps(data).encode())


def test_pinned_arguments():
    initial = codex.arguments()
    resumed = codex.arguments(SESSION)
    assert resumed == initial[:-1] + ["resume", SESSION, "-"]
    assert initial.index("--sandbox") > initial.index("exec")
    assert initial[initial.index("--sandbox") + 1] == "workspace-write"
    assert "--last" not in resumed and "--ephemeral" not in resumed
    assert "--dangerously-bypass-approvals-and-sandbox" not in resumed
    assert initial[initial.index("--ask-for-approval") + 1] == "never"


@pytest.mark.parametrize(
    "value", [None, "", "--last", "not-uuid", "00000000-0000-0000-0000-000000000000"]
)
def test_invalid_session(value):
    with pytest.raises(codex.ProtocolError):
        codex.session_id(value)


def test_session_callback_is_immediate():
    saved = []
    parser = codex.Events(saved.append)
    accept(parser, {"type": "thread.started", "thread_id": SESSION})
    assert saved == [SESSION] and not parser.turn
    accept(parser, {"type": "turn.started"})
    accept(parser, {"type": "error", "message": "quota secret"})
    accept(parser, {"type": "turn.failed", "error": {"message": "quota secret"}})
    assert parser.finish(1) == "PAUSED"
    assert "secret" not in repr(vars(parser))


@pytest.mark.parametrize(
    "raw",
    [
        b"{bad secret",
        b"\xff",
        b"[]",
        b'{"type":"turn.started","type":"turn.completed"}',
        b'{"type":NaN}',
    ],
)
def test_invalid_json(raw):
    with pytest.raises(codex.ProtocolError) as error:
        codex.Events(lambda value: None).accept(raw)
    assert "secret" not in str(error.value)


@pytest.mark.parametrize(
    "usage",
    [
        None,
        {},
        {"input_tokens": True},
        {"input_tokens": -1, "cached_input_tokens": 0, "output_tokens": 1},
    ],
)
def test_usage_schema(usage):
    parser = codex.Events(lambda value: None)
    accept(parser, {"type": "thread.started", "thread_id": SESSION})
    accept(parser, {"type": "turn.started"})
    with pytest.raises(codex.ProtocolError):
        accept(parser, {"type": "turn.completed", "usage": usage})
