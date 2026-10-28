"""Pinned CLI arguments and a deliberately small, nonsecret JSONL state machine."""

import json
import uuid

VERSION = "0.164.0"


class ProtocolError(Exception):
    """Never contains untrusted output."""


def session_id(value):
    try:
        parsed = uuid.UUID(value) if isinstance(value, str) else None
        if parsed is None or str(parsed) != value or parsed.version not in (4, 7):
            raise ValueError
        return value
    except (ValueError, AttributeError):
        raise ProtocolError("invalid_session") from None


def arguments(session=None):
    # exec options precede the resume subcommand in the pinned CLI parser.
    args = [
        "/usr/bin/codex",
        "--no-daemon",
        "--ask-for-approval",
        "never",
        "-c",
        "sandbox_workspace_write.writable_roots=[]",
        "-c",
        "sandbox_workspace_write.network_access=false",
        "-c",
        "sandbox_workspace_write.exclude_slash_tmp=true",
        "-c",
        "sandbox_workspace_write.exclude_tmpdir_env_var=true",
        "-c",
        'model_provider="agent_platform"',
        "-c",
        'model_providers.agent_platform.name="Isolated inference"',
        "-c",
        'model_providers.agent_platform.base_url="http://127.0.0.1:31847/v1"',
        "-c",
        'model_providers.agent_platform.wire_api="responses"',
        "-c",
        "model_providers.agent_platform.requires_openai_auth=false",
        "-c",
        "model_providers.agent_platform.supports_websockets=false",
        "-c",
        "model_providers.agent_platform.request_max_retries=0",
        "-c",
        "model_providers.agent_platform.stream_max_retries=0",
        "exec",
        "--json",
        "--sandbox",
        "workspace-write",
        "--skip-git-repo-check",
        "--ignore-user-config",
        "--ignore-rules",
    ]
    if session is not None:
        args += ["resume", session_id(session)]
    return [*args, "-"]


class Events:
    def __init__(self, record_session, expected=None):
        self.record_session = record_session
        self.expected = expected
        self.session = None
        self.turn = False
        self.terminal = None
        self.usage = None
        self.count = 0

    def accept(self, raw: bytes):
        self.count += 1
        if self.count > 10000:
            raise ProtocolError("event_limit")
        try:

            def pairs(values):
                result = {}
                for key, value in values:
                    if key in result:
                        raise ValueError
                    result[key] = value
                return result

            def constant(value):
                raise ValueError

            data = json.loads(
                raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant
            )
        except (ValueError, RecursionError):
            raise ProtocolError("invalid_jsonl") from None
        if not isinstance(data, dict) or self.terminal:
            raise ProtocolError("event_sequence")
        kind = data.get("type")
        if kind == "thread.started":
            if self.session is not None or self.turn:
                raise ProtocolError("duplicate_session")
            value = session_id(data.get("thread_id"))
            if self.expected is not None and value != self.expected:
                raise ProtocolError("session_mismatch")
            self.session = value
            self.record_session(
                value
            )  # Synchronous durable write before consuming more events.
        elif kind == "turn.started" and self.session and not self.turn:
            self.turn = True
        elif (
            kind in ("item.started", "item.updated", "item.completed", "error")
            and self.turn
        ):
            pass  # Discard arbitrary items and errors.
        elif kind in ("turn.completed", "turn.failed") and self.turn:
            self.terminal = kind
            if kind == "turn.completed":
                usage = data.get("usage")
                if not isinstance(usage, dict):
                    raise ProtocolError("invalid_usage")
                keys = ("input_tokens", "cached_input_tokens", "output_tokens")
                values = {key: usage.get(key) for key in keys}
                if not all(type(n) is int and 0 <= n < 2**63 for n in values.values()):
                    raise ProtocolError("invalid_usage")
                self.usage = values
        else:
            raise ProtocolError("event_sequence")

    def finish(self, returncode):
        if self.session and self.terminal == "turn.completed" and returncode == 0:
            return "COMPLETED"
        if self.session and self.terminal == "turn.failed" and returncode in (0, 1):
            return "PAUSED"  # A confirmed terminal failure; never match error prose.
        raise ProtocolError("ambiguous_exit")
