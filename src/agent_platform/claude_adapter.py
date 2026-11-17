"""HAR-03 parser-only Claude Code 2.1.295 fixture profile. Never invokes a CLI.

Native data is untrusted. Only synthetic, separately supplied observations may
complete an OFFLINE lifecycle; no output grants runtime or publishing authority.
Unknown variants poison the whole parse. No Codex parser/session is reused.
"""

import hashlib
import json
import math
import re
import time
import uuid
from dataclasses import asdict, dataclass, field, replace

from . import harness_admission as har

VERSION = "2.1.295"
SCHEMA = "AP-CLAUDE-EVENTS/1"
MAX_EVENT = 16 * 1024
MAX_STREAM = 1024 * 1024
MAX_EVENTS = 512
MAX_DEPTH = 8
MAX_NODES = 4096
MAX_ITEMS = 256
MAX_TEXT = 8192
MAX_CORRELATIONS = 128
MAX_SECONDS = 2.0


class Invalid(ValueError):
    """Contains a fixed reason only, never vendor data or decoder exceptions."""


def need(condition, reason="PROTOCOL_INVALID"):
    if not condition:
        raise Invalid(reason)


def identifier(value):
    need(type(value) is str and re.fullmatch(r"[A-Za-z0-9_:-]{1,128}", value))
    return har.digest(value)


def native_uuid(value):
    need(type(value) is str and len(value) == 36)
    try:
        parsed = uuid.UUID(value)
        # Project restriction, not an assertion about every vendor UUID version.
        need(str(parsed) == value and parsed.version == 4)
    except (ValueError, AttributeError):
        raise Invalid("PROTOCOL_INVALID") from None
    return value


def shape(value, required, optional=()):
    need(type(value) is dict)
    need(set(required) <= set(value) <= set(required) | set(optional))


def text(value):
    need(type(value) is str and len(value) <= MAX_TEXT)
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise Invalid("PROTOCOL_INVALID") from None


def count(value):
    need(type(value) is int and 0 <= value <= 2**63 - 1)


def strings(value):
    need(type(value) is list and len(value) <= MAX_ITEMS)
    for item in value:
        text(item)


def decode(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_EVENT, "RESOURCE_LIMIT")
    # Quote-aware preflight bounds depth BEFORE json.loads/recursive allocation.
    depth = 0
    quoted = escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            need(depth <= MAX_DEPTH, "RESOURCE_LIMIT")
        elif byte in (93, 125):
            depth -= 1
            need(depth >= 0)
    need(depth == 0 and not quoted)

    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result)
            result[key] = value
        return result

    def constant(_value):
        raise Invalid("PROTOCOL_INVALID")

    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant
        )
    except (ValueError, UnicodeError, RecursionError):
        raise Invalid("PROTOCOL_INVALID") from None
    pending = [value]
    nodes = 0
    while pending:
        node = pending.pop()
        nodes += 1
        need(nodes <= MAX_NODES, "RESOURCE_LIMIT")
        if type(node) is dict:
            need(len(node) <= MAX_ITEMS, "RESOURCE_LIMIT")
            for key in node:
                text(key)
            pending.extend(node.values())
        elif type(node) is list:
            need(len(node) <= MAX_ITEMS, "RESOURCE_LIMIT")
            pending.extend(node)
        elif type(node) is str:
            text(node)
        elif type(node) in (int, float):
            need(abs(node) <= 2**63 - 1 and math.isfinite(node))
        else:
            need(node is None or type(node) is bool)
    need(type(value) is dict)
    return value


@dataclass(frozen=True, slots=True)
class ClaudeSession:
    binding: har.Binding
    assignment_sha256: str
    session_ref: str
    native_id: str = field(repr=False)
    cli_version: str = VERSION
    schema: str = "AP-CLAUDE-SESSION/1"

    def __post_init__(self):
        need(type(self.binding) is har.Binding, "BINDING_MISMATCH")
        replace(self.binding)
        need(self.binding.harness_id is har.HarnessId.CLAUDE_CODE, "BINDING_MISMATCH")
        har.sha(self.assignment_sha256)
        har.public_ref(self.session_ref)
        native_uuid(self.native_id)
        need(self.cli_version == VERSION and type(self.cli_version) is str)
        need(self.schema == "AP-CLAUDE-SESSION/1" and type(self.schema) is str)

    @property
    def native_digest(self):
        return har.digest({"harness_id": "claude_code", "native_id": self.native_id})


@dataclass(frozen=True, slots=True)
class Context:
    assignment: har.HarnessAssignment
    session: ClaudeSession
    expected_binding: har.Binding
    expected_assignment_sha256: str
    seen_event_sha256: tuple[str, ...] = ()
    next_seq: int = 3
    continuation: "ContinuationIntent | None" = None
    schema: str = "AP-CLAUDE-CONTEXT/1"

    def __post_init__(self):
        need(type(self.assignment) is har.HarnessAssignment, "BINDING_MISMATCH")
        need(type(self.session) is ClaudeSession, "BINDING_MISMATCH")
        need(type(self.expected_binding) is har.Binding, "BINDING_MISMATCH")
        replace(self.assignment)
        replace(self.session)
        replace(self.expected_binding)
        har.sha(self.expected_assignment_sha256)
        need(
            self.assignment.binding == self.session.binding == self.expected_binding,
            "BINDING_MISMATCH",
        )
        need(
            self.assignment.digest
            == self.expected_assignment_sha256
            == self.session.assignment_sha256,
            "BINDING_MISMATCH",
        )
        need(
            type(self.seen_event_sha256) is tuple
            and len(self.seen_event_sha256) <= MAX_EVENTS,
            "RESOURCE_LIMIT",
        )
        for item in self.seen_event_sha256:
            har.sha(item)
        need(len(set(self.seen_event_sha256)) == len(self.seen_event_sha256))
        count(self.next_seq)
        need(3 <= self.next_seq < 2**63)
        if self.continuation is not None:
            need(type(self.continuation) is ContinuationIntent, "BINDING_MISMATCH")
            replace(self.continuation)
            need(
                self.assignment == self.continuation.next_assignment
                and self.session.native_id == self.continuation.previous.native_id,
                "BINDING_MISMATCH",
            )
        need(self.schema == "AP-CLAUDE-CONTEXT/1" and type(self.schema) is str)


@dataclass(frozen=True, slots=True)
class ContinuationIntent:
    """Comparison-only; cannot produce argv, read sessions or authorize resume."""

    previous: ClaudeSession
    previous_assignment: har.HarnessAssignment
    next_assignment: har.HarnessAssignment
    expected_binding: har.Binding
    checkpoint_sha256: str
    previous_outcome: str
    schema: str = "AP-CLAUDE-CONTINUATION/1"

    def __post_init__(self):
        need(type(self.previous) is ClaudeSession, "BINDING_MISMATCH")
        need(type(self.next_assignment) is har.HarnessAssignment, "BINDING_MISMATCH")
        need(type(self.expected_binding) is har.Binding, "BINDING_MISMATCH")
        need(
            type(self.previous_assignment) is har.HarnessAssignment, "BINDING_MISMATCH"
        )
        replace(self.previous_assignment)
        need(
            self.previous_assignment.digest == self.previous.assignment_sha256,
            "BINDING_MISMATCH",
        )
        for name in (
            "task_authorization_sha256",
            "model_policy_sha256",
            "account_policy_ref",
        ):
            need(
                getattr(self.previous_assignment, name)
                == getattr(self.next_assignment, name),
                "BINDING_MISMATCH",
            )
        replace(self.previous)
        replace(self.next_assignment)
        replace(self.expected_binding)
        har.sha(self.checkpoint_sha256)
        need(self.checkpoint_sha256 != har.ZERO and self.previous_outcome == "PAUSED")
        need(
            self.previous.binding
            == self.next_assignment.binding
            == self.expected_binding,
            "BINDING_MISMATCH",
        )
        need(self.previous.assignment_sha256 != self.next_assignment.digest)
        need(self.schema == "AP-CLAUDE-CONTINUATION/1" and type(self.schema) is str)


@dataclass(frozen=True, slots=True)
class ProcessFixture:
    """Independent fabricated capture/termination evidence, NEVER host evidence."""

    assignment_sha256: str
    stream_sha256: str
    exit_code: int | None
    eof: bool
    effects: str  # UNKNOWN or FIXTURE_QUIESCENT; never HOST_PASS.
    termination: str = "NONE"
    duration_ms: int = 0
    schema: str = "AP-CLAUDE-PROCESS-FIXTURE/1"

    def __post_init__(self):
        har.sha(self.assignment_sha256)
        har.sha(self.stream_sha256)
        need(
            self.exit_code is None
            or (type(self.exit_code) is int and -255 <= self.exit_code <= 255)
        )
        need(type(self.eof) is bool)
        need(
            type(self.effects) is str
            and self.effects in {"UNKNOWN", "FIXTURE_QUIESCENT"}
        )
        need(
            type(self.termination) is str
            and self.termination in {"NONE", "SIGTERM", "SIGINT", "TIMEOUT"}
        )
        count(self.duration_ms)
        need(self.schema == "AP-CLAUDE-PROCESS-FIXTURE/1" and type(self.schema) is str)


class _Trace:
    def __init__(self, context):
        self.context = context
        self.seen = set(context.seen_event_sha256)
        self.initialized = False
        self.messages = set()
        self.tools = set()
        self.pending = set()
        self.denials = set()
        self.tasks = {}
        self.seen_tasks = set()
        self.background = False
        self.diagnostic = "NONE"
        self.terminal = None
        self.partial = None
        self.partial_done = None
        self.ready = "ASSISTANT"

    def common(self, event):
        native_uuid(event.get("uuid"))
        need(event.get("session_id") == self.context.session.native_id)
        key = har.digest({"namespace": "claude_code", "uuid": event["uuid"]})
        need(key not in self.seen, "EVENT_REPLAY")
        need(len(self.seen) < MAX_EVENTS, "RESOURCE_LIMIT")
        self.seen.add(key)
        need(self.terminal is None)

    def accept(self, event):
        self.common(event)
        kind = event.get("type")
        if kind == "system" and event.get("subtype") == "init":
            need(not self.initialized)
            shape(
                event,
                (
                    "type",
                    "subtype",
                    "uuid",
                    "session_id",
                    "claude_code_version",
                    "cwd",
                    "tools",
                    "mcp_servers",
                    "model",
                    "permissionMode",
                    "slash_commands",
                    "apiKeySource",
                    "output_style",
                    "skills",
                    "plugins",
                ),
                ("agents", "betas", "capabilities"),
            )
            need(event["claude_code_version"] == VERSION)
            for name in (
                "cwd",
                "model",
                "permissionMode",
                "apiKeySource",
                "output_style",
            ):
                text(event[name])
            for name in (
                "tools",
                "slash_commands",
                "skills",
                "agents",
                "betas",
                "capabilities",
            ):
                strings(event.get(name, []))
            # Nonempty discovery/configuration needs a separately reviewed profile.
            need(
                event["mcp_servers"] == []
                and event["plugins"] == []
                and event.get("capabilities", []) == [],
                "UNSUPPORTED_VARIANT",
            )
            self.initialized = True
            return
        if kind == "result":
            need(self.initialized or event.get("subtype") == "error_during_execution")
            self.result(event)
            return
        need(self.initialized)
        if kind in ("assistant", "user"):
            self.message(event)
        elif kind == "rate_limit_event":
            shape(event, ("type", "uuid", "session_id", "rate_limit_info"))
            info = event["rate_limit_info"]
            shape(
                info,
                ("status",),
                (
                    "resetsAt",
                    "utilization",
                    "errorCode",
                    "canUserPurchaseCredits",
                    "hasChargeableSavedPaymentMethod",
                    "overageEnabled",
                ),
            )
            need(info["status"] in {"allowed", "allowed_warning", "rejected"})
            if "resetsAt" in info:
                count(info["resetsAt"])
            if "utilization" in info:
                need(
                    type(info["utilization"]) in (int, float)
                    and info["utilization"] >= 0
                )
            if "errorCode" in info:
                need(info["errorCode"] == "credits_required")
            for name in (
                "canUserPurchaseCredits",
                "hasChargeableSavedPaymentMethod",
                "overageEnabled",
            ):
                if name in info:
                    need(type(info[name]) is bool)
            if info["status"] == "rejected":
                self.diagnostic = "RATE_LIMIT"
        elif kind == "system" and event.get("subtype") == "permission_denied":
            shape(
                event,
                (
                    "type",
                    "subtype",
                    "uuid",
                    "session_id",
                    "tool_name",
                    "tool_use_id",
                    "message",
                ),
                ("agent_id", "decision_reason_type", "decision_reason"),
            )
            key = identifier(event["tool_use_id"])
            need(key in self.pending and key not in self.denials)
            text(event["tool_name"])
            text(event["message"])
            if "agent_id" in event:
                identifier(event["agent_id"])
            for name in ("decision_reason", "decision_reason_type"):
                if name in event:
                    text(event[name])
            self.denials.add(key)
            self.diagnostic = "TOOL_DENIED"
        elif kind == "system" and event.get("subtype") in {
            "task_started",
            "task_notification",
        }:
            self.task(event)
        elif kind == "stream_event":
            self.stream_event(event)
        else:
            raise Invalid("UNSUPPORTED_VARIANT")

    def message(self, event):
        shape(
            event,
            ("type", "uuid", "session_id", "message", "parent_tool_use_id"),
            ("error", "aborted", "agent_id") if event["type"] == "assistant" else (),
        )
        if "agent_id" in event:
            identifier(event["agent_id"])
        parent = event["parent_tool_use_id"]
        if parent is not None:
            need(identifier(parent) in self.pending)
            self.background = True
        message = event["message"]
        if parent is None:
            need(
                self.ready == ("ASSISTANT" if event["type"] == "assistant" else "TOOL")
            )
        if event["type"] == "assistant":
            shape(
                message,
                (
                    "id",
                    "type",
                    "role",
                    "model",
                    "content",
                    "stop_reason",
                    "stop_sequence",
                    "usage",
                ),
            )
            need(message["type"] == "message" and message["role"] == "assistant")
            key = identifier(message["id"])
            need(key not in self.messages and self.partial is None)
            need(len(self.messages) < MAX_CORRELATIONS, "RESOURCE_LIMIT")
            self.messages.add(key)
            text(message["model"])
            need(type(message["usage"]) is dict)
            need(
                message["stop_reason"]
                in {None, "end_turn", "tool_use", "max_tokens", "stop_sequence"}
            )
            need(
                message["stop_sequence"] is None
                or type(message["stop_sequence"]) is str
            )
            if self.partial_done is not None:
                expected_id, expected_text = self.partial_done
                need(message["id"] == expected_id)
                blocks = message["content"]
                need(all(type(b) is dict and b.get("type") == "text" for b in blocks))
                observed = hashlib.sha256(
                    "".join(b["text"] for b in blocks).encode()
                ).hexdigest()
                need(observed == expected_text)
                self.partial_done = None
            if "error" in event:
                need(
                    event["error"]
                    in {
                        "authentication_failed",
                        "oauth_org_not_allowed",
                        "account_on_hold",
                        "billing_error",
                        "rate_limit",
                        "overloaded",
                        "invalid_request",
                        "model_not_found",
                        "server_error",
                        "max_output_tokens",
                        "cloud_credential_error",
                        "unknown",
                    }
                )
                self.diagnostic = (
                    "AUTH_ERROR"
                    if event["error"]
                    in {
                        "authentication_failed",
                        "oauth_org_not_allowed",
                        "account_on_hold",
                        "billing_error",
                        "cloud_credential_error",
                    }
                    else "RATE_LIMIT"
                    if event["error"] == "rate_limit"
                    else "VENDOR_ERROR"
                )
            if "aborted" in event:
                need(event["aborted"] is True)
                self.diagnostic = "CANCELLED"
        else:
            shape(message, ("role", "content"))
            need(message["role"] == "user")
        blocks = message["content"]
        need(type(blocks) is list and 0 < len(blocks) <= MAX_ITEMS)
        for block in blocks:
            kind = block.get("type") if type(block) is dict else None
            if kind == "text":
                shape(block, ("type", "text"))
                text(block["text"])
                need(
                    event["type"] == "assistant" or parent is not None,
                    "UNSUPPORTED_VARIANT",
                )
            elif kind == "tool_use" and event["type"] == "assistant":
                shape(block, ("type", "id", "name", "input"))
                key = identifier(block["id"])
                identifier(block["name"])
                need(type(block["input"]) is dict and key not in self.tools)
                need(len(self.tools) < MAX_CORRELATIONS, "RESOURCE_LIMIT")
                self.tools.add(key)
                self.pending.add(key)
            elif kind == "tool_result" and event["type"] == "user":
                shape(block, ("type", "tool_use_id", "content"), ("is_error",))
                key = identifier(block["tool_use_id"])
                need(key in self.pending)
                need(type(block.get("is_error", False)) is bool)
                need(type(block["content"]) in (str, list))
                if type(block["content"]) is list:
                    for part in block["content"]:
                        shape(part, ("type", "text"))
                        need(part["type"] == "text", "UNSUPPORTED_VARIANT")
                        text(part["text"])
                self.pending.remove(key)
                if block.get("is_error"):
                    self.diagnostic = (
                        "TOOL_ERROR" if not self.denials else "TOOL_DENIED"
                    )
            else:
                raise Invalid("UNSUPPORTED_VARIANT")

        if parent is None:
            if event["type"] == "assistant":
                has_tools = any(block["type"] == "tool_use" for block in blocks)
                if has_tools:
                    need(message["stop_reason"] == "tool_use")
                    self.ready = "TOOL"
                else:
                    need(
                        message["stop_reason"] == "end_turn"
                        or "error" in event
                        or "aborted" in event
                    )
                    self.ready = "RESULT"
            elif not self.pending:
                self.ready = "ASSISTANT"

    def result(self, event):
        shape(
            event,
            (
                "type",
                "subtype",
                "uuid",
                "session_id",
                "duration_ms",
                "duration_api_ms",
                "is_error",
                "num_turns",
                "stop_reason",
                "total_cost_usd",
                "usage",
                "modelUsage",
                "permission_denials",
            ),
            (
                "result",
                "errors",
                "result_index",
                "terminal_reason",
                "queued_turn_count",
                "api_error_status",
                "startup_failure_reason",
                "structured_output",
            ),
        )
        need(self.partial is None and self.partial_done is None)
        need(not self.pending, "UNRESOLVED_TOOL")
        need(type(event["is_error"]) is bool)
        for name in ("duration_ms", "duration_api_ms", "num_turns"):
            count(event[name])
        need(
            type(event["total_cost_usd"]) in (int, float)
            and event["total_cost_usd"] >= 0
        )
        need(type(event["usage"]) is type(event["modelUsage"]) is dict)
        if "api_error_status" in event and event["api_error_status"] is not None:
            status = event["api_error_status"]
            need(type(status) is int and 100 <= status <= 599)
            if status >= 400:
                self.diagnostic = (
                    "AUTH_ERROR"
                    if status in {401, 403}
                    else "RATE_LIMIT"
                    if status == 429
                    else "VENDOR_ERROR"
                )
        if "result_index" in event:
            need(type(event["result_index"]) is int and event["result_index"] == 0)
        if "queued_turn_count" in event:
            count(event["queued_turn_count"])
        denials = event["permission_denials"]
        need(type(denials) is list)
        ids = set()
        for denial in denials:
            shape(denial, ("tool_name", "tool_use_id", "tool_input"))
            identifier(denial["tool_name"])
            need(type(denial["tool_input"]) is dict)
            key = identifier(denial["tool_use_id"])
            need(key not in ids)
            need(not self.initialized or key in self.tools)
            ids.add(key)
        need(self.denials <= ids)
        if ids:
            self.diagnostic = "TOOL_DENIED"
        need(
            event["stop_reason"]
            in {None, "end_turn", "tool_use", "max_tokens", "stop_sequence"},
            "UNSUPPORTED_VARIANT",
        )
        if "terminal_reason" in event:
            need(
                event["terminal_reason"]
                in {
                    "completed",
                    "max_turns",
                    "tool_deferred",
                    "aborted_streaming",
                    "aborted_tools",
                    "hook_stopped",
                    "stop_hook_prevented",
                    "background_requested",
                    "blocking_limit",
                    "rapid_refill_breaker",
                    "prompt_too_long",
                    "image_error",
                    "model_error",
                    "api_error",
                    "malformed_tool_use_exhausted",
                    "budget_exhausted",
                    "structured_output_retry_exhausted",
                    "tool_deferred_unavailable",
                    "turn_setup_failed",
                },
                "UNSUPPORTED_VARIANT",
            )
        subtype = event["subtype"]
        if subtype == "success":
            need("startup_failure_reason" not in event)
            need(not self.initialized or self.ready == "RESULT")
            need("result" in event and "errors" not in event)
            text(event["result"])
            need(not event["is_error"])
        else:
            need(
                subtype
                in {
                    "error_max_turns",
                    "error_during_execution",
                    "error_max_budget_usd",
                    "error_max_structured_output_retries",
                }
            )
            need(event["is_error"] and "errors" in event and "result" not in event)
            need("structured_output" not in event and "api_error_status" not in event)
            if "startup_failure_reason" in event:
                need(subtype == "error_during_execution")
                text(event["startup_failure_reason"])
            strings(event["errors"])
            if self.diagnostic == "NONE":
                self.diagnostic = (
                    "RATE_LIMIT"
                    if subtype in {"error_max_turns", "error_max_budget_usd"}
                    else "VENDOR_ERROR"
                )
        if event.get("terminal_reason") in {"aborted_streaming", "aborted_tools"}:
            self.diagnostic = "CANCELLED"
        self.terminal = {
            key: event[key]
            for key in (
                "subtype",
                "is_error",
                "num_turns",
                "stop_reason",
                "terminal_reason",
                "queued_turn_count",
                "result_index",
            )
            if key in event
        }

    def task(self, event):
        if event["subtype"] == "task_started":
            shape(
                event,
                ("type", "subtype", "uuid", "session_id", "task_id", "description"),
                (
                    "run_id",
                    "tool_use_id",
                    "task_type",
                    "is_backgrounded",
                    "spawn_depth",
                    "parent_task_id",
                    "ambient",
                ),
            )
            key = identifier(event["task_id"])
            need(key not in self.seen_tasks)
            need(len(self.seen_tasks) < MAX_CORRELATIONS, "RESOURCE_LIMIT")
            self.seen_tasks.add(key)
            self.tasks[key] = identifier(event["run_id"]) if "run_id" in event else None
            text(event["description"])
        else:
            shape(
                event,
                (
                    "type",
                    "subtype",
                    "uuid",
                    "session_id",
                    "task_id",
                    "status",
                    "output_file",
                    "summary",
                ),
                ("run_id", "tool_use_id", "ambient", "usage"),
            )
            key = identifier(event["task_id"])
            need(
                key in self.tasks
                and event["status"] in {"completed", "failed", "stopped"}
            )
            need(
                self.tasks[key]
                == (identifier(event["run_id"]) if "run_id" in event else None)
            )
            del self.tasks[key]
            text(event["output_file"])
            text(event["summary"])
        if "task_type" in event:
            text(event["task_type"])
        if "usage" in event:
            shape(event["usage"], ("total_tokens", "tool_uses", "duration_ms"))
            for number in event["usage"].values():
                count(number)
        for name in ("ambient", "is_backgrounded"):
            if name in event:
                need(type(event[name]) is bool)
        if "spawn_depth" in event:
            count(event["spawn_depth"])
            need(event["spawn_depth"] <= MAX_DEPTH)
        if "tool_use_id" in event:
            need(identifier(event["tool_use_id"]) in self.tools)
        if "parent_task_id" in event:
            need(identifier(event["parent_task_id"]) in self.seen_tasks)
        self.background = True

    def stream_event(self, event):
        shape(event, ("type", "uuid", "session_id", "parent_tool_use_id", "event"))
        need(event["parent_tool_use_id"] is None)
        item = event["event"]
        need(type(item) is dict)
        kind = item.get("type")
        if "index" in item:
            count(item["index"])
        if kind == "message_start":
            shape(item, ("type", "message"))
            need(self.partial is None and self.partial_done is None)
            message = item["message"]
            shape(
                message,
                (
                    "id",
                    "type",
                    "role",
                    "model",
                    "content",
                    "stop_reason",
                    "stop_sequence",
                    "usage",
                ),
            )
            identifier(message["id"])
            need(
                message["type"] == "message"
                and message["role"] == "assistant"
                and message["content"] == []
                and message["stop_reason"] is None
            )
            self.partial = {
                "id": message["id"],
                "index": 0,
                "open": False,
                "ended": False,
                "hash": hashlib.sha256(),
            }
            return
        need(self.partial is not None)
        partial = self.partial
        if kind == "content_block_start":
            shape(item, ("type", "index", "content_block"))
            need(
                not partial["open"]
                and not partial["ended"]
                and item["index"] == partial["index"]
            )
            shape(item["content_block"], ("type", "text"))
            need(item["content_block"]["type"] == "text")
            text(item["content_block"]["text"])
            partial["hash"].update(item["content_block"]["text"].encode())
            partial["open"] = True
        elif kind == "content_block_delta":
            shape(item, ("type", "index", "delta"))
            need(partial["open"] and item["index"] == partial["index"])
            shape(item["delta"], ("type", "text"))
            need(item["delta"]["type"] == "text_delta", "UNSUPPORTED_VARIANT")
            text(item["delta"]["text"])
            partial["hash"].update(item["delta"]["text"].encode())
        elif kind == "content_block_stop":
            shape(item, ("type", "index"))
            need(partial["open"] and item["index"] == partial["index"])
            partial["open"] = False
            partial["index"] += 1
        elif kind == "message_delta":
            shape(item, ("type", "delta", "usage"))
            shape(item["delta"], ("stop_reason", "stop_sequence"))
            need(
                not partial["open"]
                and not partial["ended"]
                and item["delta"]["stop_reason"] == "end_turn"
                and item["delta"]["stop_sequence"] is None
                and type(item["usage"]) is dict
            )
            partial["ended"] = True
        elif kind == "message_stop":
            shape(item, ("type",))
            need(partial["ended"] and not partial["open"])
            self.partial_done = (partial["id"], partial["hash"].hexdigest())
            self.partial = None
        else:
            raise Invalid("UNSUPPORTED_VARIANT")


def parse(raw, context, *, output_format="stream-json", process=None):
    """Parse bounded in-memory fixtures; no callbacks, I/O, state writes or argv.

    PASS means a complete protocol observation only. Without independent bound
    FIXTURE_QUIESCENT evidence, even a valid success remains UNKNOWN lifecycle.
    """
    started = time.monotonic()
    report = {
        "schema": "AP-CLAUDE-REPORT/1",
        "profile": SCHEMA,
        "cli_version": VERSION,
        "protocol": "FAIL",
        "outcome": "UNKNOWN",
        "diagnostic": "PROTOCOL_INVALID",
        "event": None,
        "session": None,
        "event_count": 0,
        "evidence": "VERIFIED_OFFLINE",
        "host_evidence": "HOST_NOT_RUN",
        "effects": "UNKNOWN",
        "runtime": "LIVE_NO_GO",
        "subscription": "SUBSCRIPTION_ISOLATION_BLOCKED",
        "gate_73": "BLOCKED",
        "runtime_exit_code": 13,
        "launch_allowed": False,
        "resume_authorized": False,
        "publish_authorized": False,
    }
    valid_context = False
    valid_process = False
    reason = "PROTOCOL_INVALID"
    try:
        need(type(context) is Context, "BINDING_MISMATCH")
        replace(context)
        valid_context = True
        context_before = har.digest(asdict(context))
        need(type(raw) is bytes and 0 < len(raw) <= MAX_STREAM, "RESOURCE_LIMIT")
        need(type(output_format) is str and output_format in {"json", "stream-json"})
        if process is not None:
            need(type(process) is ProcessFixture)
            replace(process)
            need(
                process.assignment_sha256 == context.assignment.digest
                and process.stream_sha256 == hashlib.sha256(raw).hexdigest(),
                "BINDING_MISMATCH",
            )
            process_before = har.digest(asdict(process))
            valid_process = True
            need(process.duration_ms <= 15_000, "RESOURCE_LIMIT")
        trace = _Trace(context)
        if output_format == "json":
            event = decode(raw)
            need(event.get("type") == "result")
            trace.common(event)
            trace.result(event)
            report["event_count"] = 1
        else:
            need(raw.endswith(b"\n"), "INCOMPLETE_STREAM")
            need(0 < raw.count(b"\n") <= MAX_EVENTS, "RESOURCE_LIMIT")
            lines = raw.split(b"\n")[:-1]
            need(0 < len(lines) <= MAX_EVENTS, "RESOURCE_LIMIT")
            for line in lines:
                need(time.monotonic() - started <= MAX_SECONDS, "RESOURCE_LIMIT")
                trace.accept(decode(line))
                report["event_count"] += 1
        need(time.monotonic() - started <= MAX_SECONDS, "RESOURCE_LIMIT")
        need(
            trace.terminal is not None
            and trace.partial is None
            and trace.partial_done is None,
            "INCOMPLETE_STREAM",
        )
        need(not trace.pending, "UNRESOLVED_TOOL")
        need(context_before == har.digest(asdict(context)), "BINDING_MISMATCH")
        report["protocol"] = "PASS"
        terminal = trace.terminal
        report["diagnostic"] = trace.diagnostic
        reason = "OUTCOME_UNKNOWN"
        independent = (
            process is not None
            and process.eof
            and process.termination == "NONE"
            and process.effects == "FIXTURE_QUIESCENT"
            and not trace.background
            and not trace.tasks
            and process.duration_ms <= 15_000
        )
        complete = (
            terminal["subtype"] == "success"
            and trace.diagnostic == "NONE"
            and terminal.get("terminal_reason") == "completed"
            and terminal.get("stop_reason") == "end_turn"
            and terminal.get("num_turns", 0) > 0
            and terminal.get("queued_turn_count") == 0
            and terminal.get("result_index") == 0
        )
        if independent and process.exit_code == 0 and complete:
            report.update(outcome="COMPLETED", effects="FIXTURE_QUIESCENT")
            reason = "NONE"
        elif trace.diagnostic == "AUTH_ERROR":
            reason = "AUTH_UNVERIFIED"
        elif trace.diagnostic == "RATE_LIMIT":
            reason = "RESOURCE_LIMIT"
        elif trace.diagnostic == "CANCELLED":
            reason = "CANCEL_UNCONFIRMED"
        elif independent and process.exit_code == 1 and terminal["is_error"]:
            report.update(outcome="PAUSED", effects="FIXTURE_QUIESCENT")
            reason = "NATIVE_TURN_FAILED"
        elif trace.background:
            report["diagnostic"] = "BACKGROUND_UNVERIFIED"
        if process is not None and process.termination != "NONE":
            reason = (
                "RESOURCE_LIMIT"
                if process.termination == "TIMEOUT"
                else "CANCEL_UNCONFIRMED"
            )
            report.update(
                outcome="UNKNOWN", effects="UNKNOWN", diagnostic="INTERRUPTED"
            )
        elif report["outcome"] == "UNKNOWN" and report["diagnostic"] == "NONE":
            report["diagnostic"] = "EFFECTS_UNVERIFIED"
    except Invalid as error:
        code = str(error)
        if code in {
            "BINDING_MISMATCH",
            "RESOURCE_LIMIT",
            "EVENT_REPLAY",
            "INCOMPLETE_STREAM",
            "UNRESOLVED_TOOL",
            "UNSUPPORTED_VARIANT",
            "PROTOCOL_INVALID",
        }:
            report["diagnostic"] = code
        reason = "RESOURCE_LIMIT" if code == "RESOURCE_LIMIT" else "PROTOCOL_INVALID"
        if code in {"INCOMPLETE_STREAM", "UNRESOLVED_TOOL"}:
            reason = "OUTCOME_UNKNOWN"
        if code == "BINDING_MISMATCH":
            valid_context = False
    except Exception:
        # Decoder, malformed native values and trusted-input errors are all redacted.
        reason = "PROTOCOL_INVALID"
    if valid_context:
        try:
            replace(context)
            need(context_before == har.digest(asdict(context)), "BINDING_MISMATCH")
        except Exception:
            valid_context = False
            report.update(
                protocol="FAIL",
                outcome="UNKNOWN",
                effects="UNKNOWN",
                diagnostic="BINDING_MISMATCH",
            )
    if valid_process:
        try:
            replace(process)
            need(process_before == har.digest(asdict(process)), "BINDING_MISMATCH")
        except Exception:
            valid_context = False
            valid_process = False
            report.update(
                protocol="FAIL",
                outcome="UNKNOWN",
                effects="UNKNOWN",
                diagnostic="BINDING_MISMATCH",
            )
    if valid_context and valid_process and process.termination != "NONE":
        reason = (
            "RESOURCE_LIMIT"
            if process.termination == "TIMEOUT"
            else "CANCEL_UNCONFIRMED"
        )
        report.update(outcome="UNKNOWN", effects="UNKNOWN", diagnostic="INTERRUPTED")
    if valid_context:
        # No native ID or vendor content is copied to canonical output.
        session = context.session
        report["session"] = {
            "schema": "AP-HSESSION/1",
            "session_ref": session.session_ref,
            "assignment_sha256": context.assignment.digest,
            "binding": context.expected_binding.record(),
            "native_session_sha256": session.native_digest,
            "mode": "RESUME" if context.continuation else "NEW",
            "parent_checkpoint_sha256": (
                context.continuation.checkpoint_sha256
                if context.continuation
                else har.ZERO
            ),
            "launch_allowed": False,
        }
        report["event"] = {
            "schema": "AP-HEVENT/1",
            "session_ref": session.session_ref,
            "assignment_sha256": context.assignment.digest,
            "binding": context.expected_binding.record(),
            "seq": context.next_seq,
            "state": report["outcome"]
            if report["outcome"] != "UNKNOWN"
            else "NEEDS_HUMAN",
            "reason": reason,
            "usage": "UNAVAILABLE",
            "launch_allowed": False,
        }
    return report
