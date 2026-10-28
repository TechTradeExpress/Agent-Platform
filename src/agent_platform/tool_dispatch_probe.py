"""Offline-only 0.164.0 callback proof; never a launcher or security boundary.

This strict subset recognizes one inert synthetic tool. Built-in tools do not
necessarily arrive here. No transport, worker, auth, filesystem or resume support
is provided. Passing the proof cannot authorize subscription execution.
"""

import hashlib
import json
import re

VERSION = "0.164.0"
SCHEMA_SHA256 = "401bba20cfbd95762bef0467d840430c46be53369093ad9f26425ba757e34efc"
SPEC = {
    "type": "function",
    "name": "synthetic_canary",
    "description": "Inert offline fixture; performs no operation",
    "inputSchema": {
        "type": "object",
        "properties": {"canary": {"const": "FABRICATED_CANARY"}},
        "required": ["canary"],
        "additionalProperties": False,
    },
}
INVENTORY_SHA256 = hashlib.sha256(
    json.dumps([SPEC], sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
MAX_LINE = 8192
MAX_TOTAL = 32768
MAX_CALLS = 16


class ProofDenied(ValueError):
    """Generic, nonsecret failure. The proof must be discarded after denial."""


def _deny():
    raise ProofDenied("offline_callback_denied") from None


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            _deny()
        value[key] = item
    return value


def _identifier(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,96}", value)


def _request_id(value):
    return _identifier(value) or (
        type(value) is int and -(2**63) <= value < 2**63
    )


class CallbackProof:
    """Consume fabricated callbacks only; all failures permanently close proof.

    Version/schema/inventory and thread/turn bindings are explicit fixture inputs,
    not attestations supplied by a real server, repository or model. No process
    is connected. close() models local cancellation/disconnect, not OS reaping.
    """

    def __init__(
        self, *, version, schema_sha256, inventory_sha256, thread_id, turn_id
    ):
        if (
            version != VERSION
            or schema_sha256 != SCHEMA_SHA256
            or inventory_sha256 != INVENTORY_SHA256
            or not _identifier(thread_id)
            or not _identifier(turn_id)
        ):
            _deny()
        self.thread_id = thread_id
        self.turn_id = turn_id
        self.closed = False
        self.total = 0
        self.requests = set()
        self.calls = set()

    def close(self):
        self.closed = True

    def accept(self, line):
        try:
            return self._accept(line)
        except (ValueError, TypeError, RecursionError):
            self.close()
            _deny()

    def _accept(self, line):
        if self.closed or type(line) is not bytes or not 0 < len(line) <= MAX_LINE:
            _deny()
        self.total += len(line)
        if self.total > MAX_TOTAL or len(self.calls) >= MAX_CALLS:
            _deny()
        # One JSON object per frame. No duplicate keys, NaN/Infinity or commands.
        value = json.loads(
            line.decode("utf-8"),
            object_pairs_hook=_object,
            parse_constant=lambda _: _deny(),
        )
        if type(value) is not dict or set(value) != {"id", "method", "params"}:
            _deny()
        request_id = value["id"]
        if (
            not _request_id(request_id)
            or request_id in self.requests
            or value["method"] != "item/tool/call"
        ):
            _deny()
        params = value["params"]
        required = {"arguments", "callId", "threadId", "tool", "turnId"}
        if type(params) is not dict or set(params) - {"namespace"} != required:
            _deny()
        if (
            not _identifier(params["callId"])
            or params["callId"] in self.calls
            or params["threadId"] != self.thread_id
            or params["turnId"] != self.turn_id
            or params.get("namespace") is not None
            or params["tool"] != "synthetic_canary"
            or params["arguments"] != {"canary": "FABRICATED_CANARY"}
        ):
            _deny()
        self.requests.add(request_id)
        self.calls.add(params["callId"])
        return {
            "id": request_id,
            "result": {
                "contentItems": [{"type": "inputText", "text": "OFFLINE_CANARY_ACK"}],
                "success": True,
            },
        }
