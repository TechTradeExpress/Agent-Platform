"""Deliberately narrow Responses policy. No tool or schema is ever executed."""

import json
import re
from dataclasses import dataclass


class Rejected(Exception):
    """Fixed local failure only; never carry request/upstream diagnostics."""


def require(value):
    if not value:
        raise Rejected()


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result)
        result[key] = value
    return result


def invalid(value):
    raise Rejected()


def decode(raw):
    try:
        return json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid
        )
    except (ValueError, RecursionError):
        raise Rejected() from None


def text(value, limit=512 * 1024):
    require(isinstance(value, str) and len(value) <= limit)


def fields(value, allowed, required=()):
    require(
        isinstance(value, dict)
        and value.keys() <= set(allowed)
        and set(required) <= value.keys()
    )


NAME = re.compile(r"[A-Za-z0-9_-]{1,64}")
ENDPOINT = "https://api.openai.com/v1/responses"


@dataclass(frozen=True)
class Policy:
    broker_id: str
    peers: tuple[tuple[int, int], ...]
    models: tuple[str, ...]
    request_bytes: int = 512 * 1024
    response_bytes: int = 8 * 1024 * 1024
    event_bytes: int = 64 * 1024
    events: int = 10000
    concurrency: int = 2
    requests_per_peer: int = 32
    total_requests: int = 64
    total_response_bytes: int = 32 * 1024 * 1024
    request_seconds: int = 120
    idle_seconds: int = 10
    lifetime_seconds: int = 300
    max_output_tokens: int = 4096

    @classmethod
    def parse(cls, data):
        fields(
            data,
            {"version", "endpoint", "broker_id", "peers", "models", "limits"},
            {"version", "endpoint", "broker_id", "peers", "models"},
        )
        require(type(data["version"]) is int and data["version"] == 1)
        require(data["endpoint"] == ENDPOINT)
        require(
            isinstance(data["broker_id"], str)
            and re.fullmatch("[a-f0-9]{64}", data["broker_id"])
        )
        peers, models = data["peers"], data["models"]
        require(isinstance(peers, list) and 1 <= len(peers) <= 16)
        require(
            all(
                isinstance(p, list)
                and len(p) == 2
                and all(type(n) is int and 0 <= n < 2**32 for n in p)
                for p in peers
            )
        )
        require(len(set(map(tuple, peers))) == len(peers))
        require(isinstance(models, list) and 1 <= len(models) <= 16)
        require(
            all(
                isinstance(m, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", m)
                for m in models
            )
        )
        require(len(set(models)) == len(models))
        base = cls(data["broker_id"], tuple(map(tuple, peers)), tuple(models))
        limits = data.get("limits", {})
        allowed = set(cls.__dataclass_fields__) - {"broker_id", "peers", "models"}
        fields(limits, allowed)
        require(
            all(
                type(v) is int and 1 <= v <= getattr(base, k) for k, v in limits.items()
            )
        )
        return cls(base.broker_id, base.peers, base.models, **limits)

    def request(self, raw):
        require(0 < len(raw) <= self.request_bytes)
        data = decode(raw)
        fields(
            data,
            {
                "model",
                "input",
                "instructions",
                "stream",
                "store",
                "background",
                "tools",
                "tool_choice",
                "parallel_tool_calls",
                "reasoning",
                "text",
                "max_output_tokens",
                "include",
            },
            {"model", "input", "stream"},
        )
        require(data["model"] in self.models and data["stream"] is True)
        # Explicit false is compatible with Codex; omission is normalized false.
        require(
            data.get("store", False) is False and data.get("background", False) is False
        )
        data["store"] = data["background"] = False
        require(data.get("include", []) in ([], ["reasoning.encrypted_content"]))
        if "instructions" in data:
            text(data["instructions"])
        output = data.get("max_output_tokens", self.max_output_tokens)
        require(type(output) is int and 1 <= output <= self.max_output_tokens)
        data["max_output_tokens"] = output
        if "parallel_tool_calls" in data:
            require(type(data["parallel_tool_calls"]) is bool)
        require(data.get("tool_choice", "auto") in ("auto", "none"))
        tools = data.get("tools", [])
        require(isinstance(tools, list) and len(tools) <= 64)
        names = set()
        for tool in tools:
            fields(
                tool,
                {"type", "name", "description", "parameters", "strict", "format"},
                {"type", "name"},
            )
            require(isinstance(tool["name"], str) and NAME.fullmatch(tool["name"]))
            require(tool["name"] not in names)
            names.add(tool["name"])
            if "description" in tool:
                text(tool["description"], 16384)
            if tool["type"] == "function":
                require(
                    "format" not in tool and isinstance(tool.get("parameters"), dict)
                )
                if "strict" in tool:
                    require(type(tool["strict"]) is bool)

                # JSON Schema is inert metadata; refuse external reference hints.
                def schema(value, depth=0):
                    require(depth <= 32)
                    if isinstance(value, dict):
                        for key, child in value.items():
                            if key in ("$ref", "$dynamicRef"):
                                require(
                                    isinstance(child, str) and child.startswith("#")
                                )
                            schema(child, depth + 1)
                    elif isinstance(value, list):
                        for child in value:
                            schema(child, depth + 1)

                schema(tool["parameters"])
            elif tool["type"] == "custom":
                require("parameters" not in tool and "strict" not in tool)
                fmt = tool.get("format", {"type": "text"})
                require(
                    fmt == {"type": "text"}
                    or (
                        isinstance(fmt, dict)
                        and fmt.keys() == {"type", "syntax", "definition"}
                        and fmt["type"] == "grammar"
                        and fmt["syntax"] in ("lark", "regex")
                        and isinstance(fmt["definition"], str)
                    )
                )
            else:
                raise Rejected()
        value = data["input"]
        if isinstance(value, str):
            text(value)
        else:
            require(isinstance(value, list) and len(value) <= 2048)
            for item in value:
                self.item(item, names)
        if "reasoning" in data:
            reasoning = data["reasoning"]
            fields(reasoning, {"effort", "summary"})
            require(
                reasoning.get("effort", "medium")
                in ("none", "minimal", "low", "medium", "high", "xhigh")
            )
            require(reasoning.get("summary", "auto") in ("auto", "concise", "detailed"))
        if "text" in data:
            fields(data["text"], {"format", "verbosity"})
            require(data["text"].get("format", {"type": "text"}) == {"type": "text"})
            require(
                data["text"].get("verbosity", "medium") in ("low", "medium", "high")
            )
        encoded = json.dumps(data, separators=(",", ":"), ensure_ascii=True).encode()
        require(len(encoded) <= self.request_bytes)
        return encoded

    def item(self, item, names):
        require(isinstance(item, dict))
        kind = item.get("type", "message")
        if kind == "message":
            fields(
                item,
                {"type", "role", "content", "id", "status", "phase"},
                {"role", "content"},
            )
            require(item["role"] in ("system", "developer", "user", "assistant"))
            content = item["content"]
            if isinstance(content, str):
                text(content)
            else:
                require(isinstance(content, list) and len(content) <= 2048)
                for part in content:
                    fields(part, {"type", "text", "annotations"}, {"type", "text"})
                    require(part["type"] in ("input_text", "output_text"))
                    require(part.get("annotations", []) == [])
                    text(part["text"])
        elif kind in ("function_call", "custom_tool_call"):
            key = "arguments" if kind == "function_call" else "input"
            fields(
                item,
                {"type", "id", "call_id", "name", key, "status"},
                {"type", "call_id", "name", key},
            )
            require(item["name"] in names)
            text(item[key])
            text(item["call_id"], 256)
        elif kind in ("function_call_output", "custom_tool_call_output"):
            fields(
                item, {"type", "id", "call_id", "output"}, {"type", "call_id", "output"}
            )
            text(item["call_id"], 256)
            text(item["output"])
        elif kind == "reasoning":
            fields(
                item,
                {"type", "id", "summary", "encrypted_content"},
                {"type", "summary"},
            )
            require(isinstance(item["summary"], list) and len(item["summary"]) <= 256)
            for part in item["summary"]:
                fields(part, {"type", "text"}, {"type", "text"})
                require(part["type"] == "summary_text")
                text(part["text"])
            if "encrypted_content" in item:
                text(item["encrypted_content"])
        else:
            raise Rejected()
