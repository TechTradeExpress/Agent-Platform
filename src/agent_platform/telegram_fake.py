"""Token-free Bot API contract and scripted fake only. No HTTP implementation."""

import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from agent_platform import issues, publisher
from agent_platform.notifications import SafeNotification, need


class Outcome(StrEnum):
    PENDING = "pending"
    DELIVERED = "delivered"
    UNKNOWN = "unknown"


class Category(StrEnum):
    DELIVERED = "delivered"
    RATE_LIMITED = "rate_limited"
    NOT_SENT = "not_sent"
    REJECTED = "rejected"
    UNCERTAIN = "uncertain"
    INVALID_RESPONSE = "invalid_response"


@dataclass(frozen=True, slots=True)
class Delivery:
    outcome: Outcome
    category: Category
    retry_after: int = 0

    def __post_init__(self):
        need(
            type(self.outcome) is Outcome
            and type(self.category) is Category
            and type(self.retry_after) is int
        )
        allowed = {
            Outcome.DELIVERED: {Category.DELIVERED},
            Outcome.PENDING: {
                Category.NOT_SENT,
                Category.RATE_LIMITED,
                Category.REJECTED,
            },
            Outcome.UNKNOWN: {Category.UNCERTAIN, Category.INVALID_RESPONSE},
        }
        need(self.category in allowed[self.outcome])
        need(
            1 <= self.retry_after <= 86400
            if self.category == Category.RATE_LIMITED
            else self.retry_after == 0
        )


@dataclass(frozen=True, slots=True)
class TelegramRequest:
    chat_id: int
    notification: SafeNotification
    origin: str = field(default="https://api.telegram.org", init=False)
    method: str = field(default="sendMessage", init=False)
    timeout: int = field(default=5, init=False)
    redirects: bool = field(default=False, init=False)

    def __post_init__(self):
        need(
            type(self.chat_id) is int
            and 0 < self.chat_id < 2**52
            and type(self.notification) is SafeNotification
        )

    @property
    def body(self):
        return publisher.encoded(
            {
                "chat_id": self.chat_id,
                "text": self.notification.text,
                "link_preview_options": {"is_disabled": True},
                "protect_content": True,
                "allow_paid_broadcast": False,
            }
        )


class Transport(Protocol):
    def send(self, request: TelegramRequest) -> Delivery: ...


@dataclass(frozen=True, slots=True)
class FakeReply:
    status: int
    body: bytes = field(repr=False)

    def __post_init__(self):
        need(
            type(self.status) is int
            and 100 <= self.status <= 599
            and type(self.body) is bytes
            and len(self.body) <= 65536
        )


class FakeFault(StrEnum):
    TIMEOUT = "timeout"
    NOT_SENT = "not_sent"
    ERROR = "error"


def classify(reply, request):
    unknown = Delivery(Outcome.UNKNOWN, Category.INVALID_RESPONSE)
    if type(reply) is FakeFault:
        return (
            Delivery(Outcome.PENDING, Category.NOT_SENT)
            if reply == FakeFault.NOT_SENT
            else Delivery(Outcome.UNKNOWN, Category.UNCERTAIN)
        )
    if type(reply) is not FakeReply or len(reply.body) > 8192:
        return unknown
    try:
        data = json.loads(
            reply.body.decode("utf-8"),
            object_pairs_hook=issues.unique_object,
            parse_constant=issues.invalid_constant,
        )
        if type(data) is not dict or type(data.get("ok")) is not bool:
            return unknown
        if reply.status == 200 and data["ok"] is True and set(data) == {"ok", "result"}:
            result = data["result"]
            chat = result["chat"]
            if (
                type(result) is dict
                and issues.positive_int(result["message_id"])
                and type(chat) is dict
                and type(chat["id"]) is int
                and chat["id"] == request.chat_id
                and chat["type"] == "private"
                and result["text"] == request.notification.text
            ):
                return Delivery(Outcome.DELIVERED, Category.DELIVERED)
        if (
            data["ok"] is False
            and type(data.get("error_code")) is int
            and data["error_code"] == reply.status
            and set(data) <= {"ok", "error_code", "description", "parameters"}
            and ("description" not in data or type(data["description"]) is str)
        ):
            if reply.status == 429:
                params = data["parameters"]
                delay = params["retry_after"]
                if (
                    type(params) is dict
                    and set(params) == {"retry_after"}
                    and type(delay) is int
                    and 1 <= delay <= 86400
                ):
                    return Delivery(Outcome.PENDING, Category.RATE_LIMITED, delay)
            elif reply.status in (400, 401, 403):
                return Delivery(Outcome.PENDING, Category.REJECTED)
        return unknown
    except (ValueError, TypeError, KeyError, RecursionError, issues.AdmissionError):
        return unknown


class FakeTelegram:
    """Bounded scripted responses, not a callback or configurable HTTP client."""

    def __init__(self, replies=()):
        need(
            type(replies) is tuple
            and len(replies) <= 32
            and all(type(r) in (FakeReply, FakeFault) for r in replies)
        )
        self._replies = list(replies)
        self.requests = []

    def send(self, request):
        need(type(request) is TelegramRequest and len(self.requests) < 32)
        self.requests.append(request)
        reply = self._replies.pop(0) if self._replies else FakeFault.NOT_SENT
        return classify(reply, request)
