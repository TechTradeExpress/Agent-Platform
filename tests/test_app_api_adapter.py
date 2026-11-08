"""AP-AL/1 integration: fabricated credentials, no real signing/network/host access."""

import copy
import json
import pickle
from dataclasses import asdict, replace

import pytest
from test_app_metadata import NOW
from test_app_metadata import case as case

from agent_platform import app_api_adapter as adapter
from agent_platform import app_metadata as metadata
from agent_platform import publisher
from agent_platform.app_api_wire import AdapterError, Operation, _Reply, route


class Journal:
    complete = True

    def __init__(self):
        self.events = []
        self.hook = None

    def snapshot(self):
        return tuple(self.events)

    def append(self, event):
        if self.hook:
            self.hook(event)
        self.events.append(event)


class Signer:
    def __init__(self):
        self.calls = []
        self.hook = None

    def sign(self, claims, *, timeout):
        assert 0 < timeout <= 5
        self.calls.append(claims)
        header = {"alg": "RS256", "typ": "JWT"}
        payload = claims.payload
        if self.hook:
            header, payload = self.hook(header, payload)
        return ".".join(
            (
                adapter._b64(publisher.encoded(header)),
                adapter._b64(publisher.encoded(payload)),
                adapter._b64(b"offline-invalid-RSA-signature"),
            )
        )


class HTTP:
    def __init__(self, case, journal):
        self.data = case["transport"].data
        self.journal = journal
        self.calls = []
        self.tokens = []
        self.hook = None
        self.token = "fixture-only-opaque-token"

    def exchange(self, op, pins, bearer, *, timeout):
        assert 0 < timeout <= 5
        method, path, kind, status = route(op, pins)
        assert (bearer is None) if kind == "public" else bearer.kind == kind
        self.calls.append(op)
        if op is Operation.ISSUE_TOKEN:
            assert self.journal.events[-1].state == "UNKNOWN"
            self.tokens.append(self.token + str(len(self.tokens)))
            raw = publisher.encoded(
                dict(
                    token=self.tokens[-1],
                    permissions={"metadata": "read"},
                    repository_selection="selected",
                    expires_at="2026-11-08T00:19:59Z",
                )
            )
            # Compute expiry from this fixture's explicitly fixed wall clock.
            from datetime import UTC, datetime

            value = json.loads(raw)
            value["expires_at"] = datetime.fromtimestamp(NOW + 3599, UTC).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            raw = publisher.encoded(value)
        elif op is Operation.REVOKE_TOKEN:
            assert bearer.value in self.tokens
            raw = b""
        else:
            raw = publisher.encoded(self.data[path.split("?")[0]])
        reply = _Reply(raw)
        return self.hook(op, reply) if self.hook else reply


@pytest.fixture
def configured(case):
    journal, signer = Journal(), Signer()
    http = HTTP(case, journal)
    value = adapter.Adapter(
        pins=case["pins"],
        source_id=case["observation"].source_id,
        signer=signer,
        wire=http,
        journal=journal,
        clock=case["clock"],
    )
    return case, value, journal, signer, http


def observe(configured, **changes):
    case, value, _, _, _ = configured
    result = metadata.observe(**(case | dict(custody=value, transport=value) | changes))
    assert not any(
        (
            result.reserved,
            result.prepare_authorized,
            result.launch_allowed,
            result.publish_authorized,
            result.resume_authorized,
        )
    )
    assert (
        result.app_attributed_bot_action == "NOT_OBSERVED"
        and result.runtime_exit_code == 13
    )
    assert "fixture-only-opaque" not in publisher.encoded(asdict(result)).decode()
    return result


def test_two_independent_leases_preflight_and_exact_revocations(configured):
    result = observe(configured)
    _, value, journal, signer, http = configured
    assert result.status == "METADATA_ONLY_BOT_ATTRIBUTION_UNVERIFIED"
    assert result.cleanup == "CONFIRMED"
    assert (
        http.calls.count(Operation.ISSUE_TOKEN)
        == http.calls.count(Operation.REVOKE_TOKEN)
        == 2
    )
    assert len(signer.calls) == 2 and len(journal.events) == 8
    assert [e.state for e in journal.events] == [
        "UNKNOWN",
        "ISSUED",
        "REVOKE_UNKNOWN",
        "REVOKED",
    ] * 2
    assert len({e.lease_id for e in journal.events}) == 2
    assert len({e.binding_sha256 for e in journal.events}) == 2
    assert all(c.app_id == configured[0]["pins"].app.app_id for c in signer.calls)
    assert "fixture-only" not in repr(value) + repr(journal.events)
    assert value._active is None
    with pytest.raises(AdapterError):
        pickle.dumps(value)


@pytest.mark.parametrize("kind", ["alg", "issuer", "extra", "iat", "exp", "float"])
def test_bad_signer_claims_block_before_http(configured, kind):
    def corrupt(header, payload):
        if kind == "alg":
            header["alg"] = "none"
        elif kind == "issuer":
            payload["iss"] = "999"
        elif kind == "extra":
            payload["arbitrary"] = "secret"
        elif kind == "iat":
            payload["iat"] += 100
        elif kind == "float":
            payload["iat"] = float(payload["iat"])
        else:
            payload["exp"] += 601
        return header, payload

    configured[3].hook = corrupt
    assert observe(configured).status == "BLOCKED"
    assert not configured[4].calls and not configured[2].events


@pytest.mark.parametrize(
    "change", ["permissions", "expiry", "selection", "malformed", "oversize"]
)
def test_known_invalid_token_revokes_unknown_body_does_not_guess(configured, change):
    def corrupt(op, reply):
        if op is not Operation.ISSUE_TOKEN:
            return reply
        if change == "malformed":
            return _Reply(b'{"token":"secret"')
        if change == "oversize":
            # A broken injected wire cannot bypass the adapter body bound.
            reply.body = b"x" * 65537
            return reply
        raw = json.loads(reply.body)
        if change == "permissions":
            raw["permissions"]["contents"] = "write"
        elif change == "selection":
            raw["repository_selection"] = "all"
        else:
            raw["expires_at"] = "2000-01-01T00:00:00Z"
        return _Reply(publisher.encoded(raw))

    configured[4].hook = corrupt
    result = observe(configured)
    assert result.status == "BLOCKED"
    calls = configured[4].calls
    assert calls.count(Operation.ISSUE_TOKEN) == 1
    assert calls.count(Operation.REVOKE_TOKEN) == (
        0 if change in {"malformed", "oversize"} else 1
    )
    # No retry, even from a reconstructed instance with same retained history.
    if change in {"malformed", "oversize"}:
        case, _, journal, signer, http = configured
        with pytest.raises(AdapterError):
            adapter.Adapter(
                pins=case["pins"],
                source_id=case["observation"].source_id,
                signer=signer,
                wire=http,
                journal=journal,
                clock=case["clock"],
            )


@pytest.mark.parametrize("operation", [Operation.ISSUE_TOKEN, Operation.REVOKE_TOKEN])
def test_ambiguous_side_effect_is_unknown_and_never_retried(configured, operation):
    def timeout(op, reply):
        if op is operation:
            raise TimeoutError("secret token Authorization: Bearer hostile")
        return reply

    configured[4].hook = timeout
    assert observe(configured).status == "BLOCKED"
    assert configured[2].events[-1].state in {"UNKNOWN", "REVOKE_UNKNOWN"}
    before = list(configured[4].calls)
    assert observe(configured).status == "BLOCKED"
    assert configured[4].calls == before


@pytest.mark.parametrize("when", ["UNKNOWN", "ISSUED", "REVOKE_UNKNOWN", "REVOKED"])
def test_journal_failure_cannot_authorize_retry_or_skip_known_cleanup(configured, when):
    def fail(event):
        if event.state == when:
            raise OSError("secret path")

    configured[2].hook = fail
    assert observe(configured).status == "BLOCKED"
    calls = configured[4].calls
    assert calls.count(Operation.ISSUE_TOKEN) == (0 if when == "UNKNOWN" else 1)
    assert calls.count(Operation.REVOKE_TOKEN) == (0 if when == "UNKNOWN" else 1)


@pytest.mark.parametrize("size", [1, 17, 4097, 16000])
def test_token_format_and_length_not_assumed(configured, size):
    configured[4].token = "~" * size
    assert observe(configured).status == "METADATA_ONLY_BOT_ATTRIBUTION_UNVERIFIED"


def test_whole_response_delivered_late_still_cleans_known_token(configured):
    def late(op, reply):
        if op is Operation.ISSUE_TOKEN:
            configured[0]["clock"].elapsed += 6
        return reply

    configured[4].hook = late
    assert observe(configured).status == "BLOCKED"
    assert configured[4].calls.count(Operation.REVOKE_TOKEN) == 1


def test_jwt_rotates_per_pass_and_new_bad_pin_preflight_blocks(configured):
    configured[4].data["/app"]["permissions"]["contents"] = "write"
    assert observe(configured).status == "BLOCKED"
    assert Operation.ISSUE_TOKEN not in configured[4].calls


@pytest.mark.parametrize(
    "field,value",
    [
        ("auth_kind", "installation"),
        ("source_id", "f" * 64),
        ("lease_id", "f" * 64),
        ("binding_sha256", "f" * 64),
        ("path", "/installation/token"),
        ("trust_env", True),
    ],
)
def test_active_lease_request_cannot_swap_domain_or_scope(configured, field, value):
    case, obj, _, _, _ = configured
    lease = obj.acquire(case["pins"], "d" * 64, timeout=5)
    request = metadata.Request(
        "/app", "app_jwt", (), lease.binding_sha256, lease.lease_id, lease.source_id
    )
    request = copy.copy(request)
    object.__setattr__(request, field, value)
    with pytest.raises(AdapterError) as error:
        obj.get(request, timeout=5, limit=65536)
    assert error.value.__context__ is None
    assert obj.revoke(lease, timeout=5)


def test_journal_replay_missing_history_and_cross_rotation_unknown_block(configured):
    case, obj, journal, signer, http = configured
    lease = obj.acquire(case["pins"], "d" * 64, timeout=5)
    with pytest.raises(AdapterError):
        adapter.Adapter(
            pins=case["pins"],
            source_id="e" * 64,
            signer=signer,
            wire=http,
            journal=journal,
            clock=case["clock"],
        )
    assert obj.revoke(lease, timeout=5)
    fresh = adapter.Adapter(
        pins=case["pins"],
        source_id=lease.source_id,
        signer=signer,
        wire=http,
        journal=journal,
        clock=case["clock"],
    )
    with pytest.raises(AdapterError):
        fresh.acquire(case["pins"], "d" * 64, timeout=5)
    journal.complete = False
    with pytest.raises(AdapterError):
        adapter.Adapter(
            pins=case["pins"],
            source_id=lease.source_id,
            signer=signer,
            wire=http,
            journal=journal,
            clock=case["clock"],
        )


def test_cancel_explicitly_cleans_once_and_does_not_serialize_secrets(configured):
    case, obj, _, _, http = configured
    lease = obj.acquire(case["pins"], "d" * 64, timeout=5)
    entry = obj._active
    assert "fixture-only" not in repr(entry) + repr(entry.token) + repr(entry.jwt)
    with pytest.raises(AdapterError):
        pickle.dumps(entry.token)
    obj.close()
    obj.close()
    assert http.calls.count(Operation.REVOKE_TOKEN) == 1
    assert entry.token is entry.jwt is None
    assert not obj.revoke(lease, timeout=5)


@pytest.mark.parametrize("change", ["replay", "history", "expired", "assignment"])
def test_apam_gate_blocks_without_signing_or_network(configured, change):
    case = configured[0]
    fields = {
        "replay": {"seen_challenges": (case["observation"].challenge,)},
        "history": {"history_complete": False},
        "expired": {"expires_at": NOW},
        "assignment": {"assignment_reference": "f" * 64},
    }[change]
    assert (
        observe(configured, observation=replace(case["observation"], **fields)).status
        == "BLOCKED"
    )
    assert not configured[3].calls and not configured[4].calls


@pytest.mark.parametrize("change", ["repo", "extra_repo", "bot", "second_pass"])
def test_observed_metadata_mismatch_revokes_current_token(configured, change):
    http = configured[4]
    if change == "repo":
        http.data["/installation/repositories"]["repositories"][0]["id"] = 2
    elif change == "extra_repo":
        http.data["/installation/repositories"]["repositories"] *= 2
    elif change == "bot":
        path = configured[0]["transport"].bot
        http.data[path]["id"] = 2
    else:

        def drift(op, reply):
            if op is Operation.APP and http.calls.count(Operation.ISSUE_TOKEN) == 2:
                raw = json.loads(reply.body)
                raw["id"] = 2
                return _Reply(publisher.encoded(raw))
            return reply

        http.hook = drift
    assert observe(configured).status == "BLOCKED"
    assert http.calls.count(Operation.REVOKE_TOKEN) == http.calls.count(
        Operation.ISSUE_TOKEN
    )


@pytest.mark.parametrize(
    "body", [b'{"token":"one","token":"two"}', b'{"token":NaN}', b"null"]
)
def test_duplicate_invalid_or_nonobject_token_response_remains_unknown(
    configured, body
):
    configured[4].hook = lambda op, reply: (
        _Reply(body) if op is Operation.ISSUE_TOKEN else reply
    )
    assert observe(configured).status == "BLOCKED"
    assert configured[2].events[-1].state == "UNKNOWN"
    assert Operation.REVOKE_TOKEN not in configured[4].calls


def test_acquire_known_cancel_and_get_cancel_are_redacted(configured):
    def cancel(op, reply):
        if op is Operation.REPOSITORIES:
            raise KeyboardInterrupt("secret Authorization data")
        return reply

    configured[4].hook = cancel
    assert observe(configured).status == "BLOCKED"
    assert configured[2].events[-1].state == "REVOKED"


def test_journal_load_exception_has_no_hostile_context(configured):
    case, _, journal, signer, http = configured

    def fail():
        raise OSError("secret custody path")

    journal.snapshot = fail
    with pytest.raises(AdapterError) as caught:
        adapter.Adapter(
            pins=case["pins"],
            source_id=case["observation"].source_id,
            signer=signer,
            wire=http,
            journal=journal,
        )
    assert caught.value.__context__ is None


def test_completed_challenge_binding_is_not_reissued_after_reconstruction(configured):
    assert observe(configured).status == "METADATA_ONLY_BOT_ATTRIBUTION_UNVERIFIED"
    case, _, journal, signer, http = configured
    fresh = adapter.Adapter(
        pins=case["pins"],
        source_id=case["observation"].source_id,
        signer=signer,
        wire=http,
        journal=journal,
        clock=case["clock"],
    )
    before = list(http.calls)
    assert observe(configured, custody=fresh, transport=fresh).status == "BLOCKED"
    assert http.calls == before
