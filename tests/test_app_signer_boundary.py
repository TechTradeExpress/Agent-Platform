"""A valid signing key cannot bypass missing independent adapter admission."""

import os

from test_app_api_adapter import HTTP, Journal
from test_app_metadata import case as case
from test_app_signer import keys as keys

from agent_platform import app_api_adapter as adapter
from agent_platform import app_metadata as metadata
from agent_platform import app_signer as signer
from agent_platform import app_signer_ipc as ipc


def test_legacy_adapter_signer_shape_does_not_mint_a_session(case, keys):
    peer = signer.Peer(os.getpid(), os.getuid(), os.getgid())
    policy = signer.Policy(
        case["pins"].app.app_id,
        "a" * 64,
        signer.public_fingerprint(keys[0].public_key()),
        peer,
        peer,
    )
    client = ipc.SignerClient(
        policy=policy, public_key=keys[0].public_key(), clock=case["clock"]
    )
    journal = Journal()
    http = HTTP(case, journal)
    value = adapter.Adapter(
        pins=case["pins"],
        source_id=case["observation"].source_id,
        signer=client,
        wire=http,
        journal=journal,
        clock=case["clock"],
    )
    result = metadata.observe(**(case | dict(custody=value, transport=value)))
    assert (
        result.status == "BLOCKED"
        and result.app_attributed_bot_action == "NOT_OBSERVED"
    )
    assert not any(
        (
            result.reserved,
            result.prepare_authorized,
            result.launch_allowed,
            result.resume_authorized,
            result.publish_authorized,
        )
    )
    assert result.runtime_exit_code == 13 and not http.calls and not journal.events
