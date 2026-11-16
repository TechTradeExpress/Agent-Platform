"""PKG-08 source-only secret-free harness primitives; never readiness authority.

No CLI, socket creation, service operation, credential read or default transport.
Caller supplies a bounded disposable fixture's connect operation and observations.
"""

import errno


def tcp_attempt(connect):
    """Record type/errno/stage, never exception text, addresses or paths."""
    try:
        connect()
    except OSError as error:
        kind = (
            "TimeoutError"
            if isinstance(error, TimeoutError)
            else "PermissionError"
            if isinstance(error, PermissionError)
            else "ConnectionRefusedError"
            if isinstance(error, ConnectionRefusedError)
            else "OSError"
        )
        number = error.errno
        if type(number) is not int or not 0 <= number <= 4095:
            number = None
        return {"stage": "connect", "outcome": "ERROR", "type": kind, "errno": number}
    except Exception:
        return {
            "stage": "connect",
            "outcome": "ERROR",
            "type": "Unexpected",
            "errno": None,
        }
    return {"stage": "connect", "outcome": "CONNECTED", "type": None, "errno": None}


def network_result(allow, deny, *, allow_received, deny_received):
    """A temporary negative probe never proves production cgroup attachment."""
    status, reason = "UNKNOWN", "control_or_receipt_missing"
    for item in (allow, deny):
        if (
            type(item) is not dict
            or set(item) != {"stage", "outcome", "type", "errno"}
            or item["stage"] != "connect"
            or item["outcome"] not in ("CONNECTED", "ERROR")
            or item["type"]
            not in (
                None,
                "TimeoutError",
                "PermissionError",
                "ConnectionRefusedError",
                "OSError",
                "Unexpected",
            )
            or not (
                item["errno"] is None
                or type(item["errno"]) is int
                and 0 <= item["errno"] <= 4095
            )
            or (
                item["outcome"] == "CONNECTED"
                and (item["type"] is not None or item["errno"] is not None)
            )
            or (item["outcome"] == "ERROR" and item["type"] is None)
        ):
            raise ValueError("invalid_probe_record")
    if type(allow_received) is bool and type(deny_received) is bool:
        if deny_received or deny["outcome"] == "CONNECTED":
            status, reason = "FAIL", "deny_connected"
        elif allow["outcome"] == "CONNECTED" and allow_received:
            expected = (
                deny["type"] == "TimeoutError"
                and deny["errno"] in (None, errno.ETIMEDOUT)
                or deny["type"] in ("PermissionError", "OSError")
                and deny["errno"] in (errno.EACCES, errno.EPERM)
            )
            if deny["outcome"] == "ERROR" and expected:
                status, reason = "PASS", "controlled_denial"
            else:
                status, reason = "FAIL", "unexpected_connect_failure"
    return {
        "schema": "AP-WP-ISOLATION-PROBE/1",
        "stage": "network",
        "status": status,
        "reason": reason,
        "allow": allow,
        "deny": deny,
        "configured_policy": "NOT_OBSERVED",
        "production_bpf": "NOT_RUN",
        "launch_allowed": False,
    }
