"""Non-launching subscription gate and proposed safe stop presentation.

These helpers never authenticate, authorize execution or persist checkpoint state.
"""

from agent_platform import codex


def auth_precondition(mode, logged_in):
    """Reduce nonsecret synthetic adapter evidence; never inspect a credential."""
    if not isinstance(mode, str) or mode not in ("chatgpt", "api_key", "none"):
        return "auth_mode_unverified"
    if mode == "api_key":
        return "api_auth_forbidden"
    if mode != "chatgpt" or logged_in is not True:
        return "chatgpt_login_required"
    return "tool_boundary_unverified"


def readiness():
    # No boolean, model text, local file or login mode can override this gate.
    return {
        "backend": "chatgpt_subscription",
        "status": "SUBSCRIPTION_ISOLATION_BLOCKED",
        "reason": "trusted_tool_boundary_unverified",
        "launch_allowed": False,
        "authentication": "NOT_INSPECTED",
        "live": "LIVE_NOT_RUN",
    }


def stop_presentation(events, returncode, *, protocol_failed, operator_wait=False):
    """Presentation-only design prototype; current PAUSED/NEEDS_HUMAN stay intact.

    protocol_failed must come from the trusted stream driver, never event prose.
    operator_wait represents a direct operator hold, not a provider quota signal.
    No resume, sleep, checkpoint write, quota lookup or prose parsing occurs.
    """
    phase = "NEEDS_HUMAN"
    if protocol_failed is False:
        try:
            phase = events.finish(returncode)
        except codex.ProtocolError:
            pass
    return {
        "checkpoint_state": phase,
        "display_status": "WAITING_FOR_SUBSCRIPTION"
        if phase == "PAUSED" and operator_wait is True
        else phase,
        "usage_availability": "UNAVAILABLE",
        "reset_at": None,
        "automatic_resume": False,
    }
