"""Native CLI adapter seam. Production launch is unconditionally disabled.

No CLI flag, environment variable, repository data or caller boolean enables it.
Offline tests replace the gate AND isolation launcher with synthetic fixtures.
This is not an authentication adapter or an isolation attestation.
"""

from agent_platform import codex
from agent_platform.state import PrepareError


def arguments(session=None):
    """Pinned exec parser contract; prompt goes through controlled stdin only."""
    args = [
        "/usr/bin/codex",
        "--no-daemon",
        "--ask-for-approval",
        "never",
        "-c",
        'model_provider="openai"',
        "-c",
        'forced_login_method="chatgpt"',
        "-c",
        "model_providers.openai.request_max_retries=0",
        "-c",
        "model_providers.openai.stream_max_retries=0",
        "-c",
        "sandbox_workspace_write.writable_roots=[]",
        "-c",
        "sandbox_workspace_write.network_access=false",
        "-c",
        "sandbox_workspace_write.exclude_slash_tmp=true",
        "-c",
        "sandbox_workspace_write.exclude_tmpdir_env_var=true",
        "exec",
        "--json",
        "--sandbox",
        "workspace-write",
        "--skip-git-repo-check",
        "--ignore-user-config",
        "--ignore-rules",
    ]
    # Exec flags precede resume in the 0.164.0 parser; never use session names/last.
    if session is not None:
        args += ["resume", codex.session_id(session)]
    return [*args, "-"]


def _require_reviewed_runtime():
    raise PrepareError(13, "subscription_isolation_blocked")


def execute(info, number, actors, *, resume=False):
    # Must precede inspection, locking, checkpoint writes or subprocess creation.
    _require_reviewed_runtime()
    from agent_platform.execution import _execute

    return _execute(info, number, actors, argument_builder=arguments, resume=resume)
