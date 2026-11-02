"""Historical legacy-only diagnostics retained for offline tests and analysis.

The public doctor command is quarantined before reaching this module. Direct
Python use is not a supported native readiness interface or launch authority;
no operator deployment/activation is authorized by retaining this code.
"""

from pathlib import Path

from agent_platform import cli, execution, isolation, issues, state


def diagnose(cwd: Path | None, number: int, actors: list[str], *, resume=False):
    try:
        info = cli.inspect(Path.cwd() if cwd is None else cwd)
        return execution.execute(info, number, actors, resume=resume, diagnostic=True)
    except isolation.IsolationError:
        return {"status": "unavailable", "reason": "isolation_unavailable"}, 13
    except state.PrepareError as exc:
        reason = {
            9: "admission_rejected",
            10: "lock_busy",
            11: "source_mismatch",
            12: "checkpoint_or_task_invalid",
        }.get(exc.code, "unsafe_storage")
        return {"status": "ambiguous", "reason": reason}, exc.code
    except cli.InspectionError:
        return {"status": "ambiguous", "reason": "invalid_target"}, 7
    except (issues.AdmissionError, ValueError):
        return {"status": "unavailable", "reason": "admission_unavailable"}, 8
    except (OSError, KeyboardInterrupt):
        return {"status": "unavailable", "reason": "local_unavailable"}, 12
