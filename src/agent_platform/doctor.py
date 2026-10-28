"""Readiness is a point-in-time diagnostic, never execution authorization."""

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
