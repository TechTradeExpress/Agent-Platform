"""CI-01: a rejected checkout builds, inspects, runs and uploads nothing.

The real workflow file is loaded with a strict YAML-subset loader and its step
conditions run through an offline model of GitHub's documented status-check
semantics (tests/ci_actions_model.py). This is not a GitHub Actions run; that
live evidence stays NOT_RUN here.
"""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
_spec = importlib.util.spec_from_file_location(
    "ci_actions_model", ROOT / "tests/ci_actions_model.py"
)
model = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(model)

WORKFLOW = model.load_workflow(
    (ROOT / ".github/workflows/debian-package.yml").read_text()
)
STEPS = WORKFLOW["jobs"]["lifecycle"]["steps"]
LABELS = [model.step_label(step) for step in STEPS]
CHECKOUT, VERIFY = LABELS[:2]
GATE = "steps.verify_checkout.outcome == 'success'"
# Status check of every later step before CI-01 (base 7b5f050), kept unchanged.
LEGACY = {
    "Build isolated tool and dependency images": "success()",
    "Build real N and N+1 packages and compare candidate rebuild": "success()",
    "PKG-11 pinned historical -7 and uniquely named -8 candidates": "success()",
    "Real worker01 historical -6 to -7 offline upgrade": "success()",
    "PKG-11 real historical -7 to -8 offline upgrade": "success()",
    "Real apt and dpkg lifecycle with no network or host state": "success()",
    "Multi-UID P1 provisioning and lifecycle, no live credentials": "success()",
    "Separate synthetic Codex installer lifecycle, offline and rollback": (
        "!cancelled()"
    ),
    "Prior slim manpage 0775 remains BLOCKED": "!cancelled()",
    "Inspect archives, lintian and autopkgtest in separate container": "always()",
    "actions/upload-artifact": "always()",
}
DIAGNOSTICS = [label for label, check in LEGACY.items() if check != "success()"]


def ungated():
    """The same steps with only their previous checks: candidate ded7fb3."""
    return [
        {**step, "if": "${{ " + LEGACY[label] + " }}"} if label in LEGACY else step
        for step, label in zip(STEPS, LABELS, strict=True)
    ]


def test_workflow_parses_as_the_expected_job():
    assert WORKFLOW["name"] == "Debian package"
    assert WORKFLOW["on"] == ["push", "pull_request"]
    assert WORKFLOW["permissions"] == {"contents": "read"}
    assert list(WORKFLOW["jobs"]) == ["lifecycle"]
    assert STEPS[0]["uses"].startswith("actions/checkout@")
    assert STEPS[0]["with"] == {"persist-credentials": False, "fetch-depth": 0}


def test_verification_has_a_stable_id_and_gates_every_later_step():
    verify = STEPS[1]
    assert set(verify) == {"name", "id", "run"}  # no if, no continue-on-error
    assert verify["id"] == "verify_checkout"
    assert "python3 -I ci/verify_checkout_identity.py" in verify["run"]
    assert [step.get("id") for step in STEPS].count("verify_checkout") == 1
    assert "if" not in STEPS[0]
    # Every later step is classified; a new step must declare its gate here.
    assert LABELS[2:] == list(LEGACY)
    for step, label in zip(STEPS[2:], LABELS[2:], strict=True):
        assert step["if"] == "${{ " + LEGACY[label] + " && " + GATE + " }}", label
        assert "continue-on-error" not in step


def test_rejected_skipped_or_cancelled_verification_runs_nothing_later():
    assert model.run_steps(STEPS, fail={VERIFY}) == [CHECKOUT, VERIFY]
    assert model.run_steps(STEPS, cancel=VERIFY) == [CHECKOUT, VERIFY]
    assert model.run_steps(STEPS, fail={CHECKOUT}) == [CHECKOUT]
    # Regression: without the gate a rejected checkout still ran the Codex and
    # manpage containers, archive inspection and the artifact upload.
    assert model.run_steps(ungated(), fail={VERIFY}) == [
        CHECKOUT,
        VERIFY,
        *DIAGNOSTICS,
    ]


@pytest.mark.parametrize("failed", list(LEGACY))
def test_later_failure_of_a_verified_checkout_keeps_previous_behavior(failed):
    gated = model.run_steps(STEPS, fail={failed})
    assert gated == model.run_steps(ungated(), fail={failed})
    assert set(DIAGNOSTICS) <= set(gated)
    assert gated[-2:] == DIAGNOSTICS[-2:]  # inspection, then upload


@pytest.mark.parametrize("cancelled", list(LEGACY))
def test_cancellation_after_verification_keeps_previous_behavior(cancelled):
    gated = model.run_steps(STEPS, cancel=cancelled)
    assert gated == model.run_steps(ungated(), cancel=cancelled)
    after = gated[gated.index(cancelled) + 1 :]
    assert all(LEGACY[label] == "always()" for label in after)


def test_successful_run_executes_every_step():
    assert model.run_steps(STEPS) == LABELS


def steps(*conditions, tolerant=False):
    first = {"name": "first", "id": "first", "run": "x"}
    if tolerant:
        first["continue-on-error"] = True
    return [first] + [
        {"name": f"s{i}", "run": "x", **({} if c is None else {"if": c})}
        for i, c in enumerate(conditions)
    ]


def test_model_follows_documented_status_check_semantics():
    # Implicit success() when no status function is present.
    assert model.run_steps(
        steps("steps.first.outcome == 'failure'"), fail={"first"}
    ) == ["first"]
    assert model.run_steps(
        steps("${{ !cancelled() && steps.first.outcome == 'failure' }}"),
        fail={"first"},
    ) == ["first", "s0"]
    # Cancellation: only always() continues; success() and !cancelled() stop.
    assert model.run_steps(
        steps("${{ always() }}", "${{ !cancelled() }}", None), cancel="first"
    ) == ["first", "s0"]
    # outcome is before continue-on-error, conclusion after it.
    assert model.run_steps(
        steps(
            "steps.first.outcome == 'failure'",
            "steps.first.conclusion == 'success'",
            "${{ failure() }}",
            tolerant=True,
        ),
        fail={"first"},
    ) == ["first", "s0", "s1"]


@pytest.mark.parametrize(
    "condition",
    [
        "${{ !steps.first.outcome == 'success' }}",  # precedence trap
        "${{ steps.first.outcome == 'sucess' }}",  # unknown result
        "${{ steps.first.outcome }}",  # no comparison
        "${{ contains(github.ref, 'merge') }}",  # unsupported function
        "${{ success() && steps.later.outcome == 'success' }}",  # unknown step
        "${{ always() }} && ${{ success() }}",
        "${{ (always() }}",
        "always() &&",
    ],
)
def test_model_rejects_unsupported_or_ambiguous_conditions(condition):
    with pytest.raises(ValueError):
        model.run_steps(steps(condition))


@pytest.mark.parametrize(
    "text",
    [
        "on: [push]\nif: !cancelled()\n",  # a YAML tag, not an expression
        "a: 1\na: 2\n",  # duplicate key
        "a:\n- b\n",  # indentless sequence
        "a: &x b\n",  # anchor
        "a: 'quoted'\n",  # quoted scalar
        "a: >\n  folded\n",  # folded scalar
        "a: {b: c}\n",  # flow mapping
        "a: b: c\n",  # ': ' inside a plain scalar
        "a: yes\n",  # YAML 1.1 boolean
        "a: 24.04\n",  # float-looking scalar
        "a:\n\tb: c\n",  # tab
        "a:\n",  # empty value
        "---\na: b\n",  # document marker
        "a: |-\n  x\n",  # chomping indicator
        "a:\n  - - b\n",  # nested sequence
        "a: b\n  c: d\n",  # unexpected indentation
    ],
)
def test_loader_fails_closed_outside_the_supported_subset(text):
    with pytest.raises(ValueError):
        model.load_workflow(text)


def test_loader_reads_comments_literals_and_nesting_like_yaml():
    text = (
        "a: x # comment\n"
        "b:\n"
        "  - c: 1\n"
        "    d: |\n"
        "      # kept\n"
        "      e\n"
        "  # skipped\n"
        "  - f\n"
        "g: [h, i]\n"
        "j: false\n"
    )
    assert model.load_workflow(text) == {
        "a": "x",
        "b": [{"c": 1, "d": "# kept\ne\n"}, "f"],
        "g": ["h", "i"],
        "j": False,
    }
