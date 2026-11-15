# CP-08 CI interpreter selection

Source-only follow-up to PR #103 at
`13cdd169d104bd6e3c2d1b2bd77f1059e396ffba`.
No host installation, permission repair, copy, privileged operation or product
runtime change is included. LIVE_NO_GO / HOST_NOT_RUN and all existing gates stay.

## Evidence and cause

The supplied run `43641233995` confirms `runtime_permission_bits_rejected`.
GitHub's API reports this run's own `run_number` as 216; the human handoff calls
it CI #215. The immutable run ID and HEAD identify the evidence, not that display
number. The historical failing process is no longer available for local stat;
its exact per-bit vector was not logged by the old combined predicate. Do not
invent a measured historical mode or UID.

Primary source observations:

- The pinned [setup-python source](https://github.com/actions/setup-python/blob/a26af69be951a213d495a4c3e4e4022e16d87065/src/find-python.ts)
  looks up a cached Python and adds its `bin` to PATH; it reports `python-path`.
  This does not assert CP-08-safe permissions on an existing cached interpreter.
- The official runner's [post-deployment configuration](https://github.com/actions/runner-images/blob/5ebd98a1ebebec7fe09538a221405e85ee4f42ff/images/ubuntu/scripts/build/configure-system.sh)
  applies `chmod -R 777 /opt`. The documented tool cache resides under /opt.
  For files affected by that command the forbidden bits are **group_write** and
  **other_write**, not setuid/setgid. This source-backed mechanism explains the
  permission refusal; it is not a retained stat of the historical job.
- [uv environment discovery](https://docs.astral.sh/uv/pip/environments/)
  normally uses the project virtualenv. Its Python may be a symlink into the
  selected base installation; `realpath(sys.executable)` reaches that base
  file. Creating a venv does not necessarily create a safe private binary copy.
- The official [Ubuntu 24.04 image inventory](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md)
  distinguishes system Python 3.12.3 from cached Python versions. Its
  [system Python installation source](https://github.com/actions/runner-images/blob/d5d1925f1311e0b8715da222a6233c8c415ba506/images/ubuntu/scripts/build/install-python.sh)
  installs OS-managed Python through APT during image construction. The new CI
  workflow reuses it and never invokes APT or an installer itself.

New independent fixed-ID tests observe each bit of the original `0o6022` mask:
`setuid`, `setgid`, `group_write`, `other_write`. A PRESENT bit fails; inaccessible
metadata fails UNKNOWN. They publish no paths, raw modes, owner IDs or errors.
The CI entry also emits those four fixed categories for its actual active real
executable, even on a blocked preflight. This gives direct per-run facts rather
than inferring the mode from a version label.

## Minimal environment change

The checks job now selects **ubuntu-24.04** and explicitly requests the existing
**/usr/bin/python3.12** in every uv command. setup-python is removed from this
job. The previously recorded setup-python action pin remains historical source
evidence; no action version or permissions are widened. `--no-managed-python`
and `--no-python-downloads` forbid alternate managed/downloaded interpreters.
`uv sync --locked` creates the normal dependency virtualenv; later commands use
`--no-sync` so the selected environment is not silently rebuilt for a test step.

This is deterministic **selection**, not a claim of byte-reproducible future
GitHub image releases. The OS package may receive security updates; its exact
real file metadata and SHA-256 are checked and bound within each test process.
A missing 3.12 system binary, changed version, unexpected ownership, unsafe mode,
capability error, hash/read failure or different real interpreter blocks the
step at exit 13. There is no fallback, chmod/chown, guessed PATH candidate or
permission change to /opt, /usr/bin or another user's file. No controlled copy is
needed, so no new executable-copy trust boundary is introduced.

## Binding validation to pytest

`uv run ... python ci/cp08_pytest.py` replaces the bare pytest command only in the
checks job. This source-only helper:

1. Requires Linux, CPython 3.12, unchanged non-root UID/GID identities and no
   usable inherited capabilities.
2. Calls the **unchanged** CP-08 `_runtime()` validator. Its real path must equal
   the fixed system interpreter's real path.
3. Pins the actual process ID, real path, device/inode, owner/group/mode,
   size/timestamps and bounded stable SHA-256, using the unchanged 64 MiB ceiling.
   These private correlation fields are never printed.
4. Imports pytest and verifies that pin again; calls `pytest.main([])` directly
   in the same process, without exec or subprocess, then verifies the pin again.
5. Preserves pytest's failing exit code. Drift before collection or after testing
   returns 13; no result is converted to PASS. Emitted JSON has only fixed codes,
   permission categories and non-authorizing LIVE_NO_GO/HOST_NOT_RUN flags.

Import of the helper is inert. It is not a package entrypoint, runtime adapter,
authentication service or host-isolation assessment. Tests use explicit synthetic
snapshot drift and a documented local image-path substitution to check binding;
those mocks are not evidence of the actual GitHub image. Its real fixed-path
preflight remains non-configurable in the workflow. No environment variable,
flag or operator/model data can supply an alternate allowed executable path.

## Validation limits

The local machine is not the GitHub Ubuntu image. A direct fixed-path CI entry on
an incompatible local OS must BLOCK, not repair itself. The local full pytest,
real CP-08 process cases, original negative tests, packaging and helper-unit
results are reported with the delivered exact source SHA. A separately labelled
Python 3.12 replay can model only the local path while retaining real ownership,
mode, capability and hash checks; it is not a GitHub image PASS.

The final actual image must execute the workflow and pass this gate after
separately authorized publication/review. No GitHub write or new Actions run is
performed here. If the image's system Python fails the unchanged policy, retain
BLOCKED and its fixed categories for review; do not weaken `_runtime` to make it
pass. Native/subscription/public legacy exit 13, Gate #73, SOURCE_ONLY packaging
and human-only merge remain unchanged. No real host receives services or policy.
