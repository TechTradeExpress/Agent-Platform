# Agent-Platform

Standalone Python 3.12+ CLI for read-only local GitHub repository inspection.
Git must be installed. No runtime Python dependencies or GitHub access required.
The bounded pipe reader supports POSIX systems (Linux/macOS).

Install from this checkout with `pip install .` (in a virtual environment), or
`uv tool install .`. Then invoke the installed command from a target repository:

```sh
agent-platform --help
cd /path/to/target-repository
agent-platform inspect
```

Run from the working-tree root, including linked worktree roots. Nested
directories and bare repositories are rejected. Symlinks resolve to canonical
paths. Origin must use `https://github.com/OWNER/REPO[.git]`,
`git@github.com:OWNER/REPO[.git]`, or `ssh://git@github.com/OWNER/REPO[.git]`.
Credentials, custom ports, query strings and other hosts are rejected.

Success emits one JSON object (sorted keys), for example:

```json
{"branch": "main", "linked_worktree": false, "repository": "owner/repo", "root": "/path/to/target-repository"}
```

`branch` is null for detached HEAD. Repository spelling is preserved; `.git`
is removed. Root is an absolute canonical path. Errors emit a fixed safe message
to stderr and no JSON. Exit codes: 2 non-working-tree (also argparse usage),
3 nested invocation, 4 missing/untrusted origin, 5 timeout, 6 Git execution,
output-limit or query failure, 7 unsafe/unresolvable path or value. Unborn HEAD
currently fails with code 6. Git queries each have a five-second deadline and
8 KiB limit per output stream; excess output kills the child. Inherited Git
environment overrides and global/system config are excluded. Local Git config
still applies, including URL rewrites; the effective origin is validated.

Inspection never contacts GitHub, invokes Codex, modifies a target repository,
or starts background work. No commit, push, PR creation or automatic merge.

Development:

```sh
uv sync --locked
uv run ruff check .
uv run pytest
git diff --check
uv run agent-platform --help
```

Tests use local temporary repositories and controlled subprocesses only. CI
runs Ruff and pytest on Python 3.12. See AGENTS.md for contributor guardrails.
