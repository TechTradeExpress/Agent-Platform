"""HAR-04 instruction-source diagnostics: metadata only, no CLI or host reads."""

import json
import os
import subprocess
from pathlib import Path

import pytest

from agent_platform import instruction_sources as sources

ROOT = Path(__file__).resolve().parents[1]
AGENTS = b"# canonical instructions\n"


@pytest.fixture
def tree(tmp_path):
    parent = tmp_path / "parent"
    root = parent / "worktree"
    root.mkdir(parents=True)
    (root / "AGENTS.md").write_bytes(AGENTS)
    return root


def reasons(root):
    return sources.scan(root)["reasons"]


def test_single_canonical_agents_md_is_consistent_but_not_load_proof(tree):
    report = sources.scan(tree)
    assert report["result"] == "CONSISTENT_UNVERIFIED"
    assert report["reasons"] == [] and report["root_agents_md"] == "REGULAR"
    assert (
        report["root_agents_md_sha256"]
        == __import__("hashlib").sha256(AGENTS).hexdigest()
    )
    assert report["load_confirmed"] is False
    assert report["schema"] == "AP-INSTRUCTION-SOURCES/1"


@pytest.mark.parametrize(
    "setup,reason",
    [
        (lambda r: (r / "CLAUDE.md").write_bytes(b"x"), "claude_md_in_worktree"),
        (
            lambda r: (r / "CLAUDE.local.md").write_bytes(b"x"),
            "claude_local_md_in_worktree",
        ),
        (
            lambda r: (
                (r / ".claude").mkdir(),
                (r / ".claude/CLAUDE.md").write_bytes(b"x"),
            ),
            "claude_md_in_worktree",
        ),
        (
            lambda r: (r / "CLAUDE.md").symlink_to("AGENTS.md"),
            "claude_md_in_worktree",
        ),
        (
            lambda r: (
                (r / ".claude").mkdir(),
                (r / ".claude/AGENTS.md").write_bytes(b"x"),
            ),
            "claude_dir_agents_md",
        ),
        (lambda r: (r.parent / "CLAUDE.md").write_bytes(b"x"), "claude_md_in_ancestor"),
        (
            lambda r: (r.parent / "CLAUDE.local.md").write_bytes(b"x"),
            "claude_local_md_in_ancestor",
        ),
        (lambda r: (r.parent / "AGENTS.md").write_bytes(b"x"), "agents_md_in_ancestor"),
        (
            lambda r: ((r / "pkg").mkdir(), (r / "pkg/AGENTS.md").write_bytes(b"x")),
            "agents_md_nested",
        ),
        (
            lambda r: ((r / "pkg").mkdir(), (r / "pkg/CLAUDE.md").write_bytes(b"x")),
            "claude_md_nested",
        ),
        (
            lambda r: (
                (r / "a/b").mkdir(parents=True),
                (r / "a/b/CLAUDE.local.md").write_bytes(b"x"),
            ),
            "claude_md_nested",
        ),
        (
            lambda r: (
                (r / "pkg").mkdir(),
                (r / "pkg/AGENTS.md").symlink_to("../AGENTS.md"),
            ),
            "agents_md_nested",
        ),
    ],
)
def test_competing_or_duplicate_instruction_sources_are_a_conflict(tree, setup, reason):
    setup(tree)
    report = sources.scan(tree)
    assert reason in report["reasons"]
    assert report["result"] == "CONFLICT"
    assert report["load_confirmed"] is False


def test_missing_agents_md_is_reported_not_synthesized(tree):
    (tree / "AGENTS.md").unlink()
    report = sources.scan(tree)
    assert report["result"] == "AGENTS_MD_MISSING"
    assert (
        report["root_agents_md"] == "MISSING"
        and report["root_agents_md_sha256"] is None
    )
    assert not (tree / "CLAUDE.md").exists() and not (tree / "CLAUDE.local.md").exists()
    assert sorted(p.name for p in tree.iterdir()) == []


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory"])
def test_agents_md_must_be_a_single_regular_file(tree, kind):
    target = tree.parent / "other.md"
    target.write_bytes(AGENTS)
    (tree / "AGENTS.md").unlink()
    if kind == "symlink":
        (tree / "AGENTS.md").symlink_to(target)
    elif kind == "hardlink":
        os.link(target, tree / "AGENTS.md")
    else:
        (tree / "AGENTS.md").mkdir()
    report = sources.scan(tree)
    assert "agents_md_not_regular" in report["reasons"]
    assert report["result"] == "CONFLICT" and report["root_agents_md_sha256"] is None


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file modes")
def test_unreadable_agents_md_is_not_run_not_absence(tree):
    (tree / "AGENTS.md").chmod(0)
    report = sources.scan(tree)
    assert report["result"] == "NOT_RUN" and "agents_md_unreadable" in report["reasons"]


def test_scan_limit_is_not_run(tree, monkeypatch):
    for index in range(5):
        (tree / f"f{index}").write_bytes(b"x")
    monkeypatch.setattr(sources, "MAX_ENTRIES", 3)
    report = sources.scan(tree)
    assert report["result"] == "NOT_RUN" and report["reasons"] == ["scan_limit"]


@pytest.mark.parametrize("root", ["relative/path", "/definitely/missing/path", ""])
def test_invalid_root_is_not_run(root):
    report = sources.scan(root)
    assert report["result"] == "NOT_RUN" and report["reasons"] == ["root_invalid"]


def test_report_is_path_free_and_deterministic(tree):
    (tree / "CLAUDE.md").write_bytes(b"x")
    first = sources.scan(tree)
    assert first == sources.scan(tree)
    text = json.dumps(first)
    assert str(tree) not in text and "/tmp" not in text


def test_git_directory_content_is_ignored_but_worktree_names_are_not(tree):
    (tree / ".git").mkdir()
    (tree / ".git" / "AGENTS.md").write_bytes(b"x")
    assert sources.scan(tree)["result"] == "CONSISTENT_UNVERIFIED"


@pytest.mark.parametrize(
    "version,status,result",
    [
        ("2.1.276", "UNSUPPORTED", "VERSION_BLOCKED"),
        ("2.1.277", "DOCUMENTED_GAPS", "VERSION_BLOCKED"),
        ("2.1.280", "DOCUMENTED_GAPS", "VERSION_BLOCKED"),
        ("2.1.281", "SUPPORTED_UNVERIFIED", "CONSISTENT_UNVERIFIED"),
        ("2.1.295", "SUPPORTED_UNVERIFIED", "CONSISTENT_UNVERIFIED"),
        ("2.2.0", "SUPPORTED_UNVERIFIED", "CONSISTENT_UNVERIFIED"),
    ],
)
def test_pinned_version_gate(tree, version, status, result):
    report = sources.diagnose(tree, version)
    assert report["version_status"] == status and report["result"] == result
    assert report["load_confirmed"] is False


def test_version_gate_does_not_hide_a_scan_that_did_not_run():
    assert sources.diagnose("relative", "2.1.276")["result"] == "NOT_RUN"


@pytest.mark.parametrize(
    "value", ["latest", "stable", "2.1", "v2.1.295", "2.1.295-rc", 295, None]
)
def test_only_exact_numeric_versions_are_accepted(value):
    with pytest.raises(ValueError):
        sources.parse_version(value)


def good_evidence():
    return {
        "schema": "AP-INSTRUCTION-LOAD-EVIDENCE/1",
        "claude_version": "2.1.295",
        "binary_sha256": "a" * 64,
        "agents_md_sha256": "b" * 64,
        "observed_via": "context_all",
        "startup_notice": True,
        "memory_files": ["AGENTS.md"],
        "provenance": "operator_attested_unauthenticated",
    }


def judge(record):
    return sources.validate_load_evidence(
        record, version="2.1.295", binary_sha256="a" * 64, agents_md_sha256="b" * 64
    )


def test_future_load_evidence_is_only_ever_operator_attested():
    assert judge(good_evidence()) == "OPERATOR_ATTESTED_UNAUTHENTICATED"


@pytest.mark.parametrize(
    "change",
    [
        {"claude_version": "2.1.296"},
        {"binary_sha256": "c" * 64},
        {"agents_md_sha256": "c" * 64},
        {"observed_via": "memory"},
        {"startup_notice": False},
        {"startup_notice": "yes"},
        {"memory_files": ["CLAUDE.md"]},
        {"memory_files": ["AGENTS.md", "CLAUDE.md"]},
        {"memory_files": []},
        {"provenance": "authenticated"},
        {"schema": "AP-INSTRUCTION-LOAD-EVIDENCE/2"},
        {"extra": 1},
    ],
)
def test_load_evidence_mismatch_or_extra_claims_are_rejected(change):
    assert judge(good_evidence() | change) == "REJECTED"
    record = good_evidence()
    record.pop("provenance")
    assert judge(record) == "REJECTED"
    assert judge(None) == "REJECTED" and judge([]) == "REJECTED"


def test_unsupported_version_cannot_be_attested():
    record = good_evidence() | {"claude_version": "2.1.280"}
    assert (
        sources.validate_load_evidence(
            record, version="2.1.280", binary_sha256="a" * 64, agents_md_sha256="b" * 64
        )
        == "REJECTED"
    )


# ---- repository policy: ONE canonical file, no duplicates, symlinks or copies ----


def tracked():
    try:
        out = subprocess.run(
            ["git", "ls-files", "-s"],
            cwd=ROOT,
            capture_output=True,
            check=True,
            timeout=30,
        ).stdout.decode()
    except (OSError, subprocess.SubprocessError):
        pytest.skip("not a git checkout")
    return [line.split(None, 3) for line in out.splitlines()]


def test_repository_has_exactly_one_canonical_instruction_file():
    names = {
        row[3]: row[0]
        for row in tracked()
        if Path(row[3]).name.lower()
        in ("agents.md", "claude.md", "claude.local.md", "agents.override.md")
    }
    assert names == {"AGENTS.md": "100644"}


def test_no_tracked_symlink_aliases_instructions():
    links = [row[3] for row in tracked() if row[0] == "120000"]
    assert not [p for p in links if "agents" in p.lower() or "claude" in p.lower()]


def test_gitignore_does_not_hide_or_generate_instruction_copies():
    text = (ROOT / ".gitignore").read_text()
    assert "AGENTS" not in text and "CLAUDE" not in text


def test_module_never_launches_or_reads_private_state():
    source = (ROOT / "src/agent_platform/instruction_sources.py").read_text()
    for token in ("subprocess", "socket", "os.system", "expanduser", "environ", "HOME"):
        assert token not in source.replace("environment", "")


# ---- bounded lazy directory iteration (no materialization, no real mass files) ----


class FakeEntry:
    def __init__(self, name, parent, directory=False, fail=False):
        self.name, self.path = name, f"{parent}/{name}"
        self._directory, self._fail = directory, fail

    def is_dir(self, follow_symlinks=True):
        assert follow_symlinks is False
        if self._fail:
            raise OSError("probe")
        return self._directory


class FakeScan:
    """Context manager over a lazy iterator that counts consumed entries."""

    def __init__(self, entries):
        self.iterator = iter(entries)
        self.consumed = 0
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True
        return False

    def __iter__(self):
        return self

    def __next__(self):
        item = next(self.iterator)  # May raise StopIteration or OSError.
        self.consumed += 1
        return item


class RealOsProxy:
    """Delegates to the real os module except scandir (never patches globals)."""

    def __init__(self, scandir):
        self.scandir = scandir

    def __getattr__(self, name):
        return getattr(os, name)


def install(monkeypatch, tree, factory):
    monkeypatch.setattr(sources, "os", RealOsProxy(factory))
    return tree


def endless(parent, directories=False):
    index = 0
    while True:
        index += 1
        yield FakeEntry(f"n{index}", parent, directory=directories)


def test_endless_directory_is_cut_at_the_budget_not_materialized(tree, monkeypatch):
    monkeypatch.setattr(sources, "MAX_ENTRIES", 5)
    created = []

    def factory(path):
        created.append(FakeScan(endless(str(path))))
        return created[-1]

    install(monkeypatch, tree, factory)
    report = sources.scan(tree)  # Would hang or exhaust memory if materialized.
    assert report["result"] == "NOT_RUN" and report["reasons"] == ["scan_limit"]
    assert len(created) == 1
    assert created[0].consumed == 6  # MAX_ENTRIES + exactly one probing entry.
    assert created[0].closed is True


def test_budget_is_global_across_directories_and_pending_stack_stays_bounded(
    tree, monkeypatch
):
    monkeypatch.setattr(sources, "MAX_ENTRIES", 7)
    opened = []

    def factory(path):
        opened.append(path)
        return FakeScan(endless(str(path), directories=True))  # Every entry a dir.

    install(monkeypatch, tree, factory)
    report = sources.scan(tree)
    assert report["result"] == "NOT_RUN" and report["reasons"] == ["scan_limit"]
    assert len(opened) == 1  # Budget exhausted inside the very first directory.


def test_exact_budget_is_allowed_and_one_more_is_not(tree, monkeypatch):
    monkeypatch.setattr(sources, "MAX_ENTRIES", 4)

    def run(count):
        scans = []

        def factory(path):
            scans.append(FakeScan(FakeEntry(f"f{i}", str(path)) for i in range(count)))
            return scans[-1]

        install(monkeypatch, tree, factory)
        return sources.scan(tree), scans[0]

    report, scan = run(4)
    assert report["result"] == "CONSISTENT_UNVERIFIED" and scan.consumed == 4
    report, scan = run(5)
    assert report["result"] == "NOT_RUN" and report["reasons"] == ["scan_limit"]
    assert scan.closed is True


def test_nested_names_are_still_found_through_the_lazy_iterator(tree, monkeypatch):
    def factory(path):
        if str(path) == str(tree):
            return FakeScan([FakeEntry("pkg", str(path), directory=True)])
        return FakeScan([FakeEntry("AGENTS.md", str(path))])

    install(monkeypatch, tree, factory)
    report = sources.scan(tree)
    assert "agents_md_nested" in report["reasons"] and report["result"] == "CONFLICT"


def test_directory_open_error_is_not_run(tree, monkeypatch):
    def factory(_path):
        raise PermissionError("denied")

    install(monkeypatch, tree, factory)
    report = sources.scan(tree)
    assert report["result"] == "NOT_RUN"
    assert "agents_md_unreadable" in report["reasons"]
    assert report["load_confirmed"] is False


def test_error_while_iterating_is_not_run_and_closes_the_iterator(tree, monkeypatch):
    scans = []

    def broken():
        yield FakeEntry("a", str(tree))
        raise OSError("io")

    def factory(path):
        scans.append(FakeScan(broken()))
        return scans[-1]

    install(monkeypatch, tree, factory)
    report = sources.scan(tree)
    assert report["result"] == "NOT_RUN" and "agents_md_unreadable" in report["reasons"]
    assert scans[0].closed is True


def test_entry_type_probe_error_is_not_run(tree, monkeypatch):
    install(
        monkeypatch,
        tree,
        lambda path: FakeScan([FakeEntry("x", str(path), fail=True)]),
    )
    report = sources.scan(tree)
    assert report["result"] == "NOT_RUN" and "agents_md_unreadable" in report["reasons"]


def test_unreadable_subdirectory_never_yields_consistent(tree, monkeypatch):
    def factory(path):
        if str(path) == str(tree):
            return FakeScan([FakeEntry("sub", str(path), directory=True)])
        raise OSError("gone")

    install(monkeypatch, tree, factory)
    assert sources.scan(tree)["result"] == "NOT_RUN"


def test_scan_never_materializes_a_directory_listing():
    import ast

    module = ast.parse((ROOT / "src/agent_platform/instruction_sources.py").read_text())
    calls = [n for n in ast.walk(module) if isinstance(n, ast.Call)]
    for call in calls:
        if isinstance(call.func, ast.Name) and call.func.id in (
            "list",
            "tuple",
            "sorted",
        ):
            assert not any(
                isinstance(a, ast.Call)
                and isinstance(a.func, ast.Attribute)
                and a.func.attr in ("scandir", "listdir", "walk")
                for a in call.args
            )
    withs = [
        n
        for n in ast.walk(module)
        if isinstance(n, ast.With)
        and any(
            isinstance(i.context_expr, ast.Call)
            and isinstance(i.context_expr.func, ast.Attribute)
            and i.context_expr.func.attr == "scandir"
            for i in n.items
        )
    ]
    assert withs, "scandir must be used as a context manager"


def test_real_filesystem_behaviour_is_unchanged(tree):
    (tree / "pkg").mkdir()
    (tree / "pkg" / "AGENTS.md").write_bytes(b"x")
    assert "agents_md_nested" in sources.scan(tree)["reasons"]


@pytest.mark.parametrize(
    "project", [None, "CLAUDE.md", "CLAUDE.local.md", ".claude/CLAUDE.md"]
)
def test_personal_memory_exemption_is_exact(tree, monkeypatch, project):
    home = tree.parent.parent
    monkeypatch.setattr(sources, "_account_home", lambda: str(home))
    personal = home / ".claude/CLAUDE.md"
    personal.parent.mkdir()
    personal.write_bytes(b"private contents must never be read")
    personal.chmod(0)
    if project:
        target = tree.parent / project
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(b"project")
    real_lstat = sources._lstat

    def guarded(path):
        assert str(path) != str(personal)  # Exemption does not inspect the file.
        return real_lstat(path)

    monkeypatch.setattr(sources, "_lstat", guarded)
    report = sources.scan(tree)
    assert report["result"] == ("CONFLICT" if project else "CONSISTENT_UNVERIFIED")
    assert report["load_confirmed"] is False
    assert str(home) not in json.dumps(report)


def test_forged_home_cannot_exempt_project_ancestor(tree, monkeypatch):
    monkeypatch.setenv("HOME", str(tree.parent))
    (tree.parent / ".claude").mkdir()
    (tree.parent / ".claude/CLAUDE.md").write_bytes(b"project")
    assert sources.scan(tree)["result"] == "CONFLICT"


@pytest.mark.parametrize("location", ["root", "ancestor"])
def test_account_home_that_is_project_keeps_conflicts(tree, monkeypatch, location):
    home = tree if location == "root" else tree.parent
    monkeypatch.setattr(sources, "_account_home", lambda: str(home))
    if location == "ancestor":
        (home / "AGENTS.md").write_bytes(b"ancestor project policy")
    (home / ".claude").mkdir()
    (home / ".claude/CLAUDE.md").write_bytes(b"project")
    assert sources.scan(tree)["result"] == "CONFLICT"


def test_unavailable_account_identity_is_not_run(tree, monkeypatch):
    def unavailable():
        raise KeyError("private detail")

    monkeypatch.setattr(sources, "_account_home", unavailable)
    report = sources.scan(tree)
    assert report["result"] == "NOT_RUN"
    assert report["reasons"] == ["identity_unavailable"]
    assert "private detail" not in json.dumps(report)


@pytest.mark.parametrize("home", ["", "relative", "/tmp/../other"])
def test_invalid_account_home_is_not_run(tree, monkeypatch, home):
    from types import SimpleNamespace

    monkeypatch.setattr(
        sources.pwd, "getpwuid", lambda uid: SimpleNamespace(pw_dir=home)
    )
    assert sources.scan(tree)["result"] == "NOT_RUN"


def test_symlink_claude_directory_is_not_followed(tree, monkeypatch):
    target = tree.parent / "private"
    target.mkdir()
    (tree / ".claude").symlink_to(target, target_is_directory=True)
    real_lstat = sources._lstat

    def guarded(path):
        assert not str(path).startswith(str(tree / ".claude") + "/")
        return real_lstat(path)

    monkeypatch.setattr(sources, "_lstat", guarded)
    assert sources.scan(tree)["result"] == "NOT_RUN"


def test_symlink_root_component_is_not_run(tree):
    alias = tree.parent / "alias"
    alias.symlink_to(tree, target_is_directory=True)
    assert sources.scan(alias)["result"] == "NOT_RUN"


def test_symlink_ancestor_is_rejected_before_probing_descendants(tree, monkeypatch):
    alias = tree.parent / "alias"
    alias.symlink_to(tree, target_is_directory=True)
    real_lstat = sources._lstat

    def guarded(path):
        assert not str(path).startswith(str(alias) + "/")
        return real_lstat(path)

    monkeypatch.setattr(sources, "_lstat", guarded)
    assert sources.scan(alias / "child")["result"] == "NOT_RUN"


def test_account_lookup_uses_process_uid(tree, monkeypatch):
    from types import SimpleNamespace

    calls = []

    def lookup(uid):
        calls.append(uid)
        return SimpleNamespace(pw_dir=str(tree.parent.parent))

    monkeypatch.setattr(sources.pwd, "getpwuid", lookup)
    monkeypatch.setenv("HOME", str(tree.parent))
    assert sources.scan(tree)["result"] == "CONSISTENT_UNVERIFIED"
    assert calls == [os.getuid()]
