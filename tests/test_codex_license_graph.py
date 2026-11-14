"""Conservative source reachability must not become binary-license clearance."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "license_graph", ROOT / "packaging/codex/license_graph.py"
)
graph = importlib.util.module_from_spec(spec)
spec.loader.exec_module(graph)


def inputs():
    return {
        "codex-rs/Cargo.toml": b'''[workspace]
members = ["cli", "host"]
[workspace.dependencies]
client = { path = "implicit", package = "actual-client" }
''',
        "codex-rs/cli/Cargo.toml": b'''[package]
name = "codex-cli"
[dependencies]
client = { workspace = true }
[dev-dependencies]
v8 = "1"
''',
        "codex-rs/implicit/Cargo.toml": b'''[package]
name = "actual-client"
[target.'cfg(windows)'.dependencies]
unselected = { path = "../optional", optional = true }
''',
        "codex-rs/optional/Cargo.toml": b'''[package]
name = "unselected"
''',
        "codex-rs/host/Cargo.toml": b'''[package]
name = "codex-code-mode-host"
[dependencies]
v8 = "1"
''',
    }


def test_implicit_members_renames_optional_and_foreign_target_in_upper_bound():
    report = graph.workspace_graph(inputs())
    assert report["explicit_members"] == 2
    assert report["cli_workspace_packages"] == [
        "actual-client", "codex-cli", "unselected",
    ]
    assert report["cli_v8_direct_external_edges"] == []
    assert report["host_v8_workspace_routes"] == [["codex-code-mode-host", "v8"]]
    assert not any(report[key] for key in (
        "target_resolved", "external_transitives_resolved",
        "binary_components_proven", "redistribution_allowed",
    ))
    assert graph.workspace_graph(inputs()) == report


def test_missing_implicit_member_refuses_instead_of_silently_dropping_edges():
    files = inputs()
    del files["codex-rs/implicit/Cargo.toml"]
    with pytest.raises(ValueError, match="missing_path_dependency"):
        graph.workspace_graph(files)


def test_real_normal_v8_edge_cannot_be_erased_by_companion_separation():
    files = inputs()
    files["codex-rs/optional/Cargo.toml"] += b'[dependencies]\nv8 = "1"\n'
    report = graph.workspace_graph(files)
    assert report["cli_v8_direct_external_edges"] == ["unselected"]


def test_duplicate_package_name_is_ambiguous():
    files = inputs()
    files["codex-rs/optional/Cargo.toml"] = b'[package]\nname = "actual-client"\n'
    with pytest.raises(ValueError, match="duplicate_package"):
        graph.workspace_graph(files)
