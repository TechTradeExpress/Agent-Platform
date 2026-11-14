"""Static workspace reachability upper bound, NOT Cargo feature resolution."""

import posixpath
import tomllib
from collections import deque


def workspace_graph(manifests):
    """Include optional/all-target normal edges; exclude build/dev edges.

    The caller supplies pinned manifest bytes keyed by repository-relative path.
    Missing path dependencies refuse, including implicit workspace members.
    Registry/Git transitive dependencies and linker reachability are NOT resolved.
    """
    parsed = {path: tomllib.loads(data.decode()) for path, data in manifests.items()}
    workspace = parsed["codex-rs/Cargo.toml"]["workspace"]
    packages = {path: data for path, data in parsed.items() if "package" in data}
    names = [data["package"]["name"] for data in packages.values()]
    if len(set(names)) != len(names):
        raise ValueError("duplicate_package")
    edges = {name: set() for name in names}
    external = {name: set() for name in names}
    for path, data in packages.items():
        name = data["package"]["name"]
        sections = [data.get("dependencies", {})] + [
            target.get("dependencies", {})
            for target in data.get("target", {}).values()
        ]
        for dependencies in sections:
            for alias, declaration in dependencies.items():
                origin = posixpath.dirname(path)
                if isinstance(declaration, dict) and declaration.get("workspace"):
                    base = workspace["dependencies"][alias]
                    base = base if isinstance(base, dict) else {"version": base}
                    declaration = {**base, **declaration}
                    origin = "codex-rs"
                if isinstance(declaration, dict) and "path" in declaration:
                    target = posixpath.normpath(
                        origin + "/" + declaration["path"] + "/Cargo.toml"
                    )
                    if target not in packages:
                        raise ValueError("missing_path_dependency")
                    edges[name].add(packages[target]["package"]["name"])
                else:
                    external[name].add(
                        declaration.get("package", alias)
                        if isinstance(declaration, dict) else alias
                    )

    def closure(root):
        queue = deque([[root]])
        found = {}
        while queue:
            route = queue.popleft()
            node = route[-1]
            if node in found:
                continue
            if node not in edges:
                raise ValueError("unknown_root")
            found[node] = route
            queue.extend(route + [target] for target in sorted(edges[node]))
        return found

    cli = closure("codex-cli")
    host = closure("codex-code-mode-host")
    return {
        "method": "ALL_TARGET_OPTIONAL_NORMAL_WORKSPACE_UPPER_BOUND",
        "manifest_count": len(manifests),
        "explicit_members": len(workspace["members"]),
        "cli_workspace_packages": sorted(cli),
        "cli_v8_direct_external_edges": sorted(
            name for name in cli if "v8" in external[name]
        ),
        "host_v8_workspace_routes": [
            host[name] + ["v8"] for name in sorted(host) if "v8" in external[name]
        ],
        "selected_workspace_witnesses": {
            name: cli[name] for name in (
                "codex-core", "codex-file-search", "codex-state",
                "codex-tui", "codex-utils-audio", "codex-utils-rustls-provider",
            ) if name in cli
        },
        "target_resolved": False,
        "external_transitives_resolved": False,
        "binary_components_proven": False,
        "redistribution_allowed": False,
    }
