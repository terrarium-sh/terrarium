#!/usr/bin/env python3
"""Keep the platform/hypervisor/runtime Cargo dependency boundaries one-way."""

import json
import subprocess
from collections import deque
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FORBIDDEN_PLATFORM_PACKAGES = {
    "terra-protocol",
    "terra-runtime",
}
TARGETS = (
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
    "x86_64-apple-darwin",
)


def package_id(packages, name):
    matches = [package["id"] for package in packages if package["name"] == name]
    if len(matches) != 1:
        raise SystemExit(f"expected one {name} package, found {len(matches)}")
    return matches[0]


def is_forbidden_platform_package(name):
    return (
        name in FORBIDDEN_PLATFORM_PACKAGES
        or name == "wasi"
        or name.startswith(("wasi-", "wasmtime"))
    )


def normal_dependencies(node):
    return [
        dependency["pkg"]
        for dependency in node["deps"]
        if any(kind["kind"] is None for kind in dependency["dep_kinds"])
    ]


def dependency_path(graph, start, forbidden):
    pending = deque([(start, [start])])
    visited = {start}
    while pending:
        package, path = pending.popleft()
        if package in forbidden and package != start:
            return path
        for dependency in graph.get(package, []):
            if dependency not in visited:
                visited.add(dependency)
                pending.append((dependency, [*path, dependency]))
    return None


errors = []
for target in TARGETS:
    metadata = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", target],
            check=True,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout
    )
    packages = {package["id"]: package["name"] for package in metadata["packages"]}
    graph = {
        node["id"]: [dependency["pkg"] for dependency in node["deps"]]
        for node in metadata["resolve"]["nodes"]
    }
    platform = package_id(metadata["packages"], "terra-platform")
    hypervisor = package_id(metadata["packages"], "terra-hypervisor")
    runtime = package_id(metadata["packages"], "terra-runtime")
    sandbox = package_id(metadata["packages"], "terra-sandbox")
    broker = package_id(metadata["packages"], "terra-network")
    broker_forbidden = {package for package, name in packages.items()
                        if name in {"terra-runtime", "terra-platform", "terra-hypervisor"}
                        or name.startswith(("wasmtime", "wasi"))}
    broker_path = dependency_path(graph, broker, broker_forbidden)
    if broker_path:
        errors.append(f"{target}: network broker reaches VM machinery: "
                      + " -> ".join(packages[package] for package in broker_path))
    forbidden = {package for package, name in packages.items() if is_forbidden_platform_package(name)}
    for start in (platform, hypervisor):
        path = dependency_path(graph, start, forbidden)
        if path:
            errors.append(
                f"{target}: {packages[start]} reaches a forbidden package: "
                + " -> ".join(packages[package] for package in path)
            )
    for dependency in (platform, hypervisor):
        if dependency not in graph.get(runtime, []):
            errors.append(f"{target}: terra-runtime must directly depend on {packages[dependency]}")
    normal_graph = {node["id"]: normal_dependencies(node) for node in metadata["resolve"]["nodes"]}
    for start in (platform, sandbox):
        path = dependency_path(normal_graph, start, {hypervisor})
        if path:
            errors.append(
                f"{target}: {packages[start]} reaches terra-hypervisor: "
                + " -> ".join(packages[package] for package in path)
            )
    if any(name == "terra-io" for name in packages.values()):
        errors.append(f"{target}: terra-io remains in the workspace or dependency graph")

if errors:
    raise SystemExit("\n".join(errors))
print("Validated platform/hypervisor/runtime Cargo dependency boundaries on supported targets")
