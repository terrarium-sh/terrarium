#!/usr/bin/env python3
"""Keep the platform/runtime Cargo dependency boundary one-way."""

import json
import subprocess
from collections import deque
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
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
    runtime = package_id(metadata["packages"], "terra-runtime")
    forbidden = {package for package, name in packages.items() if is_forbidden_platform_package(name)}
    path = dependency_path(graph, platform, forbidden)
    if path:
        errors.append(
            f"{target}: terra-platform reaches a forbidden package: "
            + " -> ".join(packages[package] for package in path)
        )
    if platform not in graph.get(runtime, []):
        errors.append(f"{target}: terra-runtime must directly depend on terra-platform")
    if any(name == "terra-io" for name in packages.values()):
        errors.append(f"{target}: terra-io remains in the workspace or dependency graph")

if errors:
    raise SystemExit("\n".join(errors))
print("Validated platform/runtime Cargo dependency boundary on supported targets")
