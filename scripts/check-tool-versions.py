#!/usr/bin/env python3
"""Keep the component tool versions in build entry points synchronized."""

import re
import tomllib
from pathlib import Path


ROOT = Path(__file__).parent.parent
makefile = (ROOT / "Makefile").read_text()
toolchain = tomllib.loads((ROOT / "components/rust-toolchain.toml").read_text())["toolchain"]["channel"]


def make_value(name):
    match = re.search(rf"^{name} := (.+)$", makefile, re.MULTILINE)
    if not match:
        raise SystemExit(f"Makefile does not define {name}")
    return match.group(1)


versions = {
    "nightly": toolchain,
    "wasm-tools": make_value("WASM_TOOLS_VERSION"),
    "cargo-fuzz": make_value("CARGO_FUZZ_VERSION"),
    "cargo-audit": make_value("CARGO_AUDIT_VERSION"),
    "wit-bindgen": make_value("WIT_BINDGEN_VERSION"),
    "Zig": make_value("ZIG_VERSION"),
}
sources = [
    *sorted((ROOT / ".github/workflows").glob("*.yml")),
    ROOT / "scripts/build-host.ps1",
    ROOT / "README.dev.md",
    *sorted((ROOT / "components").glob("*/Cargo.toml")),
]
patterns = {
    "nightly": re.compile(r"nightly-[0-9-]+"),
    "wasm-tools": re.compile(r"wasm-tools --version ([0-9.]+)"),
    "cargo-fuzz": re.compile(r"cargo-fuzz --version ([0-9.]+)"),
    "cargo-audit": re.compile(r"cargo-audit --version ([0-9.]+)"),
    "wit-bindgen": re.compile(r'wit-bindgen\s*=\s*(?:\{\s*version\s*=\s*)?"?=([0-9.]+)'),
    "Zig": re.compile(r"(?<=version: )[0-9]+\.[0-9]+\.[0-9]+"),
}

found = {name: False for name in versions}
for source in sources:
    text = source.read_text()
    for name, pattern in patterns.items():
        values = pattern.findall(text)
        found[name] |= bool(values)
        if values and any(value != versions[name] for value in values):
            raise SystemExit(f"{source.relative_to(ROOT)} pins {name} to {values}, expected {versions[name]}")

for name, was_found in found.items():
    if not was_found:
        raise SystemExit(f"no checked build entry point pins {name}")
