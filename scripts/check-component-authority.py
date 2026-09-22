#!/usr/bin/env python3
"""Check compiled component imports against the reviewed function allowlist."""
import json
from pathlib import Path
import subprocess
import tomllib


ROOT = Path(__file__).resolve().parent.parent
COMPONENTS = ROOT / "components"
ARTIFACTS = COMPONENTS / "target/wasm-components/release"
ALLOWLIST = Path(__file__).with_name("component-authority.json")


def components():
    workspace = tomllib.loads((COMPONENTS / "Cargo.toml").read_text())
    for member in workspace["workspace"]["members"]:
        manifest = tomllib.loads((COMPONENTS / member / "Cargo.toml").read_text())
        if "cdylib" in manifest.get("lib", {}).get("crate-type", []):
            yield manifest["package"]["name"]


def imports(artifact):
    if Path(artifact).read_bytes()[:8] != b"\0asm\x0d\0\x01\0":
        raise SystemExit(f"expected a wrapped component: {artifact}")
    result = subprocess.run(
        ["wasm-tools", "component", "wit", artifact, "--json"],
        check=True,
        capture_output=True,
        text=True,
    )
    document = json.loads(result.stdout)
    world = document["worlds"][0]
    found = {}
    for value in world["imports"].values():
        interface = document["interfaces"][value["interface"]["id"]]
        package = document["packages"][interface["package"]]["name"]
        name = f"{package}/{interface['name']}"
        functions = list(interface["functions"])
        functions.extend(
            f"[resource-drop]{name}"
            for name, type_id in interface["types"].items()
            if document["types"][type_id]["kind"] == "resource"
        )
        found[name] = sorted(functions)
    return found


def main():
    expected = json.loads(ALLOWLIST.read_text())
    actual = {}
    for package in components():
        artifact = ARTIFACTS / f"{package.replace('-', '_')}.wasm"
        if not artifact.is_file():
            raise SystemExit(f"missing component artifact: {artifact.relative_to(ROOT)}")
        actual[package] = imports(str(artifact))
    if actual != expected:
        raise SystemExit(
            "component authority changed; update scripts/component-authority.json with a feature justification\n"
            + json.dumps(actual, indent=2, sort_keys=True)
        )
    print(f"Validated host-function authority for {len(actual)} components")


if __name__ == "__main__":
    main()
