#!/usr/bin/env python3
"""Measure network policy coverage using the installed Rust/LLVM toolchain."""

import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "build" / "policy-coverage"
SOURCE = ROOT / "components/policy/src/runtime.rs"


def run(*args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, text=True, **kwargs)


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    version = run("rustc", "-vV", capture_output=True).stdout
    major = re.search(r"LLVM version: (\d+)", version).group(1)
    cov = os.environ.get("LLVM_COV", f"llvm-cov-{major}")
    profdata = os.environ.get("LLVM_PROFDATA", f"llvm-profdata-{major}")
    build = run("cargo", "rustc", "--locked", "--manifest-path", "components/policy/Cargo.toml",
                "--lib", "--profile", "test",
                "--message-format=json", "--", "-Cinstrument-coverage", stdout=subprocess.PIPE)
    artifacts = [json.loads(line) for line in build.stdout.splitlines() if line.startswith("{")]
    binary = next(a["executable"] for a in artifacts
                  if a.get("executable") and a.get("target", {}).get("name") == "terra_policy_component")
    raw = OUTPUT / "runtime.profraw"
    raw.unlink(missing_ok=True)
    run(binary, "tests::", env={**os.environ, "LLVM_PROFILE_FILE": str(raw)})
    profile = OUTPUT / "runtime.profdata"
    run(profdata, "merge", "-sparse", str(raw), "-o", str(profile))
    flags = (binary, f"-instr-profile={profile}", str(SOURCE))
    report = run(cov, "report", *flags, capture_output=True).stdout
    print(report)
    (OUTPUT / "summary.txt").write_text(report)
    exported = run(cov, "export", *flags, capture_output=True).stdout
    (OUTPUT / "coverage.json").write_text(exported)
    with (OUTPUT / "runtime.html").open("w") as output:
        run(cov, "show", *flags, "-format=html", stdout=output)
    summary = next(f["summary"] for d in json.loads(exported)["data"]
                   for f in d["files"] if Path(f["filename"]) == SOURCE)
    for metric in ("lines", "functions"):
        counts = summary[metric]
        if counts["covered"] != counts["count"]:
            raise SystemExit(f"runtime.rs {metric} coverage regressed: {counts}")


if __name__ == "__main__":
    main()
