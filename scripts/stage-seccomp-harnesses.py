#!/usr/bin/env python3
"""Stage boot and native jail test executables for a native runner."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    command = ["cargo", "test", "--locked", "-p", "terra", "--lib", "--test", "boot", "--test", "native_boot",
               "--target", args.target, "--no-run", "--message-format=json"]
    process = subprocess.Popen(command, cwd=ROOT, text=True, stdout=subprocess.PIPE)
    executables = {}
    for line in process.stdout:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("reason") == "compiler-message":
            rendered = event.get("message", {}).get("rendered")
            if rendered:
                print(rendered, file=sys.stderr, end="")
        target = event.get("target", {})
        if event.get("reason") == "compiler-artifact" and target.get("kind") == ["test"] and target.get("name") in ("boot", "native_boot"):
            executables[target["name"]] = event.get("executable")
        if event.get("reason") == "compiler-artifact" and target.get("kind") == ["lib"] and target.get("name") == "terra" and event.get("profile", {}).get("test"):
            executables["terra_lib"] = event.get("executable")
    status = process.wait()
    if status or set(executables) != {"boot", "native_boot", "terra_lib"} or not all(executables.values()):
        raise RuntimeError(f"cargo did not build all seccomp test harnesses (status {status}): {executables}")
    output = args.output.absolute()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="terra-seccomp-harnesses-", dir=output.parent) as temporary:
        staged = Path(temporary)
        for name, source in executables.items():
            shutil.copy2(source, staged / name)
            os.chmod(staged / name, 0o755)
        generation = output.parent / f".{output.name}-{os.getpid()}"
        staged.rename(generation)
        pointer = output.parent / f".{output.name}-current-{os.getpid()}"
        pointer.symlink_to(generation.name, target_is_directory=True)
        os.replace(pointer, output)
    print(f"staged seccomp test harnesses: {output}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as error:
        print(f"seccomp harness staging failed: {error}", file=sys.stderr)
        sys.exit(1)
