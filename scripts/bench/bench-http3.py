#!/usr/bin/env python3
"""Test and measure verified HTTP/3 transfers on native Linux and Terra/KVM."""

import argparse
from datetime import UTC, datetime
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile
import time


REPOSITORY = Path(__file__).resolve().parents[2]
PROBE_SOURCE = REPOSITORY / "crates/terra/tests/assets/http3_probe"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def summarize(runs):
    summaries = {}
    for launcher in ("native", "direct", "bwrap"):
        summaries[launcher] = {}
        for case in ("http3_upload", "http3_download"):
            values = [operation["mib_per_second"] for run in runs
                      if run["launcher"] == launcher for operation in run["operations"]
                      if operation["case"] == case]
            if values:
                summaries[launcher][case] = {
                    "samples": values, "median_mib_per_second": statistics.median(values),
                    "min_mib_per_second": min(values), "max_mib_per_second": max(values),
                }
    return summaries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--terra", type=Path, default=REPOSITORY / "dist/terra")
    parser.add_argument("--probe", type=Path, help="existing static Linux HTTP/3 probe; otherwise build with Go")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--mib", type=int, default=64, help="verified payload MiB per upload/download")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.runs < 1 or not 1 <= args.mib <= 1024:
        parser.error("use at least one run and 1..1024 MiB per transfer")
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "aarch64"):
        parser.error("run on native Linux x86_64 or aarch64 with /dev/kvm")
    binary = args.terra.resolve()
    args.output = args.output.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    capture = Path(tempfile.mkdtemp(prefix="http3-", dir=args.output.parent))
    environment = os.environ | {"GOMAXPROCS": "2"}
    environment.pop("RUST_LOG", None)
    report = {
        "created_at_utc": datetime.now(UTC).isoformat(), "passed": False,
        "terra_sha256": digest(binary), "capture_path": str(capture),
        "host": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
        "workload": {"runs_per_launcher": args.runs, "bytes_per_transfer": args.mib * 1048576,
                     "guest_vcpus": 2, "guest_memory_mib": 512, "host_go_max_procs": 2},
        "measurement": "One HTTP/3 stream over QUIC/TLS per transfer, after a small GET on the same connection. Client monotonic timing includes payload verification and final response, excludes VM boot, process launch and TLS handshake. Upload receives only a small acknowledgment; download has no payload echo. Native control uses the same probe and UDP-only host server. Loopback results do not model WAN latency or loss.",
        "sources": {str(path.relative_to(REPOSITORY)): digest(path) for path in
                    [Path(__file__), *sorted(PROBE_SOURCE.glob("*.go")), PROBE_SOURCE / "go.mod", PROBE_SOURCE / "go.sum"]},
        "commands": [], "runs": [],
    }

    def save():
        report["summaries"] = summarize(report["runs"])
        encoded = json.dumps(report, indent=2) + "\n"
        (capture / "report.json").write_text(encoded)
        args.output.write_text(encoded)

    def run(command, env=environment, timeout=240, cwd=None):
        record = {"command": [str(arg) for arg in command]}
        report["commands"].append(record)
        try:
            result = subprocess.run(record["command"], env=env, cwd=cwd, capture_output=True,
                                    text=True, timeout=timeout)
            record.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
            if result.returncode:
                raise RuntimeError(f"command failed: {record['command']}\n{result.stderr}")
            return result.stdout
        except subprocess.TimeoutExpired as error:
            record.update(timed_out=True, stdout=str(error.stdout), stderr=str(error.stderr))
            raise
        finally:
            save()

    server = None
    try:
        if args.probe:
            probe = args.probe.resolve()
        else:
            probe = capture / "http3-probe"
            run(["go", "build", "-trimpath", "-o", probe, "."],
                env=environment | {"CGO_ENABLED": "0", "GOOS": "linux",
                                   "GOARCH": "amd64" if platform.machine() == "x86_64" else "arm64"},
                cwd=PROBE_SOURCE)
        report["probe_sha256"] = digest(probe)
        fixture = capture / "fixture"
        fixture.mkdir()
        with (capture / "server.log").open("w") as log:
            server = subprocess.Popen([str(probe), "server", "127.0.0.1:0", str(fixture)],
                                      env=environment, stdout=log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 10
            while not (fixture / "address").exists():
                if server.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError(f"HTTP/3 fixture did not start; see {capture / 'server.log'}")
                time.sleep(0.05)
            address = (fixture / "address").read_text().strip()
            port = address.rsplit(":", 1)[1]
            launchers = ["native", "direct", "bwrap"]
            for index in range(args.runs):
                for launcher in launchers[index % 3:] + launchers[:index % 3]:
                    cell = {"run": index, "launcher": launcher, "operations": []}
                    report["runs"].append(cell)
                    with tempfile.TemporaryDirectory(prefix="th3-", dir="/tmp") as temporary:
                        root = Path(temporary)
                        home, project = root / "home", root / "project"
                        (home / ".terra").mkdir(parents=True)
                        project.mkdir()
                        env = environment | {"HOME": str(home)}
                        setup = False
                        try:
                            if launcher == "native":
                                client = [probe]
                                target, certificates = address, str(fixture)
                            else:
                                (home / ".terra/config.yaml").write_text(f"vm:\n  init: {launcher}\n")
                                recipe = root / "http3.yaml"
                                recipe.write_text(json.dumps({
                                    "hw": {"cpus": 2, "mem_mib": 512},
                                    "network": {"allow": ["HOST_LOOPBACK:" + port]},
                                    "mounts": [{"host": str(probe.parent), "guest": "/probe", "readonly": True},
                                               {"host": str(fixture), "guest": "/fixture", "readonly": True}],
                                    "workload": {"entrypoint": "/bin/sh", "args": ["-ec", "while :; do sleep 60; done"]},
                                }))
                                cell["recipe"] = json.loads(recipe.read_text())
                                run([binary, recipe, "setup", "--project", project], env)
                                setup = True
                                run([binary, "http3", "-d", "--project", project], env)
                                client = [binary, "http3", "exec", "--project", project, "-T", "--", "/probe/" + probe.name]
                                target, certificates = "100.96.0.1:" + port, "/fixture"
                            run([*client, "client", target, certificates], env)
                            cell["compatibility_passed"] = True
                            for mode in (("upload", "download") if index % 2 == 0 else ("download", "upload")):
                                payload = json.loads(run([*client, mode, target, certificates, str(args.mib * 1048576)], env))
                                if (payload["case"] != "http3_" + mode or payload["bytes"] != args.mib * 1048576
                                        or payload["protocol"] != "HTTP/3.0" or payload["verified"] is not True
                                        or not math.isfinite(payload["seconds"]) or payload["seconds"] <= 0
                                        or not math.isclose(payload["mib_per_second"], args.mib / payload["seconds"], rel_tol=1e-5)):
                                    raise RuntimeError(f"invalid HTTP/3 transfer result: {payload}")
                                cell["operations"].append(payload)
                                save()
                            print(index, launcher, {o["case"]: round(o["mib_per_second"], 2) for o in cell["operations"]}, flush=True)
                        finally:
                            if setup:
                                run([binary, "http3", "stop", "--project", project], env, timeout=30)
                    if server.poll() is not None:
                        raise RuntimeError("HTTP/3 server exited during transfers")
            report["passed"] = True
    except Exception as error:
        report["failure"] = str(error)
        raise
    finally:
        if server is not None and server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
        save()


if __name__ == "__main__":
    main()
