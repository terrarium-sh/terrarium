#!/usr/bin/env python3
"""Measure shared virtio interrupt latency with equal mount and volume pools."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from datetime import UTC, datetime

sys.dont_write_bytecode = True

def bench_helpers():
    path = Path(__file__).with_name("bench-vmm.py")
    spec = importlib.util.spec_from_file_location("terra_bench_vmm", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load benchmark helpers from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BENCH = bench_helpers()
SAMPLE_INTERVAL_SECONDS = 0.02
BUSY_BLOCK_MIB = 4


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True, help="baseline Terra binary")
    parser.add_argument("--baseline-label", default="dedicated_irqs", help="baseline result label")
    parser.add_argument("--candidate", type=Path, help="shared-IRQ Terra binary")
    parser.add_argument("--skip-baseline", action="store_true", help="retain baseline results already in --output")
    parser.add_argument("--runs", type=int, default=3, help="runs per binary (default: 3)")
    parser.add_argument("--samples", type=int, default=30, help="latency samples per run (default: 30)")
    parser.add_argument(
        "--devices-per-pool", type=int, default=4, help="mounts and volumes to provision (4-16; default: 4)"
    )
    parser.add_argument("--timeout", type=float, default=60, help="per-command timeout in seconds (default: 60)")
    parser.add_argument("--output", type=Path, required=True, help="JSON results file")
    args = parser.parse_args()
    if args.runs < 1 or args.samples < 1 or args.timeout <= 0 or not 4 <= args.devices_per_pool <= 16:
        parser.error("runs, samples, and timeout must be positive; devices-per-pool must be 4 through 16")
    if args.skip_baseline and not args.output.is_file():
        parser.error("--skip-baseline needs an existing output file")
    if args.skip_baseline and args.candidate is None:
        parser.error("--skip-baseline needs --candidate")
    for binary in (args.baseline, args.candidate):
        if binary is not None and (not binary.is_file() or not os.access(binary, os.X_OK)):
            parser.error(f"not an executable file: {binary}")
    if not Path("/dev/kvm").exists():
        parser.error("this benchmark needs /dev/kvm")
    return args


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def percentile(values: list[float], point: int) -> float:
    if len(values) == 1:
        return values[0]
    if point == 50:
        return statistics.median(values)
    return statistics.quantiles(values, n=100, method="inclusive")[point - 1]


def summary(values: list[float]) -> dict[str, float]:
    return {"p50": percentile(values, 50), "p95": percentile(values, 95), "p99": percentile(values, 99)}


def run(command: list[str], env: dict[str, str], timeout: float) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, env=env, capture_output=True, timeout=timeout)


def recipe(mounts: list[Path], devices_per_pool: int) -> str:
    mount_entries = "\n".join(
        f"  - host: {mount}\n    guest: /mount-{index}" for index, mount in enumerate(mounts)
    )
    volume_entries = "\n".join(
        f"  - name: volume-{index}\n    guest: /volume-{index}\n    size_mib: 16" for index in range(devices_per_pool)
    )
    return f"""hw:
  cpus: 2
  mem_mib: 512
workload:
  entrypoint: /bin/sh
  args: [-ec, 'while :; do sleep 60; done']
volumes:
{volume_entries}
mounts:
{mount_entries}
"""


class VmMonitor:
    def __init__(self, pid: int):
        self.pid = pid
        self.peak_rss_kib = 0
        self.before_ticks = BENCH.process_cpu_ticks(BENCH.descendant_pids(pid))
        self.started = time.monotonic()
        self.done = threading.Event()
        self.thread = threading.Thread(target=self.sample, daemon=True)

    def sample(self) -> None:
        while not self.done.wait(SAMPLE_INTERVAL_SECONDS):
            self.peak_rss_kib = max(
                self.peak_rss_kib,
                sum(BENCH.resident_kib(pid) for pid in BENCH.descendant_pids(self.pid)),
            )

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> dict[str, float | int]:
        self.done.set()
        self.thread.join()
        elapsed = time.monotonic() - self.started
        pids = BENCH.descendant_pids(self.pid)
        self.peak_rss_kib = max(self.peak_rss_kib, sum(BENCH.resident_kib(pid) for pid in pids))
        ticks = BENCH.process_cpu_ticks(pids) - self.before_ticks
        return {
            "duration_seconds": elapsed,
            "cpu_percent": 100 * ticks / (os.sysconf("SC_CLK_TCK") * elapsed),
            "peak_rss_kib": self.peak_rss_kib,
        }


def busy_command(target: str) -> str:
    return f"""rm -f /mount-0/.irq-busy-count
touch /mount-0/.irq-busy-ready /mount-0/.irq-busy-go
count=0
while [ -f /mount-0/.irq-busy-go ]; do
  dd if=/dev/zero of={target}/.irq-busy-data bs=1M count={BUSY_BLOCK_MIB} conv=fsync status=none
  count=$((count + 1))
done
printf '%s\\n' "$count" > /mount-0/.irq-busy-count
"""


def wait_for(path: Path, process: subprocess.Popen[bytes], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if process.poll() is not None:
            raise RuntimeError(f"busy peer exited with {process.returncode}")
        if time.monotonic() >= deadline:
            raise TimeoutError(f"busy peer did not create {path.name}")
        time.sleep(0.01)


def measure_pool(
    binary: Path,
    env: dict[str, str],
    project: Path,
    control: Path,
    vm_pid: int,
    busy_target: str,
    latency_target: str,
    samples: int,
    timeout: float,
) -> dict[str, object]:
    (control / ".irq-busy-ready").unlink(missing_ok=True)
    (control / ".irq-busy-go").unlink(missing_ok=True)
    busy = subprocess.Popen(
        [str(binary), "shared-irqs", "exec", "--project", str(project), "-T", "--", "/bin/sh", "-ec", busy_command(busy_target)],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    monitor = None
    try:
        wait_for(control / ".irq-busy-ready", busy, timeout)
        monitor = VmMonitor(vm_pid)
        monitor.start()
        latencies = []
        for sample in range(samples):
            started = time.monotonic()
            command = run(
                [
                    str(binary), "shared-irqs", "exec", "--project", str(project), "-T", "--", "/bin/sh", "-ec",
                    f"dd if=/dev/zero of={latency_target}/.irq-latency-{sample} bs=4096 count=1 conv=fsync status=none",
                ],
                env,
                timeout,
            )
            if command.returncode:
                raise RuntimeError(f"latency command {sample} failed: {command.stderr.decode(errors='replace')[-512:]}")
            latencies.append(time.monotonic() - started)
        console = BENCH.interactive_marker_latency(
            [str(binary), "shared-irqs", "exec", "--project", str(project), "-t", "--", "/bin/sh"],
            env,
            samples,
            timeout,
        )
        if console["exit_code"] != 0:
            raise RuntimeError(f"console latency failed: {console.get('error', console.get('output_tail', ''))}")
        (control / ".irq-busy-go").unlink()
        if busy.wait(timeout=timeout):
            raise RuntimeError(f"busy peer failed: {busy.stderr.read().decode(errors='replace')[-512:]}")
        count = int((control / ".irq-busy-count").read_text())
        host = monitor.stop()
        monitor = None
        elapsed = float(host["duration_seconds"])
        return {
            "exec_and_fsync_rtt_seconds": latencies,
            "exec_and_fsync_rtt": summary(latencies),
            "console_rtt_seconds": console["marker_round_trip_seconds"],
            "console_rtt": summary(console["marker_round_trip_seconds"]),
            "busy_peer_bytes": count * BUSY_BLOCK_MIB * 1024 * 1024,
            "busy_peer_throughput_mib_per_second": count * BUSY_BLOCK_MIB / elapsed,
            "host_vm": host,
        }
    finally:
        if monitor is not None:
            monitor.stop()
        (control / ".irq-busy-go").unlink(missing_ok=True)
        if busy.poll() is None:
            busy.terminate()
            try:
                busy.wait(timeout=5)
            except subprocess.TimeoutExpired:
                busy.kill()
                busy.wait()


def run_case(binary: Path, index: int, samples: int, timeout: float, devices_per_pool: int) -> dict[str, object]:
    binary = binary.resolve()
    with tempfile.TemporaryDirectory(prefix="terra-protocol-irqs-") as temporary:
        root = Path(temporary)
        project, home = root / "project", root / "home"
        project.mkdir()
        home.mkdir()
        mounts = [root / f"mount-{number}" for number in range(devices_per_pool)]
        for mount in mounts:
            mount.mkdir()
        recipe_path = root / "shared-irqs.yaml"
        recipe_path.write_text(recipe(mounts, devices_per_pool))
        env = os.environ | {"HOME": str(home)}
        setup_started = time.monotonic()
        setup = run([str(binary), str(recipe_path), "setup", "--project", str(project)], env, timeout)
        result: dict[str, object] = {
            "run": index + 1,
            "setup_seconds": time.monotonic() - setup_started,
            "boot_to_ready_seconds": None,
        }
        if setup.returncode:
            result["failure"] = "setup failed"
            result["setup_stderr"] = setup.stderr.decode(errors="replace")[-4096:]
            return result
        boot_started = time.monotonic()
        boot = run([str(binary), "shared-irqs", "-d", "--project", str(project)], env, timeout)
        if boot.returncode:
            result["failure"] = "detached boot failed"
            result["boot_stderr"] = boot.stderr.decode(errors="replace")[-4096:]
            return result
        try:
            ready = run(
                [str(binary), "shared-irqs", "exec", "--project", str(project), "-T", "--", "true"], env, timeout
            )
            result["boot_to_ready_seconds"] = time.monotonic() - boot_started
            if ready.returncode:
                result["failure"] = "agent readiness probe failed"
                result["ready_stderr"] = ready.stderr.decode(errors="replace")[-4096:]
                return result
            vm_pid = BENCH.box_vm_pid(binary, env, project)
            result["mount_pool"] = measure_pool(
                binary, env, project, mounts[0], vm_pid, "/mount-0", "/mount-3", samples, timeout
            )
            result["volume_pool"] = measure_pool(
                binary, env, project, mounts[0], vm_pid, "/volume-0", "/volume-3", samples, timeout
            )
        except (OSError, RuntimeError, TimeoutError, ValueError, subprocess.SubprocessError) as error:
            result["failure"] = str(error)
        finally:
            stopped = run([str(binary), "stop", "--project", str(project)], env, timeout)
            result["stop_exit_code"] = stopped.returncode
            if stopped.returncode and "failure" not in result:
                result["failure"] = "stop failed"
    return result


def pool_summary(runs: list[dict[str, object]], name: str) -> dict[str, dict[str, float]]:
    pools = [run[name] for run in runs]
    return {
        "exec_and_fsync_rtt_seconds": summary(
            [sample for pool in pools for sample in pool["exec_and_fsync_rtt_seconds"]]
        ),
        "console_rtt_seconds": summary([sample for pool in pools for sample in pool["console_rtt_seconds"]]),
        "busy_peer_throughput_mib_per_second": summary(
            [float(pool["busy_peer_throughput_mib_per_second"]) for pool in pools]
        ),
        "host_vm_cpu_percent": summary([float(pool["host_vm"]["cpu_percent"]) for pool in pools]),
        "host_vm_peak_rss_kib": summary([float(pool["host_vm"]["peak_rss_kib"]) for pool in pools]),
    }


def binary_result(label: str, binary: Path) -> dict[str, object]:
    return {
        "label": label,
        "path": str(binary.resolve()),
        "sha256": digest(binary),
        "runs": [],
    }


def summarize_result(result: dict[str, object]) -> None:
    completed = [run for run in result["runs"] if "failure" not in run]
    result["completed_runs"] = len(completed)
    result.pop("summary", None)
    if completed:
        result["summary"] = {
            "readiness_seconds": summary([float(run["boot_to_ready_seconds"]) for run in completed]),
            "mount_pool": pool_summary(completed, "mount_pool"),
            "volume_pool": pool_summary(completed, "volume_pool"),
        }


def main() -> None:
    args = arguments()
    report: dict[str, object] = json.loads(args.output.read_text()) if args.output.is_file() else {}
    retained_topology = report.get("measurement", {}).get("topology", "")
    report.update(
        {
            "schema_version": 1,
            "generated_at_utc": datetime.now(UTC).isoformat(),
            "measurement": {
                "topology": f"{args.devices_per_pool} mounts plus {args.devices_per_pool} volumes; each pool uses busy index 0 and latency index 3; remaining devices stay idle",
                "busy_peer": f"repeated {BUSY_BLOCK_MIB} MiB fsync writes on index 0",
                "latency_peer": "one 4 KiB fsync write on index 3; RTT includes terra exec startup",
                "host_metrics": "VM process tree CPU percent and sampled VmRSS every 20 ms",
                "limitations": "does not generate network traffic or collect KVM exit counts; tracefs is inaccessible",
                "run_order": "paired baseline/candidate runs alternate order to reduce host-drift bias",
            },
        }
    )
    binaries = report.setdefault("binaries", {})
    if args.skip_baseline:
        if args.baseline_label not in binaries:
            raise SystemExit(f"missing retained baseline: {args.baseline_label}")
        retained = binaries[args.baseline_label]
        if retained.get("sha256") != digest(args.baseline) or retained.get("path") != str(args.baseline.resolve()):
            raise SystemExit("retained baseline does not match --baseline")
        expected_topology = f"{args.devices_per_pool} mounts plus {args.devices_per_pool} volumes;"
        if not retained_topology.startswith(expected_topology):
            raise SystemExit("retained baseline uses a different device layout")
        active = [("shared_irqs", args.candidate)]
    else:
        binaries[args.baseline_label] = binary_result(args.baseline_label, args.baseline)
        active = [(args.baseline_label, args.baseline)]
        if args.candidate is not None:
            active.append(("shared_irqs", args.candidate))
    for label, binary in active:
        binaries[label] = binary_result(label, binary)
    execution_order = []
    for index in range(args.runs):
        ordered = active if index % 2 == 0 else list(reversed(active))
        for label, binary in ordered:
            binaries[label]["runs"].append(run_case(binary, index, args.samples, args.timeout, args.devices_per_pool))
            execution_order.append(f"{label}:{index + 1}")
    for label, _ in active:
        summarize_result(binaries[label])
    report["execution_order"] = execution_order
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    if any(binaries[label]["completed_runs"] != args.runs for label, _ in active):
        raise SystemExit("one or more benchmark runs failed")


if __name__ == "__main__":
    main()
