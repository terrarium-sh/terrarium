#!/usr/bin/env python3
"""Compare two Terra binaries on the same Linux/KVM workloads."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import signal
import statistics
import subprocess
import tempfile
import termios
import time
from datetime import UTC, datetime
from typing import Any

BASELINE_CPU_ITERATIONS = 2_000_000
BASELINE_BLOCK_MIB = 16
COMMAND_TIMEOUT_SECONDS = 180


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--legacy", type=Path, required=True, help="baseline Terra binary"
    )
    parser.add_argument("--component", type=Path, required=True, help="current component VMM binary")
    parser.add_argument("--legacy-launcher", choices=("direct", "bwrap"), help="baseline vm.init setting")
    parser.add_argument("--component-launcher", choices=("direct", "bwrap"), help="current vm.init setting")
    parser.add_argument("--runs", type=int, default=3, help="runs per baseline case (default: 3)")
    parser.add_argument(
        "--capacity-runs", type=int, default=1, help="runs for each 4/8-vCPU capacity case (default: 1)"
    )
    parser.add_argument(
        "--batch-runs", type=int, default=1, help="runs for the larger 2-vCPU workload batch (default: 1)"
    )
    parser.add_argument(
        "--interactive-samples", type=int, default=30, help="PTY shell marker round trips per run (default: 30)"
    )
    parser.add_argument(
        "--idle-sample-seconds", type=float, default=2.0, help="ready-box process-tree CPU sample duration (default: 2)"
    )
    parser.add_argument("--output", type=Path, required=True, help="JSON result path")
    parser.add_argument(
        "--command-timeout-seconds",
        type=int,
        default=COMMAND_TIMEOUT_SECONDS,
        help=f"per setup or boot timeout (default: {COMMAND_TIMEOUT_SECONDS})",
    )
    parser.add_argument(
        "--sample-ms", type=int, default=20, help="RSS sampling interval in milliseconds (default: 20)"
    )
    args = parser.parse_args()
    for name in ("runs", "capacity_runs", "batch_runs", "interactive_samples"):
        if getattr(args, name) < 1:
            parser.error(f"--{name.replace('_', '-')} must be positive")
    if args.sample_ms < 1:
        parser.error("--sample-ms must be positive")
    if args.command_timeout_seconds < 1:
        parser.error("--command-timeout-seconds must be positive")
    if args.idle_sample_seconds <= 0:
        parser.error("--idle-sample-seconds must be positive")
    for binary in (args.legacy, args.component):
        if not binary.is_file() or not os.access(binary, os.X_OK):
            parser.error(f"not an executable file: {binary}")
    if not Path("/proc").is_dir():
        parser.error("this benchmark needs Linux /proc to sample process RSS")
    return args


def digest(path: Path) -> str:
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def output_summary(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "tail": data[-4096:].decode("utf-8", errors="replace"),
    }


def process_parents() -> dict[int, int]:
    parents: dict[int, int] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            parents[int(entry.name)] = int(fields[1])
        except (OSError, IndexError, ValueError):
            continue
    return parents


def descendant_pids(root_pid: int) -> set[int]:
    parents = process_parents()
    descendants = {root_pid}
    while True:
        children = {pid for pid, parent in parents.items() if parent in descendants}
        new = children - descendants
        if not new:
            return descendants
        descendants.update(new)


def process_groups(pids: set[int]) -> set[int]:
    groups: set[int] = set()
    for pid in pids:
        try:
            fields = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
            groups.add(int(fields[2]))
        except (OSError, IndexError, ValueError):
            continue
    return groups


def signal_groups(groups: set[int], signal_number: int) -> None:
    for group in groups:
        try:
            os.killpg(group, signal_number)
        except ProcessLookupError:
            continue


def resident_kib(pid: int) -> int:
    try:
        for line in (Path("/proc") / str(pid) / "status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except (OSError, IndexError, ValueError):
        pass
    return 0


def process_cpu_ticks(pids: set[int]) -> int:
    ticks = 0
    for pid in pids:
        try:
            fields = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
            ticks += int(fields[11]) + int(fields[12])
        except (OSError, IndexError, ValueError):
            continue
    return ticks


def process_threads(pid: int) -> int:
    for line in (Path("/proc") / str(pid) / "status").read_text().splitlines():
        if line.startswith("Threads:"):
            return int(line.split()[1])
    raise ValueError(f"no thread count for PID {pid}")


def box_process_pids(binary: Path, env: dict[str, str], project: Path) -> dict[str, int]:
    listing = subprocess.run(
        [str(binary), "ls", "--tsv", "--project", str(project)],
        env=env,
        capture_output=True,
        check=True,
        text=True,
    )
    fields = listing.stdout.splitlines()[0].split("\t")
    return read_box_process_pids(Path(fields[3]))


def read_box_process_pids(directory: Path) -> dict[str, int]:
    def read_pid(name: str) -> int:
        words = (directory / name).read_text().split()
        pid = int(words[0])
        if pid <= 0:
            raise ValueError(f"invalid process identity in {name}")
        stat = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
        if stat[0] == "Z" or len(words) > 1 and int(words[1]) != int(stat[19]):
            raise ValueError(f"stale process identity in {name}")
        return pid

    vm_pid = read_pid("host.pid" if (directory / "host.pid").exists() else "terra.pid")
    pids = {"vm": vm_pid, "box_root": vm_pid}
    if (directory / "supervisor.pid").exists():
        pids["supervisor"] = read_pid("supervisor.pid")
        pids["box_root"] = pids["supervisor"]
        if vm_pid not in descendant_pids(pids["box_root"]):
            raise ValueError("VM is not a child of the published supervisor")
    return pids


def box_vm_pid(binary: Path, env: dict[str, str], project: Path) -> int:
    return box_process_pids(binary, env, project)["vm"]


def box_processes_at_ready(pids: dict[str, int]) -> list[dict[str, int | str]]:
    processes = []
    for pid in sorted(descendant_pids(pids["box_root"])):
        argv = (Path("/proc") / str(pid) / "cmdline").read_bytes().split(b"\0")
        role = "helper"
        if pid == pids["vm"]:
            role = "vm"
        elif pid == pids.get("supervisor"):
            role = "supervisor"
        elif len(argv) > 1 and argv[1] == b"__network":
            role = "network"
        processes.append({"pid": pid, "role": role, "rss_kib": resident_kib(pid), "threads": process_threads(pid)})
    return processes


def idle_box_cpu_percent(pids: dict[str, int], duration_seconds: float) -> dict[str, float]:
    roots = {"vm": pids["vm"], "box": pids["box_root"]}
    before = {role: process_cpu_ticks(descendant_pids(pid)) for role, pid in roots.items()}
    started = time.monotonic()
    time.sleep(duration_seconds)
    elapsed = time.monotonic() - started
    return {
        f"idle_{role}_process_tree_cpu_percent": 100
        * (process_cpu_ticks(descendant_pids(pid)) - before[role])
        / (os.sysconf("SC_CLK_TCK") * elapsed)
        for role, pid in roots.items()
    }


def timed_command(
    command: list[str], env: dict[str, str], directory: Path, sample_ms: int, timeout_seconds: int,
    vm_pid: int | None = None, box_root_pid: int | None = None
) -> dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=True)
    stdout_path = directory / "stdout"
    stderr_path = directory / "stderr"
    started = time.monotonic()
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        process = subprocess.Popen(command, stdout=stdout, stderr=stderr, env=env, start_new_session=True)
        peak_client_rss_kib = 0
        peak_vm_rss_kib = 0
        peak_box_rss_kib = 0
        timed_out = False
        while process.poll() is None:
            peak_client_rss_kib = max(peak_client_rss_kib, sum(resident_kib(pid) for pid in descendant_pids(process.pid)))
            if vm_pid is not None:
                peak_vm_rss_kib = max(peak_vm_rss_kib, sum(resident_kib(pid) for pid in descendant_pids(vm_pid)))
            if box_root_pid is not None:
                peak_box_rss_kib = max(peak_box_rss_kib, sum(resident_kib(pid) for pid in descendant_pids(box_root_pid)))
            if time.monotonic() - started >= timeout_seconds:
                timed_out = True
                groups = process_groups(descendant_pids(process.pid))
                signal_groups(groups, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    signal_groups(groups, signal.SIGKILL)
                    process.wait()
                else:
                    time.sleep(0.1)
                    signal_groups(groups, signal.SIGKILL)
                break
            time.sleep(sample_ms / 1000)
        peak_client_rss_kib = max(peak_client_rss_kib, sum(resident_kib(pid) for pid in descendant_pids(process.pid)))
        if vm_pid is not None:
            peak_vm_rss_kib = max(peak_vm_rss_kib, sum(resident_kib(pid) for pid in descendant_pids(vm_pid)))
        if box_root_pid is not None:
            peak_box_rss_kib = max(peak_box_rss_kib, sum(resident_kib(pid) for pid in descendant_pids(box_root_pid)))
    return {
        "command": command,
        "exit_code": process.returncode,
        "timed_out": timed_out,
        "wall_seconds": time.monotonic() - started,
        "peak_sampled_client_rss_kib": peak_client_rss_kib,
        "peak_sampled_vm_rss_kib": peak_vm_rss_kib if vm_pid is not None else None,
        "peak_sampled_box_rss_kib": peak_box_rss_kib if box_root_pid is not None else None,
        "stdout": output_summary(stdout_path),
        "stderr": output_summary(stderr_path),
    }


def interactive_marker_latency(
    command: list[str], env: dict[str, str], samples: int, timeout_seconds: int
) -> dict[str, Any]:
    master, slave = os.openpty()
    attrs = termios.tcgetattr(slave)
    attrs[3] &= ~termios.ECHO
    termios.tcsetattr(slave, termios.TCSANOW, attrs)
    started = time.monotonic()
    process = subprocess.Popen(
        command,
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env=env,
        start_new_session=True,
        close_fds=True,
    )
    os.close(slave)
    transcript = bytearray()

    def write_all(data: bytes) -> None:
        while data:
            written = os.write(master, data)
            data = data[written:]

    def read_marker(marker: bytes, deadline: float) -> bool:
        while time.monotonic() < deadline:
            readable, _, _ = select.select([master], [], [], min(0.1, deadline - time.monotonic()))
            if readable:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    return False
                if not chunk:
                    return False
                transcript.extend(chunk)
                if marker in bytes(transcript).replace(b"\r", b"").splitlines():
                    return True
        return False

    try:
        ready = b"__TERRA_INTERACTIVE_READY__"
        write_all(b"stty -echo; printf '\\n%s%s\\n' '__TERRA_' 'INTERACTIVE_READY__'\n")
        if not read_marker(ready, started + timeout_seconds):
            raise TimeoutError("interactive shell did not become ready")
        startup_seconds = time.monotonic() - started
        latencies = []
        for index in range(samples):
            marker = f"__TERRA_INTERACTIVE_RTT_{index}__".encode()
            marker_started = time.monotonic()
            split = marker.index(b"_") + 1
            write_all(b"printf '\\n%s%s\\n' '" + marker[:split] + b"' '" + marker[split:] + b"'\n")
            if not read_marker(marker, marker_started + timeout_seconds):
                raise TimeoutError(f"interactive marker {index} timed out")
            latencies.append(time.monotonic() - marker_started)
        write_all(b"exit\n")
        process.wait(timeout=5)
        return {
            "command": command,
            "exit_code": process.returncode,
            "startup_seconds": startup_seconds,
            "marker_round_trip_seconds": latencies,
            "timed_out": False,
            "output_tail": bytes(transcript[-4096:]).decode("utf-8", errors="replace"),
        }
    except (OSError, subprocess.TimeoutExpired, TimeoutError) as error:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        return {
            "command": command,
            "exit_code": process.returncode,
            "timed_out": isinstance(error, TimeoutError),
            "error": str(error),
            "output_tail": bytes(transcript[-4096:]).decode("utf-8", errors="replace"),
        }
    finally:
        os.close(master)


def stop_process_group(process: subprocess.Popen[bytes]) -> int | None:
    if process.poll() is not None:
        return process.returncode
    try:
        os.killpg(process.pid, signal.SIGTERM)
        return process.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return process.wait()


def recipe(cpus: int, mem_mib: int, mount: Path) -> str:
    return f"""hw:
  cpus: {cpus}
  mem_mib: {mem_mib}
workload:
  entrypoint: /bin/sh
  args:
    - -ec
    - |
      while :; do sleep 60; done
mounts:
  - host: {mount}
    guest: /bench
"""


def workload(iterations: int, block_mib: int) -> tuple[str, str]:
    cpu_sum = iterations * (iterations - 1) // 2
    expected = f"BENCH cpu_sum={cpu_sum} block_mib={block_mib}"
    return (
        f"""i=0
sum=0
while [ \"$i\" -lt {iterations} ]; do
  sum=$((sum + i))
  i=$((i + 1))
done
test "$(find /bench -maxdepth 1 -type f -name 'seed-*' | wc -l)" -eq 1000
printf updating > /bench/.terra-vmm-update
mv /bench/.terra-vmm-update /bench/terra-vmm-update
dd if=/dev/zero of=/tmp/terra-vmm-root.$$ bs=1M count={block_mib} conv=fsync
dd if=/dev/zero of=/bench/terra-vmm-bench.$$ bs=1M count={block_mib} conv=fsync
sync
rm -f /tmp/terra-vmm-root.$$
rm -f /bench/terra-vmm-bench.$$
printf 'BENCH cpu_sum=%s block_mib={block_mib}\\n' \"$sum\"""",
        expected,
    )


def benchmark_cases(args: argparse.Namespace) -> list[dict[str, int | str]]:
    return [
        {
            "name": "baseline-2cpu-512mib",
            "cpus": 2,
            "mem_mib": 512,
            "cpu_iterations": BASELINE_CPU_ITERATIONS,
            "block_mib": BASELINE_BLOCK_MIB,
            "runs": args.runs,
        },
        {
            "name": "capacity-4cpu-1024mib",
            "cpus": 4,
            "mem_mib": 1024,
            "cpu_iterations": BASELINE_CPU_ITERATIONS,
            "block_mib": BASELINE_BLOCK_MIB,
            "runs": args.capacity_runs,
        },
        {
            "name": "capacity-8cpu-2048mib",
            "cpus": 8,
            "mem_mib": 2048,
            "cpu_iterations": BASELINE_CPU_ITERATIONS,
            "block_mib": BASELINE_BLOCK_MIB,
            "runs": args.capacity_runs,
        },
        {
            "name": "batch-2cpu-512mib",
            "cpus": 2,
            "mem_mib": 512,
            "cpu_iterations": BASELINE_CPU_ITERATIONS * 4,
            "block_mib": BASELINE_BLOCK_MIB * 4,
            "runs": args.batch_runs,
        },
    ]


def summaries(cases: list[dict[str, Any]]) -> dict[str, Any]:
    def p95(values: list[float]) -> float | None:
        if not values:
            return None
        return statistics.quantiles(values, n=100, method="inclusive")[94] if len(values) > 1 else values[0]

    result: dict[str, Any] = {}
    for case in cases:
        runs = [run for run in case["runs"] if "failure" not in run]
        metrics = {
            "setup_seconds": [run["setup"]["wall_seconds"] for run in runs],
            "boot_detached_seconds": [run["boot_detached"]["wall_seconds"] for run in runs],
            "boot_to_agent_ready_seconds": [run["boot_to_agent_ready_seconds"] for run in runs],
            "workload_seconds": [run["workload_cpu_block_fsync"]["wall_seconds"] for run in runs],
            "shutdown_seconds": [run["shutdown"]["wall_seconds"] for run in runs],
            "peak_vm_rss_kib": [
                run["workload_cpu_block_fsync"]["peak_sampled_vm_rss_kib"]
                for run in runs
                if run["workload_cpu_block_fsync"]["peak_sampled_vm_rss_kib"] is not None
            ],
            "peak_box_rss_kib": [
                run["workload_cpu_block_fsync"]["peak_sampled_box_rss_kib"]
                for run in runs
                if run["workload_cpu_block_fsync"].get("peak_sampled_box_rss_kib") is not None
            ],
            "idle_vm_process_tree_cpu_percent": [run["idle_vm_process_tree_cpu_percent"] for run in runs if "idle_vm_process_tree_cpu_percent" in run],
            "idle_box_process_tree_cpu_percent": [run["idle_box_process_tree_cpu_percent"] for run in runs if "idle_box_process_tree_cpu_percent" in run],
            "vm_threads_at_ready": [run["vm_threads_at_ready"] for run in runs if "vm_threads_at_ready" in run],
            "box_threads_at_ready": [run["box_threads_at_ready"] for run in runs if "box_threads_at_ready" in run],
            "box_rss_at_ready_kib": [run["box_rss_at_ready_kib"] for run in runs if "box_rss_at_ready_kib" in run],
            "interactive_marker_round_trip_seconds": [
                sample for run in runs for sample in run["interactive_shell"]["marker_round_trip_seconds"]
            ],
        }
        idle_rtt = [sample for run in runs for sample in run["interactive_shell"]["marker_round_trip_seconds"]]
        loaded_rtt = [
            sample
            for run in runs
            for sample in run["interactive_shell_under_load"]["marker_round_trip_seconds"]
        ]
        result[str(case["case"]["name"])] = {
            "completed_runs": len(runs),
            "medians": {name: statistics.median(values) for name, values in metrics.items() if values},
            "p95": {
                "interactive_marker_round_trip_seconds": p95(idle_rtt),
                "interactive_marker_round_trip_under_load_seconds": p95(loaded_rtt),
            },
        }
    return result


def run_binary(
    label: str,
    binary: Path,
    cases: list[dict[str, int | str]],
    sample_ms: int,
    timeout_seconds: int,
    interactive_samples: int,
    idle_sample_seconds: float,
    launcher: str | None = None,
) -> dict[str, Any]:
    binary = binary.resolve()
    result: dict[str, Any] = {
        "label": label,
        "comparison_role": "baseline Terra binary"
        if label == "legacy"
        else "current component VMM",
        "path": str(binary),
        "sha256": digest(binary),
        "bytes": binary.stat().st_size,
        "launcher": launcher or "default",
        "cases": [],
    }
    with tempfile.TemporaryDirectory(prefix=f"tv-{label[0]}-") as temporary:
        temporary_path = Path(temporary)
        for case_index, case in enumerate(cases):
            case_result: dict[str, Any] = {"case": case, "runs": []}
            workload_script, expected = workload(int(case["cpu_iterations"]), int(case["block_mib"]))
            for index in range(int(case["runs"])):
                run_directory = temporary_path / str(case_index) / str(index)
                project = run_directory / "project"
                home = run_directory / "home"
                mount = run_directory / "mount"
                project.mkdir(parents=True)
                home.mkdir()
                if launcher is not None:
                    (home / ".terra").mkdir()
                    (home / ".terra" / "config.yaml").write_text(f"vm:\n  init: {launcher}\n")
                mount.mkdir()
                for file_index in range(1000):
                    (mount / f"seed-{file_index:04}").touch()
                recipe_path = run_directory / "bench.yaml"
                recipe_path.write_text(recipe(int(case["cpus"]), int(case["mem_mib"]), mount))
                env = os.environ | {"HOME": str(home)}
                setup = timed_command(
                    [str(binary), str(recipe_path), "setup", "--project", str(project)],
                    env,
                    run_directory / "setup",
                    sample_ms,
                    timeout_seconds,
                )
                run: dict[str, Any] = {"run": index + 1, "setup": setup}
                if setup["exit_code"] != 0:
                    run["failure"] = "setup failed"
                    case_result["runs"].append(run)
                    break
                boot_started = time.monotonic()
                boot = timed_command(
                    [str(binary), "bench", "-d", "--project", str(project)],
                    env,
                    run_directory / "boot",
                    sample_ms,
                    timeout_seconds,
                )
                run["boot_detached"] = boot
                if boot["exit_code"] != 0:
                    run["failure"] = "detached boot failed"
                    run["shutdown_after_failed_boot"] = timed_command(
                        [str(binary), "stop", "--project", str(project)],
                        env,
                        run_directory / "stop",
                        sample_ms,
                        timeout_seconds,
                    )
                    case_result["runs"].append(run)
                    break
                ready = timed_command(
                    [str(binary), "bench", "exec", "--project", str(project), "-T", "--", "true"],
                    env,
                    run_directory / "ready",
                    sample_ms,
                    timeout_seconds,
                )
                run["agent_ready_probe"] = ready
                run["boot_to_agent_ready_seconds"] = time.monotonic() - boot_started
                if ready["exit_code"] != 0:
                    run["failure"] = "agent readiness probe failed"
                else:
                    try:
                        process_pids = box_process_pids(binary, env, project)
                        vm_pid = process_pids["vm"]
                        box_root_pid = process_pids["box_root"]
                        run["process_pids"] = process_pids
                        processes = box_processes_at_ready(process_pids)
                        run["processes_at_ready"] = processes
                        run["vm_threads_at_ready"] = process_threads(vm_pid)
                        run["box_threads_at_ready"] = sum(process["threads"] for process in processes)
                        run["box_rss_at_ready_kib"] = sum(process["rss_kib"] for process in processes)
                        run.update(idle_box_cpu_percent(process_pids, idle_sample_seconds))
                    except (OSError, IndexError, ValueError, subprocess.CalledProcessError) as error:
                        vm_pid = None
                        box_root_pid = None
                        run["idle_vm_process_tree_cpu_error"] = str(error)
                    run["interactive_shell"] = interactive_marker_latency(
                        [str(binary), "bench", "exec", "--project", str(project), "-t", "--", "/bin/sh"],
                        env,
                        interactive_samples,
                        timeout_seconds,
                    )
                    if run["interactive_shell"]["exit_code"] != 0:
                        run["failure"] = "interactive shell failed"
                    else:
                        load_directory = run_directory / "background-load"
                        load_directory.mkdir()
                        load_stdout = load_directory / "stdout"
                        load_stderr = load_directory / "stderr"
                        with load_stdout.open("wb") as stdout, load_stderr.open("wb") as stderr:
                            load = subprocess.Popen(
                                [
                                    str(binary),
                                    "bench",
                                    "exec",
                                    "--project",
                                    str(project),
                                    "-T",
                                    "--",
                                    "timeout",
                                    "15",
                                    "/bin/sh",
                                    "-ec",
                                    "i=0; while [ \"$i\" -lt 20000 ]; do i=$((i + 1)); done; dd if=/dev/zero of=/bench/.terra-vmm-load bs=1M count=1 conv=fsync; printf ready > /bench/.terra-vmm-load-ready; while [ -f /bench/.terra-vmm-load-ready ]; do i=0; while [ \"$i\" -lt 20000 ]; do i=$((i + 1)); done; dd if=/dev/zero of=/bench/.terra-vmm-load bs=1M count=1 conv=fsync; done",
                                ],
                                env=env,
                                stdin=subprocess.DEVNULL,
                                stdout=stdout,
                                stderr=stderr,
                                start_new_session=True,
                            )
                            try:
                                deadline = time.monotonic() + timeout_seconds
                                while time.monotonic() < deadline and not (mount / ".terra-vmm-load-ready").is_file():
                                    if load.poll() is not None:
                                        break
                                    time.sleep(0.05)
                                if (mount / ".terra-vmm-load-ready").is_file():
                                    run["interactive_shell_under_load"] = interactive_marker_latency(
                                        [str(binary), "bench", "exec", "--project", str(project), "-t", "--", "/bin/sh"],
                                        env,
                                        interactive_samples,
                                        timeout_seconds,
                                    )
                                else:
                                    run["failure"] = "background load did not start"
                                if load.poll() is not None:
                                    run["failure"] = "background load ended before latency measurement completed"
                            finally:
                                (mount / ".terra-vmm-load-ready").unlink(missing_ok=True)
                                try:
                                    exit_code = load.wait(timeout=5)
                                except subprocess.TimeoutExpired:
                                    exit_code = stop_process_group(load)
                                (mount / ".terra-vmm-load").unlink(missing_ok=True)
                        run["background_load"] = {
                            "exit_code": exit_code,
                            "stdout": output_summary(load_stdout),
                            "stderr": output_summary(load_stderr),
                        }
                        if "failure" not in run and run["interactive_shell_under_load"]["exit_code"] != 0:
                            run["failure"] = "interactive shell under load failed"
                    if "failure" not in run:
                        batch = timed_command(
                            [str(binary), "bench", "exec", "--project", str(project), "-T", "--", "/bin/sh", "-ec", workload_script],
                            env,
                            run_directory / "workload",
                            sample_ms,
                            timeout_seconds,
                            vm_pid,
                            box_root_pid,
                        )
                        run["workload_cpu_block_fsync"] = batch
                        if batch["exit_code"] != 0:
                            run["failure"] = "workload failed"
                        elif expected not in batch["stdout"]["tail"]:
                            run["failure"] = "workload output mismatch"
                stop = timed_command(
                    [str(binary), "stop", "--project", str(project)],
                    env,
                    run_directory / "stop",
                    sample_ms,
                    timeout_seconds,
                )
                run["shutdown"] = stop
                if stop["exit_code"] != 0 and "failure" not in run:
                    run["failure"] = "shutdown failed"
                case_result["runs"].append(run)
                if "failure" in run:
                    break
            result["cases"].append(case_result)
    result["summaries"] = summaries(result["cases"])
    return result


def main() -> None:
    args = parse_args()
    cases = benchmark_cases(args)
    report = {
        "schema_version": 3,
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "measurement": {
            "block_mode": "rootfs and mounted-file dd conv=fsync writes followed by sync",
            "rss_measurement": "VmRSS sums for the client tree, VM tree, and complete box tree rooted at the supervisor when present; shared pages can be counted more than once",
            "rss_sample_ms": args.sample_ms,
            "command_timeout_seconds": args.command_timeout_seconds,
            "idle_vm_process_tree_cpu_sample_seconds": args.idle_sample_seconds,
            "idle_box_process_tree_cpu_sample_seconds": args.idle_sample_seconds,
            "interactive_measurement": "PTY shell marker write/read round trips",
        },
        "cases": cases,
        "binaries": [
            run_binary(
                "legacy",
                args.legacy,
                cases,
                args.sample_ms,
                args.command_timeout_seconds,
                args.interactive_samples,
                args.idle_sample_seconds,
                args.legacy_launcher,
            ),
            run_binary(
                "component",
                args.component,
                cases,
                args.sample_ms,
                args.command_timeout_seconds,
                args.interactive_samples,
                args.idle_sample_seconds,
                args.component_launcher,
            ),
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary_output = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary_output.write_text(json.dumps(report, indent=2) + "\n")
    temporary_output.replace(args.output)


if __name__ == "__main__":
    main()
