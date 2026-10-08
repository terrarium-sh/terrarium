#!/usr/bin/env python3
"""Compare direct and sandboxed Terra guest networking on native Linux/KVM."""

from __future__ import annotations

import argparse
from collections import deque
from contextlib import contextmanager
from datetime import UTC, datetime
import importlib.util
import json
import os
from pathlib import Path
import platform
import resource
import re
import select
import shutil
import signal
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
REPOSITORY = Path(__file__).resolve().parents[2]
TCP_CHUNK_BYTES = 8192
UDP_PAYLOAD_BYTES = 1200
MAX_TCP_BYTES = 1024 * 1024 * 1024
MAX_SAMPLES = 1_000_000
BOOT_STAGES = ("supervisor_start", "vm_entry", "agent_connected", "boot_plan_received", "networking_ready", "hooks_start", "workload_ready")


def load_benchmark_helpers():
    path = Path(__file__).with_name("bench-vmm.py")
    spec = importlib.util.spec_from_file_location("terra_bench_vmm", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BENCH = load_benchmark_helpers()


def receive_exact(connection: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        chunk = connection.recv(length - len(result))
        if not chunk:
            raise RuntimeError("benchmark TCP request ended early")
        result.extend(chunk)
    return bytes(result)


class Fixtures:
    def __init__(self, tcp_concurrency=1):
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for endpoint in (self.tcp, self.udp):
            endpoint.bind(("127.0.0.1", 0))
            endpoint.settimeout(0.1)
        self.tcp.listen(max(8, tcp_concurrency))
        self.tcp_port = self.tcp.getsockname()[1]
        self.udp_port = self.udp.getsockname()[1]
        self.tcp_concurrency = tcp_concurrency
        self.active_tcp = set()
        self.tcp_lock = threading.Lock()
        self.tcp_threads = []
        self.stop = threading.Event()
        self.errors = deque(maxlen=16)
        self.udp_received = 0
        self.threads = [
            threading.Thread(target=self.serve_tcp, daemon=True),
            threading.Thread(target=self.serve_udp, daemon=True),
        ]

    def __enter__(self):
        for thread in self.threads:
            thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        with self.tcp_lock:
            for endpoint in (*self.active_tcp, self.tcp, self.udp):
                endpoint.close()
        for threads in (self.threads, self.tcp_threads):
            for thread in threads:
                thread.join(timeout=11)
                if thread.is_alive():
                    raise RuntimeError("network fixture did not stop before its deadline")

    def serve_tcp(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.tcp.accept()
            except TimeoutError:
                continue
            except OSError:
                if self.stop.is_set():
                    return
                raise
            with self.tcp_lock:
                if self.stop.is_set():
                    connection.close()
                    return
                self.active_tcp.add(connection)
            if self.tcp_concurrency == 1:
                self.handle_tcp(connection)
            else:
                self.tcp_threads[:] = [thread for thread in self.tcp_threads if thread.is_alive()]
                thread = threading.Thread(target=self.handle_tcp, args=(connection,), daemon=True)
                self.tcp_threads.append(thread)
                thread.start()

    def handle_tcp(self, connection):
        try:
            with connection:
                connection.settimeout(10)
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                header = receive_exact(connection, 9)
                mode, count = header[:1], struct.unpack("<Q", header[1:])[0]
                if not 0 < count <= MAX_TCP_BYTES:
                    raise RuntimeError("TCP benchmark count exceeds its bound")
                if mode == b"L" and count > MAX_SAMPLES + 50:
                    raise RuntimeError("TCP latency count exceeds its bound")
                if mode not in (b"U", b"D", b"L"):
                    raise RuntimeError("unknown TCP benchmark mode")
                connection.sendall(b"R")
                if mode == b"L":
                    for _ in range(count):
                        payload = receive_exact(connection, 64)
                        connection.sendall(payload)
                elif mode == b"D":
                    if receive_exact(connection, 1) != b"G":
                        raise RuntimeError("download trigger changed")
                    remaining = count
                    while remaining:
                        length = min(TCP_CHUNK_BYTES, remaining)
                        connection.sendall(b"Z" * length)
                        remaining -= length
                else:
                    remaining = count
                    while remaining:
                        payload = connection.recv(min(TCP_CHUNK_BYTES, remaining))
                        if not payload or payload != b"Z" * len(payload):
                            raise RuntimeError("upload ended early or payload changed")
                        remaining -= len(payload)
                    connection.sendall(b"K")
        except (OSError, RuntimeError) as error:
            if not self.stop.is_set():
                self.errors.append(str(error))
        finally:
            with self.tcp_lock:
                self.active_tcp.discard(connection)

    def serve_udp(self):
        while not self.stop.is_set():
            try:
                payload, peer = self.udp.recvfrom(UDP_PAYLOAD_BYTES + 1)
                if len(payload) != UDP_PAYLOAD_BYTES:
                    raise RuntimeError("UDP payload length changed")
                self.udp_received += 1
                if self.udp.sendto(payload, peer) != len(payload):
                    raise RuntimeError("partial UDP echo")
            except TimeoutError:
                continue
            except (OSError, RuntimeError) as error:
                if not self.stop.is_set():
                    self.errors.append(str(error))


def snapshot_worker_cpu_ticks(processes: list[dict]) -> dict:
    snapshot = {}
    for process in processes:
        pid = process["pid"]
        fields = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
        if fields[0] == "Z":
            raise RuntimeError(f"benchmark worker {pid} exited during CPU accounting")
        snapshot[pid, fields[19]] = (process["role"], int(fields[11]) + int(fields[12]))
    return snapshot


def worker_cpu_seconds(before: dict, after: dict) -> dict[str, float]:
    if before.keys() != after.keys():
        raise RuntimeError(f"benchmark worker identities changed during CPU accounting: before={list(before)}, after={list(after)}")
    roles = {}
    for identity, (role, ticks) in after.items():
        previous_role, previous_ticks = before[identity]
        if role != previous_role or ticks < previous_ticks:
            raise RuntimeError(f"benchmark worker CPU accounting changed: {identity}")
        roles[role] = roles.get(role, 0) + (ticks - previous_ticks) / os.sysconf("SC_CLK_TCK")
    return roles


def snapshot_process_tree_pss(processes):
    samples = []
    for process in processes:
        sample = {"pid": process["pid"], "role": process["role"]}
        try:
            contents = (Path("/proc") / str(process["pid"]) / "smaps_rollup").read_text()
            sample["pss_kib"] = int(re.search(r"^Pss:\s+(\d+) kB$", contents, re.MULTILINE)[1])
        except (OSError, TypeError, ValueError) as error:
            sample.update(pss_kib=None, unavailable=str(error))
        samples.append(sample)
    total = sum(sample["pss_kib"] for sample in samples) if samples and all(sample["pss_kib"] is not None for sample in samples) else None
    return {"pss_kib": total, "processes": samples, "scope": "sum of Linux smaps_rollup Pss for the sampled box process tree; shared pages apportioned by the kernel"}


def snapshot_worker_context_switches(processes):
    samples = []
    errors = []
    for process in processes:
        pid = process["pid"]
        try:
            for task in sorted((Path("/proc") / str(pid) / "task").iterdir()):
                fields = (task / "stat").read_text().rsplit(")", 1)[1].split()
                status = (task / "status").read_text()
                samples.append({"pid": pid, "tid": int(task.name), "start_ticks": fields[19], "role": process["role"],
                                **{name: int(re.search(rf"^{name}:\s+(\d+)$", status, re.MULTILINE)[1])
                                   for name in ("voluntary_ctxt_switches", "nonvoluntary_ctxt_switches")}})
        except (OSError, IndexError, TypeError, ValueError) as error:
            errors.append({"pid": pid, "error": str(error)})
    return {"threads": samples, "read_errors": errors}


def worker_context_switch_deltas(before, after):
    result = {"scope": "all threads in the sampled box worker processes; start/end snapshots without polling", "before": before, "after": after}
    def identities(samples):
        return {(sample["pid"], sample["tid"], sample["start_ticks"]): sample for sample in samples["threads"]}
    previous, current = identities(before), identities(after)
    if before["read_errors"] or after["read_errors"] or previous.keys() != current.keys():
        return result | {"unavailable": "worker thread identities changed or could not be read"}
    roles = {}
    for identity, sample in current.items():
        totals = roles.setdefault(sample["role"], {"voluntary": 0, "involuntary": 0})
        for name, field in (("voluntary", "voluntary_ctxt_switches"), ("involuntary", "nonvoluntary_ctxt_switches")):
            delta = sample[field] - previous[identity][field]
            if delta < 0:
                return result | {"unavailable": "worker context-switch counter decreased"}
            totals[name] += delta
    return result | {"by_role": roles}


def snapshot_host_irqs():
    try:
        contents = Path("/proc/interrupts").read_text()
        lines = contents.splitlines()
        cpus = [int(column.removeprefix("CPU")) for column in lines[0].split()]
        counts = {}
        for line in lines[1:]:
            label, _, values = line.partition(":")
            values = values.split()[:len(cpus)]
            if len(values) == len(cpus) and all(value.isdigit() for value in values):
                counts[label.strip()] = sum(map(int, values))
        if not counts:
            raise ValueError("no per-CPU IRQ counters exposed")
        return {"cpu_columns": cpus, "counts": counts}
    except (OSError, IndexError, ValueError) as error:
        return {"unavailable": str(error)}


def host_irq_deltas(before, after):
    result = {"scope": "host /proc/interrupts across all exposed CPU columns; includes unrelated host activity, not VM-attributed", "before": before, "after": after}
    if "unavailable" in before or "unavailable" in after or before["cpu_columns"] != after["cpu_columns"] or before["counts"].keys() != after["counts"].keys():
        return result | {"unavailable": "IRQ counters unavailable or their scope changed"}
    deltas = {label: after["counts"][label] - count for label, count in before["counts"].items()}
    if any(delta < 0 for delta in deltas.values()):
        return result | {"unavailable": "host IRQ counter decreased"}
    return result | {"deltas": deltas, "total": sum(deltas.values())}


@contextmanager
def retained_capture_directory(parent, prefix):
    directory = Path(parent).resolve() / "captures"
    directory.mkdir(parents=True, exist_ok=True)
    capture = Path(tempfile.mkdtemp(prefix=prefix, dir=directory))
    print(f"raw capture: {capture}", file=sys.stderr, flush=True)
    yield capture


def collect_boot_stages(directory: Path) -> dict:
    records = {"host_utc": [], "guest_utc_and_agent_monotonic": []}
    observed = set()
    read_errors = []
    for name in ("launcher.log", "terra.log", "diagnostics.log"):
        path = directory / name
        if not path.exists():
            continue
        try:
            contents = path.read_text(errors="replace")
        except OSError as error:
            read_errors.append({"source": name, "error": str(error)})
            continue
        for line in contents.splitlines():
            match = re.search(r"\bboot_stage=([a-z_]+) unix_time_ns=(\d+)(?: agent_elapsed_ns=(\d+))?", line)
            if match is None:
                continue
            stage, unix_time, elapsed = match.groups()
            record = {"stage": stage, "unix_time_ns": int(unix_time), "source": name, "raw_line": line}
            domain = "host_utc"
            if elapsed is not None:
                domain = "guest_utc_and_agent_monotonic"
                record["agent_elapsed_ns"] = int(elapsed)
            records[domain].append(record)
            observed.add(stage)
    return {"records": records, "unavailable_stages": [stage for stage in BOOT_STAGES if stage not in observed], "read_errors": read_errors, "scope": "terra.log may include setup history; diagnostics.log belongs to the current run"}


def child_cpu_seconds() -> float:
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime


def process_start_times(pids: set[int]) -> dict[int, str]:
    identities = {}
    for pid in pids:
        try:
            fields = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
            if fields[0] != "Z":
                identities[pid] = fields[19]
        except (OSError, IndexError):
            continue
    return identities


def terminate_remaining_processes(identities: dict[int, str]) -> bool:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if not any(process_start_times({pid}).get(pid) == started for pid, started in identities.items()):
            return False
        time.sleep(0.05)
    for pid, started in identities.items():
        try:
            descriptor = os.pidfd_open(pid)
            try:
                if process_start_times({pid}).get(pid) == started:
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            finally:
                os.close(descriptor)
        except ProcessLookupError:
            continue
    return True


def timed_network_command(command, env, directory, timeout):
    directory.mkdir(parents=True, exist_ok=True)
    stdout_path, stderr_path = directory / "stdout", directory / "stderr"
    started = time.monotonic()
    timed_out = False
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        process = subprocess.Popen(command, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            descriptor = os.pidfd_open(process.pid)
            try:
                if not select.select([descriptor], [], [], timeout)[0]:
                    raise subprocess.TimeoutExpired(command, timeout)
            finally:
                os.close(descriptor)
            process.wait()
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
    return {
        "command": command,
        "capture_path": str(directory),
        "exit_code": process.returncode,
        "timed_out": timed_out,
        "wall_seconds": time.monotonic() - started,
        "peak_sampled_client_rss_kib": None,
        "peak_sampled_vm_rss_kib": None,
        "peak_sampled_box_rss_kib": None,
        "stdout": BENCH.output_summary(stdout_path),
        "stderr": BENCH.output_summary(stderr_path),
    }


@contextmanager
def record_cpu_profile(processes, directory, timeout):
    directory.mkdir(parents=True, exist_ok=True)
    workers = [process for process in processes if process["role"] in ("vm", "network")]
    for worker in workers:
        pid = worker["pid"]
        (directory / f"{worker['role']}-{pid}.maps").write_text((Path("/proc") / str(pid) / "maps").read_text())
    data_path = directory / "perf.data"
    command = ["perf", "record", "-e", "cpu-clock:u", "-F", "99", "--call-graph", "dwarf,8192",
               "-o", str(data_path), "-p", ",".join(str(worker["pid"]) for worker in workers), "--", "sleep", str(timeout)]
    metadata = {"command": command, "workers": workers, "data": str(data_path)}
    with (directory / "record.stderr").open("wb") as stderr:
        profiler = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=stderr, start_new_session=True)
        try:
            time.sleep(0.2)
            if profiler.poll() is not None:
                raise RuntimeError(f"perf attachment failed: {BENCH.output_summary(directory / 'record.stderr')['tail']}")
            yield metadata
        finally:
            if profiler.poll() is None:
                profiler.send_signal(signal.SIGINT)
            try:
                profiler.wait(timeout=10)
            except subprocess.TimeoutExpired:
                profiler.kill()
                profiler.wait(timeout=5)
            metadata["exit_code"] = profiler.returncode
    with (directory / "report.txt").open("wb") as report, (directory / "report.stderr").open("wb") as stderr:
        subprocess.run(["perf", "report", "--stdio", "--header", "--no-children", "--sort", "comm,dso", "--percent-limit", "0.5", "-i", str(data_path)], stdout=report, stderr=stderr, check=True, timeout=30)


def measure_operation(binary, env, project, pids, probe_mode, port, count, directory, timeout, fixtures, tcp_concurrency=1, sample_memory=False):
    processes = BENCH.box_processes_at_ready(pids)
    switches_before = snapshot_worker_context_switches(processes)
    irqs_before = snapshot_host_irqs()
    before = snapshot_worker_cpu_ticks(processes)
    fixture_cpu = time.process_time()
    cli_cpu = child_cpu_seconds()
    udp_received = fixtures.udp_received
    command = [str(binary), "bench", "exec", "--project", str(project), "-T", "--",
               "/bench/probe", probe_mode, "benchmark.test", str(port), str(count)]
    if probe_mode in ("upload", "download") and tcp_concurrency > 1:
        command.append(str(tcp_concurrency))
    if sample_memory:
        result = BENCH.timed_command(command, env, directory, 20, timeout, pids["vm"], pids["box_root"])
    else:
        result = timed_network_command(command, env, directory, timeout)
    result["capture_path"] = str(directory)
    fixture_cpu = time.process_time() - fixture_cpu
    cli_cpu = child_cpu_seconds() - cli_cpu
    after = snapshot_worker_cpu_ticks(BENCH.box_processes_at_ready(pids))
    switches = worker_context_switch_deltas(switches_before, snapshot_worker_context_switches(BENCH.box_processes_at_ready(pids)))
    irqs = host_irq_deltas(irqs_before, snapshot_host_irqs())
    role_cpu = worker_cpu_seconds(before, after)
    if result["exit_code"] != 0 or result["timed_out"]:
        raise RuntimeError(f"guest {probe_mode} failed: {result['stderr']['tail']} {result['stdout']['tail']}")
    payload = json.loads(result["stdout"]["tail"])
    multiplier = UDP_PAYLOAD_BYTES if probe_mode == "udp" else tcp_concurrency if probe_mode in ("upload", "download") else 1
    if probe_mode == "udp-window":
        if payload["lost_datagrams"] != 0 or payload["bytes"] != count * UDP_PAYLOAD_BYTES:
            raise RuntimeError(f"guest UDP window lost datagrams: {payload}")
    elif payload.get("bytes", payload.get("samples")) != count * multiplier:
        raise RuntimeError(f"guest {probe_mode} output count changed: {payload}")
    if probe_mode in ("udp", "udp-window") and fixtures.udp_received - udp_received != count:
        raise RuntimeError("host UDP datagram count changed")
    if fixtures.errors:
        raise RuntimeError(f"host network fixture failed: {list(fixtures.errors)}")
    box_cpu = sum(role_cpu.values())
    payload.update({
        "host_box_cpu_seconds_by_role": role_cpu,
        "host_worker_context_switches": switches,
        "host_irq_activity": irqs,
        "host_box_cpu_process_identities": list(before),
        "host_box_cpu_seconds": box_cpu,
        "host_fixture_and_harness_cpu_seconds": fixture_cpu,
        "host_cli_cpu_seconds": cli_cpu,
        "host_total_cpu_seconds": box_cpu + fixture_cpu + cli_cpu,
        "host_box_cpu_percent": 100 * box_cpu / result["wall_seconds"],
        "exec": result,
    })
    if "bytes" in payload:
        payload["host_box_cpu_seconds_per_mib"] = box_cpu / (payload["bytes"] / (1024 * 1024))
    return payload


def measure_box(binary, probe, launcher, run, args, fixtures):
    result = {"run": run, "launcher": launcher, "binary": str(binary), "operations": []}
    tcp_concurrency = getattr(args, "tcp_concurrency", 1)
    local_only = getattr(args, "local_only", False)
    sample_memory = getattr(args, "sample_memory", False)
    result.update({"network_enabled": not local_only, "operation_rss_sampling": sample_memory,
                   "setup_boot_shutdown_rss_sampling": sample_memory})
    with retained_capture_directory(args.output.parent, f"run-{run}-{launcher}-") as temporary, tempfile.TemporaryDirectory(prefix="tn-") as short_temporary:
        root = Path(temporary)
        result["capture_path"] = str(root)
        # AF_UNIX paths must stay short even when the retained output directory is deeply nested.
        short_root = Path(short_temporary) / "c"
        short_root.symlink_to(root, target_is_directory=True)
        result["runtime_path_alias"] = str(short_root)
        home, project, mount = short_root / "h", short_root / "p", short_root / "m"
        for directory in (home, project, mount):
            directory.mkdir()
        (home / ".terra").mkdir()
        (home / ".terra" / "config.yaml").write_text(f"vm:\n  init: {launcher}\n")
        shutil.copy2(probe, mount / "probe")
        recipe = {
            "hw": {"cpus": 2, "mem_mib": 512},
            "workload": {"entrypoint": "/bin/sh", "args": ["-ec", "while :; do sleep 60; done"]},
            "mounts": [{"host": str(mount), "guest": "/bench", "readonly": True}],
            "network": {
                "allow": [f"benchmark.test:{fixtures.tcp_port}", f"benchmark.test:{fixtures.udp_port}"],
                "hosts": [{"name": "benchmark.test", "addr": "HOST_LOOPBACK"}],
            },
        }
        if local_only:
            recipe["network"] = {"enabled": False}
        recipe_path = root / "bench.yaml"
        recipe_path.write_text(json.dumps(recipe))
        env = os.environ | {"HOME": str(home)}
        env.pop("RUST_LOG", None)
        try:
            for phase, command in [
                ("setup", [str(binary), str(recipe_path), "setup", "--project", str(project)]),
                ("boot_to_agent_ready", [str(binary), "bench", "-d", "--project", str(project)]),
            ]:
                started_at = datetime.now(UTC).isoformat()
                measured = (BENCH.timed_command(command, env, root / phase, 20, args.timeout)
                            if sample_memory else timed_network_command(command, env, root / phase, args.timeout))
                measured.update({"started_at_utc": started_at, "completed_at_utc": datetime.now(UTC).isoformat()})
                measured["capture_path"] = str(root / phase)
                result[phase] = measured
                if measured["exit_code"] != 0 or measured["timed_out"]:
                    raise RuntimeError(f"{launcher} {phase} failed: {measured['stderr']['tail']}")
            listing = subprocess.run([str(binary), "ls", "--tsv", "--project", str(project)], env=env, capture_output=True, check=True, text=True)
            box_directory = Path(listing.stdout.splitlines()[0].split("\t")[3])
            pids = BENCH.read_box_process_pids(box_directory)
            processes = BENCH.box_processes_at_ready(pids)
            pss = snapshot_process_tree_pss(processes)
            result.update({"process_pids": pids, "processes_at_ready": processes,
                           "process_tree_pss_at_ready": pss, "box_pss_at_ready_kib": pss["pss_kib"],
                           "box_rss_at_ready_kib": sum(process["rss_kib"] for process in processes),
                           "box_threads_at_ready": sum(process["threads"] for process in processes)})
            idle_before = snapshot_worker_cpu_ticks(processes)
            idle_switches = snapshot_worker_context_switches(processes)
            idle_irqs = snapshot_host_irqs()
            result.update(BENCH.idle_box_cpu_percent(pids, args.idle_seconds))
            worker_cpu_seconds(idle_before, snapshot_worker_cpu_ticks(BENCH.box_processes_at_ready(pids)))
            processes_after_idle = BENCH.box_processes_at_ready(pids)
            result["idle_host_worker_context_switches"] = worker_context_switch_deltas(idle_switches, snapshot_worker_context_switches(processes_after_idle))
            result["idle_host_irq_activity"] = host_irq_deltas(idle_irqs, snapshot_host_irqs())
            pss = snapshot_process_tree_pss(processes_after_idle)
            result.update(process_tree_pss_after_idle=pss, box_pss_after_idle_kib=pss["pss_kib"])
            result["box_rss_after_idle_kib"] = sum(process["rss_kib"] for process in processes_after_idle)
            operations = [
                ("churn", fixtures.tcp_port, getattr(args, "churn_samples", 100)),
                ("latency", fixtures.tcp_port, args.latency_samples),
                ("upload", fixtures.tcp_port, args.tcp_mib * 1024 * 1024),
                ("download", fixtures.tcp_port, args.tcp_mib * 1024 * 1024),
                ("udp", fixtures.udp_port, args.udp_datagrams),
                ("udp-window", fixtures.udp_port, args.udp_datagrams),
                ("localhost", 0, args.tcp_mib * 1024 * 1024),
            ]
            if local_only:
                operations = [("localhost", 0, args.tcp_mib * 1024 * 1024)]
            if args.profile_download:
                with record_cpu_profile(processes, args.profile_download / f"{run}-{launcher}", args.timeout) as profile:
                    result["profile"] = profile
                    result["operations"].append(measure_operation(binary, env, project, pids, "download", fixtures.tcp_port, args.tcp_mib * 1024 * 1024, root / "download", args.timeout, fixtures, tcp_concurrency))
                operations = []
            for mode, port, count in operations:
                result["operations"].append(measure_operation(binary, env, project, pids, mode, port, count, root / mode, args.timeout, fixtures, tcp_concurrency, sample_memory))
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
            result["failure"] = str(error)
        finally:
            remaining = set()
            if "process_pids" in result:
                result["boot_stage_records"] = collect_boot_stages(box_directory)
                remaining = BENCH.descendant_pids(result["process_pids"]["box_root"])
                remaining.update(process["pid"] for process in result["processes_at_ready"])
            identities = process_start_times(remaining)
            command = [str(binary), "stop", "--project", str(project)]
            stop = (BENCH.timed_command(command, env, root / "stop", 20, args.timeout)
                    if sample_memory else timed_network_command(command, env, root / "stop", args.timeout))
            result["shutdown"] = stop
            stop["capture_path"] = str(root / "stop")
            if stop["exit_code"] != 0 or stop["timed_out"]:
                result.setdefault("failure", f"shutdown failed: {stop['stderr']['tail']}")
            if terminate_remaining_processes(identities):
                result.setdefault("failure", "box processes survived shutdown; cleanup sent SIGKILL")
            (root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def summarize(runs: list[dict]) -> dict:
    summary = {}
    for launcher in ("direct", "bwrap"):
        completed = [run for run in runs if run["launcher"] == launcher and "failure" not in run]
        if not completed:
            continue
        metrics = {
            "boot_to_agent_ready_seconds": statistics.median(run["boot_to_agent_ready"]["wall_seconds"] for run in completed),
            "box_rss_at_ready_kib": statistics.median(run["box_rss_at_ready_kib"] for run in completed),
            "box_rss_after_idle_kib": statistics.median(run["box_rss_after_idle_kib"] for run in completed),
            "box_threads_at_ready": statistics.median(run["box_threads_at_ready"] for run in completed),
            "idle_box_process_tree_cpu_percent": statistics.median(run["idle_box_process_tree_cpu_percent"] for run in completed),
        }
        for field in ("box_pss_at_ready_kib", "box_pss_after_idle_kib"):
            values = [run[field] for run in completed if run.get(field) is not None]
            metrics[field] = statistics.median(values) if values else None
        for case in {operation["case"] for run in completed for operation in run["operations"]}:
            operations = [operation for run in completed for operation in run["operations"] if operation["case"] == case]
            metrics[case] = {name: statistics.median(operation[name] for operation in operations) for name in ("mib_per_second", "p50_us", "p95_us", "first_connect_us", "connections_per_second", "host_box_cpu_seconds", "host_total_cpu_seconds", "host_box_cpu_seconds_per_mib") if name in operations[0]}
        boot_seconds = sorted(run["boot_to_agent_ready"]["wall_seconds"] for run in completed)
        summary[launcher] = {"completed_runs": len(completed), "medians": metrics, "boot_to_agent_ready_seconds": {"p50": statistics.median(boot_seconds), "p95": boot_seconds[min(len(boot_seconds) - 1, (len(boot_seconds) * 95 + 99) // 100 - 1)], "samples": boot_seconds}}
    return summary


def summarize_pairs(runs: list[dict]) -> dict:
    completed = {(run["run"], run["launcher"]): run for run in runs if "failure" not in run}
    cases = {}
    for run_number in sorted({run["run"] for run in runs}):
        if (run_number, "direct") not in completed or (run_number, "bwrap") not in completed:
            continue
        direct = {operation["case"]: operation for operation in completed[run_number, "direct"]["operations"]}
        broker = {operation["case"]: operation for operation in completed[run_number, "bwrap"]["operations"]}
        for case in sorted(direct.keys() & broker.keys()):
            metrics = cases.setdefault(case, {})
            for field in ("mib_per_second", "p50_us", "p95_us", "first_connect_us", "connections_per_second", "host_box_cpu_seconds", "host_total_cpu_seconds", "host_box_cpu_seconds_per_mib"):
                if field in direct[case] and field in broker[case] and direct[case][field] > 0:
                    metrics.setdefault(field, []).append({"run": run_number, "direct": direct[case][field], "broker": broker[case][field], "broker_over_direct": broker[case][field] / direct[case][field]})
    return {case: {field: {"pairs": pairs, "median_ratio": statistics.median(pair["broker_over_direct"] for pair in pairs), "min_ratio": min(pair["broker_over_direct"] for pair in pairs), "max_ratio": max(pair["broker_over_direct"] for pair in pairs)} for field, pairs in metrics.items()} for case, metrics in cases.items()}


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--terra", type=Path, help="production native Terra executable")
    parser.add_argument("--guest-probe", type=Path, help="existing static Linux guest probe; default compiles the bundled C source with Zig")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--tcp-mib", type=int, default=32)
    parser.add_argument("--tcp-concurrency", type=int, default=1, help="simultaneous TCP flows per VM; TCP MiB is per flow (1..64)")
    parser.add_argument("--udp-datagrams", type=int, default=4096)
    parser.add_argument("--latency-samples", type=int, default=1000)
    parser.add_argument("--churn-samples", type=int, default=100)
    parser.add_argument("--local-only", action="store_true", help="measure candidate local-only boot and guest localhost throughput")
    parser.add_argument("--sample-memory", action="store_true", help="sample process-tree RSS every 20 ms; use a separate run from throughput measurements")
    parser.add_argument("--idle-seconds", type=float, default=2)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile-download", type=Path, help="record only long downloads with perf; save profiles here and omit performance summaries")
    parser.add_argument("--self-check", action="store_true", help="exercise the guest probe and host fixtures through local native sockets without a VM")
    args = parser.parse_args()
    if not 0 < args.runs <= 100 or not 0 < args.tcp_mib <= 1024 or not 0 < args.udp_datagrams <= MAX_SAMPLES or not 0 < args.latency_samples <= MAX_SAMPLES:
        parser.error("runs must be 1..100, TCP MiB 1..1024, datagrams and latency samples 1..1000000")
    if args.idle_seconds <= 0 or args.timeout <= 0:
        parser.error("idle seconds and timeout must be positive")
    if not 1 <= args.tcp_concurrency <= 64:
        parser.error("TCP concurrency must be 1..64")
    if not 1 <= args.churn_samples <= MAX_SAMPLES:
        parser.error("churn samples must be 1..1000000")
    if args.profile_download and (args.local_only or args.sample_memory):
        parser.error("download profiling cannot be combined with local-only or memory sampling")
    if not args.self_check and (args.terra is None or not args.terra.is_file() or not Path("/dev/kvm").exists()):
        parser.error("provide --terra and run on native Linux with /dev/kvm")
    return args


def main():
    args = parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with retained_capture_directory(args.output.parent, "probe-self-check-" if args.self_check else "probe-") as temporary:
        if args.guest_probe is None:
            probe = Path(temporary) / "probe"
            compiler_env = os.environ | {"ZIG_GLOBAL_CACHE_DIR": str(Path(temporary) / "zig-cache"), "ZIG_LOCAL_CACHE_DIR": str(Path(temporary) / "zig-local")}
            subprocess.run([str(REPOSITORY / "scripts/toolchain/zig-musl-cc"), "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static", "-pthread", str(REPOSITORY / "crates/terra-network/examples/guest-network-benchmark.c"), "-o", str(probe)], env=compiler_env, check=True, timeout=180)
        else:
            probe = args.guest_probe.resolve()
        report = {
            "schema_version": 3,
            "generated_at_utc": datetime.now(UTC).isoformat(),
            "host": {"system": platform.system(), "release": platform.release(), "machine": platform.machine(), "affinity_cpus": sorted(os.sched_getaffinity(0))},
            "probe_sha256": BENCH.digest(probe),
            "capture_path": str(temporary),
            "operation_rss_sampling": args.sample_memory,
            "setup_boot_shutdown_rss_sampling": args.sample_memory,
            "process_completion_observation": "20 ms RSS polling" if args.sample_memory else "Linux pidfd/select readiness; includes CLI and host scheduling overhead",
            "performance_measurements": args.profile_download is None and not args.sample_memory,
            "network_enabled": not args.local_only,
            "workload": {"tcp_mib": args.tcp_mib, "udp_datagrams": args.udp_datagrams, "udp_payload_bytes": UDP_PAYLOAD_BYTES, "latency_samples": args.latency_samples, "churn_samples": args.churn_samples, "idle_sample_seconds": args.idle_seconds},
            "measurement_limits": {"boot": "CLI launch to agent-ready response plus raw available stage records; host UTC and guest UTC/agent-monotonic clocks are separate, with no cross-domain subtraction", "first_connect": "first guest churn connection includes DNS, socket creation and connect; excludes boot and terra exec startup", "churn": "DNS, connect, 64-byte request/reply and close per connection; no warmup", "memory": "process-tree PSS snapshots at ready/idle; optional sampled RSS during traffic, not guest heap usage or allocation count", "context_switches": "all worker threads at operation/idle boundaries; unavailable if identities change", "irqs": "host-wide /proc/interrupts deltas, includes unrelated host activity", "unavailable_counters": ["allocations", "notifications"]},
            "runs": [],
        }
        if args.tcp_concurrency > 1:
            report["workload"]["tcp_concurrency"] = args.tcp_concurrency
        with Fixtures(max(8 if args.self_check else 1, args.tcp_concurrency)) as fixtures:
            if args.self_check:
                log_directory = Path(temporary) / "boot-logs"
                log_directory.mkdir()
                if collect_boot_stages(log_directory)["unavailable_stages"] != list(BOOT_STAGES):
                    raise RuntimeError("missing baseline stages were not marked unavailable")
                (log_directory / "terra.log").write_text("INFO terra boot_stage=vm_entry unix_time_ns=200\n")
                (log_directory / "launcher.log").write_text("terra boot_stage=supervisor_start unix_time_ns=100\n")
                (log_directory / "diagnostics.log").write_text("agent received boot planterra boot_stage=networking_ready unix_time_ns=400 agent_elapsed_ns=50\n")
                stages = collect_boot_stages(log_directory)
                if len(stages["records"]["host_utc"]) != 2 or stages["records"]["host_utc"][0]["source"] != "launcher.log" or stages["records"]["guest_utc_and_agent_monotonic"][0]["agent_elapsed_ns"] != 50 or "hooks_start" not in stages["unavailable_stages"]:
                    raise RuntimeError("boot stage extraction mixed clock domains or missing stages")
                before_cpu = {(10, "1"): ("vm", 100)}
                after_cpu = {(10, "1"): ("vm", 120)}
                if worker_cpu_seconds(before_cpu, after_cpu) != {"vm": 20 / os.sysconf("SC_CLK_TCK")}:
                    raise RuntimeError("worker CPU delta accounting changed")
                for invalid_cpu in ({(10, "2"): ("vm", 120)}, {(10, "1"): ("vm", 99)}, {}):
                    try:
                        worker_cpu_seconds(before_cpu, invalid_cpu)
                    except RuntimeError:
                        pass
                    else:
                        raise RuntimeError("worker CPU accounting accepted changed or missing identities")
                current_process = [{"pid": os.getpid(), "role": "harness"}]
                pss = snapshot_process_tree_pss(current_process)
                if pss["pss_kib"] is None or pss["pss_kib"] <= 0:
                    raise RuntimeError(f"process-tree PSS self-check failed: {pss}")
                switches = snapshot_worker_context_switches(current_process)
                stable = worker_context_switch_deltas(switches, switches)
                if stable.get("by_role", {}).get("harness") != {"voluntary": 0, "involuntary": 0}:
                    raise RuntimeError(f"worker context-switch accounting changed: {stable}")
                if "unavailable" not in worker_context_switch_deltas(switches, {"threads": [], "read_errors": []}):
                    raise RuntimeError("worker context-switch accounting accepted missing threads")
                irqs = {"cpu_columns": [0], "counts": {"LOC": 10}}
                if host_irq_deltas(irqs, {"cpu_columns": [0], "counts": {"LOC": 12}}).get("total") != 2 or "unavailable" not in host_irq_deltas(irqs, {"unavailable": "masked"}):
                    raise RuntimeError("host IRQ accounting mixed unavailable counters or scopes")
                report["counter_self_check"] = {"process_tree_pss": pss, "worker_context_switches": stable, "host_irqs": snapshot_host_irqs()}
                paired = []
                for run_number, (direct_rate, broker_rate) in enumerate(((100, 10), (100, 200), (1, 2))):
                    for launcher, rate in (("direct", direct_rate), ("bwrap", broker_rate)):
                        paired.append({"run": run_number, "launcher": launcher, "operations": [{"case": "tcp_download", "mib_per_second": rate}]})
                ratios = summarize_pairs(list(reversed(paired)))["tcp_download"]["mib_per_second"]
                if ratios["median_ratio"] != 2 or len(ratios["pairs"]) != 3:
                    raise RuntimeError("paired comparison did not match direct and broker by run")
                command = [sys.executable, "-c", "print('ready')"]
                checked = timed_network_command(command, os.environ, Path(temporary) / "command", 5)
                if checked["exit_code"] != 0 or checked["timed_out"] or checked["stdout"]["tail"].strip() != "ready":
                    raise RuntimeError("network command capture failed")
                failed = measure_box(Path("/bin/false"), probe, "direct", "retention-check", args, fixtures)
                retained = Path(failed["capture_path"])
                if "failure" not in failed or not all((retained / name).is_file() for name in ("result.json", "setup/stdout", "setup/stderr", "stop/stdout", "stop/stderr")) or Path(failed["runtime_path_alias"]).exists():
                    raise RuntimeError("failed run did not retain its capture or remove its short path alias")
                report["capture_retention_check"] = failed
                timeout_command = [sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)"]
                checked = timed_network_command(timeout_command, os.environ, Path(temporary) / "timeout", 0.1)
                if not checked["timed_out"] or checked["exit_code"] != -signal.SIGKILL:
                    raise RuntimeError("network command timeout did not kill its process group")
                for mode, port, count in [("upload", fixtures.tcp_port, 1024 * 1024), ("download", fixtures.tcp_port, 1024 * 1024), ("latency", fixtures.tcp_port, 20), ("udp", fixtures.udp_port, 20), ("udp-window", fixtures.udp_port, 64), ("churn", fixtures.tcp_port, 20), ("localhost", 0, 1024 * 1024)]:
                    result = timed_network_command([str(probe), mode, "127.0.0.1", str(port), str(count)], os.environ, Path(temporary) / mode, 30)
                    if result["exit_code"] != 0 or result["timed_out"]:
                        raise RuntimeError(f"native probe failed: {result}")
                    payload = json.loads(result["stdout"]["tail"])
                    expected = count * UDP_PAYLOAD_BYTES if mode in ("udp", "udp-window") else count
                    if payload.get("bytes", payload.get("samples")) != expected:
                        raise RuntimeError(f"native probe count changed: {payload}")
                    if mode == "churn" and not (payload["first_connect_us"] > 0 and payload["p95_us"] >= payload["p50_us"] > 0):
                        raise RuntimeError(f"native churn timing changed: {payload}")
                    if mode == "churn" and "close_seconds" in payload and not (
                        0 <= payload["close_seconds"] <= payload["seconds"]
                        and 0 <= payload["close_p50_us"] <= payload["close_p95_us"] <= payload["close_max_us"]
                    ):
                        raise RuntimeError(f"native close timing changed: {payload}")
                    report["runs"].append(payload | {"exec": result})
                for mode in ("upload", "download"):
                    count = 1024 * 1024
                    concurrency = max(8, args.tcp_concurrency)
                    result = timed_network_command([str(probe), mode, "127.0.0.1", str(fixtures.tcp_port), str(count), str(concurrency)], os.environ, Path(temporary) / f"{mode}-{concurrency}", 30)
                    if result["exit_code"] != 0 or result["timed_out"]:
                        raise RuntimeError(f"native concurrent probe failed: {result}")
                    payload = json.loads(result["stdout"]["tail"])
                    if payload["bytes"] != count * concurrency or payload["case"] != f"tcp_{mode}_concurrent_{concurrency}":
                        raise RuntimeError(f"concurrent TCP self-check count or case changed: {payload}")
                    report["runs"].append(payload | {"exec": result})
                if fixtures.errors or fixtures.udp_received != 20 + 64:
                    raise RuntimeError(f"network fixture self-check failed: {list(fixtures.errors)}")
                child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
                try:
                    identities = process_start_times({child.pid})
                    box_directory = Path(temporary) / "box"
                    box_directory.mkdir()
                    vm_identity = f"{child.pid} {identities[child.pid]}"
                    supervisor_pid = os.getpid()
                    supervisor_start = process_start_times({supervisor_pid})[supervisor_pid]
                    (box_directory / "terra.pid").write_text("1")
                    (box_directory / "host.pid").write_text(vm_identity)
                    (box_directory / "supervisor.pid").write_text(f"{supervisor_pid} {supervisor_start}")
                    pids = BENCH.read_box_process_pids(box_directory)
                    if pids != {"vm": child.pid, "box_root": supervisor_pid, "supervisor": supervisor_pid}:
                        raise RuntimeError("box lookup mixed host, guest, and supervisor identities")
                    roles = {process["role"] for process in BENCH.box_processes_at_ready(pids)}
                    if not {"vm", "supervisor"}.issubset(roles):
                        raise RuntimeError("box sampling omitted the VM or supervisor")
                    (box_directory / "supervisor.pid").write_text(f"{supervisor_pid} {int(supervisor_start) + 1}")
                    try:
                        BENCH.read_box_process_pids(box_directory)
                    except ValueError:
                        pass
                    else:
                        raise RuntimeError("box lookup accepted a stale supervisor identity")
                    (box_directory / "supervisor.pid").unlink()
                    (box_directory / "host.pid").unlink()
                    (box_directory / "terra.pid").write_text(vm_identity)
                    if BENCH.read_box_process_pids(box_directory) != {"vm": child.pid, "box_root": child.pid}:
                        raise RuntimeError("direct box lookup did not use the VM identity")
                    stale = {pid: str(int(started) + 1) for pid, started in identities.items()}
                    if terminate_remaining_processes(stale) or child.poll() is not None:
                        raise RuntimeError("cleanup accepted a stale process identity")
                    if not terminate_remaining_processes(identities) or child.wait(timeout=5) != -signal.SIGKILL:
                        raise RuntimeError("cleanup failed to terminate its tracked child")
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=5)
                report["self_check_passed"] = True
            else:
                binary = args.terra.resolve()
                report.update({"terra": str(binary), "terra_sha256": BENCH.digest(binary)})
                for run in range(args.runs):
                    for launcher in (("direct", "bwrap") if run % 2 == 0 else ("bwrap", "direct")):
                        result = measure_box(binary, probe, launcher, run, args, fixtures)
                        report["runs"].append(result)
                        if args.profile_download is None and not args.sample_memory:
                            report["summaries"] = summarize(report["runs"])
                            report["paired_comparisons"] = summarize_pairs(report["runs"])
                        args.output.write_text(json.dumps(report, indent=2) + "\n")
                        if "failure" in result:
                            raise RuntimeError(result["failure"])
        args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
