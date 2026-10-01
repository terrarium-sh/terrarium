#!/usr/bin/env python3
"""Generate a native, workload-tested Bubblewrap policy for one release binary."""

import argparse
import ctypes
import ctypes.util
import difflib
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
TARGETS = {"x86_64": ("x86_64-unknown-linux-musl", 62), "aarch64": ("aarch64-unknown-linux-musl", 183)}
SYSCALL = re.compile(r"^([a-zA-Z_][a-zA-Z_0-9]*)\(")
FORK = re.compile(r"^(?:clone|clone3|fork|vfork)\(.*\)\s+=\s+(\d+)\b")
RESUMED_FORK = re.compile(r"^<\.\.\. (?:clone|clone3|fork|vfork) resumed>.*\)\s+=\s+(\d+)\b")
IOCTL = re.compile(r"^ioctl\([^,]+,\s*(0x[0-9a-fA-F]+|[0-9]+)(?=\s*(?:[,)]|<unfinished))")
VM_EXEC = re.compile(r'^execve\("([^"]+)",\s*\[[^\n]*?"__vm"')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(command, *, env=None, timeout=30, output=None):
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=timeout, check=False)
    if output:
        output.write_text(result.stdout)
    require(result.returncode == 0, f"{' '.join(map(str, command))} exited {result.returncode}; see {output or result.stdout[-1000:]}")
    return result.stdout.strip()


def tagged_processes(token):
    marker = f"TERRA_SECCOMP_RUN_ID={token}".encode()
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            if marker in (entry / "environ").read_bytes().split(b"\0"):
                found.append(int(entry.name))
        except OSError:
            continue
    return found


def stop_tagged_processes(token):
    for process_signal in (signal.SIGTERM, signal.SIGKILL):
        found = tagged_processes(token)
        if not found:
            return
        for pid in found:
            try:
                os.kill(pid, process_signal)
            except ProcessLookupError:
                pass
        time.sleep(0.2)
    require(not tagged_processes(token), "timed-out workload left tagged VM processes running")


def run_workload_command(command, env, timeout, log, token):
    process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, start_new_session=True)
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        output, _ = process.communicate()
        log.write_bytes(output + b"\nTIMEOUT\n")
        stop_tagged_processes(token)
        raise RuntimeError(f"workload timed out after {timeout}s; see {log}")
    log.write_bytes(output)
    if process.returncode:
        stop_tagged_processes(token)
        raise RuntimeError(f"workload exited {process.returncode}; see {log}")
    return output.decode(errors="replace")


def check_host(binary, target):
    require(sys.platform == "linux", "seccomp generation needs native Linux")
    arch = platform.machine()
    require(arch in TARGETS, f"unsupported native architecture: {arch}")
    expected_target, machine = TARGETS[arch]
    require(target == expected_target, f"target {target} does not match native host {expected_target}")
    with binary.open("rb") as file:
        header = file.read(20)
    require(header[:6] == b"\x7fELF\x02\x01" and len(header) == 20, "TERRA_BIN must be a native 64-bit little-endian ELF executable")
    require(struct.unpack_from("<H", header, 18)[0] == machine, "TERRA_BIN ELF architecture does not match target")
    require(os.access(binary, os.X_OK), f"TERRA_BIN is not executable: {binary}")
    require(Path("/dev/kvm").is_char_device(), "native /dev/kvm is unavailable; no policy generated")
    try:
        fd = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC)
        os.close(fd)
    except OSError as error:
        raise RuntimeError(f"/dev/kvm is not usable: {error}") from error
    for tool in ("strace", "cargo"):
        require(shutil.which(tool), f"{tool} is required for seccomp generation")
    require(run([str(binary), "__bwrap", "--version"]).startswith("bubblewrap "),
            "TERRA_BIN must contain Bubblewrap")
    require(ctypes.util.find_library("seccomp"), "libseccomp is required for build-only BPF compilation")
    with tempfile.TemporaryDirectory(prefix="terra-strace-probe-") as directory:
        trace = Path(directory) / "execve"
        marker = "terra-harmless-env-probe"
        run(["strace", "-v", "-e", "abbrev=execve,execveat", "-o", str(trace),
             "/bin/true", "__vm"], env={"PATH": os.environ.get("PATH", ""), "PROBE_SECRET": marker}, timeout=10)
        trace_text = trace.read_text()
        require(marker not in trace_text and '"__vm"' in trace_text,
                "strace must preserve VM argv and omit environment values from diagnostics")


def load_inventory(target):
    inventory = json.loads((ROOT / "scripts/seccomp-workloads.json").read_text())
    require(inventory["version"] == 1 and inventory["workloads"], "invalid seccomp workload inventory")
    seen = set()
    for workload in inventory["workloads"]:
        key = (workload["suite"], workload["test"])
        require(key not in seen and workload["suite"] in ("boot", "native_boot", "lib") and workload["timeout_seconds"] > 0,
                f"invalid workload {key}")
        seen.add(key)
    inventory["workloads"] = [workload for workload in inventory["workloads"]
                              if target in workload.get("targets", [target])]
    require(inventory["workloads"], "no seccomp workloads apply to target")
    require(any(not workload.get("trace_exclusion_reason") for workload in inventory["workloads"]),
            "no seccomp workloads remain for native tracing")
    return inventory


def write_executable(path, content):
    path.write_text(content)
    path.chmod(0o700)


def make_test_wrapper(stage, binary):
    wrapper = stage / "terra-test-wrapper"
    write_executable(wrapper, "#!/usr/bin/env python3\n"
                     "import os, pathlib, tempfile\n"
                     "home = pathlib.Path(os.environ['HOME'])\n"
                     "config = home / '.terra' / 'config.yaml'\n"
                     "config.parent.mkdir(parents=True, exist_ok=True)\n"
                     "with tempfile.NamedTemporaryFile(dir=config.parent, delete=False) as staged:\n"
                     "    staged.write(pathlib.Path(os.environ['TERRA_SECCOMP_TEST_CONFIG']).read_bytes())\n"
                     "os.replace(staged.name, config)\n"
                     f"os.execv({str(binary)!r}, [{str(binary)!r}, *os.sys.argv[1:]])\n")
    return wrapper


def make_trace_launcher(stage, trace_dir):
    launcher = stage / "trace-vm"
    write_executable(launcher, "#!/usr/bin/env python3\n"
                     "import os, pathlib, sys, time\n"
                     "args = sys.argv[sys.argv.index('--') + 1:]\n"
                     f"directory = pathlib.Path({str(trace_dir)!r})\n"
                     "pid = os.getpid()\n"
                     "prefix = directory / f'vm-{pid}-{time.time_ns()}'\n"
                     "(directory / f'active-{pid}').write_text(str(prefix))\n"
                     "os.execvp('strace', ['strace', '-D', '-ff', '-v', '-e', 'abbrev=execve,execveat', '-X', 'raw', '-s', '4096', '-o', str(prefix), '--', *args])\n")
    return launcher


def write_config(stage, mode, launcher=None, bpf=None):
    config = stage / f"{mode}-config.yaml"
    if mode == "trace":
        config.write_text("vm:\n  init: " + json.dumps(str(launcher)) + "\n")
    else:
        config.write_text("vm:\n  bwrap:\n    policy: " + json.dumps(str(bpf)) + "\n")
    return config


def wait_for_tracers(trace_dir, token):
    deadline = time.monotonic() + 30
    for marker in trace_dir.glob("active-*"):
        pid = int(marker.name.split("-")[1])
        while Path(f"/proc/{pid}").exists():
            require(time.monotonic() < deadline, f"VM trace process {pid} did not finish after workload teardown")
            time.sleep(0.1)
        marker.unlink()
    while tagged_processes(token):
        require(time.monotonic() < deadline, "strace did not finish after workload teardown")
        time.sleep(0.1)


def run_workloads(inventory, wrapper, config, diagnostic_dir, mode, binary, trace_dir=None, harness_dir=None):
    results = []
    for workload in inventory["workloads"]:
        if mode == "trace" and workload.get("trace_exclusion_reason"):
            continue
        name = f"{workload['suite']}.{workload['test']}"
        print(f"{mode}: {name}", flush=True)
        log = diagnostic_dir / f"{mode}-{name}.log"
        env = os.environ.copy()
        token = os.urandom(16).hex()
        env["TERRA_SECCOMP_RUN_ID"] = token
        env["TERRA_BIN"] = str(wrapper)
        env["TERRA_SECCOMP_TEST_CONFIG"] = str(config)
        if mode == "enforced":
            env["TERRA_SECCOMP_ENFORCED"] = "1"
        else:
            env.pop("TERRA_SECCOMP_ENFORCED", None)
        env["TERRA_TEST_ASSETS"] = str(ROOT / "crates/terra/tests/assets")
        temp = Path(tempfile.mkdtemp(prefix="ts-", dir="/tmp"))
        env["TMPDIR"] = str(temp)
        trace_files_before = set(trace_dir.glob("vm-*.*")) if trace_dir else set()
        if harness_dir:
            harness_name = "terra_lib" if workload["suite"] == "lib" else workload["suite"]
            command = [str(harness_dir / harness_name), workload["test"], "--exact", "--ignored",
                       "--nocapture", "--test-threads=1"]
        else:
            suite_option = ["--lib"] if workload["suite"] == "lib" else ["--test", workload["suite"]]
            command = ["cargo", "test", "--locked", "-p", "terra", *suite_option,
                       workload["test"], "--", "--exact", "--ignored", "--nocapture", "--test-threads=1"]
        started = time.monotonic()
        try:
            text = run_workload_command(command, env, workload["timeout_seconds"], log, token)
            require(re.search(r"(?m)^test result: ok\. 1 passed; 0 failed; 0 ignored;", text),
                    f"workload {name} did not execute exactly one ignored test; see {log}")
            if trace_dir:
                wait_for_tracers(trace_dir, token)
                new_traces = set(trace_dir.glob("vm-*.*")) - trace_files_before
                require(new_traces, f"workload {name} launched no traced VM; see {log}")
                _, _, vm_count, _ = parse_traces(new_traces, binary)
                require(vm_count > 0, f"workload {name} launched no exact traced Terra VM; see {log}")
            require(not tagged_processes(token), f"workload {name} left a VM running")
            shutil.rmtree(temp)
            results.append({"name": name, "passed": True, "seconds": round(time.monotonic() - started, 2)})
            print(f"{mode}: {name} passed", flush=True)
        except RuntimeError as error:
            stop_tagged_processes(token)
            results.append({"name": name, "passed": False, "error": str(error), "seconds": round(time.monotonic() - started, 2)})
            (diagnostic_dir / f"{mode}-results.json").write_text(json.dumps(results, indent=2) + "\n")
            raise RuntimeError(f"{mode} workload {name} failed; see {log}; isolated test files: {temp}") from error
        (diagnostic_dir / f"{mode}-results.json").write_text(json.dumps(results, indent=2) + "\n")
    return results


def parse_traces(files, binary):
    files = sorted(path for path in files if re.search(r"\.\d+$", path.name))
    require(files, "no VM traces were captured")
    groups = {}
    for path in files:
        prefix, pid = path.name.rsplit(".", 1)
        groups.setdefault(prefix, {})[int(pid)] = path.read_text(errors="replace").splitlines()
    calls = {}
    ioctls = {}
    vm_count = 0
    process_count = 0
    for prefix, traces in groups.items():
        group_calls, group_ioctls, group_vms, group_processes = parse_trace_group(traces, binary)
        vm_count += group_vms
        process_count += group_processes
        for name, pids in group_calls.items():
            calls.setdefault(name, set()).update((prefix, pid) for pid in pids)
        for request, pids in group_ioctls.items():
            ioctls.setdefault(request, set()).update((prefix, pid) for pid in pids)
    require(vm_count > 0, "no exact `terra __vm` exec was found")
    require(calls and ioctls, "VM traces contained no normalized syscalls or ioctl requests")
    return calls, ioctls, vm_count, process_count


def parse_trace_group(traces, binary):
    parents = {}
    vm_start = {}
    for pid, lines in traces.items():
        for index, line in enumerate(lines):
            vm_exec = VM_EXEC.search(line)
            if vm_exec and vm_exec.group(1) == str(binary) and re.search(r"\)\s+=\s+0\b", line):
                vm_start[pid] = index
            child = FORK.match(line) or RESUMED_FORK.match(line)
            if child:
                parents[int(child.group(1))] = (pid, index)
    selected = {}
    for pid in traces:
        current = pid
        while current in parents and current not in vm_start:
            parent, fork_index = parents[current]
            if parent in vm_start and fork_index < vm_start[parent]:
                break
            current = parent
        if current in vm_start:
            selected[pid] = vm_start[pid] if pid == current else 0
    calls = {}
    ioctls = {}
    for pid, start in selected.items():
        for line in traces[pid][start:]:
            match = SYSCALL.match(line)
            if not match:
                continue
            name = match.group(1)
            calls.setdefault(name, set()).add(pid)
            if name == "ioctl":
                request = IOCTL.match(line)
                require(request, f"unrecognized ioctl request in VM trace {pid}: {line[:200]}")
                ioctls.setdefault(int(request.group(1), 0) & 0xffffffff, set()).add(pid)
    return calls, ioctls, len(vm_start), len(selected)


class ArgCmp(ctypes.Structure):
    _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_uint),
                ("datum_a", ctypes.c_uint64), ("datum_b", ctypes.c_uint64)]


class SeccompVersion(ctypes.Structure):
    _fields_ = [("major", ctypes.c_uint), ("minor", ctypes.c_uint), ("micro", ctypes.c_uint)]


def compile_bpf(rules, target, path):
    library = ctypes.CDLL(ctypes.util.find_library("seccomp"), use_errno=True)
    library.seccomp_arch_native.restype = ctypes.c_uint32
    library.seccomp_arch_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_arch_resolve_name.restype = ctypes.c_uint32
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_release.argtypes = [ctypes.c_void_p]
    library.seccomp_arch_exist.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    library.seccomp_arch_exist.restype = ctypes.c_int
    library.seccomp_attr_set.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32]
    library.seccomp_attr_set.restype = ctypes.c_int
    library.seccomp_attr_get.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_uint32)]
    library.seccomp_attr_get.restype = ctypes.c_int
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_syscall_resolve_name.restype = ctypes.c_int
    library.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
                                                ctypes.c_uint, ctypes.POINTER(ArgCmp)]
    library.seccomp_rule_add_array.restype = ctypes.c_int
    library.seccomp_export_bpf.argtypes = [ctypes.c_void_p, ctypes.c_int]
    library.seccomp_export_bpf.restype = ctypes.c_int
    library.seccomp_version.restype = ctypes.POINTER(SeccompVersion)
    native = library.seccomp_arch_native()
    expected = library.seccomp_arch_resolve_name(target.split("-", 1)[0].encode())
    require(native == expected, "libseccomp native ABI differs from policy target")
    context = library.seccomp_init(0x80000000)
    require(context, "libseccomp could not initialize a kill-process default filter")
    try:
        require(library.seccomp_attr_set(context, 2, 0x80000000) == 0,
                "libseccomp could not set kill-process behavior for wrong ABI")
        bad_arch_action = ctypes.c_uint32()
        require(library.seccomp_attr_get(context, 2, ctypes.byref(bad_arch_action)) == 0 and
                bad_arch_action.value == 0x80000000,
                "wrong ABI action is not kill-process")
        if target.startswith("x86_64"):
            x32 = library.seccomp_arch_resolve_name(b"x32")
            require(library.seccomp_arch_exist(context, x32) != 0, "x32 ABI unexpectedly enabled")
        for rule in rules:
            number = library.seccomp_syscall_resolve_name(rule["syscall"].encode())
            require(number >= 0, f"libseccomp does not know syscall {rule['syscall']}")
            if rule["syscall"] == "ioctl":
                for request in rule["requests"]:
                    comparison = ArgCmp(1, 7, 0xffffffff, request)
                    status = library.seccomp_rule_add_array(context, 0x7fff0000, number, 1, ctypes.byref(comparison))
                    require(status == 0, f"libseccomp rejected ioctl request {request:#x}: {status}")
            else:
                status = library.seccomp_rule_add_array(context, 0x7fff0000, number, 0, None)
                require(status == 0, f"libseccomp rejected {rule['syscall']}: {status}")
        with path.open("wb") as output:
            require(library.seccomp_export_bpf(context, output.fileno()) == 0, "libseccomp failed to export BPF")
    finally:
        library.seccomp_release(context)
    size = path.stat().st_size
    require(size >= 8 and size % 8 == 0, "libseccomp exported empty or malformed classic BPF")
    version = library.seccomp_version().contents
    return f"{version.major}.{version.minor}.{version.micro}"


def build_policy(calls, ioctls, target, inventory):
    supplement = json.loads((ROOT / "scripts/seccomp-supplements.json").read_text())
    require(supplement["version"] == 2, "unsupported seccomp supplement version")
    extra = {}
    for rule in supplement["rules"]:
        require(rule["reason"] and rule["source"] and rule["targets"], "supplement lacks review provenance")
        if target in rule["targets"]:
            extra[rule["syscall"]] = {"reason": rule["reason"], "source": rule["source"]}
    names = sorted(set(calls) | set(extra))
    rules = []
    for name in names:
        rule = {"syscall": name, "provenance": []}
        if name in calls:
            rule["provenance"].append({"kind": "observed", "vm_processes": len(calls[name])})
        if name in extra:
            rule["provenance"].append({"kind": "supplement", **extra[name]})
        if name == "ioctl":
            rule["requests"] = sorted(ioctls)
        rules.append(rule)
    return {"format_version": 1, "target": target, "default_action": "kill_process",
            "supplement_version": supplement["version"], "rules": rules,
            "workload_coverage": {
                "traced": [f"{workload['suite']}.{workload['test']}" for workload in inventory["workloads"]
                           if not workload.get("trace_exclusion_reason")],
                "enforced_only": [{"name": f"{workload['suite']}.{workload['test']}",
                                   "reason": workload["trace_exclusion_reason"]}
                                  for workload in inventory["workloads"]
                                  if workload.get("trace_exclusion_reason")],
            }}


def stable_policy(policy):
    clean = json.loads(json.dumps(policy))
    for rule in clean["rules"]:
        for source in rule["provenance"]:
            source.pop("vm_processes", None)
    return json.dumps(clean, indent=2, sort_keys=True) + "\n"


def publish(stage, output):
    output.parent.mkdir(parents=True, exist_ok=True)
    require(not output.exists() or output.is_symlink(), f"output path must be a generator-owned symlink: {output}")
    generation = output.parent / f".{output.name}-{time.time_ns()}"
    shutil.move(str(stage), generation)
    pointer = output.parent / f".{output.name}-current-{os.getpid()}"
    pointer.symlink_to(generation.name, target_is_directory=True)
    os.replace(pointer, output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--diagnostics", required=True, type=Path)
    parser.add_argument("--harness-dir", type=Path, default=os.environ.get("SECCOMP_HARNESS_DIR"))
    arguments = parser.parse_args()
    binary = arguments.bin.resolve(strict=True)
    output = arguments.output.absolute()
    check_host(binary, arguments.target)
    inventory = load_inventory(arguments.target)
    harness_dir = arguments.harness_dir.resolve(strict=True) if arguments.harness_dir else None
    if harness_dir:
        for suite in {workload["suite"] for workload in inventory["workloads"]}:
            harness = harness_dir / ("terra_lib" if suite == "lib" else suite)
            require(harness.is_file() and os.access(harness, os.X_OK), f"missing executable test harness: {harness}")
    version_output = run([str(binary), "--version"]).strip()
    require(version_output.startswith("terra "), "could not read Terra release identity")
    release_identity = version_output.removeprefix("terra ")
    require(re.fullmatch(r"[A-Za-z0-9.+_-]+", release_identity), "could not read exact Terra release identity")
    binary_hash = digest(binary.read_bytes())
    diagnostics = arguments.diagnostics.absolute() / f"{arguments.target}-{time.time_ns()}"
    diagnostics.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="terra-seccomp-") as temporary:
        work = Path(temporary)
        trace_dir = diagnostics / "traces"
        trace_dir.mkdir()
        launcher = make_trace_launcher(work, trace_dir)
        wrapper = make_test_wrapper(work, binary)
        trace_config = write_config(work, "trace", launcher=launcher)
        trace_results = run_workloads(inventory, wrapper, trace_config, diagnostics, "trace", binary, trace_dir, harness_dir)
        calls, ioctls, vm_count, process_count = parse_traces(trace_dir.iterdir(), binary)
        require(vm_count >= len(trace_results), "some traced workloads produced no VM launch")
        policy = build_policy(calls, ioctls, arguments.target, inventory)
        staged = work / "validated"
        staged.mkdir()
        policy_file = staged / "terra.seccomp.json"
        policy_file.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n")
        bpf_file = staged / "terra.seccomp.bpf"
        libseccomp_version = compile_bpf(policy["rules"], arguments.target, bpf_file)
        bpf = bpf_file.read_bytes()
        previous = (output / "terra.seccomp.json") if output.exists() else None
        before = stable_policy(json.loads(previous.read_text())).splitlines(True) if previous and previous.exists() else []
        after = stable_policy(policy).splitlines(True)
        (diagnostics / "policy.diff").write_text("".join(difflib.unified_diff(before, after, fromfile="previous", tofile="proposed")))
        validation = {"passed": True, "workloads": [entry["name"] for entry in trace_results],
                      "kernel": platform.release(), "bubblewrap": run([str(binary), "__bwrap", "--version"]),
                      "strace": run(["strace", "--version"]).splitlines()[0],
                      "libseccomp": libseccomp_version, "generator_python": platform.python_version(),
                      "vm_execs": vm_count, "vm_processes": process_count,
                      "workload_results": trace_results}
        enforced_config = write_config(work, "enforced", bpf=bpf_file)
        enforced_results = run_workloads(inventory, wrapper, enforced_config, diagnostics, "enforced", binary, harness_dir=harness_dir)
        validation["workloads"] = [entry["name"] for entry in enforced_results]
        validation["workload_results"] = enforced_results
        manifest = {"format_version": 1, "release_identity": release_identity, "target": arguments.target,
                    "executable_sha256": binary_hash, "policy_sha256": digest(policy_file.read_bytes()),
                    "bpf_sha256": digest(bpf),
                    "validation": validation, "supplement_version": policy["supplement_version"],
                    "trace_workload_results": trace_results,
                    "trace_exclusions": policy["workload_coverage"]["enforced_only"]}
        if harness_dir:
            manifest["harness_sha256"] = {suite: digest((harness_dir / ("terra_lib" if suite == "lib" else suite)).read_bytes())
                                          for suite in sorted({workload["suite"] for workload in inventory["workloads"]})}
        (staged / "terra.seccomp-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        (staged / ".validated").write_text(binary_hash + "\n")
        publish(staged, output)
    print(f"validated seccomp artifacts: {output}")
    print(f"diagnostics: {diagnostics}")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        print(f"seccomp generation failed: {error}", file=sys.stderr)
        sys.exit(1)
