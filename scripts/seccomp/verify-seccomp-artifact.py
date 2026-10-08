#!/usr/bin/env python3
"""Verify one complete policy set against its exact release executable."""

import ctypes
import ctypes.util
import hashlib
import json
import re
import struct
import sys
import tarfile
import tempfile
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(path):
    hasher = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()


ROLES = ("supervisor", "vm", "network")
ARTIFACTS = {f"{role}.seccomp.{suffix}" for role in ROLES for suffix in ("json", "bpf")} | {"manifest.json"}


def verify_bpf(bpf, rules, target):
    require(8 <= len(bpf) <= 4096 * 8 and len(bpf) % 8 == 0, "BPF has invalid instruction sizing")
    architectures = {"x86_64-unknown-linux-musl": 0xc000003e,
                     "aarch64-unknown-linux-musl": 0xc00000b7}
    require(target in architectures, "unsupported policy target")
    library_name = ctypes.util.find_library("seccomp")
    require(library_name, "libseccomp is required to resolve policy syscall names")
    library = ctypes.CDLL(library_name)
    library.seccomp_syscall_resolve_name_arch.argtypes = [ctypes.c_uint32, ctypes.c_char_p]
    library.seccomp_syscall_resolve_name_arch.restype = ctypes.c_int
    architecture = architectures[target]
    numbers = set()
    requests = set()
    ioctl_number = None
    socket_number = None
    families = set()
    sendto_number = None
    prctl_number = None
    require(len({rule["syscall"] for rule in rules}) == len(rules), "policy repeats a syscall")
    for rule in rules:
        number = library.seccomp_syscall_resolve_name_arch(architecture, rule["syscall"].encode())
        require(number >= 0, f"unknown target syscall: {rule['syscall']}")
        numbers.add(number)
        if rule["syscall"] == "ioctl":
            ioctl_number = number
            require(all(type(request) is int and 0 <= request <= 0xffffffff
                        for request in rule["requests"]), "invalid ioctl request")
            requests = set(rule["requests"])
        else:
            require("requests" not in rule, "request restrictions only apply to ioctl")
        if "families" in rule:
            require(rule["syscall"] == "socket" and rule["families"] and
                    all(type(family) is int and 0 <= family <= 0xffffffff for family in rule["families"]),
                    "invalid socket family allowlist")
            socket_number = number
            families = set(rule["families"])
        if rule.get("connected_only", False):
            require(rule["syscall"] == "sendto" and rule["connected_only"] is True,
                    "connected-only restrictions apply to sendto")
            sendto_number = number
        if rule.get("preserve_parent_death", False):
            require(rule["syscall"] == "prctl" and rule["preserve_parent_death"] is True,
                    "parent-death restrictions apply to prctl")
            prctl_number = number
    ordinary_numbers = numbers - {ioctl_number, socket_number, sendto_number, prctl_number}
    instructions = list(struct.iter_unpack("<HBBI", bpf))
    fields = {0: 0, 4: 1, 24: 2, 28: 3, 16: 4, 20: 5, 48: 6, 52: 7, 56: 8, 60: 9}
    for index, (code, yes, no, value) in enumerate(instructions):
        require(code in (0x20, 0x54, 0x05, 0x15, 0x25, 0x35, 0x06), "unsupported BPF instruction")
        if code == 0x20:
            require(value in fields, "BPF loads an unsupported seccomp field")
        if code == 0x54:
            require(value in (0, 0xffffffff), "BPF uses an unsupported argument mask")
        if code == 0x06:
            require(value in (0x7fff0000, 0x80000000), "BPF returns an unexpected action")
        else:
            jumps = [value] if code == 0x05 else [yes, no] if code in (0x15, 0x25, 0x35) else [0]
            require(all(index + 1 + jump < len(instructions) for jump in jumps), "BPF jumps outside filter")

    pending = [(0, None, 0, ((0, 0xffffffff),) * 10)]
    visited = 0
    while pending:
        index, field, constant, ranges = pending.pop()
        visited += 1
        require(visited <= 100000, "BPF decision tree exceeds verification limit")
        code, yes, no, value = instructions[index]
        if code == 0x20:
            pending.append((index + 1, fields[value], 0, ranges))
        elif code == 0x54:
            pending.append((index + 1, None if value == 0 else field, 0 if value == 0 else constant, ranges))
        elif code == 0x05:
            pending.append((index + 1 + value, field, constant, ranges))
        elif code == 0x06:
            (nr_low, nr_high), (arch_low, arch_high), (request_low, request_high), _, (family_low, family_high), _, *peer_words = ranges
            has_ioctl = ioctl_number is not None and nr_low <= ioctl_number <= nr_high
            has_socket = socket_number is not None and nr_low <= socket_number <= nr_high
            has_sendto = sendto_number is not None and nr_low <= sendto_number <= nr_high
            has_prctl = prctl_number is not None and nr_low <= prctl_number <= nr_high
            request_count = sum(request_low <= request <= request_high for request in requests)
            family_count = sum(family_low <= family <= family_high for family in families)
            ordinary_count = sum(nr_low <= number <= nr_high for number in ordinary_numbers)
            allows_any = arch_low <= architecture <= arch_high and (
                ordinary_count or has_ioctl and request_count or has_socket and family_count
                or has_sendto and all(low == 0 for low, _ in peer_words)
                or has_prctl and (family_low, family_high) != (1, 1))
            allows_all = (arch_low == arch_high == architecture and
                           ordinary_count + has_ioctl + has_socket + has_sendto + has_prctl == nr_high - nr_low + 1 and
                           (not has_ioctl or request_count == request_high - request_low + 1) and
                           (not has_socket or family_count == family_high - family_low + 1) and
                           (not has_sendto or all(low == high == 0 for low, high in peer_words)) and
                           (not has_prctl or not family_low <= 1 <= family_high))
            require(allows_all if value == 0x7fff0000 else not allows_any,
                    "BPF behavior differs from policy (architecture, syscall, ioctl request, or socket family)")
        else:
            low, high = ranges[field] if field is not None else (constant, constant)
            boundaries = (value, value + 1) if code == 0x15 else (value + 1,) if code == 0x25 else (value,)
            cuts = sorted({low, high + 1, *(boundary for boundary in boundaries if low < boundary <= high)})
            for start, end in zip(cuts, cuts[1:]):
                matched = start == value if code == 0x15 else start > value if code == 0x25 else start >= value
                branch_ranges = list(ranges)
                if field is not None:
                    branch_ranges[field] = (start, end - 1)
                pending.append((index + 1 + (yes if matched else no), field, constant, tuple(branch_ranges)))


def verify(directory, binary, target, *, require_marker=True):
    names = sorted(ARTIFACTS)
    if require_marker:
        names.append(".validated")
    for name in names:
        require((directory / name).is_file(), f"missing {name}")
    manifest = json.loads((directory / "manifest.json").read_text())
    binary_hash = sha256(binary)
    require(isinstance(manifest["release_identity"], str) and
            re.fullmatch(r"[A-Za-z0-9.+_-]+", manifest["release_identity"]),
            "manifest has an invalid Terra build identity")
    require(manifest["policy_compiler"] == "seccompiler_0_5_0",
            "manifest must identify seccompiler 0.5.0")
    require(manifest["format_version"] == 1 and set(manifest["roles"]) == set(ROLES),
            "manifest must use bundle format 1 with all three roles")
    workloads = manifest["validation"]["workloads"]
    results = manifest["validation"]["workload_results"]
    traced = ["self_test.host_components"]
    excluded = manifest["trace_exclusions"]
    validation = manifest["validation"]
    require(validation["scope"] == "host_components" and
            validation["vm_validated"] is True,
            "release policy requires guest validation of the host-generated candidate; run terra self-test --generate-policy --validate-vm")
    require(traced == ["self_test.host_components"] and
            workloads == ["self_test.host_components", "self_test.built_in_guest"] and
            [entry["name"] for entry in excluded] == ["self_test.built_in_guest"] and
            all(entry["reason"] for entry in excluded) and excluded == manifest["trace_exclusions"],
            "artifact must trace host components and enforce the same policy against the complete built-in guest workload")
    require([result["name"] for result in manifest["trace_workload_results"]] == traced and
            all(result["passed"] is True for result in manifest["trace_workload_results"]),
            "traced workload results differ from policy coverage")
    require([result["name"] for result in results] == workloads and
            all(result["passed"] is True for result in results),
            "manifest workloads and successful enforced results differ")
    require(type(validation["traced_execs"]) is int and type(validation["traced_processes"]) is int and
            validation["traced_processes"] > 0 and validation["traced_execs"] > 0,
            "artifact lacks traced host-component execution evidence")
    require(manifest["supplement_version"] == 1, "unsupported supplement version")
    require(manifest["target"] == target and
            manifest["executable_sha256"] == binary_hash,
            "artifact identity or digest differs from executable")
    require(manifest["validation"]["passed"] is True and manifest["validation"]["workloads"] and
            manifest["validation"]["workload_results"] == results,
            "artifact lacks complete enforced validation")
    require(validation["negative_enforcement"] == ["vm_native_network", "broker_vm_grants"],
            "artifact lacks negative role enforcement checks")
    if require_marker:
        require((directory / ".validated").read_text().strip() == binary_hash, "validation marker differs")
    for role in ROLES:
        policy_path = directory / f"{role}.seccomp.json"
        policy = json.loads(policy_path.read_text())
        bpf = (directory / f"{role}.seccomp.bpf").read_bytes()
        evidence = manifest["roles"][role]
        require(policy["format_version"] == 1 and policy["role"] == role and policy["target"] == target and
                policy["default_action"] == "kill_process" and policy["rules"], "invalid readable role policy")
        coverage = policy["workload_coverage"]
        require(coverage == evidence["coverage"] and coverage["scope"] == "host_components" and
                coverage["traced"] == traced and coverage["enforced_only"] == excluded,
                "role coverage differs from validation evidence")
        require(type(evidence["verified_execs"]) is int and evidence["verified_execs"] > 0,
                "role lacks verified execution coverage")
        require(policy["supplement_version"] == evidence["supplement_version"] == manifest["supplement_version"],
                "role supplement versions differ")
        ioctls = [entry for entry in policy["rules"] if entry["syscall"] == "ioctl"]
        require(len(ioctls) <= 1 and all(entry["requests"] for entry in ioctls), "ioctl requires an allowlist")
        sockets = [entry for entry in policy["rules"] if entry["syscall"] == "socket"]
        require(role != "vm" or all(entry.get("families") == [1] for entry in sockets),
                "VM policy must restrict socket creation to AF_UNIX")
        require(role != "network" or all(entry.get("families") == [2, 10] for entry in sockets),
                "network policy must restrict socket creation to AF_INET and AF_INET6")
        worker_denials = {"setsid", "setpgid", "io_uring_setup", "io_uring_enter", "io_uring_register"}
        if role == "vm":
            worker_denials |= {"connect", "sendmsg", "sendmmsg"}
        require(role == "supervisor" or all(entry["syscall"] not in worker_denials for entry in policy["rules"]),
                "worker policy permits a confinement bypass")
        for entry in policy["rules"]:
            require(role != "vm" or entry["syscall"] != "sendto" or entry.get("connected_only") is True,
                    "VM sendto must reject addressed datagrams")
            require(role == "supervisor" or entry["syscall"] != "prctl" or entry.get("preserve_parent_death") is True,
                    "worker prctl must preserve its parent-death signal")
        require(evidence["policy_sha256"] == sha256(policy_path) and evidence["bpf_sha256"] == hashlib.sha256(bpf).hexdigest(),
                "role policy digest differs from manifest")
        verify_bpf(bpf, policy["rules"], target)


def verify_archive(archive, binary, target):
    names = ARTIFACTS
    with tarfile.open(archive, "r:gz") as source, tempfile.TemporaryDirectory(prefix="terra-policy-verify-") as temporary:
        members = source.getmembers()
        require(len(members) == len(names) and {member.name for member in members} == names,
                "policy archive must contain exactly the seven role bundle artifacts")
        directory = Path(temporary)
        for member in members:
            require(member.isfile() and 0 < member.size <= 8 * 1024 * 1024, "invalid policy archive member")
            with source.extractfile(member) as content:
                (directory / member.name).write_bytes(content.read())
        verify(directory, binary, target, require_marker=False)


if __name__ == "__main__":
    try:
        archive_mode = len(sys.argv) > 1 and sys.argv[1] == "--archive"
        arguments = sys.argv[2:] if archive_mode else sys.argv[1:]
        require(len(arguments) == 3, "usage: verify-seccomp-artifact.py [--archive] <policy-dir-or-archive> <terra-bin> <target>")
        check = verify_archive if archive_mode else verify
        check(Path(arguments[0]), Path(arguments[1]).resolve(), arguments[2])
        print(f"verified seccomp artifact set: {arguments[0]}")
    except (ValueError, OSError, KeyError, tarfile.TarError) as error:
        print(f"seccomp artifact verification failed: {error}", file=sys.stderr)
        sys.exit(1)
