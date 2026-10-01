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
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
    ordinary_numbers = numbers - {ioctl_number}
    instructions = list(struct.iter_unpack("<HBBI", bpf))
    fields = {0: 0, 4: 1, 24: 2, 28: 3}
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

    pending = [(0, None, 0, ((0, 0xffffffff),) * 4)]
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
            (nr_low, nr_high), (arch_low, arch_high), (request_low, request_high), _ = ranges
            has_ioctl = ioctl_number is not None and nr_low <= ioctl_number <= nr_high
            request_count = sum(request_low <= request <= request_high for request in requests)
            ordinary_count = sum(nr_low <= number <= nr_high for number in ordinary_numbers)
            allows_any = arch_low <= architecture <= arch_high and (ordinary_count or has_ioctl and request_count)
            allows_all = (arch_low == arch_high == architecture and
                          ordinary_count + has_ioctl == nr_high - nr_low + 1 and
                          (not has_ioctl or request_count == request_high - request_low + 1))
            require(allows_all if value == 0x7fff0000 else not allows_any,
                    "BPF behavior differs from policy (architecture, syscall, or ioctl request)")
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
    names = ["terra.seccomp.json", "terra.seccomp.bpf", "terra.seccomp-manifest.json"]
    if require_marker:
        names.append(".validated")
    for name in names:
        require((directory / name).is_file(), f"missing {name}")
    policy = json.loads((directory / names[0]).read_text())
    bpf = (directory / names[1]).read_bytes()
    manifest = json.loads((directory / names[2]).read_text())
    binary_hash = sha256(binary)
    bpf_hash = hashlib.sha256(bpf).hexdigest()
    require(isinstance(manifest["release_identity"], str) and
            re.fullmatch(r"[A-Za-z0-9.+_-]+", manifest["release_identity"]),
            "manifest has an invalid Terra build identity")
    require(policy["format_version"] == manifest["format_version"] == 1,
            "policy and manifest must use format version 1")
    require(policy["target"] == target and policy["default_action"] == "kill_process" and policy["rules"],
            "readable policy has wrong target or empty/unsafe rules")
    ioctls = [rule for rule in policy["rules"] if rule["syscall"] == "ioctl"]
    require(len(ioctls) == 1 and ioctls[0]["requests"], "ioctl must have a nonempty request allowlist")
    workloads = manifest["validation"]["workloads"]
    results = manifest["validation"]["workload_results"]
    traced = policy["workload_coverage"]["traced"]
    excluded = policy["workload_coverage"]["enforced_only"]
    inventory = json.loads(Path(__file__).with_name("seccomp-workloads.json").read_text())
    required = [workload for workload in inventory["workloads"] if target in workload.get("targets", [target])]
    required_names = [f"{workload['suite']}.{workload['test']}" for workload in required]
    required_traced = [f"{workload['suite']}.{workload['test']}" for workload in required
                       if not workload.get("trace_exclusion_reason")]
    required_excluded = [{"name": f"{workload['suite']}.{workload['test']}",
                          "reason": workload["trace_exclusion_reason"]} for workload in required
                         if workload.get("trace_exclusion_reason")]
    require(workloads == required_names and traced == required_traced and excluded == required_excluded,
            "artifact coverage differs from the required workload inventory")
    require(traced and [result["name"] for result in manifest["trace_workload_results"]] == traced and
            all(result["passed"] is True for result in manifest["trace_workload_results"]),
            "traced workload results differ from policy coverage")
    require(excluded == manifest["trace_exclusions"] and
            all(entry["name"] and entry["reason"] for entry in excluded) and
            len({entry["name"] for entry in excluded}) == len(excluded),
            "trace exclusions lack explicit reasons or differ from manifest")
    require(len(traced) == len(set(traced)) and
            set(traced).isdisjoint({entry["name"] for entry in excluded}),
            "traced and enforced-only workloads overlap or repeat")
    require(set(workloads) == set(traced) | {entry["name"] for entry in excluded},
            "enforced inventory does not cover every traced and explicitly excluded workload")
    require(len(workloads) == len(results) > 0 and len(workloads) == len(set(workloads)) and
            [result["name"] for result in results] == workloads and
            all(result["passed"] is True for result in results),
            "manifest workloads and successful enforced results differ")
    require(manifest["target"] == target and
            manifest["executable_sha256"] == binary_hash and manifest["bpf_sha256"] == bpf_hash,
            "artifact identity or digest differs from executable/BPF")
    require(manifest["validation"]["passed"] is True and manifest["validation"]["workloads"] and
            manifest["validation"]["workload_results"] == results,
            "artifact lacks complete enforced validation")
    require(manifest["policy_sha256"] == sha256(directory / names[0]), "manifest policy digest differs")
    if require_marker:
        require((directory / ".validated").read_text().strip() == binary_hash, "validation marker differs")
    verify_bpf(bpf, policy["rules"], target)


def verify_archive(archive, binary, target):
    names = {"terra.seccomp.json", "terra.seccomp.bpf", "terra.seccomp-manifest.json"}
    with tarfile.open(archive, "r:gz") as source, tempfile.TemporaryDirectory(prefix="terra-policy-verify-") as temporary:
        members = source.getmembers()
        require(len(members) == len(names) and {member.name for member in members} == names,
                "policy archive must contain exactly the three policy artifacts")
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
