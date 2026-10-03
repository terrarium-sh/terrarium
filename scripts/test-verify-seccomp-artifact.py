#!/usr/bin/env python3
"""Verify artifact schema, identity, archive boundaries, and BPF restrictions."""

import hashlib
import importlib.util
import json
import struct
import tarfile
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("verify-seccomp-artifact.py")
spec = importlib.util.spec_from_file_location("verify_seccomp_artifact", SCRIPT)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)

TARGETS = {"x86_64-unknown-linux-musl": (0xc000003e, 16, 39),
           "aarch64-unknown-linux-musl": (0xc00000b7, 29, 172)}


def synthetic_filter(target, *, extra_syscall=False):
    architecture, ioctl_number, getpid_number = TARGETS[target]
    instructions = [(0x20, 0, 0, 4), (0x15, 0, 5, architecture),
                    (0x20, 0, 0, 0), (0x15, 0, 3, ioctl_number),
                    (0x20, 0, 0, 24), (0x15, 0, 1, 1),
                    (0x06, 0, 0, 0x7fff0000), (0x06, 0, 0, 0x80000000)]
    if extra_syscall:
        instructions[1] = (0x15, 0, 6, architecture)
        instructions.insert(3, (0x15, 3, 0, getpid_number))
    return b"".join(struct.pack("<HBBI", *instruction) for instruction in instructions)


def verifier_test(directory, target):
    artifacts = directory / "artifacts"
    artifacts.mkdir()
    binary = directory / "terra"
    binary.write_bytes(b"release executable for another architecture")
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    bpf_file = artifacts / "terra.seccomp.bpf"
    rules = [{"syscall": "ioctl", "requests": [1]}]
    bpf = synthetic_filter(target)
    bpf_file.write_bytes(bpf)
    bpf_hash = hashlib.sha256(bpf).hexdigest()
    policy_file = artifacts / "terra.seccomp.json"
    guest_coverage = [{"name": "self_test.built_in_guest", "reason": "Guest enforcement preserves the host-generated policy."}]
    policy_file.write_text(json.dumps({"format_version": 1, "target": target,
                                       "default_action": "kill_process",
                                       "supplement_version": 3,
                                       "workload_coverage": {"scope": "host_components", "traced": ["self_test.host_components"],
                                                             "enforced_only": guest_coverage},
                                       "rules": rules}))
    validation = {"passed": True, "scope": "host_components", "vm_validated": True,
                  "workloads": ["self_test.host_components", "self_test.built_in_guest"],
                  "traced_execs": 1, "traced_processes": 1,
                  "workload_results": [{"name": "self_test.host_components", "passed": True},
                                       {"name": "self_test.built_in_guest", "passed": True}]}
    manifest = {"format_version": 1, "target": target, "release_identity": "1.0+abc",
                "policy_compiler": "seccompiler_0_5_0",
                "executable_sha256": binary_hash, "bpf_sha256": bpf_hash,
                "policy_sha256": hashlib.sha256(policy_file.read_bytes()).hexdigest(),
                "validation": validation,
                "trace_workload_results": [{"name": "self_test.host_components", "passed": True}],
                "trace_exclusions": guest_coverage, "supplement_version": 3}
    (artifacts / "terra.seccomp-manifest.json").write_text(json.dumps(manifest))
    (artifacts / ".validated").write_text(binary_hash + "\n")
    verifier.verify(artifacts, binary, target)

    for keys, value in [(("validation", "vm_validated"), False), (("validation", "scope"), "guest"),
                        (("validation", "traced_execs"), 0), (("supplement_version",), 2),
                        (("policy_compiler",), "libseccomp"), (("format_version",), 2),
                        (("release_identity",), "invalid identity"),
                        (("validation", "passed"), False), (("validation", "traced_processes"), 0),
                        (("trace_exclusions",), []),
                        (("trace_workload_results",), [{"name": "self_test.host_components", "passed": False}]),
                        (("validation", "workload_results"), [{"name": "self_test.host_components", "passed": True}])]:
        invalid_manifest = json.loads(json.dumps(manifest))
        field = invalid_manifest
        for key in keys[:-1]:
            field = field[key]
        field[keys[-1]] = value
        (artifacts / "terra.seccomp-manifest.json").write_text(json.dumps(invalid_manifest))
        try:
            verifier.verify(artifacts, binary, target)
        except ValueError:
            pass
        else:
            raise AssertionError(f"invalid validation evidence accepted: {keys}")
    (artifacts / "terra.seccomp-manifest.json").write_text(json.dumps(manifest))

    def reject_filter(raw, message):
        bpf_file.write_bytes(raw)
        manifest["bpf_sha256"] = hashlib.sha256(raw).hexdigest()
        (artifacts / "terra.seccomp-manifest.json").write_text(json.dumps(manifest))
        try:
            verifier.verify(artifacts, binary, target)
        except ValueError as error:
            assert "BPF" in str(error), error
        else:
            raise AssertionError(message)

    reject_filter(struct.pack("<HBBI", 0x06, 0, 0, 0x7fff0000), "allow-all artifact was accepted")
    reject_filter(struct.pack("<HBBI", 0x06, 0, 0, 0x80000000), "denied allowlisted ioctl was accepted")
    architecture = TARGETS[target][0]
    other_architecture = 0xc00000b7 if architecture == 0xc000003e else 0xc000003e
    reject_filter(bpf.replace(struct.pack("<I", architecture), struct.pack("<I", other_architecture), 1),
                  "artifact with wrong architecture was accepted")
    unrestricted = list(struct.iter_unpack("<HBBI", bpf))
    request_index = next(index + 1 for index, instruction in enumerate(unrestricted)
                         if instruction == (0x20, 0, 0, 24))
    code, yes, _, value = unrestricted[request_index]
    unrestricted[request_index] = (code, yes, yes, value)
    reject_filter(b"".join(struct.pack("<HBBI", *instruction) for instruction in unrestricted),
                  "artifact allowing unlisted ioctl requests was accepted")
    reject_filter(synthetic_filter(target, extra_syscall=True), "artifact allowing an unlisted syscall was accepted")
    reject_filter(struct.pack("<HBBI", 0xffff, 0, 0, 0), "unsupported BPF opcode was accepted")
    reject_filter(struct.pack("<HBBI", 0x05, 0, 0, 0xffffffff), "out-of-range BPF jump was accepted")
    bpf_file.write_bytes(bpf)
    manifest["bpf_sha256"] = bpf_hash
    (artifacts / "terra.seccomp-manifest.json").write_text(json.dumps(manifest))

    archive = directory / "policy.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        for name in ("terra.seccomp.json", "terra.seccomp.bpf", "terra.seccomp-manifest.json"):
            bundle.add(artifacts / name, arcname=name)
    verifier.verify_archive(archive, binary, target)
    with tarfile.open(archive, "w:gz") as bundle:
        for name in ("terra.seccomp.json", "terra.seccomp.bpf", "terra.seccomp-manifest.json"):
            bundle.add(artifacts / name, arcname=name)
        bundle.add(artifacts / "terra.seccomp.bpf", arcname="../outside.bpf")
    try:
        verifier.verify_archive(archive, binary, target)
    except ValueError:
        pass
    else:
        raise AssertionError("archive with unexpected members was accepted")
    binary.write_bytes(b"different release executable")
    try:
        verifier.verify(artifacts, binary, target)
    except ValueError:
        pass
    else:
        raise AssertionError("changed release executable was accepted")
    binary.write_bytes(b"release executable for another architecture")
    bpf_file.write_bytes(bpf + b"\0" * 8)
    try:
        verifier.verify(artifacts, binary, target)
    except ValueError:
        pass
    else:
        raise AssertionError("changed BPF was accepted")
    bpf_file.write_bytes(bpf)
    original_policy = policy_file.read_text()
    policy_file.write_text(original_policy + "\n")
    try:
        verifier.verify(artifacts, binary, target)
    except ValueError:
        pass
    else:
        raise AssertionError("changed readable policy was accepted")
    policy_file.write_text(original_policy)
    manifest["validation"]["workload_results"] = []
    (artifacts / "terra.seccomp-manifest.json").write_text(json.dumps(manifest))
    try:
        verifier.verify(artifacts, binary, target)
    except ValueError:
        pass
    else:
        raise AssertionError("empty enforced results were accepted")


def cross_target_verifier_test():
    for target, architecture, ioctl_number in (("x86_64-unknown-linux-musl", 0xc000003e, 16),
                                               ("aarch64-unknown-linux-musl", 0xc00000b7, 29)):
        rules = [{"syscall": "ioctl", "requests": [1]}]
        instructions = [(0x20, 0, 0, 4), (0x15, 0, 5, architecture),
                        (0x20, 0, 0, 0), (0x15, 0, 3, ioctl_number),
                        (0x20, 0, 0, 24), (0x15, 0, 1, 1),
                        (0x06, 0, 0, 0x7fff0000), (0x06, 0, 0, 0x80000000)]
        raw = b"".join(struct.pack("<HBBI", *instruction) for instruction in instructions)
        verifier.verify_bpf(raw, rules, target)
        for broken in (struct.pack("<HBBI", 0x06, 0, 0, 0x7fff0000),
                       raw.replace(struct.pack("<I", architecture), struct.pack("<I", architecture ^ 1), 1)):
            try:
                verifier.verify_bpf(broken, rules, target)
            except ValueError:
                pass
            else:
                raise AssertionError(f"unsafe filter for {target} was accepted")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="terra-seccomp-verifier-test-") as temporary:
        directory = Path(temporary)
        for target in TARGETS:
            target_directory = directory / target
            target_directory.mkdir()
            verifier_test(target_directory, target)
        cross_target_verifier_test()
    print("seccomp artifact schema, BPF restrictions, identity, and archive verification passed")
