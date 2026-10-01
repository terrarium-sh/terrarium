#!/usr/bin/env python3
"""Check VM trace selection and the exported raw BPF's actual deny behavior."""

import importlib.util
import hashlib
import json
import platform
import subprocess
import struct
import tarfile
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("generate-seccomp.py")
spec = importlib.util.spec_from_file_location("generate_seccomp", SCRIPT)
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)
verifier_spec = importlib.util.spec_from_file_location("verify_seccomp_artifact", SCRIPT.with_name("verify-seccomp-artifact.py"))
verifier = importlib.util.module_from_spec(verifier_spec)
verifier_spec.loader.exec_module(verifier)

HELPER = r"""
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(int argc, char **argv) {
    (void)argc;
    FILE *file = fopen(argv[1], "rb");
    if (!file) return 2;
    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    rewind(file);
    struct sock_filter *filter = malloc(length);
    if (!filter || fread(filter, 1, length, file) != (size_t)length) return 3;
    fclose(file);
    int fd = open("/dev/null", O_RDONLY);
    if (fd < 0) return 4;
    struct sock_fprog program = { .len = length / sizeof(*filter), .filter = filter };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)) return 5;
    switch (argv[2][0]) {
    case 'g': return syscall(SYS_getpid) > 0 ? 0 : 6;
    case 'p': syscall(SYS_getppid); return 7;
    case 'i': return ioctl(fd, 0x1234) == -1 && errno == ENOTTY ? 0 : 8;
    case 'h': return ioctl(fd, 0xffffffff00001234UL) == -1 && errno == ENOTTY ? 0 : 12;
    case 'j': ioctl(fd, 0x1235); return 9;
#ifdef __x86_64__
    case 'x': syscall(0x40000000L | SYS_getpid); return 10;
#endif
    }
    return 11;
}
"""


def trace_test(directory):
    trace = directory / "traces"
    trace.mkdir()
    (trace / "vm-42.42").write_text(
        'clone(child_stack=NULL) = 41\n'
        'execve("/usr/bin/terra", ["terra", "__vm", "/box"], 0x0) = 0\n'
        'ioctl(3, 0x1234, 0) = -1 ENOTTY\n'
        'ioctl(3, 0xffffffff00001234, 0) = -1 ENOTTY\n'
        'ioctl(20, 0xae80 <unfinished ...>)      = ?\n'
        'clone(child_stack=NULL) = 43\n'
        'getpid() = 42\n')
    (trace / "vm-42.43").write_text('gettid() = 43\n'
                                    'socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 9\n'
                                    'getsockopt(9, SOL_SOCKET, SO_ERROR, [0], [4]) = 0\n')
    (trace / "vm-42.41").write_text('mount("/", "/", NULL, 0, NULL) = 0\n')
    (trace / "vm-100.42").write_text(
        'execve("/usr/bin/terra", ["terra", "__vm", "/box"], 0x0) = 0\n'
        'ioctl(3, 0x5678, 0) = -1 ENOTTY\n'
        'clock_gettime(0, 0x0) = 0\n')
    decoy = trace / "vm-55.55"
    decoy.write_text('execve("/usr/bin/other", ["other", "__vm"], 0x0) = 0\n'
                     'mount("/", "/", NULL, 0, NULL) = 0\n')
    try:
        generator.parse_traces([decoy], Path("/usr/bin/terra"))
    except RuntimeError:
        pass
    else:
        raise AssertionError("decoy __vm executable was selected")
    calls, ioctls, vm_count, process_count = generator.parse_traces(trace.iterdir(), Path("/usr/bin/terra"))
    assert set(calls) == {"execve", "ioctl", "clone", "getpid", "gettid", "clock_gettime", "socket", "getsockopt"}
    assert ioctls == {0x1234: {("vm-42", 42)}, 0xae80: {("vm-42", 42)},
                      0x5678: {("vm-100", 42)}}
    assert (vm_count, process_count) == (2, 3)


def bpf_test(directory):
    target = generator.TARGETS[platform.machine()][0]
    rules = [{"syscall": name, "requests": [0x1234]} if name == "ioctl" else {"syscall": name}
             for name in ("write", "exit", "exit_group", "getpid", "ioctl")]
    bpf = directory / "test.bpf"
    generator.compile_bpf(rules, target, bpf)
    verifier.verify_bpf(bpf.read_bytes(), rules, target)
    source = directory / "helper.c"
    helper = directory / "helper"
    source.write_text(HELPER)
    subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-o", str(helper), str(source)], check=True)

    def status(policy, operation):
        return subprocess.run([str(helper), str(policy), operation], check=False).returncode

    assert status(bpf, "g") == 0, "allowed getpid was denied"
    assert status(bpf, "i") == 0, "allowed ioctl request was denied"
    assert status(bpf, "h") == 0, "sign-extended ioctl request was denied"
    assert status(bpf, "p") == -31, "unexpected syscall did not kill the process"
    assert status(bpf, "j") == -31, "unexpected ioctl request did not kill the process"
    if platform.machine() == "x86_64":
        assert status(bpf, "x") == -31, "x32 syscall bit was accepted"
    raw = bpf.read_bytes()
    native = (0xc000003e if platform.machine() == "x86_64" else 0xc00000b7).to_bytes(4, "little")
    other = (0xc00000b7 if platform.machine() == "x86_64" else 0xc000003e).to_bytes(4, "little")
    assert raw.count(native) == 1, "filter did not encode one exact native ABI check"
    wrong = directory / "wrong-abi.bpf"
    wrong.write_bytes(raw.replace(native, other, 1))
    assert status(wrong, "g") == -31, "wrong ABI was accepted"


def publish_test(directory):
    output = directory / "current"
    old = directory / "old"
    old.mkdir()
    (old / "terra.seccomp.json").write_text("old")
    output.symlink_to(old.name, target_is_directory=True)
    candidate = directory / "candidate"
    candidate.mkdir()
    (candidate / "terra.seccomp.json").write_text("new")
    generator.publish(candidate, output)
    assert (output / "terra.seccomp.json").read_text() == "new"
    assert (old / "terra.seccomp.json").read_text() == "old"
    blocked = directory / "blocked"
    blocked.mkdir()
    try:
        generator.publish(blocked, old)
    except RuntimeError:
        pass
    else:
        raise AssertionError("real output directory was unexpectedly overwritten")
    assert (old / "terra.seccomp.json").read_text() == "old"


def config_test(directory):
    bpf = directory / "terra.seccomp.bpf"
    config = generator.write_config(directory, "enforced", bpf=bpf)
    assert config.read_text() == "vm:\n  bwrap:\n    policy: " + json.dumps(str(bpf)) + "\n"


def verifier_test(directory):
    (directory / "seccomp-workloads.json").write_text(json.dumps({"workloads": [
        {"suite": "boot", "test": "example"}]}))
    verifier.__file__ = str(directory / "verify-seccomp-artifact.py")
    artifacts = directory / "artifacts"
    artifacts.mkdir()
    binary = directory / "terra"
    binary.write_bytes(b"release executable for another architecture")
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    target = generator.TARGETS[platform.machine()][0]
    bpf_file = artifacts / "terra.seccomp.bpf"
    rules = [{"syscall": "ioctl", "requests": [1]}]
    generator.compile_bpf(rules, target, bpf_file)
    bpf = bpf_file.read_bytes()
    bpf_hash = hashlib.sha256(bpf).hexdigest()
    policy_file = artifacts / "terra.seccomp.json"
    policy_file.write_text(json.dumps({"format_version": 1, "target": target,
                                       "default_action": "kill_process",
                                       "workload_coverage": {"traced": ["boot.example"], "enforced_only": []},
                                       "rules": rules}))
    validation = {"passed": True, "workloads": ["boot.example"],
                  "workload_results": [{"name": "boot.example", "passed": True}]}
    manifest = {"format_version": 1, "target": target, "release_identity": "1.0+abc",
                "executable_sha256": binary_hash, "bpf_sha256": bpf_hash,
                "policy_sha256": hashlib.sha256(policy_file.read_bytes()).hexdigest(),
                "validation": validation,
                "trace_workload_results": [{"name": "boot.example", "passed": True}],
                "trace_exclusions": []}
    (artifacts / "terra.seccomp-manifest.json").write_text(json.dumps(manifest))
    (artifacts / ".validated").write_text(binary_hash + "\n")
    verifier.verify(artifacts, binary, target)

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
    architecture = 0xc000003e if platform.machine() == "x86_64" else 0xc00000b7
    other_architecture = 0xc00000b7 if platform.machine() == "x86_64" else 0xc000003e
    reject_filter(bpf.replace(struct.pack("<I", architecture), struct.pack("<I", other_architecture), 1),
                  "artifact with wrong architecture was accepted")
    unrestricted = list(struct.iter_unpack("<HBBI", bpf))
    request_index = next(index + 1 for index, instruction in enumerate(unrestricted)
                         if instruction == (0x20, 0, 0, 24))
    code, yes, _, value = unrestricted[request_index]
    unrestricted[request_index] = (code, yes, yes, value)
    reject_filter(b"".join(struct.pack("<HBBI", *instruction) for instruction in unrestricted),
                  "artifact allowing unlisted ioctl requests was accepted")
    generator.compile_bpf(rules + [{"syscall": "getpid"}], target, bpf_file)
    reject_filter(bpf_file.read_bytes(), "artifact allowing an unlisted syscall was accepted")
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
    with tempfile.TemporaryDirectory(prefix="terra-seccomp-test-") as temporary:
        directory = Path(temporary)
        trace_test(directory)
        bpf_test(directory)
        publish_test(directory)
        config_test(directory)
        verifier_test(directory)
        cross_target_verifier_test()
    print("seccomp trace parser, BPF restrictions, publication, and verifier passed")
