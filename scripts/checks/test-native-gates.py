#!/usr/bin/env python3
"""Exercise native CI admission without requiring a hypervisor."""

from pathlib import Path
import importlib.util
import itertools
import os
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / '.github/workflows/build.yml').read_text()


def workflow_command(name, workflow=WORKFLOW):
    step = workflow.split(f'      - name: {name}\n', 1)[1]
    block = step.split('        run: |\n', 1)[1]
    lines = []
    for line in block.splitlines():
        if line and not line.startswith('          '):
            break
        lines.append(line[10:])
    return '\n'.join(lines)


class NativeGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('vsock_abi', ROOT / 'scripts/kernel/check-vsock-abi.py')
        cls.vsock_checks = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.vsock_checks)

    def test_current_sources_and_release_step_use_the_fixed_vsock_abi(self):
        self.vsock_checks.check(ROOT)
        self.assertIn('      - name: Check fixed vsock ABI\n', WORKFLOW)
        self.assertIn('        run: python3 -B scripts/kernel/check-vsock-abi.py\n', WORKFLOW)

    def test_frontend_requires_stock_vsock_device_id(self):
        module = self.vsock_checks
        source = 'MmioTransport::new(memory::address_limit(), 19, 1 << 32, QUEUE_SIZE, Vec::new())'
        module.validate_device_id(source)
        for device_id in ('0', '1', '42', '65_535', '65536'):
            with self.subTest(device_id=device_id), self.assertRaises(ValueError):
                module.validate_device_id(source.replace(', 19,', f', {device_id},'))
        module.validate_device_id(source.replace(', ', ',\n    '))
        with self.assertRaises(ValueError):
            module.validate_device_id('')

    def test_guest_configs_require_built_in_stock_vsock(self):
        module = self.vsock_checks
        source = 'CONFIG_VSOCKETS=y\nCONFIG_VIRTIO_VSOCKETS=y\n'
        module.validate_kernel_config(source)
        for invalid in ('', source.replace('CONFIG_VSOCKETS=y\n', ''),
                        source.replace('CONFIG_VIRTIO_VSOCKETS=y', 'CONFIG_VIRTIO_VSOCKETS=m'),
                        source + '# CONFIG_VSOCKETS is not set\n'):
            with self.subTest(source=invalid), self.assertRaises(ValueError):
                module.validate_kernel_config(invalid)

    def test_active_patch_series_is_exact(self):
        module = self.vsock_checks
        patches = dict.fromkeys(module.PATCH_NAMES, '')
        module.validate_patch_series(patches)
        with self.assertRaises(ValueError):
            module.validate_patch_series({**patches, '0003-extra.patch': ''})
        with self.assertRaises(ValueError):
            module.validate_patch_series({})

    def test_socket_version_matches_kernel_encoder_and_ioctl(self):
        module = self.vsock_checks
        for source, kernel_source in [
            ('', '#define TERRA_SOCKET_VERSION 1'),
            ('pub const VERSION: u16 = 1;', ''),
            ('pub const VERSION: u16 = 2;', '#define TERRA_SOCKET_VERSION 1'),
        ]:
            with self.subTest(source=source, kernel_source=kernel_source), self.assertRaises(ValueError):
                module.validate_socket_version(source, kernel_source)
        module.validate_socket_version('pub const VERSION: u16 = 0x1;', '#define TERRA_SOCKET_VERSION 1')

    def test_network_application_version_header_and_opcodes_match(self):
        module = self.vsock_checks
        source = (ROOT / 'crates/terra-protocol/src/application.rs').read_text()
        kernel_source = module.load_kernel_source(ROOT)
        module.validate_application_abi(source, kernel_source)
        for invalid in (kernel_source.replace('TERRA_HEADER_BYTES 8', 'TERRA_HEADER_BYTES 32'),
                        kernel_source.replace('TERRA_OP_UDP_SEND 0x03', 'TERRA_OP_UDP_SEND 0x07'), ''):
            with self.subTest(kernel_source=invalid[:40]), self.assertRaises(ValueError):
                module.validate_application_abi(source, invalid)
        for invalid in (source.replace('VERSION: u16 = 1', 'VERSION: u16 = 2'),
                        source.replace('HEADER_BYTES: usize = 8', 'HEADER_BYTES: usize = 32'),
                        source.replace('UdpError = 0x104', 'UdpError = 0x10e'), ''):
            with self.subTest(source=invalid[:40]), self.assertRaises(ValueError):
                module.validate_application_abi(invalid, kernel_source)

    def test_fixed_endpoint_tuples_match_protocol_and_kernel(self):
        module = self.vsock_checks
        protocol = (ROOT / 'crates/terra-protocol/src/vsock.rs').read_text()
        kernel = module.load_kernel_source(ROOT)
        module.validate_endpoints(protocol, kernel)
        for guest, adapter in (
            (protocol.replace('HOST_CID: u32 = 2', 'HOST_CID: u32 = 4'), kernel),
            (protocol.replace('UDP_PORT: u32 = 6003', 'UDP_PORT: u32 = 6005'), kernel),
            (protocol, kernel.replace('TERRA_UDP_PORT 6003', 'TERRA_UDP_PORT 6001')),
            (protocol, kernel + '\n\tstruct sockaddr_vm extra = { .svm_cid = 2, .svm_port = 6001 };'),
            ('', kernel), (protocol, ''),
        ):
            with self.subTest(), self.assertRaises(ValueError):
                module.validate_endpoints(guest, adapter)

    def test_guest_socket_buffers_keep_the_reviewed_limits(self):
        module = self.vsock_checks
        kernel = module.load_kernel_source(ROOT)
        module.validate_kernel_buffers(kernel)
        for source in ('',
                       kernel.replace('TERRA_TCP_SEGMENT_BYTES 65535', 'TERRA_TCP_SEGMENT_BYTES 65536'),
                       kernel.replace('TERRA_TCP_RECEIVE_BYTES 81920', 'TERRA_TCP_RECEIVE_BYTES 32768'),
                       kernel.replace('TERRA_TCP_SEND_BYTES 49152', 'TERRA_TCP_SEND_BYTES 32768'),
                       kernel.replace('TERRA_UDP_QUEUE_BYTES 65536', 'TERRA_UDP_QUEUE_BYTES 131072'),
                       kernel.replace('TERRA_UDP_QUEUED_DATAGRAMS 48', 'TERRA_UDP_QUEUED_DATAGRAMS 96')):
            with self.subTest(source=source), self.assertRaises(ValueError):
                module.validate_kernel_buffers(source)

    def test_release_requires_all_native_gates_and_matching_policy_uploads(self):
        release = (ROOT / '.github/workflows/release.yml').read_text()
        self.assertIn('      native_vm_tests: true', release)
        self.assertIn('      release_sources: true', release)
        policy = WORKFLOW.split('  linux-policy:\n', 1)[1].split('  macos-aarch64:\n', 1)[0]
        self.assertIn('    continue-on-error: ${{ !inputs.release_sources }}', policy)
        self.assertNotIn("matrix.arch != 'x86_64'", policy)
        outcomes = itertools.product(('true', 'false', ''), ('true', 'false', ''),
                                     ('success', 'failure', 'skipped'), ('success', 'failure', 'skipped'))
        for result, available, validated, uploaded in outcomes:
            environment = {**os.environ, 'BUILD_READY': result, 'KVM_AVAILABLE': available,
                           'POLICY_VALIDATED': validated, 'POLICY_UPLOADED': uploaded}
            completed = subprocess.run(['bash', '-e', '-c', workflow_command('Require release policy validation')],
                                       env=environment, text=True, capture_output=True, check=False)
            self.assertEqual(completed.returncode,
                             int(result != 'true' or available != 'true' or validated != 'success' or uploaded != 'success'))

    def test_release_asset_assembly_rejects_missing_and_mismatched_policies(self):
        release = (ROOT / '.github/workflows/release.yml').read_text()
        command = workflow_command('Assemble validated policy assets', release)
        for has_arm_policy, rejected in ((False, ''), (True, 'aarch64-unknown-linux-musl'), (True, '')):
            with self.subTest(has_arm_policy=has_arm_policy, rejected=rejected), tempfile.TemporaryDirectory() as directory:
                policies = Path(directory) / 'policies'
                (policies / 'terra-seccomp-x86_64-unknown-linux-musl').mkdir(parents=True)
                if has_arm_policy:
                    (policies / 'terra-seccomp-aarch64-unknown-linux-musl').mkdir()
                mocks = '''
sudo() { :; }
chmod() { :; }
python3() { test "${@: -1}" != "$REJECTED_TARGET"; }
tar() { :; }
'''
                completed = subprocess.run(['bash', '-e', '-c', mocks + command], cwd=directory,
                                           env={**os.environ, 'REJECTED_TARGET': rejected},
                                           text=True, capture_output=True, check=False)
                self.assertEqual(completed.returncode, int(not has_arm_policy or bool(rejected)))

    def test_policy_generation_uses_the_distribution_without_test_harnesses(self):
        policy = WORKFLOW.split('  linux-policy:\n', 1)[1].split('  macos-aarch64:\n', 1)[0]
        for legacy in ('make ', 'cargo ', 'rustup ', 'setup-zig', 'harness'):
            self.assertNotIn(legacy, policy)
        self.assertIn('./dist/terra self-test --generate-policy --validate-vm --policy-output', policy)
        self.assertIn('--policy-diagnostics "build/seccomp-traces/${{ matrix.target }}"', policy)
        self.assertIn('python3 libseccomp2', policy)
        self.assertNotIn('strace', policy)
        self.assertNotIn('apt-get', workflow_command('Prepare policy validation'))
        self.assertNotIn('terra-policy-harnesses-', WORKFLOW)
        for step in ('KVM gates', 'KVM product gates'):
            command = workflow_command(step)
            self.assertIn('TERRA_SECCOMP_ENFORCED=1 cargo test', command)
            self.assertIn('--exact bwrap_enforces_vm_and_vcpu_threads --ignored --nocapture', command)
            self.assertIn("grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;'", command)

    def test_component_cleanup_preserves_runtime_wasm_fixtures(self):
        fixture_source = (ROOT / 'crates/terra-runtime/src/test_fixtures.rs').read_text()
        fixture_paths = re.findall(r'components/target/[^"\n]+\.wasm', fixture_source)
        self.assertTrue(fixture_paths)
        command = workflow_command('Reclaim component build space')
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(['bash', '-e', '-c', command], cwd=directory, check=True)
            for fixture in fixture_paths:
                artifact = Path(directory) / fixture
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.write_bytes(b'wasm-fixture')
            intermediate_targets = [Path(directory) / 'components/target' / target for target in (
                'release', 'debug', 'wasm32-unknown-unknown', 'wasm32-wasip3', 'x86_64-unknown-linux-gnu',
            )]
            for target in intermediate_targets:
                target.mkdir()
                (target / 'intermediate-artifact').write_bytes(b'intermediate')
            subprocess.run(['bash', '-e', '-c', command], cwd=directory, check=True)
            for fixture in fixture_paths:
                self.assertEqual((Path(directory) / fixture).read_bytes(), b'wasm-fixture')
            for target in intermediate_targets:
                self.assertFalse(target.exists(), target)

    def test_kvm_permissions_survive_device_initialization(self):
        """KVM's first open can trigger udev to discard a one-time user ACL."""
        backfill = (ROOT / '.github/workflows/policy-backfill.yml').read_text()
        for workflow, expected_setups in ((WORKFLOW, 3), (backfill, 1)):
            self.assertEqual(workflow.count('      - name: Enable KVM access\n'), expected_setups)
            for step in workflow.split('      - name: Enable KVM access\n')[1:]:
                self.assertIn("runner.environment == 'github-hosted'", step.split('        run:', 1)[0])
                command = workflow_command('Enable KVM access', '      - name: Enable KVM access\n' + step)
                for device in ('/dev/null', '/dev/terra-ci-missing-kvm'):
                    with self.subTest(device=device), tempfile.TemporaryDirectory() as directory:
                        setup = command.replace('/dev/kvm', device)
                        gate = workflow_command('KVM gates').replace('/dev/kvm', device)
                        shell = f'''
kvm_acl=0
kvm_owner=''
kvm_mode=0660
kvm_rule=''
sudo() {{
    case "$*" in
        'setfacl -m u:{os.getuid()}:rw {device}') kvm_acl=1 ;;
        'tee /etc/udev/rules.d/99-terra-kvm.rules') cat > kvm.rules ;;
        'udevadm control --reload-rules') kvm_rule=$(cat kvm.rules) ;;
        'chown {os.getuid()} {device}') kvm_owner={os.getuid()} ;;
        'chmod 0600 {device}') kvm_mode=0600 ;;
        *) echo "unexpected sudo: $*"; return 1 ;;
    esac
}}
can_open_kvm() {{
    test "$kvm_acl" = 1 || {{ test "$kvm_owner" = {os.getuid()} && test "$kvm_mode" = 0600; }}
}}
[() {{
    if test "$1" = '!'; then
        shift
        ! [ "$@"
    elif {{ test "$1" = -r || test "$1" = -w; }} && test "$2" = /dev/null; then
        can_open_kvm
    else
        builtin [ "$@"
    fi
}}
cargo() {{
    can_open_kvm || return 1
    echo native-test-command
    echo 'test result: ok. 1 passed; 0 failed; 0 ignored;'
    kvm_acl=0
    kvm_owner=''
    kvm_mode=0660
    if test "$kvm_rule" = 'KERNEL=="kvm", OWNER="{os.getuid()}", MODE="0600", OPTIONS+="static_node=kvm"'; then
        kvm_owner={os.getuid()}
        kvm_mode=0600
    fi
}}
{setup}
{gate}
'''
                        result = subprocess.run(
                            ['bash', '-e', '-o', 'pipefail', '-c', shell], text=True, cwd=directory,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
                        )
                        self.assertEqual(result.returncode, int(device != '/dev/null'), result.stdout)
                        self.assertEqual(result.stdout.count('native-test-command'), 5 if device == '/dev/null' else 0)
                        if device != '/dev/null':
                            self.assertIn('require a native /dev/terra-ci-missing-kvm device', result.stdout)

    def test_native_gate_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            missing_kvm = str(Path(directory) / 'missing-kvm')
            for step, runner_variable, is_mandatory in (
                ('KVM gates', 'LINUX_X64_VM_RUNNER', True),
                ('KVM product gates', 'LINUX_ARM64_VM_RUNNER', False),
            ):
                for has_kvm, has_access in ((False, False), (True, False), (True, True)):
                    for requested, runner in (
                        ('false', ''),
                        ('true', ''),
                        ('false', 'native-runner'),
                    ):
                        with self.subTest(step=step, has_kvm=has_kvm, has_access=has_access,
                                          requested=requested, runner=runner):
                            should_run = is_mandatory or requested == 'true' or bool(runner)
                            command = workflow_command(step).replace(
                                '/dev/kvm', '/dev/null' if has_kvm else missing_kvm,
                            )
                            command = command.replace('${{ inputs.native_vm_tests }}', requested)
                            command = command.replace('${{ vars.' + runner_variable + ' }}', runner)
                            if has_kvm and not has_access:
                                command = command.replace('[ ! -r /dev/null ]', 'true')
                            command = "cargo() { echo native-test-command; echo 'test result: ok. 1 passed; 0 failed; 0 ignored;'; }\n" + command
                            result = subprocess.run(
                                ['bash', '-e', '-o', 'pipefail', '-c', command],
                                text=True, cwd=directory, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                check=False,
                            )
                            self.assertEqual(
                                result.returncode, int(should_run and not has_access), result.stdout,
                            )
                            self.assertEqual(
                                'native-test-command' in result.stdout, should_run and has_access, result.stdout,
                            )
                            if not should_run:
                                self.assertIn('::notice', result.stdout)
                            elif not has_access:
                                self.assertIn('::error', result.stdout)
                                self.assertIn('cannot read/write' if has_kvm else 'require', result.stdout)


if __name__ == '__main__':
    unittest.main()
