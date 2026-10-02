#!/usr/bin/env python3
"""Exercise native CI admission without requiring a hypervisor."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
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
    def test_kvm_permissions_repaired_before_mandatory_gate(self):
        backfill = (ROOT / '.github/workflows/policy-backfill.yml').read_text()
        for workflow, expected_setups in ((WORKFLOW, 3), (backfill, 1)):
            self.assertEqual(workflow.count('      - name: Enable KVM access\n'), expected_setups)
            for step in workflow.split('      - name: Enable KVM access\n')[1:]:
                self.assertIn("runner.environment == 'github-hosted'", step.split('        run:', 1)[0])
                command = workflow_command('Enable KVM access', '      - name: Enable KVM access\n' + step)
                for device in ('/dev/null', '/dev/terra-ci-missing-kvm'):
                    with self.subTest(device=device):
                        setup = command.replace('/dev/kvm', device)
                        gate = workflow_command('KVM gates').replace('/dev/kvm', device)
                        shell = f'''
kvm_access=0
sudo() {{
    test "$*" = "setfacl -m u:{os.getuid()}:rw {device}"
    kvm_access=1
}}
[() {{
    if {{ test "$1" = -r || test "$1" = -w; }} && test "$2" = /dev/null; then
        test "$kvm_access" = 1
    else
        builtin [ "$@"
    fi
}}
cargo() {{ echo native-test-command; }}
{setup}
{gate}
'''
                        result = subprocess.run(
                            ['bash', '-e', '-o', 'pipefail', '-c', shell], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
                        )
                        self.assertEqual(result.returncode, int(device != '/dev/null'), result.stdout)
                        self.assertEqual('native-test-command' in result.stdout, device == '/dev/null')
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
                            command = 'cargo() { echo native-test-command; }\n' + command
                            result = subprocess.run(
                                ['bash', '-e', '-o', 'pipefail', '-c', command],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
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
