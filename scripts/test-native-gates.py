#!/usr/bin/env python3
"""Exercise native CI admission without requiring a hypervisor."""

from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = (ROOT / '.github/workflows/build.yml').read_text()


def workflow_command(name):
    step = WORKFLOW.split(f'      - name: {name}\n', 1)[1]
    block = step.split('        run: |\n', 1)[1]
    lines = []
    for line in block.splitlines():
        if line and not line.startswith('          '):
            break
        lines.append(line[10:])
    return '\n'.join(lines)


class NativeGateTests(unittest.TestCase):
    def test_native_gate_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            missing_kvm = str(Path(directory) / 'missing-kvm')
            for step, runner_variable, is_mandatory in (
                ('KVM gates', 'LINUX_X64_VM_RUNNER', True),
                ('KVM product gates', 'LINUX_ARM64_VM_RUNNER', False),
            ):
                for has_kvm in (False, True):
                    for requested, runner in (
                        ('false', ''),
                        ('true', ''),
                        ('false', 'native-runner'),
                    ):
                        with self.subTest(step=step, has_kvm=has_kvm, requested=requested, runner=runner):
                            should_run = is_mandatory or requested == 'true' or bool(runner)
                            command = workflow_command(step).replace(
                                '/dev/kvm', '/dev/null' if has_kvm else missing_kvm,
                            )
                            command = command.replace('${{ inputs.native_vm_tests }}', requested)
                            command = command.replace('${{ vars.' + runner_variable + ' }}', runner)
                            command = 'cargo() { echo native-test-command; }\n' + command
                            result = subprocess.run(
                                ['bash', '-e', '-o', 'pipefail', '-c', command],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                check=False,
                            )
                            self.assertEqual(
                                result.returncode, int(should_run and not has_kvm), result.stdout,
                            )
                            self.assertEqual(
                                'native-test-command' in result.stdout, should_run and has_kvm, result.stdout,
                            )
                            if not should_run:
                                self.assertIn('::notice', result.stdout)
                            elif not has_kvm:
                                self.assertIn('::error', result.stdout)


if __name__ == '__main__':
    unittest.main()
