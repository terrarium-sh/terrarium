#!/usr/bin/env python3
"""Exercise backfill preflight and checksum retries without a release or KVM."""

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = (ROOT / '.github/workflows/policy-backfill.yml').read_text()
TARGETS = ('x86_64-unknown-linux-musl', 'aarch64-unknown-linux-musl')


def workflow_command(name):
    step = WORKFLOW.split(f'      - name: {name}\n', 1)[1]
    block = step.split('        run: |\n', 1)[1]
    lines = []
    for line in block.splitlines():
        if line and not line.startswith('          '):
            break
        lines.append(line[10:])
    return '\n'.join(lines)


class BackfillTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.environment = dict(os.environ, RELEASE_TAG='v-old', GITHUB_REPOSITORY='owner/repo',
                                GITHUB_STEP_SUMMARY=str(self.root / 'summary'))

    def run_step(self, name):
        return subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', workflow_command(name)],
                              cwd=self.root, env=self.environment, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)

    def write_file(self, name, contents):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
        return path

    def test_generation_uses_the_release_binary_without_building_sources(self):
        generation = WORKFLOW.split('  publish:\n', 1)[0]
        self.assertNotIn('ref: ${{ inputs.release_tag }}', generation)
        for legacy in ('make ', 'cargo ', 'rustup ', 'setup-zig', 'harness', 'seccomp-workloads.json'):
            self.assertNotIn(legacy, generation)
        self.assertIn('./release-bin/terra self-test --generate-policy --validate-vm --policy-output', generation)
        self.assertIn('--policy-diagnostics "build/seccomp-traces/${{ matrix.target }}"', generation)
        self.assertIn('python3 libseccomp2', generation)
        self.assertNotIn('strace', generation)

    def test_old_binary_preflight(self):
        binary = self.write_file('release-bin/terra', '#!/bin/sh\necho terra-old\n')
        binary.chmod(0o755)
        result = self.run_step('Check release self-test policy support')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('lacks terra self-test VM policy generation', result.stdout)
        options = ('--generate-policy', '--policy-output', '--policy-diagnostics',
                   '--policy-timeout', '--validate-vm')
        help_text = ' '.join(options)
        binary.write_text(f'#!/bin/sh\necho "{help_text}"\nexit 1\n')
        self.assertNotEqual(self.run_step('Check release self-test policy support').returncode, 0)
        binary.write_text('#!/bin/sh\n[ "$*" = "workload --help" ] || exit 1\necho "--output --diagnostics --validate-vm"\n')
        self.assertNotEqual(self.run_step('Check release self-test policy support').returncode, 0)
        for missing in options:
            with self.subTest(missing=missing):
                available = ' '.join(option for option in options if option != missing)
                binary.write_text(f'#!/bin/sh\necho "{available}"\n')
                self.assertNotEqual(self.run_step('Check release self-test policy support').returncode, 0)
        binary.write_text(f'#!/bin/sh\n[ "$*" = "self-test --help" ] || exit 1\necho "{help_text}"\n')
        result = self.run_step('Check release self-test policy support')
        self.assertEqual(result.returncode, 0, result.stdout)

    def prepare_release(self):
        gh = self.write_file('bin/gh', '''#!/usr/bin/env python3
import json, os, shutil, sys
from pathlib import Path
root = Path(os.environ['FAKE_RELEASE'])
arguments = sys.argv[1:]
with (root / 'calls').open('a') as log:
    log.write(json.dumps(arguments) + '\\n')
if arguments[1] == 'view':
    print('\\n'.join(path.name for path in root.glob('*.tar.gz')))
elif arguments[1] == 'download':
    source = root / arguments[arguments.index('--pattern') + 1]
    shutil.copyfile(source, Path(arguments[arguments.index('--dir') + 1]) / source.name)
elif arguments[1] == 'upload':
    source = Path(arguments[3])
    if source.name == 'SHA256SUMS' and os.environ.get('FAIL_CHECKSUM'):
        sys.exit(1)
    shutil.copyfile(source, root / source.name)
else:
    sys.exit(2)
''')
        gh.chmod(0o755)
        self.environment.update(PATH=f"{self.root / 'bin'}:{os.environ['PATH']}",
                                FAKE_RELEASE=str(self.root / 'release'))
        self.write_file('release/SHA256SUMS', 'original-binary-checksum  terra.tar.gz\n')
        self.write_file('stage/SHA256SUMS', 'original-binary-checksum  terra.tar.gz\n')
        self.write_file('scripts/verify-seccomp-artifact.py', '''import json, sys
from pathlib import Path
assert sys.argv[1] == '--archive'
assert Path(sys.argv[3]).read_bytes() == b'exact binary'
with Path('verified').open('a') as log:
    log.write(json.dumps(sys.argv[1:]) + '\\n')
assert Path(sys.argv[2]).read_bytes().startswith(b'original-policy-')
''')
        for target in TARGETS:
            self.write_file(f'stage/terra-seccomp-{target}.tar.gz', f'original-policy-{target}')
            self.write_file(f'published/{target}/terra', 'exact binary')

    def test_retry_hashes_existing_archive_after_checksum_upload_failure(self):
        self.prepare_release()
        self.environment['FAIL_CHECKSUM'] = '1'
        self.assertNotEqual(self.run_step('Attach assets and update checksums').returncode, 0)
        del self.environment['FAIL_CHECKSUM']
        for target in TARGETS:
            self.write_file(f'stage/terra-seccomp-{target}.tar.gz', f'regenerated-policy-{target}')
        result = self.run_step('Attach assets and update checksums')
        self.assertEqual(result.returncode, 0, result.stdout)
        checksums = (self.root / 'release/SHA256SUMS').read_text()
        for target in TARGETS:
            name = f'terra-seccomp-{target}.tar.gz'
            existing = (self.root / 'release' / name).read_bytes()
            self.assertIn(f'{hashlib.sha256(existing).hexdigest()}  {name}\n', checksums)
            self.assertNotEqual(existing, (self.root / 'stage' / name).read_bytes())
        verified = [json.loads(line) for line in (self.root / 'verified').read_text().splitlines()]
        self.assertEqual([entry[2] for entry in verified],
                         [f'published/{target}/terra' for target in TARGETS])

    def test_invalid_existing_archive_stops_checksum_update(self):
        self.prepare_release()
        target = TARGETS[0]
        self.write_file(f'release/terra-seccomp-{target}.tar.gz', 'invalid archive')
        original_checksums = (self.root / 'release/SHA256SUMS').read_bytes()
        result = self.run_step('Attach assets and update checksums')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / 'release/SHA256SUMS').read_bytes(), original_checksums)
        self.assertEqual((self.root / 'stage/SHA256SUMS').read_bytes(), original_checksums)


if __name__ == '__main__':
    unittest.main()
