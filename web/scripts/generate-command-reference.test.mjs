import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const generator = fileURLToPath(new URL('./generate-command-reference.mjs', import.meta.url));

function fakeTerra(dir) {
  const binary = join(dir, 'terra');
  writeFileSync(
    binary,
    '#!/usr/bin/env node\nconst out = JSON.parse(process.env.TERRA_FIXTURE)[process.argv.slice(2).join(" ")];\nif (out === undefined) process.exit(1);\nprocess.stdout.write(out);\n',
  );
  chmodSync(binary, 0o755);
  return binary;
}

function generate(binary, output, fixture, releaseTag = '') {
  return spawnSync(process.execPath, [generator, output], {
    encoding: 'utf8',
    env: { ...process.env, TERRA_BIN: binary, TERRA_RELEASE_TAG: releaseTag, TERRA_FIXTURE: JSON.stringify(fixture) },
  });
}

test('renders nested commands with corrected usage and stable metadata', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'terra-reference-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const binary = fakeTerra(dir);
  const output = join(dir, 'commands.json');
  const fixture = {
    '--help': 'Terra fake\n\nUsage: terra [OPTIONS] [BOX] [COMMAND]\n\nCommands:\n  storage  Manage images\n  ls       List boxes\n  help     Help\n',
    'storage --help': 'Manage images\n\nUsage: terra storage [COMMAND]\n\nCommands:\n  show  Show images\n  help  Help\n\nOptions:\n      --project <DIR>\n',
    'storage show --help': 'Show images\n\nUsage: terra storage show [OPTIONS]\n\nOptions:\n      --project <DIR>\n',
    'ls --help': 'List boxes\n\nUsage: terra ls [OPTIONS]\n\nOptions:\n      --project <DIR>\n',
    '--version': 'terra 9.9.9\n',
  };
  assert.equal(generate(binary, output, fixture).status, 0);
  const first = readFileSync(output, 'utf8');
  assert.equal(generate(binary, output, fixture).status, 0);
  assert.equal(readFileSync(output, 'utf8'), first);
  const records = JSON.parse(first);
  assert.deepEqual(records.map(({ slug }) => slug), ['terra', 'terra-storage', 'terra-storage-show', 'terra-ls']);
  assert.match(records[2].title, /terra \[BOX\] storage show/);
  assert.match(records[2].help, /Usage: terra \[BOX\] storage show/);
  assert.match(records[2].help, /--project <DIR>/);
  assert.equal(records[3].title, 'terra ls');
  assert.deepEqual(JSON.parse(readFileSync(join(dir, 'version.json'), 'utf8')), { version: 'terra 9.9.9', releaseTag: 'v9.9.9' });
  assert.equal(generate(binary, output, fixture, 'v9.9.9').status, 0);
  const mismatch = generate(binary, output, fixture, 'v1.0.0');
  assert.notEqual(mismatch.status, 0);
  assert.match(mismatch.stderr, /does not match binary/);
  assert.equal(generate(binary, output, { ...fixture, '--version': 'terra dev+abcdef' }).status, 0);
  assert.equal(JSON.parse(readFileSync(join(dir, 'version.json'), 'utf8')).releaseTag, null);
  const nestedFailure = { ...fixture };
  delete nestedFailure['storage show --help'];
  const failed = generate(binary, output, nestedFailure);
  assert.notEqual(failed.status, 0);
  assert.notEqual(failed.stderr, '');
  assert.match(failed.stderr, /storage show.*--help/);
});

test('fails when the root help has no commands', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'terra-reference-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const result = generate(fakeTerra(dir), join(dir, 'commands.json'), {
    '--help': 'Terra fake\n',
    '--version': 'terra 9.9.9\n',
  });
  assert.notEqual(result.status, 0);
  assert.notEqual(result.stderr, '');
  assert.match(result.stderr, /no Commands section/);
});
