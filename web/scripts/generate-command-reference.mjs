import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const output = resolve(process.argv[2] ?? `${webRoot}/src/lib/generated/commands.json`);
const versionOutput = resolve(`${dirname(output)}/version.json`);
const terra = process.env.TERRA_BIN ?? 'terra';
const options = {
  encoding: 'utf8',
  env: { ...process.env, NO_COLOR: '1', COLUMNS: '120' },
};

function readHelp(path) {
  return execFileSync(terra, [...path, '--help'], options);
}

function parseSubcommands(helpText) {
  const section = helpText.split('\nCommands:\n')[1]?.split('\n\n')[0] ?? '';
  return [...section.matchAll(/^  (\S+)\s{2,}(.+)$/gm)]
    .filter(([, name]) => name !== 'help')
    .map(([, name, description]) => ({ name, description }));
}

function takesBox(path) {
  return !['ls', 'completions'].includes(path[0]);
}

function formatTitle(path) {
  if (path.length === 0) return 'terra [BOX]';
  return `terra${takesBox(path) ? ' [BOX]' : ''} ${path.join(' ')}`;
}

function correctHelp(helpText, path) {
  if (path.length === 0 || !takesBox(path)) return helpText;
  return helpText.replace(
    `Usage: terra ${path.join(' ')}`,
    `Usage: terra [BOX] ${path.join(' ')}`,
  );
}

function collectCommands(path, description, records) {
  const helpText = readHelp(path);
  records.push({
    slug: ['terra', ...path].join('-'),
    title: formatTitle(path),
    description: description ?? helpText.split('\n', 1)[0],
    help: correctHelp(helpText, path),
  });
  const commands = parseSubcommands(helpText);
  if (path.length === 0 && commands.length === 0) {
    throw new Error('terra --help has no Commands section');
  }
  for (const command of commands) {
    collectCommands([...path, command.name], command.description, records);
  }
}

const version = execFileSync(terra, ['--version'], options).trim();
const binaryRelease = version.match(/^terra (\d+\.\d+\.\d+)(?:\+\S+)?$/)?.[1];
const releaseTag = process.env.TERRA_RELEASE_TAG || (binaryRelease ? `v${binaryRelease}` : null);
if (releaseTag && releaseTag !== `v${binaryRelease}`) {
  throw new Error(`Release ${releaseTag} does not match binary ${version}`);
}
const records = [];
collectCommands([], undefined, records);
mkdirSync(dirname(output), { recursive: true });
writeFileSync(output, `${JSON.stringify(records, null, 2)}\n`);
writeFileSync(
  versionOutput,
  `${JSON.stringify({ version, releaseTag }, null, 2)}\n`,
);
