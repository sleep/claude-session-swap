import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

// Everything here spawns a fresh node so the module is evaluated with a real
// argv[1] that is not the script: exactly what a program importing ccswitch
// as a library looks like.

const ROOT = path.resolve(new URL('..', import.meta.url).pathname);
const MODULE = path.join(ROOT, 'ccswitch.mjs');

function scratch(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ccswitch-lib-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function runScript(dir, source) {
  const file = path.join(dir, 'entry.mjs');
  fs.writeFileSync(file, source);
  return spawnSync(process.execPath, [file], {
    encoding: 'utf8',
    env: { ...process.env, CCSWITCH_HOME: path.join(dir, 'home'), CCSWITCH_CLAUDE_JSON: path.join(dir, 'claude.json') },
  });
}

test('importing the module as a library runs no command and prints nothing', (t) => {
  const dir = scratch(t);
  const r = runScript(
    dir,
    `import * as m from ${JSON.stringify(MODULE)};\nprocess.stdout.write(typeof m.main + ' ' + typeof m.config);\n`,
  );
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, 'function function'); // no help text, no table, no exit from main()
  assert.equal(r.stderr, '');
});

test('the package resolves as a bare "ccswitch" import through its exports map', (t) => {
  const dir = scratch(t);
  fs.mkdirSync(path.join(dir, 'node_modules'));
  fs.symlinkSync(ROOT, path.join(dir, 'node_modules', 'ccswitch'), 'dir');
  const r = runScript(
    dir,
    `import { config } from 'ccswitch';\nimport { listProfiles } from 'ccswitch/ccswitch.mjs';\n` +
      `process.stdout.write(config('kimi').target + ' ' + JSON.stringify(listProfiles(config('claude'))));\n`,
  );
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, 'kimi []');
});

test('ccswitch.d.ts declares exactly the value exports of the module', async () => {
  const runtime = Object.keys(await import(MODULE)).sort();
  const dts = fs.readFileSync(path.join(ROOT, 'ccswitch.d.ts'), 'utf8');
  const declared = [...dts.matchAll(/^export (?:function|class|const|let) (\w+)/gm)].map((m) => m[1]);
  assert.deepEqual([...new Set(declared)].sort(), runtime);
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  assert.equal(pkg.types, './ccswitch.d.ts');
  assert.equal(pkg.exports['.'].types, './ccswitch.d.ts');
  assert.ok(pkg.files.includes('ccswitch.d.ts'));
});
