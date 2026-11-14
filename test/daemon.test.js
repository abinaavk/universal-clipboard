// End-to-end: two real `uclip daemon` processes with file-backed clipboards.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { after, test } from 'node:test';
import { startRelay, until } from './helpers.js';

const CLI = resolve('cli/uclip.js');
const relay = await startRelay();
const dir = mkdtempSync(join(tmpdir(), 'uc-daemon-'));
const procs = [];
after(async () => {
  procs.forEach((p) => p.kill());
  await relay.close();
  rmSync(dir, { recursive: true, force: true });
});

function env(name) {
  return {
    ...process.env,
    UCLIP_CONFIG: join(dir, `${name}.json`),
    UCLIP_CLIPBOARD_FILE: join(dir, `${name}.clip`),
    UCLIP_POLL_MS: '100',
  };
}

function cli(name, ...args) {
  return new Promise((res, rej) => {
    const p = spawn('node', [CLI, ...args], { env: env(name) });
    let out = '';
    p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (out += d));
    p.on('close', (c) => (c === 0 ? res(out) : rej(new Error(out))));
  });
}

test('copy on one machine, paste on another (daemon <-> daemon)', async () => {
  const pass = 'e2e-test-passphrase';
  await cli('win', 'init', '--server', relay.url, '--passphrase', pass, '--device', 'win');
  await cli('lin', 'init', '--server', relay.url, '--passphrase', pass, '--device', 'lin');
  writeFileSync(join(dir, 'win.clip'), '');
  writeFileSync(join(dir, 'lin.clip'), '');

  for (const name of ['win', 'lin']) {
    const p = spawn('node', [CLI, 'daemon'], { env: env(name) });
    procs.push(p);
    await new Promise((r) => p.stdout.on('data', (d) => /connection: online/.test(String(d)) && r()));
  }

  writeFileSync(join(dir, 'win.clip'), 'copied on windows 🪟');
  await until(() => readFileSync(join(dir, 'lin.clip'), 'utf8') === 'copied on windows 🪟');

  writeFileSync(join(dir, 'lin.clip'), 'copied on linux 🐧');
  await until(() => readFileSync(join(dir, 'win.clip'), 'utf8') === 'copied on linux 🐧');

  // No ping-pong: after settling there should be exactly two items in history.
  await new Promise((r) => setTimeout(r, 600));
  const hist = await cli('win', 'history');
  assert.equal(hist.trim().split('\n').length, 2);
});

test('CLI copy / paste / pair', async () => {
  await cli('lin', 'copy', 'via cli');
  assert.equal(await cli('win', 'paste'), 'via cli');
  const link = await cli('win', 'pair');
  assert.match(link, /\/#pp=e2e-test-passphrase/);
});
