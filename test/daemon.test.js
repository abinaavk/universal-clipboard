// End-to-end: real `uclip` processes with file-backed clipboards against a real relay and real accounts.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { after, test } from 'node:test';
import { signup } from '../shared/auth.js';
import { createApi, createClient } from '../shared/client.js';
import { importVaultKey } from '../shared/crypto.js';
import { PASSWORD, startRelay, until } from './helpers.js';

const CLI = resolve('cli/uclip.js');
const relay = await startRelay();
const dir = mkdtempSync(join(tmpdir(), 'uc-daemon-'));
const procs = [];
after(async () => {
  procs.forEach((p) => p.kill());
  await relay.close();
  rmSync(dir, { recursive: true, force: true });
});

const env = (name) => ({ ...process.env, UCLIP_CONFIG: join(dir, `${name}.json`), UCLIP_CLIPBOARD_FILE: join(dir, `${name}.clip`), UCLIP_POLL_MS: '100' });
const clip = (name) => (existsSync(join(dir, `${name}.clip`)) ? readFileSync(join(dir, `${name}.clip`), 'utf8') : '');
const setClip = (name, text) => writeFileSync(join(dir, `${name}.clip`), text);
const config = (name) => JSON.parse(readFileSync(join(dir, `${name}.json`), 'utf8'));

function cli(name, args, { stdin } = {}) {
  return new Promise((res, rej) => {
    const p = spawn('node', [CLI, ...args], { env: env(name) });
    let out = '';
    p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (out += d));
    p.on('close', (c) => (c === 0 ? res(out) : rej(new Error(out))));
    p.stdin.end(stdin ?? '');
  });
}

function daemon(name) {
  const p = spawn('node', [CLI, 'daemon'], { env: env(name) });
  procs.push(p);
  const d = { p, log: '', waitFor: (re, n = 1) => until(() => (d.log.match(new RegExp(re, 'g')) ?? []).length >= n) };
  p.stdout.on('data', (c) => (d.log += c));
  p.stderr.on('data', (c) => (d.log += c));
  return d;
}

const login = (name, email, device) => cli(name, ['login', '--server', relay.url, '--email', email, '--device', device, '--password-stdin'], { stdin: PASSWORD });

/** Approve the oldest pending device request the way the website does, from an already signed-in browser. */
async function webApprove(browser, userCode) {
  const { sealForDevice } = await import('../shared/crypto.js');
  const req = await browser.api.call('POST', '/api/v1/device/lookup', { userCode });
  await browser.api.call('POST', '/api/v1/device/approve', { userCode, sealed: await sealForDevice(req.pub, browser.vaultKey) });
}

test('copy on one machine, paste on another (two signed-in daemons), no ping-pong', async () => {
  const api = createApi({ server: relay.url });
  const res = await signup(api, { email: 'e2e@example.com', password: PASSWORD, device: 'site', platform: 'web', client: 'cli' });
  const web = { api: createApi({ server: relay.url, token: res.token }), vaultKey: res.vaultKey };

  await login('win', 'e2e@example.com', 'win');
  await login('lin', 'e2e@example.com', 'lin');
  assert.match(readFileSync(join(dir, 'win.json'), 'utf8'), /"token": "uc_/);
  assert.equal((statSync(join(dir, 'win.json')).mode & 0o077), 0, 'config is private (0600)');
  setClip('win', '');
  setClip('lin', '');

  const d = { win: daemon('win'), lin: daemon('lin') };
  await d.win.waitFor(/connection: online/);
  await d.lin.waitFor(/connection: online/);

  setClip('win', 'copied on windows 🪟');
  await until(() => clip('lin') === 'copied on windows 🪟');
  setClip('lin', 'copied on linux 🐧');
  await until(() => clip('win') === 'copied on linux 🐧');

  await new Promise((r) => setTimeout(r, 600));
  assert.equal((await cli('win', ['history'])).trim().split('\n').length, 2, 'exactly two items: no echo loop');

  await cli('lin', ['copy', 'via cli']);
  assert.equal(await cli('win', ['paste']), 'via cli');
  assert.match(await cli('win', ['whoami']), /e2e@example.com/);
  assert.match(await cli('win', ['devices']), /lin/);

  // ---- session-only behaviour ----
  // 1. Revoking a device on the website stops it immediately: its clipboard is no longer touched, in either direction.
  const { sessions } = await createClient({ server: relay.url, token: res.token, key: await importVaultKey(res.vaultKey), device: 'site' }).sessions();
  const linId = sessions.find((s) => s.device === 'lin').id;
  await web.api.call('DELETE', `/api/v1/sessions/${linId}`);
  await d.lin.waitFor(/session inactive/);
  assert.ok(!('token' in config('lin')), 'revoked device wiped its token');
  assert.ok(!('vaultKey' in config('lin')), 'revoked device wiped its vault key');

  const before = clip('lin');
  setClip('win', 'after revoke from windows');
  await new Promise((r) => setTimeout(r, 800));
  assert.equal(clip('lin'), before, 'revoked device does not receive new clips');
  setClip('lin', 'copied while signed out');
  await new Promise((r) => setTimeout(r, 800));
  assert.ok(!(await cli('win', ['history', '-n', '20'])).includes('copied while signed out'), 'signed-out device does not upload');
  assert.match(await cli('lin', ['paste']).catch((e) => e.message), /Not signed in/);

  // 2. Signing in again resumes the same daemon automatically, and never uploads what was already on the clipboard.
  setClip('lin', 'stale text from before login');
  await login('lin', 'e2e@example.com', 'lin');
  await d.lin.waitFor(/session active for/, 2);
  await d.lin.waitFor(/connection: online/, 2);
  await new Promise((r) => setTimeout(r, 500));
  assert.ok(!(await cli('win', ['history', '-n', '20'])).includes('stale text'), 'pre-login clipboard is not uploaded');
  setClip('win', 'back in business');
  await until(() => clip('lin') === 'back in business');

  // 3. `uclip logout` ends the session on the server and silences the daemon.
  await cli('lin', ['logout']);
  await d.lin.waitFor(/session inactive/, 2);
  assert.ok(!('token' in config('lin')));
  setClip('win', 'after logout');
  await new Promise((r) => setTimeout(r, 600));
  assert.equal(clip('lin'), 'back in business');
  assert.match(await cli('win', ['devices']), /win/);
  assert.ok(!(await cli('win', ['devices'])).includes('lin '), 'logged-out device is gone from the device list');
  void webApprove;
});

test('device-approval login: uclip login shows a code, the website approves it', async () => {
  const api = createApi({ server: relay.url });
  const res = await signup(api, { email: 'approve@example.com', password: PASSWORD, device: 'site', platform: 'web', client: 'cli' });
  const web = { api: createApi({ server: relay.url, token: res.token }), vaultKey: res.vaultKey };

  const p = spawn('node', [CLI, 'login', '--server', relay.url, '--device', 'new-laptop'], { env: env('approved') });
  procs.push(p);
  let out = '';
  p.stdout.on('data', (c) => (out += c));
  p.stderr.on('data', (c) => (out += c));
  const code = await until(() => /confirm this code: ([A-Z0-9]{4}-[A-Z0-9]{4})/.exec(out)?.[1]);
  assert.match(out, new RegExp(`${relay.url}/device\\?code=${code}`));
  await webApprove(web, code);
  await until(() => /Signed in as approve@example.com/.test(out), 10_000);

  setClip('approved', '');
  const d = daemon('approved');
  await d.waitFor(/connection: online/);
  await createClient({ server: relay.url, token: res.token, key: await importVaultKey(res.vaultKey), device: 'site' }).pushText('hello approved device');
  await until(() => clip('approved') === 'hello approved device');
});

