import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { createPassphraseWrap, passphraseChangeBody, passwordChangeBody, resetBody, unlock } from '../shared/auth.js';
import { createApi, createClient } from '../shared/client.js';
import { generateDeviceKeyPair, importVaultKey, openFromApprover, sealForDevice, deriveFromPassword } from '../shared/crypto.js';
import { PASSWORD, deviceFor, rejects, startRelay, until } from './helpers.js';

const relay = await startRelay({ maxItems: 5 });
after(() => relay.close());
const anon = () => createApi({ server: relay.url });

test('API requires authentication', async () => {
  for (const headers of [{}, { authorization: 'Bearer nope' }, { authorization: 'Bearer uc_' + 'a'.repeat(43) }]) {
    const res = await fetch(`${relay.url}/api/v1/items`, { headers });
    assert.equal(res.status, 401);
  }
});

test('two devices on one account sync; another account sees nothing; wrong password is rejected', async () => {
  const laptop = await deviceFor(relay.url, 'a@example.com', 'laptop', { create: true });
  const phone = await deviceFor(relay.url, 'a@example.com', 'phone');
  const stranger = await deviceFor(relay.url, 'b@example.com', 'stranger', { create: true });

  await laptop.client.pushText('hello from laptop');
  const { items } = await phone.client.list();
  assert.equal(items.length, 1);
  assert.equal(items[0].text, 'hello from laptop');
  assert.equal(items[0].device, 'laptop');
  assert.equal((await stranger.client.list()).items.length, 0);

  await assert.rejects(deviceFor(relay.url, 'a@example.com', 'thief', { password: 'wrong password here' }), /wrong email or password/);
  await rejects(anon().call('POST', '/api/v1/auth/signup', { email: 'a@example.com', authKey: '0'.repeat(64), wrap: { kind: 'password', nonce: 'AAAA', ct: 'AAAA' } }), 409, 'email_taken');
  await rejects(anon().call('POST', '/api/v1/auth/login', { email: 'nobody@example.com', authKey: '1'.repeat(64) }), 401, 'invalid_credentials');
});

test('server stores no password, no vault key and no clipboard text', async () => {
  const d = await deviceFor(relay.url, 'c@example.com', 'x', { create: true });
  await d.client.pushText('super-secret-needle');
  await new Promise((r) => setTimeout(r, 400)); // debounced save
  const raw = readFileSync(join(relay.dataDir, 'db.json'), 'utf8');
  const { authKey } = await deriveFromPassword(PASSWORD, 'c@example.com');
  for (const secret of ['super-secret-needle', PASSWORD, authKey, Buffer.from(d.vaultKey).toString('base64'), d.token]) assert.ok(!raw.includes(secret), `leaked ${secret.slice(0, 8)}…`);
  assert.ok(raw.includes('"auth":{"salt"'), 'authKey is stored only as a salted scrypt hash');
});

test('live push over SSE with resume; revoking a session ends its stream immediately', async () => {
  const a = await deviceFor(relay.url, 'd@example.com', 'a', { create: true });
  const b = await deviceFor(relay.url, 'd@example.com', 'b');
  const got = [];
  const statuses = [];
  const stop = b.client.subscribe({ since: 0, onItem: (i) => got.push(i.text), onStatus: (s) => statuses.push(s) });
  await until(() => statuses.includes('online'));
  await a.client.pushText('one');
  await a.client.pushText('two');
  await until(() => got.length === 2);
  assert.deepEqual(got, ['one', 'two']);
  stop();

  await a.client.pushText('three');
  const later = [];
  const stop2 = b.client.subscribe({ since: 2, onItem: (i) => later.push(i.text) });
  await until(() => later.length === 1);
  assert.deepEqual(later, ['three']);
  stop2();

  const live = [];
  b.client.subscribe({ since: 99, onItem: () => {}, onStatus: (s) => live.push(s) });
  await until(() => live.includes('online'));
  const { sessions } = await a.client.sessions();
  assert.equal(sessions.length, 2);
  assert.ok(sessions.find((s) => s.device === 'b').online);
  await a.client.revokeSession(sessions.find((s) => s.device === 'b').id);
  await until(() => live.includes('ended'));
  await rejects(b.client.list(), 401, 'session_ended');
  assert.equal((await a.client.list()).items.length, 3, 'other device is unaffected');
});

test('logout, revoke-others and session listing', async () => {
  const a = await deviceFor(relay.url, 'e@example.com', 'a', { create: true });
  const b = await deviceFor(relay.url, 'e@example.com', 'b');
  const c = await deviceFor(relay.url, 'e@example.com', 'c');
  await a.api.call('DELETE', '/api/v1/sessions');
  await rejects(b.client.list(), 401);
  await rejects(c.client.list(), 401);
  await a.client.list();
  await a.api.call('POST', '/api/v1/auth/logout');
  await rejects(a.client.list(), 401);
});

test('delete, clear, retention cap, idempotent ids', async () => {
  const { client, token } = await deviceFor(relay.url, 'f@example.com', 'f', { create: true });
  const ids = [];
  for (let i = 0; i < 8; i++) ids.push((await client.pushText(`n${i}`)).id);
  let { items } = await client.list();
  assert.deepEqual(items.map((i) => i.text), ['n3', 'n4', 'n5', 'n6', 'n7']);
  await client.remove(ids[7]);
  ({ items } = await client.list());
  assert.equal(items.length, 4);
  await client.clear();
  assert.equal((await client.list()).items.length, 0);

  const post = () => fetch(`${relay.url}/api/v1/items`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ id: 'same', nonce: 'n', ct: 'c' }) });
  assert.equal((await post()).status, 201);
  assert.equal((await post()).status, 200);
});

test('oversized bodies are rejected', async () => {
  const small = await startRelay({ maxBodyBytes: 100 });
  try {
    const { token } = await deviceFor(small.url, 'g@example.com', 'g', { create: true });
    const res = await fetch(`${small.url}/api/v1/items`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ id: 'x', nonce: 'n', ct: 'c'.repeat(500) }),
    }).catch(() => ({ status: 413 }));
    assert.equal(res.status, 413);
  } finally {
    await small.close();
  }
});

test('invite code gates sign-up; closed sign-ups refuse everyone', async () => {
  const gated = await startRelay({ inviteCode: 'letmein' });
  try {
    const api = createApi({ server: gated.url });
    const body = { email: 'h@example.com', authKey: '2'.repeat(64), wrap: { kind: 'password', nonce: 'AAAA', ct: 'AAAA' } };
    await rejects(api.call('POST', '/api/v1/auth/signup', body), 403, 'invite_required');
    await rejects(api.call('POST', '/api/v1/auth/signup', { ...body, inviteCode: 'nope' }), 403, 'invite_required');
    await api.call('POST', '/api/v1/auth/signup', { ...body, inviteCode: 'letmein' });
  } finally {
    await gated.close();
  }
  const closed = await startRelay({ signups: 'closed' });
  try {
    await rejects(createApi({ server: closed.url }).call('POST', '/api/v1/auth/signup', { email: 'i@example.com', authKey: '3'.repeat(64), wrap: { kind: 'password', nonce: 'AAAA', ct: 'AAAA' } }), 403, 'signups_closed');
  } finally {
    await closed.close();
  }
});

test('email verification gates the clipboard when required', async () => {
  const r = await startRelay({ requireVerifiedEmail: true });
  try {
    const d = await deviceFor(r.url, 'v@example.com', 'v', { create: true });
    await rejects(d.client.list(), 403, 'email_not_verified');
    assert.equal((await d.client.account()).user.emailVerified, false);
    await rejects(createApi({ server: r.url }).call('POST', '/api/v1/auth/verify', { token: 'bogus' }), 400, 'invalid_token');
    const token = r.mailToken('v@example.com', 'confirm');
    assert.ok(token, 'verification mail was sent');
    await createApi({ server: r.url }).call('POST', '/api/v1/auth/verify', { token });
    await d.client.list();
    await rejects(createApi({ server: r.url }).call('POST', '/api/v1/auth/verify', { token }), 400, 'invalid_token'); // single use
  } finally {
    await r.close();
  }
});

test('forgot + reset: same answer for unknown emails, resets keys, wipes items, ends sessions', async () => {
  const d = await deviceFor(relay.url, 'r@example.com', 'r', { create: true });
  await d.client.pushText('before reset');
  const before = relay.mails.length;
  assert.deepEqual(await anon().call('POST', '/api/v1/auth/forgot', { email: 'ghost@example.com' }), { ok: true });
  assert.equal(relay.mails.length, before, 'no mail for unknown account');
  await anon().call('POST', '/api/v1/auth/forgot', { email: 'r@example.com' });
  await until(() => relay.mailToken('r@example.com', 'reset'));
  const token = relay.mailToken('r@example.com', 'reset');
  assert.equal((await anon().call('POST', '/api/v1/auth/reset/inspect', { token })).email, 'r@example.com');
  await anon().call('POST', '/api/v1/auth/reset', { token, ...(await resetBody('r@example.com', 'a brand new password')) });
  await rejects(anon().call('POST', '/api/v1/auth/reset', { token, ...(await resetBody('r@example.com', 'a brand new password')) }), 400, 'invalid_token');
  await rejects(d.client.list(), 401);
  await assert.rejects(deviceFor(relay.url, 'r@example.com', 'r2'), /wrong email or password/);
  const again = await deviceFor(relay.url, 'r@example.com', 'r2', { password: 'a brand new password' });
  assert.equal((await again.client.list()).items.length, 0);
  await again.client.pushText('works');
});

test('password change keeps the vault key, ends other sessions', async () => {
  const a = await deviceFor(relay.url, 'p@example.com', 'a', { create: true });
  const b = await deviceFor(relay.url, 'p@example.com', 'b');
  await a.client.pushText('survives');
  const { user, wrap } = await a.client.account();
  await rejects(a.api.call('POST', '/api/v1/account/password', { ...(await passwordChangeBody(user, wrap, PASSWORD, 'new password 12345')), authKey: '4'.repeat(64) }), 401, 'invalid_credentials');
  await a.api.call('POST', '/api/v1/account/password', await passwordChangeBody(user, wrap, PASSWORD, 'new password 12345'));
  await rejects(b.client.list(), 401);
  const c = await deviceFor(relay.url, 'p@example.com', 'c', { password: 'new password 12345' });
  assert.equal((await c.client.list()).items[0].text, 'survives');
});

test('device approval hands the vault key to a CLI without the server seeing it', async () => {
  const browser = await deviceFor(relay.url, 'dev@example.com', 'browser', { create: true });
  await browser.client.pushText('already here');
  const pair = await generateDeviceKeyPair();
  const api = anon();
  const start = await api.call('POST', '/api/v1/device/start', { device: 'new box', platform: 'windows', pub: pair.publicKey });
  await rejects(api.call('POST', '/api/v1/device/token', { deviceCode: start.deviceCode }), 400, 'authorization_pending');
  const found = await browser.api.call('POST', '/api/v1/device/lookup', { userCode: start.userCode.toLowerCase() });
  assert.deepEqual([found.device, found.platform, found.pub], ['new box', 'windows', pair.publicKey]);
  const sealed = await sealForDevice(found.pub, browser.vaultKey);
  await browser.api.call('POST', '/api/v1/device/approve', { userCode: start.userCode, sealed });
  const res = await api.call('POST', '/api/v1/device/token', { deviceCode: start.deviceCode });
  const vaultKey = await openFromApprover(pair.privateKey, res.sealed);
  const cli = createClient({ server: relay.url, token: res.token, key: await importVaultKey(vaultKey), device: 'new box' });
  assert.equal((await cli.list()).items[0].text, 'already here');
  await rejects(api.call('POST', '/api/v1/device/token', { deviceCode: start.deviceCode }), 400, 'expired_token'); // single use
  assert.ok(!JSON.stringify(res).includes(Buffer.from(browser.vaultKey).toString('base64')));

  const second = await api.call('POST', '/api/v1/device/start', { device: 'evil', platform: 'linux', pub: pair.publicKey });
  await browser.api.call('POST', '/api/v1/device/approve', { userCode: second.userCode, deny: true });
  await rejects(api.call('POST', '/api/v1/device/token', { deviceCode: second.deviceCode }), 400, 'access_denied');
  await rejects(anon().call('POST', '/api/v1/device/lookup', { userCode: start.userCode }), 401);
});

test('browser sessions use an HttpOnly cookie and are CSRF-protected', async () => {
  const web = createApi({ server: relay.url, web: true });
  const authKey = (await deriveFromPassword(PASSWORD, 'w@example.com')).authKey;
  const res = await fetch(`${relay.url}/api/v1/auth/signup`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'w@example.com', authKey, wrap: { kind: 'password', nonce: 'AAAA', ct: 'AAAA' }, client: 'web', device: 'Chrome' }),
  });
  assert.equal(res.status, 201);
  const setCookie = res.headers.get('set-cookie');
  assert.match(setCookie, /^uc_session=uc_[\w-]+; Path=\/; HttpOnly; SameSite=Strict/);
  assert.equal((await res.json()).token, undefined, 'no token in the body for browsers');
  const cookie = setCookie.split(';')[0];

  const get = await fetch(`${relay.url}/api/v1/account`, { headers: { cookie } });
  assert.equal(get.status, 200);
  const noHeader = await fetch(`${relay.url}/api/v1/items`, { method: 'DELETE', headers: { cookie } });
  assert.equal(noHeader.status, 403);
  const crossOrigin = await fetch(`${relay.url}/api/v1/items`, { method: 'DELETE', headers: { cookie, 'x-uc-csrf': '1', origin: 'https://evil.example' } });
  assert.equal(crossOrigin.status, 403);
  const ok = await fetch(`${relay.url}/api/v1/items`, { method: 'DELETE', headers: { cookie, 'x-uc-csrf': '1', origin: relay.url } });
  assert.equal(ok.status, 204);
  void web;
});

test('account deletion needs the email (and password) and removes everything', async () => {
  const d = await deviceFor(relay.url, 'del@example.com', 'd', { create: true });
  await d.client.pushText('bye');
  await rejects(d.api.call('POST', '/api/v1/account/delete', { confirmEmail: 'wrong@example.com' }), 400, 'confirm_email');
  const { authKey } = await deriveFromPassword(PASSWORD, 'del@example.com');
  await rejects(d.api.call('POST', '/api/v1/account/delete', { confirmEmail: 'del@example.com', authKey: '5'.repeat(64) }), 401);
  await d.api.call('POST', '/api/v1/account/delete', { confirmEmail: 'del@example.com', authKey });
  await rejects(d.client.list(), 401);
  await assert.rejects(deviceFor(relay.url, 'del@example.com', 'again'), /wrong email or password/);
  await deviceFor(relay.url, 'del@example.com', 'again', { create: true }); // address is free again
});

// ---- Google ------------------------------------------------------------------------------------

test('Google sign-in: state/cookie binding, ticket exchange, passphrase key setup, verified-email linking', async () => {
  let claims;
  const google = createServer((req, res) => {
    const idToken = ['x', Buffer.from(JSON.stringify(claims)).toString('base64url'), 'y'].join('.');
    req.resume();
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ id_token: idToken }));
  });
  await new Promise((r) => google.listen(0, '127.0.0.1', r));
  const r = await startRelay({ googleClientId: 'cid', googleClientSecret: 'sec', googleTokenUrl: `http://127.0.0.1:${google.address().port}/token`, googleAuthUrl: 'https://accounts.example/auth' });
  const claimsFor = (email, sub, extra = {}) => ({ aud: 'cid', iss: 'https://accounts.google.com', exp: Math.floor(Date.now() / 1000) + 600, sub, email, email_verified: true, name: 'Gina', ...extra });

  let oauthCookie = '';
  async function googleLogin(cookieOverride) {
    const start = await fetch(`${r.url}/api/v1/auth/google/start`, { redirect: 'manual' });
    assert.equal(start.status, 302);
    const loc = new URL(start.headers.get('location'));
    assert.equal(loc.origin + loc.pathname, 'https://accounts.example/auth');
    assert.equal(loc.searchParams.get('code_challenge_method'), 'S256');
    assert.equal(loc.searchParams.get('client_id'), 'cid');
    const state = loc.searchParams.get('state');
    const cookie = cookieOverride ?? start.headers.get('set-cookie').split(';')[0];
    oauthCookie = cookie;
    const cb = await fetch(`${r.url}/api/v1/auth/google/callback?code=abc&state=${state}`, { redirect: 'manual', headers: { cookie } });
    return new URL(cb.headers.get('location'), r.url).hash.slice(1);
  }
  const exchange = async (ticket, cookie = oauthCookie) => {
    const res = await fetch(`${r.url}/api/v1/auth/google/exchange`, { method: 'POST', headers: { 'content-type': 'application/json', cookie }, body: JSON.stringify({ ticket, device: 'Firefox', platform: 'linux' }) });
    return { res, body: await res.json() };
  };

  try {
    assert.equal((await createApi({ server: r.url }).call('GET', '/api/v1/auth/providers')).google, true);

    // A browser that did not start the flow (missing/foreign cookie) cannot complete it.
    assert.equal(await googleLogin('uc_oauth=forged'), 'error=google_failed');

    // New Google user: no wrapped key yet -> client creates a clipboard passphrase
    claims = claimsFor('gina@example.com', 'sub-1');
    const frag = await googleLogin();
    const ticket = new URLSearchParams(frag).get('ticket');
    assert.ok(ticket);
    // A ticket is useless to any browser other than the one that started the flow (login CSRF / leaked-ticket defence)
    assert.equal((await exchange(ticket, 'uc_oauth=other')).res.status, 400);
    claims = claimsFor('gina@example.com', 'sub-1');
    const again = await googleLogin();
    const ticket2 = new URLSearchParams(again).get('ticket');
    const first = await exchange(ticket2);
    assert.equal(first.res.status, 200);
    assert.equal(first.body.wrap, null);
    assert.equal(first.body.user.emailVerified, true);
    assert.equal(first.body.user.hasPassword, false);
    assert.equal((await exchange(ticket2)).res.status, 400, 'ticket is single use');
    const cookie = first.res.headers.get('set-cookie').split(';')[0];
    const web = (method, path, body) => fetch(r.url + path, { method, headers: { cookie, 'content-type': 'application/json', 'x-uc-csrf': '1' }, body: body && JSON.stringify(body) });

    const { wrap, authKey, vaultKey } = await createPassphraseWrap(first.body.user, 'abcde-fghjk-mnpqr');
    assert.equal((await web('POST', '/api/v1/account/key', { wrap, authKey })).status, 204);
    // Replacing the key needs proof of the current passphrase: a stolen session alone cannot lock the owner out
    const other = await createPassphraseWrap(first.body.user, 'zzzzz-yyyyy-xxxxx');
    assert.equal((await web('POST', '/api/v1/account/key', { wrap: other.wrap, authKey: other.authKey })).status, 401);
    assert.equal((await web('POST', '/api/v1/account/key', { wrap: other.wrap, authKey: other.authKey, oldAuthKey: other.authKey })).status, 401);
    const change = await passphraseChangeBody(first.body.user, wrap, 'abcde-fghjk-mnpqr', 'newer-passphrase-12');
    assert.equal((await web('POST', '/api/v1/account/key', change)).status, 204);
    assert.deepEqual(Buffer.from(await unlock(change.wrap, first.body.user, 'newer-passphrase-12')), Buffer.from(vaultKey), 'same vault key, new wrap');
    assert.equal((await web('POST', '/api/v1/account/key', { wrap, authKey })).status, 401, 'old passphrase no longer authorises');
    await assert.rejects(passphraseChangeBody(first.body.user, change.wrap, 'newer-passphrase-12', 'short'), /at least 10/i);
    const acct = await (await web('GET', '/api/v1/account')).json();
    assert.deepEqual(Buffer.from(await unlock(acct.wrap, acct.user, 'newer-passphrase-12')), Buffer.from(vaultKey));
    await assert.rejects(unlock(acct.wrap, acct.user, 'wrong-passphrase'), /Wrong clipboard passphrase/);

    // Second sign-in on another browser returns the same wrapped key
    const second = await exchange(new URLSearchParams(await googleLogin()).get('ticket'));
    assert.deepEqual(second.body.wrap, change.wrap);

    // Google signs in to an existing *verified* password account: linked, wrapped key stays password-based
    const pw = await deviceFor(r.url, 'link@example.com', 'pc', { create: true });
    await createApi({ server: r.url }).call('POST', '/api/v1/auth/verify', { token: r.mailToken('link@example.com', 'confirm') });
    claims = claimsFor('link@example.com', 'sub-2');
    const linked = await exchange(new URLSearchParams(await googleLogin()).get('ticket'));
    assert.equal(linked.body.user.id, pw.res.user.id);
    assert.equal(linked.body.user.hasPassword, true);
    assert.equal(linked.body.wrap.kind, 'password');

    // An unverified password squatter on a mailbox is replaced when the real owner signs in with Google
    await deviceFor(r.url, 'squat@example.com', 'attacker', { create: true });
    claims = claimsFor('squat@example.com', 'sub-3');
    const owner = await exchange(new URLSearchParams(await googleLogin()).get('ticket'));
    assert.equal(owner.body.user.hasPassword, false);
    await assert.rejects(deviceFor(r.url, 'squat@example.com', 'attacker2'), /wrong email or password/);

    // Unverified Google email, wrong audience: rejected
    claims = claimsFor('x@example.com', 'sub-4', { email_verified: false });
    assert.equal(await googleLogin(), 'error=google_failed');
    claims = claimsFor('x@example.com', 'sub-4', { aud: 'someone-else' });
    assert.equal(await googleLogin(), 'error=google_failed');
  } finally {
    await r.close();
    await new Promise((res) => google.close(res));
  }
});

test('Google endpoints are off when not configured', async () => {
  assert.equal((await anon().call('GET', '/api/v1/auth/providers')).google, false);
  assert.equal((await fetch(`${relay.url}/api/v1/auth/google/start`, { redirect: 'manual' })).status, 404);
});

// ---- hardening / website -------------------------------------------------------------------------

test('rate limits: brute-forcing one account is throttled', async () => {
  const r = await startRelay({ rateLimit: true });
  try {
    const api = createApi({ server: r.url });
    let last;
    for (let i = 0; i < 12; i++) last = await api.call('POST', '/api/v1/auth/login', { email: 'victim@example.com', authKey: String(i % 10).repeat(64) }).catch((e) => e);
    assert.equal(last.status, 429);
    assert.equal(last.code, 'rate_limited');
  } finally {
    await r.close();
  }
});

test('security headers, HSTS only over https, CORS closed', async () => {
  const res = await fetch(`${relay.url}/`);
  assert.match(res.headers.get('content-security-policy'), /default-src 'self'.*script-src 'self'.*frame-ancestors 'none'/);
  assert.doesNotMatch(res.headers.get('content-security-policy'), /unsafe-inline|unsafe-eval/);
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('x-frame-options'), 'DENY');
  assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(res.headers.get('strict-transport-security'), null);
  assert.equal(res.headers.get('access-control-allow-origin'), null);
  const https = await startRelay({ publicUrl: 'https://uclip.example' });
  try {
    assert.match((await fetch(`${https.url}/`)).headers.get('strict-transport-security'), /max-age=\d+; includeSubDomains/);
  } finally {
    await https.close();
  }
});

test('website pages, SEO files, OpenAPI and 404', async () => {
  const page = async (path, headers = {}) => {
    const res = await fetch(relay.url + path, { headers });
    return { res, text: await res.text() };
  };
  for (const path of ['/', '/docs', '/privacy', '/terms', '/security']) {
    const { res, text } = await page(path);
    assert.equal(res.status, 200, path);
    assert.match(res.headers.get('content-type'), /text\/html/);
    assert.match(text, /<title>[^<]+<\/title>/);
    assert.match(text, /<meta name="description" content="[^"]{40,}/);
    assert.match(text, /<link rel="canonical" href="http:\/\/127\.0\.0\.1/);
    assert.doesNotMatch(text, /\{\{ORIGIN\}\}/);
  }
  const home = (await page('/')).text;
  assert.match(home, /property="og:image"/);
  assert.match(home, /application\/ld\+json/);
  assert.doesNotMatch(home, /<script(?![^>]*\bsrc=)(?![^>]*ld\+json)[^>]*>/, 'no inline scripts (CSP)');

  for (const path of ['/app', '/login', '/signup', '/reset', '/verify', '/device']) {
    const { res } = await page(path);
    assert.equal(res.status, 200, path);
    assert.match(res.headers.get('x-robots-tag'), /noindex/);
  }
  const robots = (await page('/robots.txt')).text;
  assert.match(robots, /Sitemap: http:\/\/127\.0\.0\.1\/sitemap\.xml/);
  assert.match(robots, /Disallow: \/app/);
  const sitemap = (await page('/sitemap.xml')).text;
  assert.match(sitemap, /<loc>http:\/\/127\.0\.0\.1\/<\/loc>/);
  assert.doesNotMatch(sitemap, /\/app</);
  assert.match((await page('/.well-known/security.txt')).text, /^Contact: /m);
  assert.equal((await page('/og.png')).res.headers.get('content-type'), 'image/png');
  assert.equal((await page('/manifest.webmanifest')).res.status, 200);

  const spec = JSON.parse((await page('/api/v1/openapi.json')).text);
  assert.equal(spec.openapi, '3.1.0');
  for (const p of ['/api/v1/auth/login', '/api/v1/items', '/api/v1/device/approve']) assert.ok(spec.paths[p], p);

  const etag = (await page('/')).res.headers.get('etag');
  assert.equal((await page('/', { 'if-none-match': etag })).res.status, 304);
  const gz = await fetch(`${relay.url}/docs`, { headers: { 'accept-encoding': 'gzip' } });
  assert.equal(gz.headers.get('content-encoding'), 'gzip');

  const missing = await page('/nope');
  assert.equal(missing.res.status, 404);
  assert.match(missing.text, /<title>[^<]*Not found/i);
  assert.equal((await page('/api/v1/nope')).res.status, 404);
  assert.equal((await fetch(`${relay.url}/api/v1/items`, { method: 'PUT' })).status, 405);
});

test('static files: path traversal and internal files are not served', async () => {
  assert.equal((await fetch(`${relay.url}/shared/crypto.js`)).status, 200);
  for (const p of ['/..%2fpackage.json', '/..%2fserver%2fserver.js', '/shared/..%2fserver%2fserver.js', '/%2e%2e/package.json', '/app.html', '/shared/', '/server/server.js']) {
    const res = await fetch(relay.url + p);
    assert.equal(res.status, 404, p);
    assert.doesNotMatch(await res.text(), /createRelay|"name": "universal-clipboard"/);
  }
});

test('installer scripts are served and the Linux/macOS installer really installs a working uclip', async () => {
  const sh = await (await fetch(`${relay.url}/install.sh`)).text();
  assert.match(sh, /^ORIGIN="http:\/\/127\.0\.0\.1"$/m);
  assert.match(await (await fetch(`${relay.url}/install.ps1`)).text(), /\$Origin = 'http:\/\/127\.0\.0\.1'/);
  for (const f of ['cli/uclip.js', 'cli/clipboard.js', 'shared/client.js', 'shared/crypto.js', 'shared/auth.js']) assert.equal((await fetch(`${relay.url}/dl/${f}`)).status, 200, f);
  assert.equal((await fetch(`${relay.url}/dl/cli/..%2fserver%2fserver.js`)).status, 404);
  assert.equal((await fetch(`${relay.url}/dl/shared/..%2fserver%2fserver.js`)).status, 404);

  const home = mkdtempSync(join(tmpdir(), 'uc-install-'));
  try {
    const script = join(home, 'install.sh');
    writeFileSync(script, sh.replaceAll('http://127.0.0.1', relay.url));
    const run = (cmd, args, env = {}) => new Promise((res) => execFile(cmd, args, { env: { ...process.env, HOME: home, ...env } }, (err, stdout, stderr) => res({ err, out: stdout + stderr })));
    const installed = await run('sh', [script]);
    assert.ifError(installed.err);
    const status = await run(join(home, '.local/bin/uclip'), ['status'], { UCLIP_CONFIG: join(home, 'cfg.json'), UCLIP_CLIPBOARD_FILE: join(home, 'clip') });
    assert.ifError(status.err);
    assert.match(status.out, new RegExp(`server:\\s+${relay.url.replaceAll('.', '\\.')}`));
    assert.match(status.out, /session:\s+signed out/);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('concurrent signups for one address create exactly one account', async () => {
  const body = { email: 'race@example.com', authKey: '6'.repeat(64), wrap: { kind: 'password', nonce: 'AAAA', ct: 'AAAA' } };
  const results = await Promise.all(Array.from({ length: 4 }, () => fetch(`${relay.url}/api/v1/auth/signup`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }).then((r) => r.status)));
  assert.deepEqual(results.sort(), [201, 409, 409, 409]);
  assert.equal(Object.values(relay.server.relay.store.data.users).filter((u) => u.email === 'race@example.com').length, 1);
});

test('per-account storage ceiling drops the oldest items first', async () => {
  const small = await startRelay({ maxVaultBytes: 3000 });
  try {
    const { client } = await deviceFor(small.url, 'quota@example.com', 'q', { create: true });
    for (let i = 0; i < 6; i++) await client.pushText(`${i}`.repeat(400));
    const { items } = await client.list();
    assert.ok(items.length < 6 && items.length >= 1);
    assert.equal(items.at(-1).text[0], '5', 'newest survives');
  } finally {
    await small.close();
  }
});

test('ciphertext is bound to its item id (a server cannot re-label items)', async () => {
  const a = await deviceFor(relay.url, 'aad@example.com', 'a', { create: true });
  const sent = await a.client.pushText('bound');
  const raw = relay.server.relay.store.data.items[a.res.user.id].items.find((i) => i.id === sent.id);
  const moved = { ...raw, id: 'another-id' };
  const { decryptPayload } = await import('../shared/crypto.js');
  await assert.rejects(decryptPayload(a.key, moved, moved.id));
  assert.equal((await decryptPayload(a.key, raw, raw.id)).text, 'bound');
});
