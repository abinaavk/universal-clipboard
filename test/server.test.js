import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { clientFor, startRelay, until } from './helpers.js';

const relay = await startRelay({ maxItems: 5 });
after(() => relay.close());

test('rejects missing/malformed auth', async () => {
  for (const headers of [{}, { authorization: 'Bearer nope' }]) {
    const res = await fetch(`${relay.url}/api/v1/items`, { headers });
    assert.equal(res.status, 401);
  }
});

test('two devices in one vault sync; a different vault sees nothing', async () => {
  const { client: laptop } = await clientFor(relay.url, 'vault-A', 'laptop');
  const { client: phone } = await clientFor(relay.url, 'vault-A', 'phone');
  const { client: stranger } = await clientFor(relay.url, 'vault-B', 'stranger');

  await laptop.pushText('hello from laptop');
  const { items } = await phone.list();
  assert.equal(items.length, 1);
  assert.equal(items[0].text, 'hello from laptop');
  assert.equal(items[0].device, 'laptop');
  assert.equal((await stranger.list()).items.length, 0);
});

test('server stores only ciphertext', async () => {
  const { client } = await clientFor(relay.url, 'vault-C', 'x');
  await client.pushText('super-secret-needle');
  await new Promise((r) => setTimeout(r, 400)); // allow debounced save
  const raw = readFileSync(join(relay.dataDir, 'vaults.json'), 'utf8');
  assert.ok(!raw.includes('super-secret-needle'));
  assert.ok(!raw.includes('"x"'));
});

test('live push over SSE, with resume via since', async () => {
  const { client: a } = await clientFor(relay.url, 'vault-D', 'a');
  const { client: b } = await clientFor(relay.url, 'vault-D', 'b');
  const got = [];
  const stop = b.subscribe({ since: 0, onItem: (i) => got.push(i.text) });
  await until(() => true);
  await a.pushText('one');
  await a.pushText('two');
  await until(() => got.length === 2);
  assert.deepEqual(got, ['one', 'two']);
  stop();

  await a.pushText('three');
  const later = [];
  const stop2 = b.subscribe({ since: 2, onItem: (i) => later.push(i.text) });
  await until(() => later.length === 1);
  assert.deepEqual(later, ['three']);
  stop2();
});

test('delete, clear, and retention cap', async () => {
  const { client } = await clientFor(relay.url, 'vault-E', 'e');
  const ids = [];
  for (let i = 0; i < 8; i++) ids.push((await client.pushText(`n${i}`)).id);
  let { items } = await client.list();
  assert.deepEqual(items.map((i) => i.text), ['n3', 'n4', 'n5', 'n6', 'n7']);
  await client.remove(ids[7]);
  ({ items } = await client.list());
  assert.equal(items.length, 4);
  await client.clear();
  assert.equal((await client.list()).items.length, 0);
});

test('duplicate ids are idempotent', async () => {
  const { token } = await clientFor(relay.url, 'vault-F', 'f');
  const post = () =>
    fetch(`${relay.url}/api/v1/items`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ id: 'same', nonce: 'n', ct: 'c' }),
    });
  assert.equal((await post()).status, 201);
  assert.equal((await post()).status, 200);
  const list = await (await fetch(`${relay.url}/api/v1/items`, { headers: { authorization: `Bearer ${token}` } })).json();
  assert.equal(list.items.length, 1);
});

test('oversized bodies are rejected', async () => {
  const small = await startRelay({ maxBodyBytes: 100 });
  try {
    const { token } = await clientFor(small.url, 'vault-G', 'g');
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

test('invite code gates new vaults but not existing ones', async () => {
  const gated = await startRelay({ inviteCode: 'letmein' });
  try {
    const { token } = await clientFor(gated.url, 'vault-H', 'h');
    const call = (headers) => fetch(`${gated.url}/api/v1/items`, { headers: { authorization: `Bearer ${token}`, ...headers } });
    assert.equal((await call({})).status, 403);
    assert.equal((await call({ 'x-invite-code': 'letmein' })).status, 200);
    assert.equal((await call({})).status, 200);
  } finally {
    await gated.close();
  }
});

test('static files are served and path traversal is blocked', async () => {
  assert.equal((await fetch(`${relay.url}/`)).status, 200);
  assert.equal((await fetch(`${relay.url}/shared/crypto.js`)).status, 200);
  const res = await fetch(`${relay.url}/..%2fpackage.json`);
  assert.notEqual(res.status, 200);
  assert.equal((await fetch(`${relay.url}/..%2fserver%2fserver.js`)).status === 200, false);
});
