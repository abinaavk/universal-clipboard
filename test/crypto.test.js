import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decryptPayload, deriveKeys, encryptPayload, generatePassphrase } from '../shared/crypto.js';

test('encrypt/decrypt round trip, including unicode', async () => {
  const { key } = await deriveKeys('correct horse');
  const payload = { kind: 'text', text: 'héllo 🌍\n\tmultiline', device: 'a' };
  const sealed = await encryptPayload(key, payload);
  assert.ok(!sealed.ct.includes('llo'));
  assert.deepEqual(await decryptPayload(key, sealed), payload);
});

test('wrong passphrase cannot decrypt; tampering is detected', async () => {
  const a = await deriveKeys('passphrase-one');
  const b = await deriveKeys('passphrase-two');
  const sealed = await encryptPayload(a.key, { text: 'secret' });
  await assert.rejects(decryptPayload(b.key, sealed));
  const bytes = Buffer.from(sealed.ct, 'base64');
  bytes[0] ^= 1;
  await assert.rejects(decryptPayload(a.key, { ...sealed, ct: bytes.toString('base64') }));
});

test('derivation is deterministic, whitespace-insensitive, and the token is 64 hex chars', async () => {
  const a = await deriveKeys('abc def');
  const b = await deriveKeys(' abcdef ');
  assert.equal(a.token, b.token);
  assert.match(a.token, /^[0-9a-f]{64}$/);
});

test('generated passphrases are well-formed and unique', () => {
  const p = generatePassphrase();
  assert.match(p, /^([a-z2-9]{5}-){7}[a-z2-9]{5}$/);
  assert.notEqual(p, generatePassphrase());
});
