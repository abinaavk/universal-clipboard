import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  decryptPayload,
  deriveFromPassphrase,
  deriveFromPassword,
  encryptPayload,
  generateDeviceKeyPair,
  generatePassphrase,
  importVaultKey,
  newVaultKeyBytes,
  openFromApprover,
  sealForDevice,
  unwrapVaultKey,
  wrapVaultKey,
} from '../shared/crypto.js';

test('passphrases are well-formed and unique', () => {
  const a = generatePassphrase();
  assert.match(a, /^([a-z2-9]{5}-){7}[a-z2-9]{5}$/);
  assert.notEqual(a, generatePassphrase());
});

test('password derivation: stable, email-normalised, authKey independent of the wrapping key', async () => {
  const a = await deriveFromPassword('hunter2hunter2', 'Me@Example.com');
  const b = await deriveFromPassword('hunter2hunter2', ' me@example.com ');
  const c = await deriveFromPassword('another password', 'me@example.com');
  assert.equal(a.authKey, b.authKey);
  assert.notEqual(a.authKey, c.authKey);
  assert.match(a.authKey, /^[0-9a-f]{64}$/);
  // A KEK from the same password can unwrap what another derivation wrapped
  const raw = newVaultKeyBytes();
  const wrap = await wrapVaultKey(a.kek, raw);
  assert.deepEqual(await unwrapVaultKey(b.kek, wrap), raw);
  await assert.rejects(unwrapVaultKey(c.kek, wrap));
});

test('vault key round trip and tamper detection', async () => {
  const key = await importVaultKey(newVaultKeyBytes());
  const sealed = await encryptPayload(key, { text: 'héllo 🌍', device: 'x' });
  assert.deepEqual(await decryptPayload(key, sealed), { text: 'héllo 🌍', device: 'x' });
  const flipped = { ...sealed, ct: sealed.ct.slice(0, -4) + (sealed.ct.endsWith('AAAA') ? 'BBBB' : 'AAAA') };
  await assert.rejects(decryptPayload(key, flipped));
  await assert.rejects(decryptPayload(await importVaultKey(newVaultKeyBytes()), sealed));
});

test('passphrase wrap is bound to the user id', async () => {
  const a = await deriveFromPassphrase('abcde-fghjk', 'user1');
  const b = await deriveFromPassphrase('abcde-fghjk', 'user2');
  const wrap = await wrapVaultKey(a.kek, newVaultKeyBytes());
  await assert.rejects(unwrapVaultKey(b.kek, wrap));
});

test('device approval: only the device holding the private key can open the sealed vault key', async () => {
  const device = await generateDeviceKeyPair();
  const attacker = await generateDeviceKeyPair();
  const raw = newVaultKeyBytes();
  const sealed = await sealForDevice(device.publicKey, raw);
  assert.deepEqual(await openFromApprover(device.privateKey, sealed), raw);
  await assert.rejects(openFromApprover(attacker.privateKey, sealed));
});
