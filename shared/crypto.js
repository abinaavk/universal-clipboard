// End-to-end encryption helpers. Runs unchanged in browsers and Node (WebCrypto).
//
// Model: every account has one random 256-bit *vault key* that encrypts clipboard items (AES-GCM).
// The server stores that key only in *wrapped* form, encrypted under a key-encryption key (KEK)
// that is derived on the device from a secret the server never sees:
//   - password accounts:   the account password   -> { authKey, kek }
//   - Google-only accounts: a clipboard passphrase -> { kek }
// `authKey` is a second, independent slice of the same derivation. It is what the server verifies
// (it stores only a salted scrypt hash of it), so the password itself never leaves the device.

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

const ITERATIONS = 310_000;
const ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789'; // no look-alike characters

export const MIN_PASSWORD_LENGTH = 10;

export function toHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function toB64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

export function fromB64(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

/** 40 random symbols (~198 bits), grouped for typing: xxxxx-xxxxx-... (8 groups of 5). */
export function generatePassphrase() {
  let chars = '';
  while (chars.length < 40) {
    for (const b of globalThis.crypto.getRandomValues(new Uint8Array(64))) {
      // 248 = 31 * 8; reject higher values so the distribution stays uniform
      if (b < 248 && chars.length < 40) chars += ALPHABET[b % 31];
    }
  }
  return chars.match(/.{5}/g).join('-');
}

export function normalizePassphrase(p) {
  return p.trim().replace(/\s+/g, '');
}

export const normalizeEmail = (e) => String(e).trim().toLowerCase();

async function stretch(secret, salt) {
  const base = await subtle.importKey('raw', enc.encode(secret), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: ITERATIONS }, base, 512));
}

const kekFrom = (bits) => subtle.importKey('raw', bits, 'AES-GCM', false, ['encrypt', 'decrypt']);

/** Password account derivation. The email is the salt, so a login needs no server round trip. */
export async function deriveFromPassword(password, email) {
  const bits = await stretch(password, `universal-clipboard/v2/pw:${normalizeEmail(email)}`);
  return { authKey: toHex(bits.slice(0, 32)), kek: await kekFrom(bits.slice(32)) };
}

/** Clipboard-passphrase derivation for accounts that sign in with Google. `authKey` proves knowledge of the passphrase. */
export async function deriveFromPassphrase(passphrase, userId) {
  const bits = await stretch(normalizePassphrase(passphrase), `universal-clipboard/v2/pp:${userId}`);
  return { authKey: toHex(bits.slice(0, 32)), kek: await kekFrom(bits.slice(32)) };
}

export function newVaultKeyBytes() {
  return globalThis.crypto.getRandomValues(new Uint8Array(32));
}

/** Import raw vault-key bytes for encrypt/decrypt. Non-extractable unless asked otherwise. */
export const importVaultKey = (raw, extractable = false) => subtle.importKey('raw', raw, 'AES-GCM', extractable, ['encrypt', 'decrypt']);

/** Wrap raw vault-key bytes under a KEK. Returns { nonce, ct } (base64). */
export async function wrapVaultKey(kek, raw) {
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce }, kek, raw));
  return { nonce: toB64(nonce), ct: toB64(ct) };
}

/** Returns raw vault-key bytes. Throws if the KEK is wrong (i.e. wrong password/passphrase). */
export async function unwrapVaultKey(kek, { nonce, ct }) {
  return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(nonce) }, kek, fromB64(ct)));
}

/** Encrypt a JSON-serialisable payload. `aad` (the item id) is authenticated, so a server cannot re-label ciphertext. */
export async function encryptPayload(key, payload, aad = '') {
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: enc.encode(aad) }, key, enc.encode(JSON.stringify(payload))));
  return { nonce: toB64(nonce), ct: toB64(ct) };
}

/** Decrypt an item's { nonce, ct }. Throws if the key is wrong or data was tampered with. */
export async function decryptPayload(key, { nonce, ct }, aad = '') {
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(nonce), additionalData: enc.encode(aad) }, key, fromB64(ct));
  return JSON.parse(dec.decode(pt));
}

export function newId() {
  return globalThis.crypto.randomUUID();
}

// --- Device approval: hand the vault key to a new device (CLI) without the server ever seeing it.
// The new device publishes an ephemeral ECDH public key; an already-trusted browser seals the vault
// key to it. The server only relays the sealed blob.

export async function generateDeviceKeyPair() {
  const pair = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  return { privateKey: pair.privateKey, publicKey: toB64(new Uint8Array(await subtle.exportKey('raw', pair.publicKey))) };
}

async function sharedKey(privateKey, peerPublic) {
  const peer = await subtle.importKey('raw', fromB64(peerPublic), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const bits = await subtle.deriveBits({ name: 'ECDH', public: peer }, privateKey, 256);
  const hk = await subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('universal-clipboard/v2/device-approval') },
    hk,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** Seal raw vault-key bytes to a device's public key. Returns { pub, nonce, ct } (base64). */
export async function sealForDevice(devicePublic, rawVaultKey) {
  const eph = await generateDeviceKeyPair();
  const key = await sharedKey(eph.privateKey, devicePublic);
  return { pub: eph.publicKey, ...(await wrapVaultKey(key, rawVaultKey)) };
}

export async function openFromApprover(devicePrivate, { pub, nonce, ct }) {
  return unwrapVaultKey(await sharedKey(devicePrivate, pub), { nonce, ct });
}

/** Short, human-comparable fingerprint of a device public key ("1A2B-3C4D"). Shown on the device and in the approval dialog. */
export async function fingerprint(publicKeyB64) {
  const d = new Uint8Array(await subtle.digest('SHA-256', fromB64(publicKeyB64)));
  const hex = toHex(d.slice(0, 4)).toUpperCase();
  return `${hex.slice(0, 4)}-${hex.slice(4)}`;
}
