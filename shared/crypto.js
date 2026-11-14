// End-to-end encryption helpers. Runs unchanged in browsers and Node (WebCrypto).
// The passphrase never leaves the device: it is stretched into an auth token
// (sent to the server, which only stores its SHA-256) and an AES-GCM key
// (never sent anywhere).

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

const SALT = 'universal-clipboard/v1';
const ITERATIONS = 310_000;
const ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789'; // no look-alike characters

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

/** Derive { token, key } from a passphrase. `token` is a 64-char hex string. */
export async function deriveKeys(passphrase) {
  const base = await subtle.importKey('raw', enc.encode(normalizePassphrase(passphrase)), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(
    await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(SALT), iterations: ITERATIONS }, base, 512),
  );
  const key = await subtle.importKey('raw', bits.slice(32), 'AES-GCM', false, ['encrypt', 'decrypt']);
  return { token: toHex(bits.slice(0, 32)), key };
}

/** Encrypt a JSON-serialisable payload. Returns { nonce, ct } (base64). */
export async function encryptPayload(key, payload) {
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, enc.encode(JSON.stringify(payload))));
  return { nonce: toB64(nonce), ct: toB64(ct) };
}

/** Decrypt an item's { nonce, ct }. Throws if the key is wrong or data was tampered with. */
export async function decryptPayload(key, { nonce, ct }) {
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(nonce) }, key, fromB64(ct));
  return JSON.parse(dec.decode(pt));
}

export function newId() {
  return globalThis.crypto.randomUUID();
}
