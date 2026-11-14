// Client-side account flows shared by the web app and the CLI. All key material is derived and wrapped
// here, on the device; the server receives only an `authKey` (never the password) and a wrapped vault key.
import {
  MIN_PASSWORD_LENGTH,
  deriveFromPassphrase,
  deriveFromPassword,
  importVaultKey,
  newVaultKeyBytes,
  unwrapVaultKey,
  wrapVaultKey,
} from './crypto.js';

export class WrongSecretError extends Error {
  constructor(kind) {
    super(kind === 'passphrase' ? 'Wrong clipboard passphrase.' : 'Wrong password.');
    this.code = 'wrong_secret';
  }
}

export function checkPassword(password) {
  if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH) throw new Error(`Use at least ${MIN_PASSWORD_LENGTH} characters.`);
}

/** Create an account. Returns the server response plus the raw vault key. */
export async function signup(api, { email, password, inviteCode, ...info }) {
  checkPassword(password);
  const { authKey, kek } = await deriveFromPassword(password, email);
  const vaultKey = newVaultKeyBytes();
  const wrap = { kind: 'password', ...(await wrapVaultKey(kek, vaultKey)) };
  const res = await api.call('POST', '/api/v1/auth/signup', { email, authKey, wrap, inviteCode, ...info });
  return { ...res, vaultKey };
}

/** Sign in with email+password. Returns the server response plus the raw vault key. */
export async function login(api, { email, password, ...info }) {
  const { authKey, kek } = await deriveFromPassword(password, email);
  const res = await api.call('POST', '/api/v1/auth/login', { email, authKey, ...info });
  const vaultKey = await unwrap(kek, res.wrap, 'password');
  return { ...res, vaultKey };
}

async function unwrap(kek, wrap, kind) {
  try {
    return await unwrapVaultKey(kek, wrap);
  } catch {
    throw new WrongSecretError(kind);
  }
}

/** Derive the KEK for an existing wrapped key from whatever secret that wrap needs. */
export async function kekFor(wrap, user, secret) {
  return wrap.kind === 'password' ? (await deriveFromPassword(secret, user.email)).kek : (await deriveFromPassphrase(secret, user.id)).kek;
}

/** Unlock the vault key of an already signed-in account (new browser after Google sign-in, device approval, ...). */
export async function unlock(wrap, user, secret) {
  return unwrap(await kekFor(wrap, user, secret), wrap, wrap.kind);
}

/** First-time key setup for Google accounts: wrap a fresh vault key under a clipboard passphrase. */
export async function createPassphraseWrap(user, passphrase) {
  const { kek, authKey } = await deriveFromPassphrase(passphrase, user.id);
  const vaultKey = newVaultKeyBytes();
  return { wrap: { kind: 'passphrase', ...(await wrapVaultKey(kek, vaultKey)) }, authKey, vaultKey };
}

/** The proof the server checks for destructive actions on passphrase accounts (it stores only a hash of it). */
export async function passphraseAuthKey(user, passphrase) {
  return (await deriveFromPassphrase(passphrase, user.id)).authKey;
}

/** Build the request body for a password change: unwrap with the old password, re-wrap under the new one. */
export async function passwordChangeBody(user, wrap, oldPassword, newPassword) {
  checkPassword(newPassword);
  const old = await deriveFromPassword(oldPassword, user.email);
  const vaultKey = await unwrap(old.kek, wrap, 'password');
  const next = await deriveFromPassword(newPassword, user.email);
  return { authKey: old.authKey, newAuthKey: next.authKey, wrap: { kind: 'password', ...(await wrapVaultKey(next.kek, vaultKey)) } };
}

/** Re-wrap the vault key of a Google (passphrase) account under a new clipboard passphrase. */
export async function passphraseChangeBody(user, wrap, oldPassphrase, newPassphrase) {
  checkPassword(newPassphrase);
  const vaultKey = await unlock(wrap, user, oldPassphrase);
  const { kek, authKey } = await deriveFromPassphrase(newPassphrase, user.id);
  return { oldAuthKey: await passphraseAuthKey(user, oldPassphrase), authKey, wrap: { kind: 'passphrase', ...(await wrapVaultKey(kek, vaultKey)) } };
}

/** Body for completing a password reset: new password, brand-new vault key (the old one is unrecoverable). */
export async function resetBody(email, newPassword) {
  checkPassword(newPassword);
  const { authKey, kek } = await deriveFromPassword(newPassword, email);
  return { authKey, wrap: { kind: 'password', ...(await wrapVaultKey(kek, newVaultKeyBytes())) } };
}

export { importVaultKey };
