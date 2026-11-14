import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRelay } from '../server/server.js';
import { login, signup } from '../shared/auth.js';
import { ApiError, createApi, createClient } from '../shared/client.js';
import { importVaultKey } from '../shared/crypto.js';

export const PASSWORD = 'correct horse battery';

export async function startRelay(opts = {}) {
  const dataDir = mkdtempSync(join(tmpdir(), 'uc-test-'));
  const server = createRelay({ dataDir, rateLimit: false, logMail: false, requireVerifiedEmail: false, publicUrl: 'http://127.0.0.1', ...opts });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}`;
  // Links in mails use publicUrl; tests only need the token out of them.
  const mails = server.relay.mailer.outbox;
  return {
    server,
    url,
    dataDir,
    mails,
    mailToken: (to, kind) => {
      const mail = [...mails].reverse().find((m) => m.to === to && m.subject.toLowerCase().includes(kind));
      return mail && /#token=([\w-]+)/.exec(mail.text)?.[1];
    },
    async close() {
      server.closeAllConnections();
      await new Promise((r) => server.close(r));
      rmSync(dataDir, { recursive: true, force: true });
    },
  };
}

/** Sign up (or log in) as a CLI-style device and return a ready client. */
export async function deviceFor(url, email, device, { create = false, password = PASSWORD } = {}) {
  const api = createApi({ server: url });
  const info = { device, platform: 'linux', client: 'cli' };
  const res = create ? await signup(api, { email, password, ...info }) : await login(api, { email, password, ...info });
  const key = await importVaultKey(res.vaultKey);
  const client = createClient({ server: url, token: res.token, key, device });
  return { client, token: res.token, res, key, vaultKey: res.vaultKey, api: client.api };
}

export { ApiError };

export const until = async (fn, ms = 5000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const v = await fn();
    if (v) return v;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error('timed out waiting for condition');
};

export async function rejects(promise, status, code) {
  try {
    await promise;
  } catch (e) {
    if (!(e instanceof ApiError)) throw e;
    if (e.status !== status || (code && e.code !== code)) throw new Error(`expected ${status}${code ? ` ${code}` : ''}, got ${e.status} ${e.code}: ${e.message}`);
    return e;
  }
  throw new Error(`expected request to fail with ${status}`);
}
