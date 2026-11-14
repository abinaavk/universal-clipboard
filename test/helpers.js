import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRelay } from '../server/server.js';
import { createClient } from '../shared/client.js';
import { deriveKeys } from '../shared/crypto.js';

export async function startRelay(opts = {}) {
  const dataDir = mkdtempSync(join(tmpdir(), 'uc-test-'));
  const server = createRelay({ dataDir, ...opts });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}`;
  return {
    server,
    url,
    dataDir,
    async close() {
      server.closeAllConnections();
      await new Promise((r) => server.close(r));
      rmSync(dataDir, { recursive: true, force: true });
    },
  };
}

export async function clientFor(url, passphrase, device) {
  const { token, key } = await deriveKeys(passphrase);
  return { token, client: createClient({ server: url, token, key, device }) };
}

export const until = async (fn, ms = 5000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const v = await fn();
    if (v) return v;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error('timed out waiting for condition');
};
