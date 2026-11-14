#!/usr/bin/env node
// Universal Clipboard relay. Zero dependencies.
// The server only ever sees ciphertext: items are encrypted client-side (AES-GCM)
// and a vault is identified by the SHA-256 of a token derived from the passphrase.
import { createHash, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdirSync, readFileSync, renameSync, writeFileSync, existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, extname, join, normalize, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.webmanifest': 'application/manifest+json',
  '.png': 'image/png',
};

export function createRelay(opts = {}) {
  const cfg = {
    dataDir: opts.dataDir ?? process.env.UC_DATA_DIR ?? join(ROOT, 'data'),
    maxItems: Number(opts.maxItems ?? process.env.UC_MAX_ITEMS ?? 100),
    ttlMs: Number(opts.ttlHours ?? process.env.UC_TTL_HOURS ?? 24 * 7) * 3600_000,
    maxBodyBytes: Number(opts.maxBodyBytes ?? process.env.UC_MAX_BODY_BYTES ?? 1_000_000),
    maxVaults: Number(opts.maxVaults ?? process.env.UC_MAX_VAULTS ?? 100),
    inviteCode: opts.inviteCode ?? process.env.UC_INVITE_CODE ?? '',
  };

  mkdirSync(cfg.dataDir, { recursive: true });
  const dbFile = join(cfg.dataDir, 'vaults.json');
  /** @type {Record<string, {created:number,nextSeq:number,items:any[]}>} */
  let vaults = {};
  if (existsSync(dbFile)) vaults = JSON.parse(readFileSync(dbFile, 'utf8'));

  let saveTimer = null;
  function save() {
    if (saveTimer) return;
    saveTimer = setTimeout(flush, 200);
    saveTimer.unref?.();
  }
  function flush() {
    clearTimeout(saveTimer);
    saveTimer = null;
    const tmp = dbFile + '.tmp';
    writeFileSync(tmp, JSON.stringify(vaults), { mode: 0o600 });
    renameSync(tmp, dbFile);
  }

  /** vaultId -> Set<ServerResponse> */
  const listeners = new Map();

  function broadcast(vaultId, event, data) {
    for (const res of listeners.get(vaultId) ?? []) {
      res.write(`event: ${event}\n${event === 'item' ? `id: ${data.seq}\n` : ''}data: ${JSON.stringify(data)}\n\n`);
    }
  }

  function prune(v) {
    const cutoff = Date.now() - cfg.ttlMs;
    v.items = v.items.filter((i) => i.ts >= cutoff).slice(-cfg.maxItems);
  }

  /** Resolve the vault for a request, creating it on first use. Returns [vaultId, vault] or sends an error. */
  function authenticate(req, res) {
    const m = /^Bearer ([0-9a-f]{64})$/.exec(req.headers.authorization ?? '');
    if (!m) return send(res, 401, { error: 'missing or malformed token' });
    const vaultId = createHash('sha256').update(m[1]).digest('hex');
    let v = vaults[vaultId];
    if (!v) {
      if (cfg.inviteCode && !safeEqual(String(req.headers['x-invite-code'] ?? ''), cfg.inviteCode)) {
        return send(res, 403, { error: 'invite code required to create a new vault' });
      }
      if (Object.keys(vaults).length >= cfg.maxVaults) return send(res, 403, { error: 'server is full' });
      v = vaults[vaultId] = { created: Date.now(), nextSeq: 1, items: [] };
      save();
    }
    return [vaultId, v];
  }

  async function readJson(req, res) {
    const chunks = [];
    let size = 0;
    for await (const c of req) {
      size += c.length;
      if (size > cfg.maxBodyBytes) {
        send(res, 413, { error: 'item too large' });
        req.destroy();
        return null;
      }
      chunks.push(c);
    }
    try {
      return JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      send(res, 400, { error: 'invalid json' });
      return null;
    }
  }

  async function handleApi(req, res, url) {
    const auth = authenticate(req, res);
    if (!auth) return;
    const [vaultId, v] = auth;
    const path = url.pathname;

    if (req.method === 'POST' && path === '/api/v1/items') {
      const body = await readJson(req, res);
      if (!body) return;
      const { id, nonce, ct } = body;
      if (![id, nonce, ct].every((s) => typeof s === 'string' && s.length > 0 && s.length <= cfg.maxBodyBytes) || id.length > 64) {
        return send(res, 400, { error: 'expected {id, nonce, ct} strings' });
      }
      const dup = v.items.find((i) => i.id === id);
      if (dup) return send(res, 200, dup);
      const item = { id, seq: v.nextSeq++, ts: Date.now(), nonce, ct };
      v.items.push(item);
      prune(v);
      save();
      broadcast(vaultId, 'item', item);
      return send(res, 201, item);
    }

    if (req.method === 'GET' && path === '/api/v1/items') {
      prune(v);
      const since = Number(url.searchParams.get('since') ?? 0) || 0;
      return send(res, 200, { items: v.items.filter((i) => i.seq > since), lastSeq: v.nextSeq - 1 });
    }

    if (req.method === 'DELETE' && path === '/api/v1/items') {
      const ids = v.items.map((i) => i.id);
      v.items = [];
      save();
      for (const id of ids) broadcast(vaultId, 'delete', { id });
      return send(res, 204);
    }

    const del = req.method === 'DELETE' && /^\/api\/v1\/items\/([^/]+)$/.exec(path);
    if (del) {
      const id = decodeURIComponent(del[1]);
      const before = v.items.length;
      v.items = v.items.filter((i) => i.id !== id);
      if (v.items.length !== before) {
        save();
        broadcast(vaultId, 'delete', { id });
      }
      return send(res, 204);
    }

    if (req.method === 'GET' && path === '/api/v1/events') {
      res.writeHead(200, {
        'content-type': 'text/event-stream',
        'cache-control': 'no-store',
        connection: 'keep-alive',
        'x-accel-buffering': 'no',
      });
      res.write(': connected\n\n');
      prune(v);
      const since = Number(req.headers['last-event-id'] ?? url.searchParams.get('since') ?? 0) || 0;
      for (const item of v.items.filter((i) => i.seq > since)) {
        res.write(`event: item\nid: ${item.seq}\ndata: ${JSON.stringify(item)}\n\n`);
      }
      if (!listeners.has(vaultId)) listeners.set(vaultId, new Set());
      listeners.get(vaultId).add(res);
      const ping = setInterval(() => res.write(': ping\n\n'), 25_000);
      req.on('close', () => {
        clearInterval(ping);
        listeners.get(vaultId)?.delete(res);
      });
      return;
    }

    send(res, 404, { error: 'not found' });
  }

  async function handleStatic(req, res, url) {
    if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, { error: 'method not allowed' });
    let rel = decodeURIComponent(url.pathname);
    let base = join(ROOT, 'web');
    if (rel.startsWith('/shared/')) {
      base = join(ROOT, 'shared');
      rel = rel.slice('/shared'.length);
    }
    if (rel.endsWith('/')) rel += 'index.html';
    const file = normalize(join(base, rel));
    if (file !== base && !file.startsWith(base + sep)) return send(res, 403, { error: 'forbidden' });
    try {
      const data = await readFile(file);
      res.writeHead(200, {
        'content-type': MIME[extname(file)] ?? 'application/octet-stream',
        'cache-control': 'no-cache',
      });
      res.end(req.method === 'HEAD' ? undefined : data);
    } catch {
      send(res, 404, { error: 'not found' });
    }
  }

  const server = createServer(async (req, res) => {
    // The relay is happy to be embedded in a page on another origin only if the operator opts in.
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('referrer-policy', 'no-referrer');
    res.setHeader('content-security-policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'");
    try {
      const url = new URL(req.url, 'http://localhost');
      if (url.pathname === '/healthz') return send(res, 200, { ok: true });
      if (url.pathname.startsWith('/api/')) return await handleApi(req, res, url);
      return await handleStatic(req, res, url);
    } catch (err) {
      console.error(err);
      if (!res.headersSent) send(res, 500, { error: 'internal error' });
      else res.end();
    }
  });

  server.on('close', () => {
    if (saveTimer) flush();
  });

  return server;
}

function send(res, status, body) {
  if (status === 204) {
    res.writeHead(204);
    return res.end();
  }
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}

function safeEqual(a, b) {
  const x = createHash('sha256').update(a).digest();
  const y = createHash('sha256').update(b).digest();
  return timingSafeEqual(x, y);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 8787);
  const host = process.env.HOST ?? '127.0.0.1';
  const server = createRelay();
  server.listen(port, host, () => console.log(`Universal Clipboard relay listening on http://${host}:${port}`));
  for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => server.close(() => process.exit(0)).closeAllConnections());
}
