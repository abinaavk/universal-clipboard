// Tiny API client shared by the browser app and the CLI daemon.
import { decryptPayload, encryptPayload, newId } from './crypto.js';

export function createClient({ server, token, key, device, fetchImpl = globalThis.fetch, inviteCode }) {
  const base = server.replace(/\/+$/, '');
  const headers = (extra = {}) => ({
    authorization: `Bearer ${token}`,
    ...(inviteCode ? { 'x-invite-code': inviteCode } : {}),
    ...extra,
  });

  async function call(method, path, body) {
    const res = await fetchImpl(base + path, {
      method,
      headers: headers(body ? { 'content-type': 'application/json' } : {}),
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
      const err = new Error(`${method} ${path} -> ${res.status} ${(await res.text().catch(() => '')).slice(0, 200)}`);
      err.status = res.status;
      throw err;
    }
    return res.status === 204 ? null : res.json();
  }

  async function open(item) {
    try {
      const p = await decryptPayload(key, item);
      return { id: item.id, seq: item.seq, ts: item.ts, device: p.device, kind: p.kind, text: p.text };
    } catch {
      return null; // wrong key or tampered: ignore
    }
  }

  return {
    /** Encrypt and upload text. Returns the decrypted view of the stored item. */
    async pushText(text) {
      const id = newId();
      const sealed = await encryptPayload(key, { kind: 'text', text, device });
      const stored = await call('POST', '/api/v1/items', { id, ...sealed });
      return open(stored);
    },

    async list(since = 0) {
      const { items, lastSeq } = await call('GET', `/api/v1/items?since=${since}`);
      const opened = (await Promise.all(items.map(open))).filter(Boolean);
      return { items: opened, lastSeq };
    },

    remove: (id) => call('DELETE', `/api/v1/items/${encodeURIComponent(id)}`),
    clear: () => call('DELETE', '/api/v1/items'),

    /**
     * Stream new items over SSE, reconnecting with backoff and resuming from the last seen seq.
     * Returns a stop() function.
     */
    subscribe({ since = 0, onItem, onDelete, onStatus = () => {} }) {
      let stopped = false;
      let last = since;
      let controller;

      (async () => {
        let delay = 500;
        while (!stopped) {
          controller = new AbortController();
          try {
            const res = await fetchImpl(`${base}/api/v1/events?since=${last}`, {
              headers: headers({ accept: 'text/event-stream' }),
              signal: controller.signal,
            });
            if (res.status === 401 || res.status === 403) {
              onStatus('unauthorized');
              return;
            }
            if (!res.ok || !res.body) throw new Error(`events -> ${res.status}`);
            onStatus('online');
            delay = 500;
            await readSse(res.body, async (evt) => {
              if (evt.event === 'delete') return onDelete?.(JSON.parse(evt.data).id);
              if (evt.event !== 'item') return;
              const item = JSON.parse(evt.data);
              last = Math.max(last, item.seq);
              const view = await open(item);
              if (view) await onItem(view);
            });
          } catch (err) {
            if (stopped) return;
          }
          if (stopped) return;
          onStatus('offline');
          await new Promise((r) => setTimeout(r, delay));
          delay = Math.min(delay * 2, 15000);
        }
      })();

      return () => {
        stopped = true;
        controller?.abort();
      };
    },
  };
}

async function readSse(body, onEvent) {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return;
    buf += decoder.decode(value, { stream: true });
    let idx;
    while ((idx = buf.search(/\r?\n\r?\n/)) !== -1) {
      const raw = buf.slice(0, idx);
      buf = buf.slice(idx).replace(/^\r?\n\r?\n/, '');
      const evt = { event: 'message', data: '' };
      for (const line of raw.split(/\r?\n/)) {
        if (line.startsWith(':')) continue;
        const c = line.indexOf(':');
        const field = c === -1 ? line : line.slice(0, c);
        const val = c === -1 ? '' : line.slice(c + 1).replace(/^ /, '');
        if (field === 'event') evt.event = val;
        else if (field === 'data') evt.data += (evt.data ? '\n' : '') + val;
      }
      if (evt.data) await onEvent(evt);
    }
  }
}
