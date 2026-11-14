// API client shared by the browser app and the CLI daemon.
import { decryptPayload, encryptPayload, newId } from './crypto.js';

export class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

/**
 * Low-level JSON caller. Devices pass `token` (Bearer); the browser passes `web: true` and relies on the
 * HttpOnly session cookie (plus the CSRF header the server requires for cookie-authenticated writes).
 */
export function createApi({ server, token, web = false, fetchImpl = globalThis.fetch }) {
  const base = server.replace(/\/+$/, '');
  const headers = (extra = {}) => ({
    ...(token ? { authorization: `Bearer ${token}` } : {}),
    ...(web ? { 'x-uc-csrf': '1' } : {}),
    ...extra,
  });

  async function call(method, path, body) {
    const res = await fetchImpl(base + path, {
      method,
      headers: headers(body !== undefined ? { 'content-type': 'application/json' } : {}),
      body: body !== undefined ? JSON.stringify(body) : undefined,
      ...(web ? { credentials: 'same-origin' } : {}),
    });
    if (!res.ok) {
      let code = 'http_error';
      let message = `${method} ${path} -> ${res.status}`;
      try {
        const j = await res.json();
        code = j.error ?? code;
        message = j.message ?? message;
      } catch {}
      throw new ApiError(res.status, code, message);
    }
    return res.status === 204 ? null : res.json();
  }

  return { base, headers, call, fetchImpl, web };
}

export function createClient({ server, token, key, device, web = false, fetchImpl = globalThis.fetch }) {
  const api = createApi({ server, token, web, fetchImpl });
  const { call } = api;

  async function open(item) {
    try {
      const p = await decryptPayload(key, item, item.id);
      return { id: item.id, seq: item.seq, ts: item.ts, device: p.device, kind: p.kind, text: p.text };
    } catch {
      return null; // wrong key or tampered: ignore
    }
  }

  return {
    api,

    /** Encrypt and upload text. Returns the decrypted view of the stored item. */
    async pushText(text) {
      const id = newId();
      const sealed = await encryptPayload(key, { kind: 'text', text, device }, id);
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
    account: () => call('GET', '/api/v1/account'),
    sessions: () => call('GET', '/api/v1/sessions'),
    revokeSession: (id) => call('DELETE', `/api/v1/sessions/${id}`),

    /**
     * Stream new items over SSE, reconnecting with backoff and resuming from the last seen seq.
     * Status callbacks: 'online' | 'offline' | 'ended' (session revoked/expired: stop syncing, sign in again)
     * | 'forbidden' (e.g. email not confirmed). 'ended' and 'forbidden' are terminal. Returns a stop() function.
     */
    subscribe({ since = 0, onItem, onDelete, onSessions, onStatus = () => {} }) {
      let stopped = false;
      let last = since;
      let controller;

      (async () => {
        let delay = 500;
        while (!stopped) {
          controller = new AbortController();
          try {
            const res = await fetchImpl(`${api.base}/api/v1/events?since=${last}`, {
              headers: api.headers({ accept: 'text/event-stream' }),
              signal: controller.signal,
              ...(web ? { credentials: 'same-origin' } : {}),
            });
            if (res.status === 401) return onStatus('ended');
            if (res.status === 403) return onStatus('forbidden');
            if (!res.ok || !res.body) throw new Error(`events -> ${res.status}`);
            onStatus('online');
            delay = 500;
            let ended = false;
            await readSse(res.body, async (evt) => {
              if (evt.event === 'session-ended') ended = true;
              else if (evt.event === 'sessions') onSessions?.();
              else if (evt.event === 'delete') onDelete?.(JSON.parse(evt.data).id);
              else if (evt.event === 'item') {
                const item = JSON.parse(evt.data);
                last = Math.max(last, item.seq);
                const view = await open(item);
                if (view) await onItem(view);
              }
            });
            if (ended) return onStatus('ended');
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
