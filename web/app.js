// Universal Clipboard web app: session + key handling, live sync, routing. Views live in /js/views.js.
import { ApiError, createApi, createClient } from '/shared/client.js';
import { importVaultKey } from '/shared/crypto.js';
import { copyText, deviceName, h, platformOf, toast } from '/js/ui.js';
import * as V from '/js/views.js';

// --- The vault key is kept as a non-extractable CryptoKey in IndexedDB: scripts can use it but never read
// its bytes. It is removed whenever the session ends.
const idb = () =>
  new Promise((resolve, reject) => {
    const req = indexedDB.open('universal-clipboard', 2);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains('kv')) req.result.createObjectStore('kv');
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
async function kv(mode, fn) {
  const db = await idb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('kv', mode);
    const r = fn(tx.objectStore('kv'));
    tx.oncomplete = () => resolve(r?.result);
    tx.onerror = () => reject(tx.error);
  });
}
const loadVault = () => kv('readonly', (s) => s.get('vault')).catch(() => null);
const saveVault = (v) => kv('readwrite', (s) => s.put(v, 'vault'));
const clearVault = () => kv('readwrite', (s) => s.delete('vault')).catch(() => {});

const pref = (name, fallback = false) => ({
  get: () => (localStorage.getItem(`uc-${name}`) ?? String(fallback)) === 'true',
  set: (v) => localStorage.setItem(`uc-${name}`, String(v)),
});

const root = document.getElementById('root');

export const app = {
  api: createApi({ server: location.origin, web: true }),
  providers: { google: false, signups: true, inviteRequired: false, emailVerification: false },
  device: deviceName(),
  platform: platformOf(),
  prefs: { auto: pref('auto'), capture: pref('capture') },

  user: null,
  wrap: null,
  session: null,
  key: null,
  client: null,
  items: [],
  sessions: [],
  status: 'offline',
  needsVerify: false,
  pendingCode: null,
  ui: null, // set by the main view: { renderTape, renderDevices, renderStatus }

  stop: null,
  ownIds: new Set(),
  lastClip: null,

  mount(node) {
    root.className = '';
    root.replaceChildren(node);
  },

  go(path) {
    history.pushState(null, '', path);
    return route();
  },

  /** True only while this browser has a live, signed-in session with a key: the sole condition for touching the clipboard. */
  get active() {
    return Boolean(this.session && this.client && this.key);
  },

  // ---- sign-in plumbing ----
  async signedIn(res, vaultKey) {
    this.user = res.user;
    this.wrap = res.wrap;
    this.session = res.session;
    if (vaultKey) return this.useKey(vaultKey);
    return this.needKey();
  },

  /** Signed in, but the vault key is not on this browser yet: unlock (existing wrap) or create a passphrase (Google, first time). */
  needKey() {
    this.ui = null;
    return this.mount(this.wrap ? V.unlockView(this) : V.createPassphraseView(this));
  },

  async useKey(rawBytes) {
    this.key = await importVaultKey(rawBytes, false);
    await saveVault({ userId: this.user.id, key: this.key });
    return this.start();
  },

  async start() {
    this.client = createClient({ server: location.origin, key: this.key, device: this.device, web: true });
    this.items = [];
    this.needsVerify = false;
    this.lastClip = null;
    this.mount(V.mainView(this));
    try {
      const { items, lastSeq } = await this.client.list();
      this.items = items;
      this.ui.renderTape();
      this.openStream(lastSeq);
    } catch (e) {
      if (e instanceof ApiError && e.code === 'email_not_verified') {
        this.needsVerify = true;
        this.ui.renderTape();
      } else if (!(await this.handleAuthError(e))) toast(`Could not load clipboard: ${e.message}`);
    }
    this.refreshSessions();
    if (this.pendingCode) {
      const code = this.pendingCode;
      this.pendingCode = null;
      V.approveModal(this, code);
    }
    this.takeSharedText();
  },

  openStream(since) {
    this.stop?.();
    this.stop = this.client.subscribe({
      since,
      onStatus: (s) => {
        if (s === 'ended') return this.sessionEnded('This device was signed out.');
        if (s === 'forbidden') return void ((this.needsVerify = true), this.ui?.renderTape());
        this.status = s;
        this.ui?.renderStatus();
      },
      onSessions: () => this.refreshSessions(),
      onDelete: (id) => {
        this.items = this.items.filter((i) => i.id !== id);
        this.ui?.renderTape();
      },
      onItem: (item) => {
        if (!this.active || this.items.some((i) => i.id === item.id)) return;
        this.items.push(item);
        this.ui?.renderTape(item.id);
        const mine = this.ownIds.has(item.id);
        if (!mine && this.prefs.auto.get() && document.hasFocus()) {
          this.lastClip = item.text;
          copyText(item.text).then((ok) => ok && toast('Copied to your clipboard'));
        }
      },
    });
  },

  async refreshSessions() {
    if (!this.client) return;
    try {
      this.sessions = (await this.client.sessions()).sessions;
      this.ui?.renderDevices();
    } catch (e) {
      await this.handleAuthError(e);
    }
  },

  /** Returns true if the error meant our session is over (and handled it). */
  async handleAuthError(e) {
    if (e instanceof ApiError && e.status === 401) {
      await this.sessionEnded('Your session ended. Sign in again to keep syncing.');
      return true;
    }
    return false;
  },

  /** Tear everything down: no key, no stream, no clipboard access. */
  async sessionEnded(message) {
    this.stop?.();
    this.stop = this.client = this.key = this.session = null;
    this.user = this.wrap = null;
    this.items = [];
    this.sessions = [];
    this.ui = null;
    this.ownIds.clear();
    await clearVault();
    this.mount(V.authView(this, location.pathname === '/signup' ? 'signup' : 'login', { notice: message }));
  },

  async signOut() {
    try {
      await this.api.call('POST', '/api/v1/auth/logout');
    } catch {}
    await this.sessionEnded('Signed out.');
  },

  // ---- clipboard ----
  async send(text) {
    if (!this.active || !text) return null;
    const sent = await this.client.pushText(text);
    if (sent) {
      this.ownIds.add(sent.id);
      if (!this.items.some((i) => i.id === sent.id)) {
        this.items.push(sent);
        this.ui?.renderTape(sent.id);
      }
    }
    return sent;
  },

  /** "Capture on return": when the tab regains focus, send whatever was copied elsewhere meanwhile. */
  async captureClipboard({ baselineOnly = false } = {}) {
    if (!this.active || this.needsVerify || (!baselineOnly && !this.prefs.capture.get())) return;
    try {
      const text = await navigator.clipboard.readText();
      if (!text || text === this.lastClip) return;
      this.lastClip = text;
      if (!baselineOnly) {
        await this.send(text);
        toast('Sent what you copied');
      }
    } catch {
      // permission denied or not focused: nothing to do
    }
  },

  async takeSharedText() {
    // Android "Share → uclip" arrives as /app?title=…&text=…&url=…. Any web page can link here, so the text is only
    // put in the composer: nothing is sent until the user presses Send.
    const q = new URLSearchParams(location.search);
    const shared = [q.get('title'), q.get('text'), q.get('url')].filter(Boolean).join('\n');
    if (!shared) return;
    history.replaceState(null, '', location.pathname);
    if (this.active && !this.needsVerify) {
      this.ui?.setDraft(shared);
      toast('Review the shared text, then press Send');
    }
  },
};

// --- Browser-level hooks. Each one checks `app.active` first: no session, no clipboard.
document.addEventListener('paste', (e) => {
  if (!app.active || app.needsVerify || /^(INPUT|TEXTAREA)$/.test(document.activeElement?.tagName ?? '')) return;
  const text = e.clipboardData?.getData('text');
  if (text) {
    e.preventDefault();
    app.lastClip = text;
    app.send(text).then(() => toast('Sent to your other devices'));
  }
});
window.addEventListener('focus', () => app.captureClipboard());
document.addEventListener('visibilitychange', () => document.visibilityState === 'visible' && app.captureClipboard());
setInterval(() => app.ui?.renderTape(), 30_000); // refresh relative times

// ---- routing ----
async function route() {
  const path = location.pathname.replace(/\/+$/, '') || '/';
  const frag = new URLSearchParams(location.hash.slice(1));
  const query = new URLSearchParams(location.search);
  if (location.hash) history.replaceState(null, '', location.pathname + location.search); // never leave secrets in the URL bar

  if (path === '/verify') return V.verifyScreen(app, frag.get('token'));
  if (path === '/reset') return app.mount(V.resetView(app, frag.get('token')));
  if (path === '/forgot') return app.mount(V.forgotView(app));
  if (path === '/device') app.pendingCode = query.get('code') ?? '';

  if (frag.get('ticket')) {
    try {
      const res = await app.api.call('POST', '/api/v1/auth/google/exchange', { ticket: frag.get('ticket'), device: app.device, platform: app.platform });
      return await app.signedIn(res, null);
    } catch (e) {
      return app.mount(V.authView(app, 'login', { error: e.message }));
    }
  }
  if (frag.get('error')) {
    const msg = { signups_closed: 'New sign-ups are closed.', server_full: 'This server is full.' }[frag.get('error')] ?? 'Google sign-in did not complete. Please try again.';
    return app.mount(V.authView(app, 'login', { error: msg }));
  }

  try {
    const res = await app.api.call('GET', '/api/v1/account');
    app.user = res.user;
    app.wrap = res.wrap;
    app.session = res.session;
    if (app.key && app.active) return; // already running
    const saved = await loadVault();
    if (saved?.key && saved.userId === res.user.id) {
      app.key = saved.key;
      return await app.start();
    }
    return app.needKey();
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) {
      await clearVault(); // a revoked/expired session must not leave the key behind
      const notice = app.pendingCode !== null ? 'Sign in to approve the device that is waiting.' : undefined;
      return app.mount(V.authView(app, path === '/signup' ? 'signup' : 'login', { notice }));
    }
    return app.mount(h('div', { class: 'center-page' }, h('div', { class: 'auth-card' }, h('h1', { text: 'Cannot reach the server' }), h('p', { class: 'sub', text: e.message }), h('button', { class: 'btn block', text: 'Retry', onclick: () => route() }))));
  }
}

window.addEventListener('popstate', route);
if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});

try {
  const p = await app.api.call('GET', '/api/v1/auth/providers');
  Object.assign(app.providers, p);
} catch {}
await route();
