import { createClient } from '/shared/client.js';
import { deriveKeys, generatePassphrase } from '/shared/crypto.js';

const $ = (id) => document.getElementById(id);
const DEVICE = (() => {
  let d = localStorage.getItem('uc-device');
  if (!d) {
    const ua = navigator.userAgent;
    const os = /Android/.test(ua) ? 'Android' : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : /Mac/.test(ua) ? 'Mac' : /iPhone|iPad/.test(ua) ? 'iOS' : 'Browser';
    d = `${os} browser ${Math.random().toString(36).slice(2, 5)}`;
    localStorage.setItem('uc-device', d);
  }
  return d;
})();

// --- Session storage: the derived AES key is stored as a non-extractable CryptoKey in IndexedDB,
// so the passphrase itself is never persisted and the key bytes can't be read back by scripts.
const idb = () =>
  new Promise((resolve, reject) => {
    const req = indexedDB.open('universal-clipboard', 1);
    req.onupgradeneeded = () => req.result.createObjectStore('kv');
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
const loadSession = () => kv('readonly', (s) => s.get('session'));
const saveSession = (v) => kv('readwrite', (s) => s.put(v, 'session'));
const clearSession = () => kv('readwrite', (s) => s.delete('session'));

// --- State
let client = null;
let stop = null;
let items = []; // newest last
let session = null;

const show = (id, on) => ($(id).hidden = !on);

function relTime(ts) {
  const s = Math.round((Date.now() - ts) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(ts).toLocaleDateString();
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback for browsers/contexts without the async clipboard API
    const ta = Object.assign(document.createElement('textarea'), { value: text });
    document.body.append(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  }
}

function render() {
  const ul = $('history');
  ul.replaceChildren();
  for (const item of [...items].reverse()) {
    const li = document.createElement('li');
    const pre = document.createElement('pre');
    pre.textContent = item.text; // textContent: clipboard data is untrusted
    const meta = document.createElement('div');
    meta.className = 'meta';
    meta.textContent = `${item.device} · ${relTime(item.ts)}`;
    const actions = document.createElement('div');
    actions.className = 'actions';
    const copy = Object.assign(document.createElement('button'), { textContent: 'Copy', type: 'button' });
    copy.onclick = async () => {
      copy.textContent = (await copyText(item.text)) ? 'Copied ✓' : 'Failed';
      setTimeout(() => (copy.textContent = 'Copy'), 1200);
    };
    const del = Object.assign(document.createElement('button'), { textContent: 'Delete', type: 'button', className: 'secondary' });
    del.onclick = () => client.remove(item.id).catch(() => {});
    actions.append(copy, del);
    li.append(pre, meta, actions);
    ul.append(li);
  }
  show('empty', items.length === 0);
}

function setStatus(s) {
  const el = $('status');
  el.textContent = s;
  el.classList.toggle('online', s === 'online');
  if (s === 'unauthorized') signOut();
}

async function start(sess) {
  session = sess;
  client = createClient({ server: location.origin, token: sess.token, key: sess.key, device: DEVICE });
  show('login', false);
  show('app', true);
  $('auto').checked = localStorage.getItem('uc-auto') === '1';

  const { items: initial, lastSeq } = await client.list();
  items = initial;
  render();

  stop = client.subscribe({
    since: lastSeq,
    onStatus: setStatus,
    onItem: async (item) => {
      if (items.some((i) => i.id === item.id)) return;
      items.push(item);
      render();
      if ($('auto').checked && item.device !== DEVICE && document.hasFocus()) copyText(item.text);
    },
    onDelete: (id) => {
      items = items.filter((i) => i.id !== id);
      render();
    },
  });

  // Share target (Android "Share → Universal Clipboard") arrives as /?text=…&url=…
  const q = new URLSearchParams(location.search);
  const shared = [q.get('title'), q.get('text'), q.get('url')].filter(Boolean).join('\n');
  if (shared) {
    history.replaceState(null, '', '/');
    await client.pushText(shared);
  }
}

async function signOut() {
  stop?.();
  await clearSession();
  items = [];
  show('app', false);
  show('login', true);
}

async function login(passphrase) {
  const { token, key } = await deriveKeys(passphrase);
  const sess = { token, key };
  const probe = createClient({ server: location.origin, token, key, device: DEVICE });
  await probe.list(); // 401/403/network errors throw here; unknown tokens create the vault
  await saveSession(sess);
  await start(sess);
}

$('login-form').onsubmit = async (e) => {
  e.preventDefault();
  show('login-error', false);
  try {
    await login($('passphrase').value);
  } catch (err) {
    $('login-error').textContent = `Could not connect: ${err.message}`;
    show('login-error', true);
  }
};

$('generate').onclick = () => {
  const p = generatePassphrase();
  $('passphrase').type = 'text';
  $('passphrase').value = p;
  $('generated').textContent = 'Write this passphrase down: it cannot be recovered. Press Connect to create the vault, then enter the same passphrase on your other devices.';
  show('generated', true);
};

$('send-form').onsubmit = async (e) => {
  e.preventDefault();
  const text = $('text').value;
  if (!text) return;
  await client.pushText(text);
  $('text').value = '';
};

$('paste').onclick = async () => {
  try {
    const text = await navigator.clipboard.readText();
    if (text) await client.pushText(text);
  } catch {
    alert('The browser did not allow reading the clipboard. Paste into the box instead.');
  }
};

$('auto').onchange = () => localStorage.setItem('uc-auto', $('auto').checked ? '1' : '0');
$('logout').onclick = signOut;

$('share-link').onclick = () => {
  const pp = prompt('Enter your passphrase to build a sign-in link (it is not stored in this browser):');
  if (!pp) return;
  copyText(`${location.origin}/#pp=${encodeURIComponent(pp)}`);
};

// --- Boot
(async () => {
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});

  const m = /^#pp=(.+)$/.exec(location.hash);
  if (m) {
    history.replaceState(null, '', location.pathname + location.search); // drop secret from URL/history
    try {
      return await login(decodeURIComponent(m[1]));
    } catch (err) {
      show('login', true);
      $('login-error').textContent = `Could not connect: ${err.message}`;
      return show('login-error', true);
    }
  }

  const saved = await loadSession().catch(() => null);
  if (saved) {
    try {
      return await start(saved);
    } catch (err) {
      setStatus('offline');
    }
  }
  show('login', true);
})();
