// Caches the app shell so the PWA opens offline. API calls always go to the network and are never cached.
const CACHE = 'uc-shell-v2';
const SHELL = ['/style.css', '/icon.svg', '/manifest.webmanifest', '/app.js', '/js/ui.js', '/js/views.js', '/shared/crypto.js', '/shared/client.js', '/shared/auth.js'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin || url.pathname.startsWith('/api/')) return;
  // Network first so updates ship immediately; fall back to the cache when offline. Pages with a query string
  // (share-target launches carry the shared text there) are never cached.
  e.respondWith(
    fetch(e.request)
      .then((res) => {
        if (res.ok && !url.search && SHELL.includes(url.pathname)) {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(e.request, copy));
        }
        return res;
      })
      .catch(() => caches.match(e.request, { ignoreSearch: true }).then((r) => r ?? (e.request.mode === 'navigate' ? caches.match('/app') : undefined))),
  );
});
