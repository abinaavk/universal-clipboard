// Caches the app shell so the PWA installs and opens offline. API calls always go to the network.
const CACHE = 'uc-shell-v1';
const SHELL = ['/', '/app.js', '/style.css', '/icon.svg', '/manifest.webmanifest', '/shared/crypto.js', '/shared/client.js'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin || url.pathname.startsWith('/api/')) return;
  // Network first so updates ship immediately; fall back to cache when offline.
  // Ignore the query string so share-target launches (/?text=...) still match '/'.
  e.respondWith(
    fetch(e.request)
      .then((res) => {
        // Never cache URLs with a query string: share-target launches carry the shared text there.
        if (res.ok && !url.search) {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(e.request, copy));
        }
        return res;
      })
      .catch(() => caches.match(e.request, { ignoreSearch: true })),
  );
});
