// Unique deployment cache namespace. Freshness is handled by stale-while-revalidate,
// so content updates arrive without manually bumping this name.
const CACHE_NAME = 'rasnira-swr-20261017-1749';
const APP_SHELL = ['./', './index.html', './styles.css', './app.js', './scanner.js', './scanner-worker.js', './file-inspector.js', './site-client.js', './config.js', './supabase-client.js', './manifest.webmanifest', './icon-192.png', './icon-512.png', './icon-maskable-512.png'];
self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(APP_SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(key => (key.startsWith('haris-alnitaq-') || key.startsWith('rasnira-')) && key !== CACHE_NAME).map(key => caches.delete(key)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);
  // API/auth, external origins, non-GET, and user-generated report requests are never cached.
  if (request.method !== 'GET' || url.origin !== self.location.origin || url.pathname.startsWith('/api/')) return;
  const update = fetch(request).then(async response => {
    if (response.ok && response.type !== 'opaque') {
      const cache = await caches.open(CACHE_NAME);
      await cache.put(request, response.clone());
    }
    return response;
  });
  event.waitUntil(update.then(() => undefined).catch(() => undefined));
  event.respondWith(caches.open(CACHE_NAME).then(async cache => (await cache.match(request)) || update));
});
