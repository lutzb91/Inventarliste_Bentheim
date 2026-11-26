'use strict';

// Offline-Unterstützung: erst Netz (damit Updates ankommen), sonst Cache.
const CACHE = 'inventar-v1';
const FILES = [
  './',
  'index.html',
  'style.css',
  'app.js',
  'data.enc.json',
  'manifest.webmanifest',
  'icons/icon.svg',
  'icons/icon-180.png',
  'icons/icon-192.png',
  'icons/icon-512.png',
];
const TIMEOUT_MS = 3000;

self.addEventListener('install', (ev) => {
  ev.waitUntil(caches.open(CACHE).then((c) => c.addAll(FILES)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (ev) => {
  ev.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()));
});

self.addEventListener('fetch', (ev) => {
  const req = ev.request;
  if (req.method !== 'GET' || new URL(req.url).origin !== self.location.origin) return;

  ev.respondWith((async () => {
    const cache = await caches.open(CACHE);
    const network = fetch(req, { cache: 'no-cache' }).then((res) => {
      if (res.ok) cache.put(req, res.clone());
      return res;
    });
    const cached = await cache.match(req, { ignoreSearch: true });
    if (!cached) return network;
    // Bei schlechtem Empfang nicht ewig warten
    const timeout = new Promise((resolve) => setTimeout(() => resolve(cached), TIMEOUT_MS));
    return Promise.race([network.catch(() => cached), timeout]);
  })());
});
