// hust-helper Service Worker
// 策略：静态外壳预缓存；页面导航 network-first（保证每次部署拿到最新）；
// 跨域 API（腾讯云 SCF）不缓存，直接走网络，保证订单/问答/消息实时。
const APP_PREFIX = 'husthelper_';
const CACHE_VERSION = 'v1';
const CACHE_NAME = APP_PREFIX + CACHE_VERSION;

const PRECACHE_ASSETS = [
  '/hust-helper/',
  '/hust-helper/index.html',
  '/hust-helper/manifest.webmanifest',
  '/hust-helper/icons/icon-192.png',
  '/hust-helper/icons/icon-512.png',
  '/hust-helper/favicon.png',
  '/hust-helper/version.txt'
];

self.addEventListener('install', function (event) {
  event.waitUntil(
    caches.open(CACHE_NAME).then(function (cache) {
      return cache.addAll(PRECACHE_ASSETS);
    }).then(function () { return self.skipWaiting(); })
  );
});

self.addEventListener('activate', function (event) {
  event.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(keys.map(function (k) {
        if (k.indexOf(APP_PREFIX) === 0 && k !== CACHE_NAME) {
          return caches.delete(k);
        }
        return null;
      }));
    }).then(function () { return self.clients.claim(); })
  );
});

self.addEventListener('fetch', function (event) {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);

  // 跨域 API（腾讯云 SCF）：不缓存，直接走网络，保证实时数据
  if (url.origin !== self.location.origin) {
    event.respondWith(fetch(req));
    return;
  }

  // 页面导航：network-first，失败回退缓存外壳（支持离线打开框架）
  if (req.mode === 'navigate' || req.destination === 'document') {
    event.respondWith(
      fetch(req).then(function (res) {
        const copy = res.clone();
        caches.open(CACHE_NAME).then(function (c) { c.put(req, copy); });
        return res;
      }).catch(function () {
        return caches.match(req).then(function (r) { return r || caches.match('/hust-helper/index.html'); });
      })
    );
    return;
  }

  // 同源静态资源：cache-first
  event.respondWith(
    caches.match(req).then(function (cached) {
      if (cached) return cached;
      return fetch(req).then(function (res) {
        const copy = res.clone();
        caches.open(CACHE_NAME).then(function (c) { c.put(req, copy); });
        return res;
      });
    })
  );
});
