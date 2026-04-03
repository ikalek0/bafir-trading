// ─── BAFIR SERVICE WORKER ─────────────────────────────────────────────────────
const CACHE = "bafir-v1";
const STATIC = ["/app", "/app-icon.svg", "/manifest.json"];

self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(STATIC)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim()));
});

self.addEventListener("fetch", e => {
  // Solo cachear assets estáticos, no la API
  if (e.request.url.includes("/api/")) return;
  e.respondWith(caches.match(e.request).then(r => r || fetch(e.request)));
});

// ── NOTIFICACIONES PUSH ───────────────────────────────────────────────────────
self.addEventListener("push", e => {
  const data = e.data?.json() || {};
  e.waitUntil(
    self.registration.showNotification(data.title || "BAFIR TRADING", {
      body:    data.body || "",
      icon:    "/app-icon.svg",
      badge:   "/app-icon.svg",
      tag:     data.tag || "bafir",
      vibrate: [200, 100, 200],
      data:    { url: data.url || "/app" },
      actions: data.actions || [],
    })
  );
});

self.addEventListener("notificationclick", e => {
  e.notification.close();
  e.waitUntil(clients.openWindow(e.notification.data?.url || "/app"));
});
