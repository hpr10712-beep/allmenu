const CACHE = "cazoo-v4";
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", e => e.waitUntil(self.clients.claim()));
self.addEventListener("fetch", e => {
  if (e.request.method !== "GET") return;
  const url = new URL(e.request.url);
  if (url.origin.includes("firebaseio.com") ||
      url.origin.includes("googleapis.com") ||
      url.origin.includes("gstatic.com") ||
      url.origin.includes("googleusercontent.com")) return;
  e.respondWith(
    caches.open(CACHE).then(async c => {
      const cached = await c.match(e.request);
      const fetchP = fetch(e.request).then(res => {
        if (res.ok) c.put(e.request, res.clone());
        return res;
      }).catch(() => cached);
      return cached || fetchP;
    })
  );
});
