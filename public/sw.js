const CACHE='vault-offline-stage11-v2';
self.addEventListener('install',event=>{event.waitUntil(caches.open(CACHE).then(cache=>cache.add(new Request('/offline.html',{cache:'reload'}))));});
self.addEventListener('activate',event=>{event.waitUntil((async()=>{for(const key of await caches.keys())if(key.startsWith('vault-offline-stage11-') && key!==CACHE)await caches.delete(key);await self.clients.claim();})());});
self.addEventListener('fetch',event=>{
 const url=new URL(event.request.url);
 if(url.origin!==self.location.origin || event.request.method!=='GET' || event.request.mode!=='navigate' || !['/','/index.html'].includes(url.pathname))return;
 event.respondWith(fetch(event.request).catch(async()=> (await caches.open(CACHE)).match('/offline.html')));
});
