const C="egk-v26",F=["/","/manifest.webmanifest","/icon-192.png","/icon-512.png"];
self.addEventListener("install",e=>{e.waitUntil(caches.open(C).then(c=>c.addAll(F)));self.skipWaiting()});
self.addEventListener("activate",e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!=C).map(x=>caches.delete(x)))));self.clients.claim()});
self.addEventListener("fetch",e=>{const u=new URL(e.request.url);if(e.request.method!="GET"||u.pathname.startsWith("/api/"))return;e.respondWith(fetch(e.request).then(r=>{const c=r.clone();caches.open(C).then(x=>x.put(e.request,c));return r}).catch(()=>caches.match(e.request).then(r=>r||caches.match("/"))))});
// notifiche: formato dichiarativo (Safari 18.4+ lo mostra da solo, gli altri browser passano di qui)
self.addEventListener("push",e=>{let d={};try{d=e.data?e.data.json():{}}catch(x){d={notification:{title:"Elite GK",body:e.data?e.data.text():""}}}
 const n=d.notification||d,url=n.navigate||n.url||"/";
 e.waitUntil(self.registration.showNotification(n.title||"Zeno Fit",{body:n.body||"",icon:"/icon-192.png",badge:"/icon-192.png",tag:n.tag,data:{url},lang:"it"}))});
self.addEventListener("notificationclick",e=>{e.notification.close();const url=(e.notification.data&&e.notification.data.url)||"/";
 e.waitUntil(self.clients.matchAll({type:"window",includeUncontrolled:true}).then(cs=>{for(const c of cs){if("focus"in c){c.navigate&&c.navigate(url);return c.focus()}}return self.clients.openWindow(url)}))});
