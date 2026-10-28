"use strict";
const base=new URL('./',self.location).href;
self.addEventListener('install',event=>event.waitUntil(self.skipWaiting()));
self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));
function json(status,value){return new Response(JSON.stringify(value),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store'}});}
self.addEventListener('fetch',event=>{
 const request=event.request,url=new URL(request.url);
 if(url.origin!==self.location.origin)return;
 const path=url.pathname;
 if(path==='/api/status'){
  event.respondWith(Promise.resolve(json(200,{live_ready:false,reason:'This hosted demo only replays recorded evidence. Live execution is unavailable.',token:'',active_id:null})));return;
 }
 if(path==='/api/recording'&&request.method==='GET'){
  event.respondWith(fetch(new URL('ui/data/recorded-run.json',base),{cache:'no-store'}));return;
 }
 if(path.startsWith('/api/')){event.respondWith(Promise.resolve(json(503,{error:'Live execution is unavailable in this static demo.'})));return;}
 if(request.method!=='GET')return;
 const files=new Set(['/story.js','/story.css','/tokens.css']);
 if(files.has(path)||/^\/assets\/fonts\/[A-Za-z0-9_.-]+$/.test(path)){
  event.respondWith(fetch(new URL('ui'+path,base)));return;
 }
});
