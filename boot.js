"use strict";
(async()=>{
 const loading=document.getElementById('loading');
 try{
  if(!('serviceWorker' in navigator))throw new Error('This demo needs a browser with service worker support.');
  await navigator.serviceWorker.register('./static-demo-worker.js',{scope:'./'});
  await navigator.serviceWorker.ready;
  if(!navigator.serviceWorker.controller)await new Promise(resolve=>navigator.serviceWorker.addEventListener('controllerchange',resolve,{once:true}));
  const frame=document.createElement('iframe');frame.title='TRACE recorded investigation';frame.src='./ui/index.html';
  frame.addEventListener('load',()=>loading.remove(),{once:true});document.body.append(frame);
 }catch(error){loading.textContent=error.message+' Open this page over HTTPS or localhost.';}
})();
