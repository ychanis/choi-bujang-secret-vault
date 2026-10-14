const network=document.querySelector('#network-status'),button=document.querySelector('#install-app'),help=document.querySelector('#install-help');
let prompt=null;
function showNetwork(){network.textContent=navigator.onLine?'온라인 상태입니다. 보호 요청은 서버가 확인합니다.':'오프라인 상태입니다. 보호 자료를 표시하거나 저장하지 않습니다.';}
showNetwork();window.addEventListener('online',showNetwork);window.addEventListener('offline',showNetwork);
window.addEventListener('beforeinstallprompt',event=>{event.preventDefault();prompt=event;button.hidden=false;});
button.onclick=async()=>{if(!prompt)return;const current=prompt;prompt=null;button.hidden=true;try{await current.prompt();await current.userChoice;}catch{help.textContent='브라우저 메뉴에서 앱 설치를 다시 시도해 주세요.';}};
window.addEventListener('appinstalled',()=>{button.hidden=true;help.textContent='앱이 설치되었습니다. 기기 승인은 별도로 확인해야 합니다.';});
if('serviceWorker' in navigator)navigator.serviceWorker.register('/sw.js').catch(()=>{help.textContent='오프라인 안내를 준비하지 못했습니다. 온라인에서 다시 시도해 주세요.';});
