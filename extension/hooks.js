// Load the injected script using web_accessible_resources
const script = document.createElement('script');
script.src = chrome.runtime.getURL('injected.js');
script.onload = function() {
  this.remove();
};
(document.head || document.documentElement).appendChild(script);
console.log('[BSM] Injected script loader installed');
