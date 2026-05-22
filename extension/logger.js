// Inject immediately before page loads
const injectScript = () => {
  const script = document.createElement('script');
  script.textContent = `
(() => {
  window.BSM_DATA = {calls: [], detections: [], startTime: Date.now()};
  console.log('[BSM-PAGE] Data store created');
  
  // Wrap fetch
  const origFetch = window.fetch;
  window.fetch = function(...args) {
    window.BSM_DATA.calls.push({type: 'fetch', t: Date.now()});
    return origFetch.apply(this, args);
  };
  
  // Wrap eval
  try {
    const origEval = window.eval;
    window.eval = function(...args) {
      window.BSM_DATA.detections.push({type: 'eval'});
      return origEval.apply(this, args);
    };
  } catch(e) {}
  
  console.log('[BSM-PAGE] ✅ Ready - window.BSM_DATA exists');
})();
  `;
  
  if (document.head) {
    document.head.insertBefore(script, document.head.firstChild);
  } else if (document.documentElement) {
    document.documentElement.insertBefore(script, document.documentElement.firstChild);
  }
};

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', injectScript);
} else {
  injectScript();
}

// Also try immediately
injectScript();

console.log('[BSM-CONTENT] Injection initialized');
