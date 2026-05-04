console.log('[BSM] Injected script running');

window.BSM_PAGE_DATA = {
  calls: [],
  detections: [],
  startTime: Date.now()
};

const origFetch = window.fetch;
window.fetch = function(...args) {
  window.BSM_PAGE_DATA.calls.push({type: 'fetch', time: Date.now()});
  window.postMessage({type: 'bsm_api_call', data: {type: 'fetch'}}, '*');
  return origFetch.apply(this, args);
};

try {
  const origEval = window.eval;
  window.eval = function(...args) {
    window.BSM_PAGE_DATA.detections.push({type: 'eval', time: Date.now()});
    window.postMessage({type: 'bsm_detection', data: {type: 'eval'}}, '*');
    return origEval.apply(this, args);
  };
} catch(e) {}

try {
  const origOpen = window.open;
  window.open = function(...args) {
    window.BSM_PAGE_DATA.calls.push({type: 'open', time: Date.now()});
    window.postMessage({type: 'bsm_api_call', data: {type: 'open'}}, '*');
    return origOpen.apply(this, args);
  };
} catch(e) {}

const origPrompt = window.prompt;
window.prompt = function(msg, def) {
  const result = origPrompt.call(window, msg, def);
  if (result) {
    const kw = ['ignore', 'bypass', 'jailbreak', 'password', 'token', 'secret'];
    let score = 0;
    for (let k of kw) {
      if (result.toLowerCase().includes(k)) score += 10;
    }
    if (score > 20) {
      window.BSM_PAGE_DATA.detections.push({type: 'prompt', score: score});
      window.postMessage({type: 'bsm_prompt', data: {score: score}}, '*');
    }
  }
  return result;
};

window.exportBSMData = function() {
  const data = {
    ...window.BSM_PAGE_DATA,
    timestamp: new Date().toISOString()
  };
  console.log('=== BSM DATA ===');
  console.log(JSON.stringify(data, null, 2));
  copy(JSON.stringify(data, null, 2));
  return data;
};

console.log('[BSM] ✅ Ready - Run: window.exportBSMData()');
