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
    const analysis = analyzePIDetection(result);
    if (analysis.score >= 15) {
      window.BSM_PAGE_DATA.detections.push({
        type: 'prompt_injection',
        score: analysis.score,
        matched: analysis.matched,
        features: analysis.features
      });
      window.postMessage({
        type: 'bsm_prompt',
        data: {score: analysis.score, matched: analysis.matched}
      }, '*');
    }
  }
  return result;
};

function analyzePIDetection(input) {
  let threat_score = 0;
  let matched = [];

  const lower = input.toLowerCase();

  // ---- TIER 1: Keyword Pattern Matching (6 categories) ----

  // Category 1: Instruction override (+10)
  const INSTRUCTION_OVERRIDE = [
    'ignore previous', 'ignore above', 'ignore all',
    'forget your instructions', 'ignore your instructions',
    'new instructions', 'override', 'you are now', 'act as', 'pretend to be',
    'system prompt', 'reveal your prompt',
    'show me your instructions', 'disregard',
    'ignore prior', 'ignore earlier', 'reset your',
    'original instructions', 'initial prompt'
  ];
  
  if (INSTRUCTION_OVERRIDE.some(k => lower.includes(k))) {
    threat_score += 10;
    matched.push('instruction_override');
  }

  // Category 2: SQL injection (+10)
  const SQL_INJECTION = [
    'drop table', 'select * from', 'union select',
    '1=1', 'or 1=1', "'; drop", '-- ', '/*',
    'insert into', 'delete from', 'update set',
    'exec sp_', 'xp_cmdshell'
  ];
  if (SQL_INJECTION.some(k => lower.includes(k))) {
    threat_score += 10;
    matched.push('sql_injection');
  }

  // Category 3: Code execution (+10)
  const CODE_EXECUTION = [
    'eval(', 'exec(', 'os.system', 'subprocess',
    'import os', '__import__', 'shell_exec',
    'system(', 'passthru(', 'popen(',
    'child_process', 'require("fs")'
  ];
  if (CODE_EXECUTION.some(k => lower.includes(k))) {
    threat_score += 10;
    matched.push('code_execution');
  }

  // Category 4: Credential extraction (+8)
  const CREDENTIAL_EXTRACTION = [
    'password', 'api key', 'secret key', 'token',
    'credential', 'access key', 'private key',
    'auth token', 'session id', 'cookie',
    'encryption key', 'ssh key'
  ];
  if (CREDENTIAL_EXTRACTION.some(k => lower.includes(k))) {
    threat_score += 8;
    matched.push('credential_extraction');
  }

  // Category 5: Constraint bypass (+10)
  const CONSTRAINT_BYPASS = [
    'jailbreak', 'dan', 'do anything now',
    'no restrictions', 'bypass', 'unlocked mode',
    'ignore safety', 'remove filter',
    'without limitations', 'unrestricted'
  ];
  if (CONSTRAINT_BYPASS.some(k => lower.includes(k))) {
    threat_score += 10;
    matched.push('constraint_bypass');
  }

  // Category 6: Data modification (+8)
  const DATA_MODIFICATION = [
    'modify data', 'change record', 'alter table',
    'overwrite', 'replace content', 'edit database',
    'update record', 'delete record'
  ];
  if (DATA_MODIFICATION.some(k => lower.includes(k))) {
    threat_score += 8;
    matched.push('data_modification');
  }

  // ---- TIER 2: Linguistic Feature Analysis ----

  const features = {};

  // Feature 1: Prompt length
  features.prompt_length = input.length;
  if (input.length > 500) {
    threat_score += 5;
    matched.push('long_prompt');
  }

  // Feature 2: Token count
  features.token_count = input.split(/\s+/).filter(t => t.length > 0).length;

  // Feature 3: Special character ratio
  const specialChars = input.replace(/[a-zA-Z0-9\s]/g, '').length;
  features.special_char_ratio = specialChars / Math.max(input.length, 1);

  // Feature 4: Capitalization ratio
  const upperCount = (input.match(/[A-Z]/g) || []).length;
  const alphaCount = (input.match(/[a-zA-Z]/g) || []).length;
  features.cap_ratio = upperCount / Math.max(alphaCount, 1);

  // Feature 5: Dictionary word percentage (simplified - checks common words)
  const tokens = input.toLowerCase().split(/\s+/);
  // Simplified check: tokens < 3 chars or with special chars are "non-dictionary"
  const dictLike = tokens.filter(t => /^[a-z]{3,}$/.test(t)).length;
  features.dict_word_pct = dictLike / Math.max(tokens.length, 1);

  // Feature 6: Keyword match score (already computed above)
  features.keyword_score = threat_score;

  // Feature 7: Command verb presence
  const CMD_VERBS = ['execute', 'run', 'delete', 'send', 'fetch',
                      'download', 'upload', 'install', 'remove', 'kill'];
  features.cmd_verb = CMD_VERBS.some(v => lower.includes(v)) ? 1 : 0;

  // Features 8-10: Already counted in keyword categories above

  // Feature 11: Prompt template similarity (simplified Jaccard)
  const TEMPLATE_TOKENS = new Set(['ignore', 'previous', 'instructions',
    'instead', 'following', 'output', 'respond', 'system', 'prompt',
    'reveal', 'bypass', 'restriction', 'jailbreak', 'pretend']);
  const inputTokens = new Set(lower.split(/\s+/));
  const intersection = [...TEMPLATE_TOKENS].filter(t => inputTokens.has(t)).length;
  features.template_similarity = intersection / Math.max(TEMPLATE_TOKENS.size, 1);

  // Feature 12: Semantic divergence (OOV ratio)
  // Simplified: tokens with special chars or very long tokens
  const oov = tokens.filter(t => /[^a-z]/.test(t) || t.length > 20).length;
  features.semantic_divergence = oov / Math.max(tokens.length, 1);

  // Feature 13: Multilingual indicators (Unicode script transitions)
  const scripts = input.match(/[\u0400-\u04FF]|[\u4E00-\u9FFF]|[\u0600-\u06FF]|[\u3040-\u309F]/g);
  features.multilingual = scripts ? scripts.length : 0;

  // Feature 14: Encoding anomalies
  const urlEncoded = (input.match(/%[0-9A-Fa-f]{2}/g) || []).length;
  const unicodeEsc = (input.match(/\\u[0-9A-Fa-f]{4}/g) || []).length;
  const base64 = (input.match(/[A-Za-z0-9+\/]{20,}={0,2}/g) || []).length;
  features.encoding_anomalies = urlEncoded + unicodeEsc + base64;

  // Feature 15: Newline/escape density
  const escapes = (input.match(/[\n\r\t]|\\n|\\r|\\t/g) || []).length;
  features.escape_density = escapes / Math.max(input.length, 1);
  if (escapes > 0) {
    threat_score += 8;
    matched.push('escape_chars');
  }

  return {
    score: threat_score,
    matched: matched,
    features: features,
    classification: threat_score >= 15 ? 'INJECTION' : 'BENIGN'
  };
}

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
