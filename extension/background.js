let stats = {
  startTime: Date.now(),
  apiCalls: 0,
  detections: 0,
  prompts: 0,
  apiCallsList: [],
  detectionsList: [],
  promptsList: []
};

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  
  // Handle data collection
  if (request.type === 'api_call') {
    stats.apiCalls++;
    stats.apiCallsList.push({type: request.data.type, url: sender.url});
    console.log(`[BSM] API #${stats.apiCalls}: ${request.data.type}`);
  }
  
  if (request.type === 'detection') {
    stats.detections++;
    stats.detectionsList.push({type: request.data.type, url: sender.url});
    console.log(`[BSM] DETECTION #${stats.detections}: ${request.data.type}`);
  }
  
  if (request.type === 'prompt_injection') {
    stats.prompts++;
    stats.promptsList.push({score: request.data.score, url: sender.url});
    console.log(`[BSM] PROMPT #${stats.prompts}: Score ${request.data.score}`);
  }
  
  // Handle stats request
  if (request.type === 'get_stats') {
    sendResponse({
      collected: true,
      apiCalls: stats.apiCalls,
      detections: stats.detections,
      prompts: stats.prompts,
      uptime: Math.round((Date.now() - stats.startTime) / 1000),
      apiCallsList: stats.apiCallsList.slice(-20),
      detectionsList: stats.detectionsList,
      promptsList: stats.promptsList
    });
  }
  
  sendResponse({ok: true});
});

console.log('[BSM-BG] Ready');
