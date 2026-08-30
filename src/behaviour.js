'use strict';

// ---------------------------------------------------------------------------
// Behaviour Baseline + Deviation Detection
// ---------------------------------------------------------------------------

var WINDOW_MS = 5 * 60 * 1000; // 5-minute rolling window

function recordBehaviour(ip, endpoint, method, statusCode, behaviourStore) {
  if (!ip || !behaviourStore) return;
  var key = ip;
  var now = Date.now();
  var record = behaviourStore.get(key) || {
    ip: ip, windows: [], baseline: null, totalRequests: 0
  };

  var currentWindow = null;
  for (var i = 0; i < record.windows.length; i++) {
    if (now - record.windows[i].startMs < WINDOW_MS) {
      currentWindow = record.windows[i];
      break;
    }
  }
  if (!currentWindow) {
    currentWindow = { startMs: now, count: 0, endpoints: {}, methods: {}, statuses: {} };
    record.windows.push(currentWindow);
    // evict windows older than 30 min
    record.windows = record.windows.filter(function(w) { return now - w.startMs < 30 * 60 * 1000; });
  }

  currentWindow.count += 1;
  currentWindow.endpoints[endpoint] = (currentWindow.endpoints[endpoint] || 0) + 1;
  currentWindow.methods[method] = (currentWindow.methods[method] || 0) + 1;
  currentWindow.statuses[statusCode] = (currentWindow.statuses[statusCode] || 0) + 1;
  record.totalRequests += 1;

  if (record.totalRequests % 10 === 0 && record.windows.length > 1) {
    record.baseline = computeBaseline(record.windows.slice(0, -1));
  }

  behaviourStore.set(key, record);
}

function getBehaviourDeviation(ip, behaviourStore) {
  var empty = { deviationPercent: 0, currentRpm: 0, baselineRpm: 0, details: {} };
  if (!ip || !behaviourStore) return empty;
  var record = behaviourStore.get(ip);
  if (!record || !record.baseline || record.windows.length < 2) return empty;

  var now = Date.now();
  var currentWindow = null;
  for (var i = 0; i < record.windows.length; i++) {
    if (now - record.windows[i].startMs < WINDOW_MS) { currentWindow = record.windows[i]; break; }
  }
  if (!currentWindow) return empty;

  var elapsedMinutes = Math.max((now - currentWindow.startMs) / 60000, 0.1);
  var currentRpm = currentWindow.count / elapsedMinutes;
  var baselineRpm = record.baseline.avgRpm;
  var deviationPercent = 0;
  if (baselineRpm > 0) {
    deviationPercent = Math.min(100, Math.round(((currentRpm - baselineRpm) / baselineRpm) * 100));
    if (deviationPercent < 0) deviationPercent = 0;
  }

  return {
    deviationPercent: deviationPercent,
    currentRpm: Math.round(currentRpm * 10) / 10,
    baselineRpm: Math.round(baselineRpm * 10) / 10,
    details: {
      currentWindow: summariseWindow(currentWindow),
      baseline: record.baseline
    }
  };
}

function getBehaviourSummary(ip, behaviourStore) {
  if (!ip || !behaviourStore) return null;
  var record = behaviourStore.get(ip);
  if (!record) return null;
  return {
    ip: ip,
    totalRequests: record.totalRequests,
    baseline: record.baseline,
    windowCount: record.windows.length,
    latestWindow: record.windows.length > 0
      ? summariseWindow(record.windows[record.windows.length - 1])
      : null
  };
}

function computeBaseline(windows) {
  if (!windows.length) return null;
  var totalCount = 0;
  var allEndpoints = {}, allMethods = {}, allStatuses = {};
  for (var i = 0; i < windows.length; i++) {
    var w = windows[i];
    totalCount += w.count;
    Object.keys(w.endpoints || {}).forEach(function(ep) {
      allEndpoints[ep] = (allEndpoints[ep] || 0) + w.endpoints[ep];
    });
    Object.keys(w.methods || {}).forEach(function(m) {
      allMethods[m] = (allMethods[m] || 0) + w.methods[m];
    });
    Object.keys(w.statuses || {}).forEach(function(s) {
      allStatuses[s] = (allStatuses[s] || 0) + w.statuses[s];
    });
  }
  var avgRpm = totalCount / (windows.length * (WINDOW_MS / 60000));
  var errorCount = Object.keys(allStatuses).filter(function(s) { return Number(s) >= 400; })
    .reduce(function(sum, s) { return sum + allStatuses[s]; }, 0);
  return {
    avgRpm: Math.round(avgRpm * 10) / 10,
    totalRequests: totalCount,
    topEndpoints: Object.entries(allEndpoints).sort(function(a,b){ return b[1]-a[1]; }).slice(0,5)
      .map(function(e) { return { endpoint: e[0], count: e[1] }; }),
    topMethods: Object.entries(allMethods).sort(function(a,b){ return b[1]-a[1]; })
      .map(function(e) { return { method: e[0], count: e[1] }; }),
    errorRate: totalCount > 0 ? Math.round((errorCount / totalCount) * 100) : 0
  };
}

function summariseWindow(w) {
  if (!w) return null;
  var elapsedMinutes = Math.max((Date.now() - w.startMs) / 60000, 0.1);
  return {
    count: w.count,
    rpm: Math.round((w.count / elapsedMinutes) * 10) / 10,
    topEndpoints: Object.entries(w.endpoints || {}).sort(function(a,b){ return b[1]-a[1]; }).slice(0,3)
      .map(function(e) { return { endpoint: e[0], count: e[1] }; }),
    methods: Object.entries(w.methods || {}).map(function(e) { return { method: e[0], count: e[1] }; })
  };
}

module.exports = { recordBehaviour, getBehaviourDeviation, getBehaviourSummary, WINDOW_MS };
