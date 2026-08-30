'use strict';

const { isRuleEnabled } = require('./rules');

// ---------------------------------------------------------------------------
// Attack Rule Definitions — each rule has: name, configKey, score, label, category, regex
// ---------------------------------------------------------------------------

const ATTACK_RULES = [
  { name: 'sql_injection', configKey: 'sqlInjection', score: 40, label: 'SQL Injection pattern', category: 'injection',
    regex: /('|%27)\s*(or|and)\s*('|%27)?\d+=\d+|union\s+select|drop\s+table|insert\s+into|delete\s+from|update\s+\w+\s+set|exec\s*\(|execute\s*\(|xp_cmdshell|--\s*$/i },
  { name: 'xss_pattern', configKey: 'xss', score: 35, label: 'Cross-Site Scripting (XSS) attempt', category: 'injection',
    regex: /<script[\s>]|javascript\s*:|onerror\s*=|onload\s*=|onfocus\s*=|onclick\s*=|eval\s*\(|document\.cookie|document\.write|innerHTML\s*=|src\s*=\s*["']?javascript/i },
  { name: 'path_traversal', configKey: 'pathTraversal', score: 35, label: 'Path traversal attack', category: 'traversal',
    regex: /\.\.\//i },
  { name: 'secret_probe', configKey: 'secretProbe', score: 30, label: 'Secret / config file probe', category: 'recon',
    regex: /\.env|config\.json|wp-config|private[-_]?key|id_rsa|\.git\/config|\.htaccess|passwd|shadow|docker-compose\.yml/i },
  { name: 'command_injection', configKey: 'commandInjection', score: 45, label: 'Command injection attempt', category: 'injection',
    regex: /;\s*(ls|cat|wget|curl|bash|sh|nc|netcat|python|perl|ruby|id|whoami|uname)\b|&&\s*(ls|cat|id|whoami)|\|\s*(cat|bash|sh|nc)\b|`[^`]+`|\$\([^)]+\)/ },
  { name: 'ssti_pattern', configKey: 'ssti', score: 40, label: 'Server-Side Template Injection (SSTI)', category: 'injection',
    regex: /\{\{[\s\S]*?\}\}|\$\{[\s\S]*?\}|#\{[\s\S]*?\}|<%[\s\S]*?%>|\{%[\s\S]*?%\}|{{7\*7}|\${7\*7}/i },
  { name: 'nosql_injection', configKey: 'nosqlInjection', score: 40, label: 'NoSQL Injection attempt', category: 'injection',
    regex: /\$where|\$gt\s*:|"\s*\$ne\s*"|\$regex|\$exists|\$in\s*:\s*\[|\$or\s*:\s*\[|"\s*\$gt\s*"\s*:/i },
  { name: 'ldap_injection', configKey: 'ldapInjection', score: 35, label: 'LDAP Injection attempt', category: 'injection',
    regex: /[)(|*\\]{3,}|\(\|[\w=*]+\)|\(&[\w=*]+\)/ },
  { name: 'xxe_pattern', configKey: 'xxe', score: 40, label: 'XXE / XML Injection', category: 'injection',
    regex: /<!ENTITY|<!DOCTYPE[\s\S]*?SYSTEM|SYSTEM\s+["']https?:|file:\/\/\/|<!ELEMENT|<!ATTLIST/i },
  { name: 'open_redirect', configKey: 'openRedirect', score: 25, label: 'Open redirect attempt', category: 'redirect',
    regex: /[?&](redirect|return|url|next|to|dest|destination|ref|redir|return_url)\s*=\s*https?:\/\//i },
  { name: 'base64_payload', configKey: 'base64Payload', score: 20, label: 'Suspicious base64-encoded payload', category: 'evasion',
    regex: /[?&][^=]+=(?:[A-Za-z0-9+/]{40,}={0,2})(?:&|$)/ },
  { name: 'header_injection', configKey: 'headerInjection', score: 35, label: 'HTTP header injection', category: 'injection',
    regex: /(%0d%0a|%0a%0d|\r\n|\n\r).*?:/i }
];

// ---------------------------------------------------------------------------
// Scanner / Bot User-Agent patterns
// ---------------------------------------------------------------------------

const SCANNER_UA_PATTERNS = [
  { name: 'sqlmap', score: 50, regex: /sqlmap/i },
  { name: 'nikto', score: 50, regex: /nikto/i },
  { name: 'masscan', score: 45, regex: /masscan/i },
  { name: 'nmap', score: 45, regex: /nmap/i },
  { name: 'zgrab', score: 45, regex: /zgrab/i },
  { name: 'dirbuster', score: 50, regex: /dirbuster/i },
  { name: 'gobuster', score: 50, regex: /gobuster/i },
  { name: 'wfuzz', score: 50, regex: /wfuzz/i },
  { name: 'hydra', score: 50, regex: /hydra/i },
  { name: 'burpsuite', score: 40, regex: /burpsuite|burp\s*suite/i },
  { name: 'metasploit', score: 55, regex: /metasploit/i },
  { name: 'headless_chrome', score: 30, regex: /HeadlessChrome/i },
  { name: 'phantomjs', score: 35, regex: /PhantomJS/i },
  { name: 'puppeteer', score: 25, regex: /puppeteer/i },
  { name: 'python_requests', score: 15, regex: /python-requests\//i },
  { name: 'go_http', score: 15, regex: /^Go-http-client\//i },
  { name: 'curl_automated', score: 10, regex: /^curl\//i },
  { name: 'wget', score: 20, regex: /^Wget\//i },
  { name: 'java_ua', score: 15, regex: /^Java\//i },
  { name: 'libwww', score: 20, regex: /libwww-perl|LWP::/i }
];

// ---------------------------------------------------------------------------
// Core Analysis Function
// Returns: { score, riskLevel, action, threats, reasons, breakdown, confidence, anomalies }
// ---------------------------------------------------------------------------

function analyzeRequest(req, storage, config) {
  const ip = (req.iriShieldClient && req.iriShieldClient.ip) || getClientIp(req);
  const endpoint = req.originalUrl || req.url || '/';
  const userAgent = (req.iriShieldClient && req.iriShieldClient.userAgent) || req.headers['user-agent'] || '';
  const headerSignals = (req.iriShieldClient && req.iriShieldClient.headerSignals) || {};
  const text = collectText(req);

  const scoreParts = [];
  const threats = [];
  const reasons = [];
  const breakdown = [];
  const anomalies = [];

  const modeMultiplier = getSecurityMultiplier(config.security);

  // --- Payload / URL attack pattern scanning ---
  for (const rule of ATTACK_RULES) {
    if (!isRuleEnabled(config, rule.configKey)) continue;
    if (rule.regex.test(text)) {
      scoreParts.push(rule.score);
      threats.push(rule.name);
      reasons.push(rule.name);
      breakdown.push({
        rule: rule.name,
        label: rule.label,
        points: rule.score,
        category: rule.category,
        confidence: 90
      });
    }
  }

  // --- Scanner / Bot detection ---
  if (isRuleEnabled(config, 'scannerDetection')) {
    for (const rule of SCANNER_UA_PATTERNS) {
      if (rule.regex.test(userAgent)) {
        scoreParts.push(rule.score);
        threats.push('scanner_ua_' + rule.name);
        reasons.push('ua_matches_' + rule.name);
        breakdown.push({
          rule: 'scanner_ua_' + rule.name,
          label: 'Scanner / Bot detected (' + rule.name + ')',
          points: rule.score,
          category: 'scanner',
          confidence: 95
        });
        break;
      }
    }
  }

  // --- Empty / missing User-Agent ---
  if (!userAgent.trim()) {
    scoreParts.push(20);
    threats.push('missing_user_agent');
    reasons.push('no_user_agent_header');
    breakdown.push({ rule: 'missing_user_agent', label: 'Missing User-Agent header', points: 20, category: 'anomaly', confidence: 80 });
    anomalies.push('missing_user_agent');
  }

  // --- HTTP Method anomaly ---
  const allowed = (config.anomaly && config.anomaly.allowedMethods) || ['GET','POST','PUT','PATCH','DELETE','OPTIONS'];
  if (allowed.length && !allowed.includes(req.method)) {
    scoreParts.push(20);
    threats.push('unusual_http_method');
    reasons.push('method_' + req.method + '_not_allowed');
    breakdown.push({ rule: 'unusual_http_method', label: 'Unusual HTTP method: ' + req.method, points: 20, category: 'anomaly', confidence: 75 });
    anomalies.push('unusual_http_method');
  }

  // --- Single endpoint flood ---
  const endpointHits = storage.recordEndpointHit(ip, endpoint);
  if (endpointHits > ((config.anomaly && config.anomaly.singleEndpointMax) || 80)) {
    scoreParts.push(25);
    threats.push('single_endpoint_flood');
    reasons.push('endpoint_hits_' + endpointHits);
    breakdown.push({ rule: 'single_endpoint_flood', label: 'Abnormal request rate to single endpoint (' + endpointHits + ' hits)', points: 25, category: 'anomaly', confidence: 85 });
    anomalies.push('single_endpoint_flood');
  }

  // --- Sensitive endpoint access ---
  const normalizedEndpoint = endpoint.toLowerCase();
  const sensitivePatterns = (config.anomaly && config.anomaly.sensitiveEndpoints) || ['/admin','/internal','/debug','/.env'];
  if (sensitivePatterns.some(function(item) { return normalizedEndpoint.includes(item.toLowerCase()); })) {
    scoreParts.push(20);
    threats.push('sensitive_endpoint_access');
    reasons.push('sensitive_endpoint_' + endpoint);
    breakdown.push({ rule: 'sensitive_endpoint_access', label: 'Access to sensitive endpoint: ' + endpoint, points: 20, category: 'anomaly', confidence: 80 });
    anomalies.push('sensitive_endpoint_access');
  }

  // --- Failed auth tracking ---
  if (isFailedAuthRequest(req)) {
    const failedCount = storage.recordFailedAuth(ip);
    if (failedCount >= ((config.anomaly && config.anomaly.failedAuthMax) || 5)) {
      scoreParts.push(35);
      threats.push('repeated_failed_auth');
      reasons.push('failed_auth_count_' + failedCount);
      breakdown.push({ rule: 'repeated_failed_auth', label: 'Repeated failed authentication (' + failedCount + ' attempts)', points: 35, category: 'anomaly', confidence: 88 });
      anomalies.push('repeated_failed_auth');
    }
  }

  // --- Header anomalies ---
  if (isRuleEnabled(config, 'headerAnomaly')) {
    if (headerSignals.missingBrowserHeaders) {
      scoreParts.push(15);
      threats.push('header_anomaly_missing_browser_headers');
      reasons.push('browser_ua_without_standard_headers');
      breakdown.push({ rule: 'header_anomaly_missing_browser_headers', label: 'Browser UA without standard headers', points: 15, category: 'anomaly', confidence: 70 });
      anomalies.push('header_anomaly_missing_browser_headers');
    }
    if (headerSignals.missingModernHeaders) {
      scoreParts.push(10);
      threats.push('header_anomaly_missing_modern_headers');
      reasons.push('chrome_ua_without_sec_fetch_headers');
      breakdown.push({ rule: 'header_anomaly_missing_modern_headers', label: 'Chrome UA without Sec-Fetch headers', points: 10, category: 'anomaly', confidence: 65 });
      anomalies.push('header_anomaly_missing_modern_headers');
    }
  }

  // --- Compute score ---
  const rawScore = scoreParts.reduce(function(sum, v) { return sum + v; }, 0);
  const score = Math.min(100, Math.round(rawScore * modeMultiplier));
  const riskLevel = riskFromScore(score, config);
  const action = actionFromRisk(riskLevel);

  // --- Compute confidence ---
  // Confidence = weighted average of individual rule confidences
  const confidence = breakdown.length > 0
    ? Math.round(breakdown.reduce(function(sum, b) { return sum + b.confidence; }, 0) / breakdown.length)
    : 0;

  return {
    score,
    riskLevel,
    action,
    threats,
    reasons,
    breakdown,
    confidence,
    anomalies
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function collectText(req) {
  const chunks = [req.originalUrl || req.url || '', req.headers['user-agent'] || ''];
  if (req.query) chunks.push(JSON.stringify(req.query));
  if (req.body && typeof req.body === 'object') {
    const bodyClone = Object.assign({}, req.body);
    delete bodyClone.__iri;
    delete bodyClone.iriShieldTest;
    chunks.push(JSON.stringify(bodyClone));
  }
  if (typeof req.body === 'string') chunks.push(req.body);
  const suspiciousHeaders = ['x-forwarded-for','referer','x-custom-ip'];
  for (const h of suspiciousHeaders) {
    if (req.headers[h]) chunks.push(req.headers[h]);
  }
  return chunks.join(' ');
}

function isFailedAuthRequest(req) {
  const path = String(req.originalUrl || req.url || '').toLowerCase();
  return (
    req.method === 'POST' &&
    (path.includes('/login') || path.includes('/auth') || path.includes('/signin')) &&
    !req.headers.authorization
  );
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) return forwarded.split(',')[0].trim();
  return req.ip || (req.socket && req.socket.remoteAddress) || (req.connection && req.connection.remoteAddress) || 'unknown';
}

function getSecurityMultiplier(mode) {
  if (mode === 'high') return 1.3;
  if (mode === 'low') return 0.7;
  return 1.0;
}

function riskFromScore(score, config) {
  const anomaly = (config && config.anomaly) || {};
  if (score >= (anomaly.criticalThreshold || 90)) return 'critical';
  if (score >= (anomaly.highThreshold || 65)) return 'high';
  if (score >= (anomaly.mediumThreshold || 35)) return 'medium';
  if (score > 0) return 'low';
  return 'none';
}

function actionFromRisk(riskLevel) {
  if (riskLevel === 'critical') return 'blocked';
  if (riskLevel === 'high') return 'temporary_block';
  if (riskLevel === 'medium') return 'rate_limited';
  if (riskLevel === 'low') return 'logged';
  return 'none';
}

module.exports = {
  analyzeRequest,
  ATTACK_RULES,
  SCANNER_UA_PATTERNS,
  riskFromScore,
  actionFromRisk,
  getSecurityMultiplier
};
