'use strict';

// ---------------------------------------------------------------------------
// Threat Detection Rules
// ---------------------------------------------------------------------------

const ATTACK_RULES = [
  // SQL Injection
  {
    name: 'sql_injection',
    score: 40,
    regex: /('|%27)\s*(or|and)\s*('|%27)?\d+=\d+|union\s+select|drop\s+table|insert\s+into|delete\s+from|update\s+\w+\s+set|exec\s*\(|execute\s*\(|xp_cmdshell|--\s*$/i
  },
  // XSS
  {
    name: 'xss_pattern',
    score: 35,
    regex: /<script[\s>]|javascript\s*:|onerror\s*=|onload\s*=|onfocus\s*=|onclick\s*=|eval\s*\(|document\.cookie|document\.write|innerHTML\s*=|src\s*=\s*["']?javascript/i
  },
  // Path Traversal
  {
    name: 'path_traversal',
    score: 35,
    regex: /\.\.\//i
  },
  // Secret / Config File Probing
  {
    name: 'secret_probe',
    score: 30,
    regex: /\.env|config\.json|wp-config|private[-_]?key|id_rsa|\.git\/config|\.htaccess|passwd|shadow|docker-compose\.yml/i
  },
  // Command Injection
  {
    name: 'command_injection',
    score: 45,
    regex: /;\s*(ls|cat|wget|curl|bash|sh|nc|netcat|python|perl|ruby|id|whoami|uname)\b|&&\s*(ls|cat|id|whoami)|\|\s*(cat|bash|sh|nc)\b|`[^`]+`|\$\([^)]+\)/
  },
  // Server-Side Template Injection (SSTI)
  {
    name: 'ssti_pattern',
    score: 40,
    regex: /\{\{[\s\S]*?\}\}|\$\{[\s\S]*?\}|#\{[\s\S]*?\}|<%([\s\S]*?)%>|\{\%[\s\S]*?\%\}|{{7\*7}}|\${7\*7}/i
  },
  // NoSQL Injection
  {
    name: 'nosql_injection',
    score: 40,
    regex: /\$where|\$gt\s*:|"\s*\$ne\s*"|\$regex|\$exists|\$in\s*:\s*\[|\$or\s*:\s*\[|"\s*\$gt\s*"\s*:/i
  },
  // LDAP Injection
  {
    name: 'ldap_injection',
    score: 35,
    regex: /[)(|*\\]{3,}|\(\|[\w=*]+\)|\(&[\w=*]+\)/
  },
  // XXE / XML Injection
  {
    name: 'xxe_pattern',
    score: 40,
    regex: /<!ENTITY|<!DOCTYPE[\s\S]*?SYSTEM|SYSTEM\s+["']https?:|file:\/\/\/|<!ELEMENT|<!ATTLIST/i
  },
  // Open Redirect
  {
    name: 'open_redirect',
    score: 25,
    regex: /[?&](redirect|return|url|next|to|dest|destination|ref|redir|return_url)\s*=\s*https?:\/\//i
  },
  // Base64 Encoded Payloads (suspicious encoding)
  {
    name: 'base64_payload',
    score: 20,
    regex: /[?&][^=]+=(?:[A-Za-z0-9+/]{40,}={0,2})(?:&|$)/
  },
  // HTTP Response Splitting
  {
    name: 'header_injection',
    score: 35,
    regex: /(%0d%0a|%0a%0d|\r\n|\n\r).*?:/i
  }
];

// ---------------------------------------------------------------------------
// User-Agent / Bot Detection
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
// ---------------------------------------------------------------------------

function analyzeRequest(req, storage, config) {
  const ip = req.iriShieldClient?.ip || getClientIp(req);
  const endpoint = req.originalUrl || req.url || '/';
  const userAgent = req.iriShieldClient?.userAgent || req.headers['user-agent'] || '';
  const headerSignals = req.iriShieldClient?.headerSignals || {};
  const text = collectText(req);

  const scoreParts = [];
  const threats = [];
  const reasons = [];

  // Security mode multiplier
  const modeMultiplier = getSecurityMultiplier(config.security);

  // --- Payload / URL attack pattern scanning ---
  for (const rule of ATTACK_RULES) {
    if (rule.regex.test(text)) {
      scoreParts.push(rule.score);
      threats.push(rule.name);
      reasons.push(rule.name);
    }
  }

  // --- Scanner / Bot User-Agent detection ---
  for (const rule of SCANNER_UA_PATTERNS) {
    if (rule.regex.test(userAgent)) {
      scoreParts.push(rule.score);
      threats.push(`scanner_ua_${rule.name}`);
      reasons.push(`ua_matches_${rule.name}`);
      break; // one match is enough for UA category
    }
  }

  // --- Empty or missing User-Agent ---
  if (!userAgent.trim()) {
    scoreParts.push(20);
    threats.push('missing_user_agent');
    reasons.push('no_user_agent_header');
  }

  // --- HTTP Method anomaly ---
  const allowed = config.anomaly?.allowedMethods || ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
  if (allowed.length && !allowed.includes(req.method)) {
    scoreParts.push(20);
    threats.push('unusual_http_method');
    reasons.push(`method_${req.method}_not_allowed`);
  }

  // --- Single endpoint flood ---
  const endpointHits = storage.recordEndpointHit(ip, endpoint);
  if (endpointHits > (config.anomaly?.singleEndpointMax || 80)) {
    scoreParts.push(25);
    threats.push('single_endpoint_flood');
    reasons.push(`endpoint_hits_${endpointHits}`);
  }

  // --- Sensitive endpoint access ---
  const normalizedEndpoint = endpoint.toLowerCase();
  const sensitivePatterns = config.anomaly?.sensitiveEndpoints || ['/admin', '/internal', '/debug', '/.env'];
  if (sensitivePatterns.some((item) => normalizedEndpoint.includes(item.toLowerCase()))) {
    scoreParts.push(20);
    threats.push('sensitive_endpoint_access');
    reasons.push(`sensitive_endpoint_${endpoint}`);
  }

  // --- Failed authentication tracking ---
  if (isFailedAuthRequest(req)) {
    const failedCount = storage.recordFailedAuth(ip);
    if (failedCount >= (config.anomaly?.failedAuthMax || 5)) {
      scoreParts.push(35);
      threats.push('repeated_failed_auth');
      reasons.push(`failed_auth_count_${failedCount}`);
    }
  }

  // --- Header anomaly: claims to be browser but missing standard headers ---
  if (headerSignals.missingBrowserHeaders) {
    scoreParts.push(15);
    threats.push('header_anomaly_missing_browser_headers');
    reasons.push('browser_ua_without_standard_headers');
  }

  // --- Claims to be modern browser but missing sec-fetch / sec-ch-ua ---
  if (headerSignals.missingModernHeaders) {
    scoreParts.push(10);
    threats.push('header_anomaly_missing_modern_headers');
    reasons.push('chrome_ua_without_sec_fetch_headers');
  }

  // --- Apply security mode multiplier ---
  const rawScore = scoreParts.reduce((sum, v) => sum + v, 0);
  const score = Math.min(100, Math.round(rawScore * modeMultiplier));
  const riskLevel = riskFromScore(score, config);
  const action = actionFromRisk(riskLevel);

  return { score, riskLevel, action, threats, reasons };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function collectText(req) {
  const chunks = [req.originalUrl || req.url || '', req.headers['user-agent'] || ''];
  if (req.query) chunks.push(JSON.stringify(req.query));
  // Collect body — exclude __iri testing override to avoid false positives
  if (req.body && typeof req.body === 'object') {
    const bodyClone = { ...req.body };
    delete bodyClone.__iri;
    delete bodyClone.iriShieldTest;
    chunks.push(JSON.stringify(bodyClone));
  }
  if (typeof req.body === 'string') chunks.push(req.body);
  // Check suspicious headers
  const suspiciousHeaders = ['x-forwarded-for', 'referer', 'x-custom-ip'];
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
  return req.ip || req.socket?.remoteAddress || req.connection?.remoteAddress || 'unknown';
}

function getSecurityMultiplier(mode) {
  if (mode === 'high') return 1.3;
  if (mode === 'low') return 0.7;
  return 1.0; // medium (default)
}

function riskFromScore(score, config) {
  const anomaly = config.anomaly || {};
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
