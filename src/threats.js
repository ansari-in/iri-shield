'use strict';

const suspiciousRules = [
  { name: 'sql_injection_pattern', score: 35, regex: /('|%27)\s*(or|and)\s*('|%27)?\d+=\d+|union\s+select|drop\s+table|--/i },
  { name: 'xss_pattern', score: 30, regex: /<script|javascript:|onerror\s*=|onload\s*=/i },
  { name: 'path_traversal_pattern', score: 30, regex: /\.\.\/|\.\.\\|%2e%2e/i },
  { name: 'secret_probe', score: 25, regex: /\.env|config\.json|wp-config|private-key|id_rsa/i }
];

function getClientIp(req) {
  if (req.iriShieldClient?.ip) return req.iriShieldClient.ip;
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) return forwarded.split(',')[0].trim();
  return req.ip || req.socket?.remoteAddress || req.connection?.remoteAddress || 'unknown';
}

function collectText(req) {
  const chunks = [req.originalUrl || req.url || '', req.headers['user-agent'] || ''];
  if (req.query) chunks.push(JSON.stringify(req.query));
  if (req.body && typeof req.body === 'object') chunks.push(JSON.stringify(req.body));
  if (typeof req.body === 'string') chunks.push(req.body);
  return chunks.join(' ');
}

function analyzeRequest(req, storage, config) {
  const ip = getClientIp(req);
  const endpoint = req.originalUrl || req.url || '/';
  const text = collectText(req);
  const scoreParts = [];
  const threats = [];
  const reasons = [];

  for (const rule of suspiciousRules) {
    if (rule.regex.test(text)) {
      scoreParts.push(rule.score);
      threats.push(rule.name);
      reasons.push(rule.name);
    }
  }

  const allowed = config.anomaly.allowedMethods || [];
  if (allowed.length && !allowed.includes(req.method)) {
    scoreParts.push(20);
    threats.push('unusual_http_method');
    reasons.push(`method_${req.method}_not_allowed`);
  }

  const endpointHits = storage.recordEndpointHit(ip, endpoint);
  if (endpointHits > config.anomaly.singleEndpointMax) {
    scoreParts.push(25);
    threats.push('single_endpoint_flood');
    reasons.push(`endpoint_hits_${endpointHits}`);
  }

  const normalizedEndpoint = endpoint.toLowerCase();
  if ((config.anomaly.sensitiveEndpoints || []).some((item) => normalizedEndpoint.includes(item.toLowerCase()))) {
    scoreParts.push(20);
    threats.push('sensitive_endpoint_access');
    reasons.push(`sensitive_endpoint_${endpoint}`);
  }

  if (resFailedAuth(req)) {
    const failedCount = storage.recordFailedAuth(ip);
    if (failedCount >= config.anomaly.failedAuthMax) {
      scoreParts.push(35);
      threats.push('repeated_failed_auth');
      reasons.push(`failed_auth_${failedCount}`);
    }
  }

  const score = Math.min(100, scoreParts.reduce((sum, value) => sum + value, 0));
  const riskLevel = riskFromScore(score, config);
  const action = actionFromRisk(riskLevel);
  return { score, riskLevel, action, threats, reasons };
}

function resFailedAuth(req) {
  const path = String(req.originalUrl || req.url || '').toLowerCase();
  return req.method === 'POST' && (path.includes('/login') || path.includes('/auth')) && !req.headers.authorization;
}

function riskFromScore(score, config) {
  if (score >= config.anomaly.criticalThreshold) return 'critical';
  if (score >= config.anomaly.highThreshold) return 'high';
  if (score >= config.anomaly.mediumThreshold) return 'medium';
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

module.exports = { analyzeRequest, suspiciousRules };
