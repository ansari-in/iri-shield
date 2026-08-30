'use strict';

// ---------------------------------------------------------------------------
// Custom & Built-in Rule Engine
// Evaluates configurable rules against incoming requests
// ---------------------------------------------------------------------------

/**
 * Apply custom rules defined in config.rules.customRules[]
 * Each custom rule can match on: endpoint, method, ip, userAgent, body fields
 */
function applyCustomRules(req, config) {
  const customRules = config.rules && config.rules.customRules ? config.rules.customRules : [];
  const scoreParts = [];
  const threats = [];
  const reasons = [];
  const breakdown = [];

  if (!customRules.length) return { score: 0, threats, reasons, breakdown };

  const endpoint = (req.originalUrl || req.url || '/').toLowerCase();
  const method = (req.method || 'GET').toUpperCase();
  const userAgent = (
    (req.iriShieldClient && req.iriShieldClient.userAgent) ||
    req.headers['user-agent'] || ''
  ).toLowerCase();
  const ip = (req.iriShieldClient && req.iriShieldClient.ip) || '';

  for (const rule of customRules) {
    if (!rule || !rule.name) continue;

    let matched = false;

    // Endpoint match (string or regex)
    if (rule.match && rule.match.endpoint) {
      const pattern = rule.match.endpoint;
      if (typeof pattern === 'string') {
        matched = endpoint.includes(pattern.toLowerCase());
      } else if (pattern instanceof RegExp) {
        matched = pattern.test(endpoint);
      }
    }

    // Method match
    if (matched && rule.match && rule.match.method) {
      const methods = Array.isArray(rule.match.method)
        ? rule.match.method.map(function(m) { return m.toUpperCase(); })
        : [rule.match.method.toUpperCase()];
      if (!methods.includes(method)) matched = false;
    }

    // UserAgent match
    if (rule.match && rule.match.userAgent) {
      const uaPattern = rule.match.userAgent;
      if (typeof uaPattern === 'string') {
        matched = userAgent.includes(uaPattern.toLowerCase());
      } else if (uaPattern instanceof RegExp) {
        matched = uaPattern.test(userAgent);
      }
    }

    // IP match (exact or prefix)
    if (rule.match && rule.match.ip) {
      matched = ip.startsWith(rule.match.ip);
    }

    // Body field match
    if (rule.match && rule.match.bodyField && req.body && typeof req.body === 'object') {
      const entries = Object.entries(rule.match.bodyField);
      if (entries.length > 0) {
        const field = entries[0][0];
        const value = entries[0][1];
        if (field && value !== undefined) {
          matched = String(req.body[field] || '').toLowerCase().includes(String(value).toLowerCase());
        }
      }
    }

    if (matched) {
      const pts = rule.score || 25;
      scoreParts.push(pts);
      threats.push('custom_rule_' + rule.name);
      reasons.push(rule.reason || 'custom_rule_' + rule.name + '_matched');
      breakdown.push({
        rule: 'custom_rule_' + rule.name,
        label: rule.label || 'Custom Rule: ' + rule.name,
        points: pts,
        category: 'custom',
        confidence: rule.confidence || 85
      });
    }
  }

  const score = scoreParts.reduce(function(s, v) { return s + v; }, 0);
  return { score, threats, reasons, breakdown };
}

/**
 * Check if a built-in rule is enabled via config.rules.{ruleName}: true/false
 * Defaults to true
 */
function isRuleEnabled(config, ruleName) {
  if (!config.rules) return true;
  const key = camelCase(ruleName);
  if (config.rules[key] === false) return false;
  return true;
}

function camelCase(str) {
  return str.replace(/_([a-z])/g, function(_, c) { return c.toUpperCase(); });
}

module.exports = { applyCustomRules, isRuleEnabled, camelCase };
