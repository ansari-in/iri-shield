'use strict';

// ---------------------------------------------------------------------------
// Attack Sequence Correlation
// Detects known multi-step attack chains by analysing per-IP request history
// ---------------------------------------------------------------------------

var MAX_SEQUENCE_LENGTH = 30;

var ATTACK_CHAINS = [
  {
    name: 'account_takeover',
    label: 'Possible account takeover / reconnaissance',
    confidence: 88,
    riskBonus: 20,
    detect: function(seq) {
      var loginFails = seq.filter(function(s) { return s.threat === 'repeated_failed_auth'; }).length;
      var postAuth = seq.some(function(s) {
        return s.endpoint.includes('/user') || s.endpoint.includes('/admin') || s.endpoint.includes('/profile');
      });
      return loginFails >= 3 && postAuth;
    }
  },
  {
    name: 'secret_enumeration',
    label: 'Secret / config file enumeration chain',
    confidence: 92,
    riskBonus: 25,
    detect: function(seq) {
      return seq.filter(function(s) { return s.threat === 'secret_probe'; }).length >= 2;
    }
  },
  {
    name: 'multi_vector_attack',
    label: 'Multi-vector attack chain (injection + traversal)',
    confidence: 90,
    riskBonus: 30,
    detect: function(seq) {
      var injectionThreats = ['sql_injection','nosql_injection','command_injection','ssti_pattern','xxe_pattern'];
      var hasInjection = seq.some(function(s) { return injectionThreats.indexOf(s.threat) !== -1; });
      var hasTraversal = seq.some(function(s) { return s.threat === 'path_traversal'; });
      return hasInjection && hasTraversal;
    }
  },
  {
    name: 'scanner_sweep',
    label: 'Automated scanner sweep detected',
    confidence: 85,
    riskBonus: 20,
    detect: function(seq) {
      var endpoints = {};
      seq.forEach(function(s) { endpoints[s.endpoint] = true; });
      var uniqueCount = Object.keys(endpoints).length;
      var hasScanner = seq.some(function(s) { return s.threat && s.threat.indexOf('scanner_ua_') === 0; });
      return uniqueCount >= 5 && hasScanner;
    }
  },
  {
    name: 'brute_force_escalation',
    label: 'Brute force escalating to privilege escalation',
    confidence: 87,
    riskBonus: 25,
    detect: function(seq) {
      var failedAuths = seq.filter(function(s) { return s.threat === 'repeated_failed_auth'; }).length;
      var sensitiveAccess = seq.some(function(s) { return s.threat === 'sensitive_endpoint_access'; });
      return failedAuths >= 2 && sensitiveAccess;
    }
  },
  {
    name: 'xss_data_exfil',
    label: 'XSS attempt followed by sensitive data access',
    confidence: 80,
    riskBonus: 20,
    detect: function(seq) {
      var hasXss = seq.some(function(s) { return s.threat === 'xss_pattern'; });
      var hasSensitive = seq.some(function(s) {
        return s.endpoint.includes('/cookie') || s.endpoint.includes('/token') || s.endpoint.includes('/session');
      });
      return hasXss && hasSensitive;
    }
  }
];

function recordSequence(ip, endpoint, threats, sequenceStore) {
  if (!ip || !sequenceStore) return;
  var seq = sequenceStore.get(ip) || [];
  var list = threats && threats.length ? threats : ['none'];
  for (var i = 0; i < list.length; i++) {
    seq.push({ timestamp: Date.now(), endpoint: endpoint || '/', threat: list[i] || 'none' });
  }
  sequenceStore.set(ip, seq.slice(-MAX_SEQUENCE_LENGTH));
}

function detectCorrelation(ip, sequenceStore) {
  if (!ip || !sequenceStore) return null;
  var seq = sequenceStore.get(ip);
  if (!seq || seq.length < 3) return null;
  for (var i = 0; i < ATTACK_CHAINS.length; i++) {
    var chain = ATTACK_CHAINS[i];
    try {
      if (chain.detect(seq)) {
        return {
          pattern: chain.name,
          label: chain.label,
          confidence: chain.confidence,
          riskBonus: chain.riskBonus,
          sequenceLength: seq.length
        };
      }
    } catch (_) { /* never crash middleware */ }
  }
  return null;
}

function getSequence(ip, sequenceStore) {
  if (!ip || !sequenceStore) return [];
  return (sequenceStore.get(ip) || []).slice(-10);
}

module.exports = { recordSequence, detectCorrelation, getSequence, ATTACK_CHAINS };
