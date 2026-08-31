'use strict';

// ---------------------------------------------------------------------------
// Redactor — PII and secrets redaction for responses AND request logs
// ---------------------------------------------------------------------------

const valuePatterns = [
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  /\b(?:\+?91[-\s]?)?[6-9]\d{9}\b/g,
  /\b(?:\+?1[-\s]?)?\(?\d{3}\)?[-\s]?\d{3}[-\s]?\d{4}\b/g,
  /\b(?:Bearer\s+)?[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b/g,
  /\b(?:sk|pk|api|key|secret)(?:_mock|_live|_test|_key|_secret)?_[A-Za-z0-9_-]{10,}\b/gi
];

/**
 * Deep-redact a payload (response body or object)
 * @param {*} payload
 * @param {object} options  — { mask, fields[] }
 * @returns {{ value: *, redactions: number }}
 */
function redactPayload(payload, options) {
  options = options || {};
  const state = { redactions: 0, mask: options.mask || '[REDACTED]', fields: normalizeFields(options.fields || []) };
  const value = redactValue(payload, state);
  return { value, redactions: state.redactions };
}

/**
 * Redact a request body object before storing in logs
 * Only redacts known sensitive field names — does NOT scan string values
 * (to avoid false positives on legitimate request data)
 * @param {object|string} body
 * @param {object} options
 * @returns {object|string}
 */
function redactRequestBody(body, options) {
  options = options || {};
  if (!body) return body;
  if (typeof body === 'string') {
    // Best-effort: replace known field patterns in JSON strings
    try {
      const parsed = JSON.parse(body);
      const result = redactPayload(parsed, options);
      return JSON.stringify(result.value);
    } catch (_) {
      return body; // not JSON, return as-is
    }
  }
  if (typeof body === 'object') {
    return redactPayload(body, options).value;
  }
  return body;
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

function normalizeFields(fields) {
  return new Set(fields.map(function(f) { return String(f).toLowerCase().replace(/[^a-z0-9]/g, ''); }));
}

function isSensitiveKey(key, fieldsSet) {
  if (!key) return false;
  const clean = String(key).toLowerCase().replace(/[^a-z0-9]/g, '');
  if (fieldsSet.has(clean)) return true;
  for (const f of fieldsSet) {
    if (f.length >= 4 && clean.includes(f)) return true;
  }
  return false;
}

function redactValue(value, state, key) {
  key = key || '';
  if (value == null) return value;
  if (isSensitiveKey(key, state.fields)) {
    state.redactions += 1;
    return state.mask;
  }
  if (typeof value === 'string') return redactString(value, state);
  if (Array.isArray(value)) return value.map(function(item) { return redactValue(item, state); });
  if (typeof value === 'object') {
    const output = {};
    for (const childKey of Object.keys(value)) {
      output[childKey] = redactValue(value[childKey], state, childKey);
    }
    return output;
  }
  return value;
}

function redactString(value, state) {
  let output = value;
  for (const pattern of valuePatterns) {
    pattern.lastIndex = 0;
    output = output.replace(pattern, function() {
      state.redactions += 1;
      return state.mask;
    });
  }
  return output;
}

module.exports = { redactPayload, redactRequestBody, valuePatterns };
