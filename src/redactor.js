'use strict';

const valuePatterns = [
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  /\b(?:\+?91[-\s]?)?[6-9]\d{9}\b/g,
  /\b(?:Bearer\s+)?[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b/g,
  /\b(?:sk|pk|api|key|secret)_[A-Za-z0-9]{12,}\b/gi
];

function redactPayload(payload, options = {}) {
  const state = { redactions: 0, mask: options.mask || '[REDACTED]', fields: normalizeFields(options.fields || []) };
  const value = redactValue(payload, state);
  return { value, redactions: state.redactions };
}

function normalizeFields(fields) {
  return new Set(fields.map((field) => String(field).toLowerCase()));
}

function redactValue(value, state, key = '') {
  if (value == null) return value;
  if (state.fields.has(String(key).toLowerCase())) {
    state.redactions += 1;
    return state.mask;
  }
  if (typeof value === 'string') return redactString(value, state);
  if (Array.isArray(value)) return value.map((item) => redactValue(item, state));
  if (typeof value === 'object') {
    const output = {};
    for (const [childKey, childValue] of Object.entries(value)) {
      output[childKey] = redactValue(childValue, state, childKey);
    }
    return output;
  }
  return value;
}

function redactString(value, state) {
  let output = value;
  for (const pattern of valuePatterns) {
    output = output.replace(pattern, () => {
      state.redactions += 1;
      return state.mask;
    });
  }
  return output;
}

module.exports = { redactPayload, valuePatterns };
