'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { analyzeRequest } = require('../src/threats');
const { MemoryStorage } = require('../src/storage');

const config = {
  anomaly: {
    mediumThreshold: 35,
    highThreshold: 65,
    criticalThreshold: 90,
    singleEndpointMax: 10,
    failedAuthMax: 5,
    allowedMethods: ['GET', 'POST'],
    sensitiveEndpoints: ['/admin']
  }
};

test('detects suspicious SQL-like input', () => {
  const storage = new MemoryStorage();
  storage.hitRateLimit('127.0.0.1', { enabled: true, windowMs: 60000, max: 50 });
  const req = {
    method: 'GET',
    originalUrl: '/users?q=%27 or 1=1',
    headers: { 'user-agent': 'node-test' },
    query: { q: "' or 1=1" },
    ip: '127.0.0.1'
  };

  const result = analyzeRequest(req, storage, config);
  assert.ok(result.score >= 35);
  assert.ok(result.threats.includes('sql_injection_pattern'));
});
