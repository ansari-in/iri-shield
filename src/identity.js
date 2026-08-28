'use strict';

const { createHash, randomUUID } = require('crypto');

function buildClientContext(req, res, config) {
  const override = getTestingOverride(req, config);
  const ip = override.ip || getClientIp(req);
  const userAgent = override.userAgent || req.headers['user-agent'] || '';
  const cookie = override.cookie || req.headers.cookie || '';
  const sessionId = override.sessionId || req.headers['x-session-id'] || readCookie(cookie, 'connect.sid') || '';
  const declaredUserId = override.userId || req.headers['x-user-id'] || req.body?.userId || req.query?.userId || '';
  const deviceId = override.deviceId || req.headers['x-device-id'] || '';
  const existingClientId = override.clientId || req.headers['x-iri-client-id'] || readCookie(cookie, 'iri_shield_uid');
  const clientId = existingClientId || randomUUID();

  if (!existingClientId && res && !res.headersSent) {
    res.setHeader('Set-Cookie', `iri_shield_uid=${clientId}; HttpOnly; SameSite=Lax; Path=/; Max-Age=31536000`);
  }

  const fingerprintSource = [
    declaredUserId,
    deviceId,
    sessionId,
    userAgent,
    normalizeIpFamily(ip)
  ].filter(Boolean).join('|');

  return {
    clientId,
    userId: declaredUserId || clientId,
    ip,
    userAgent,
    cookie,
    sessionId,
    deviceId,
    fingerprint: sha256(fingerprintSource || clientId),
    timestamp: new Date().toISOString(),
    isTestingOverride: Boolean(override.used)
  };
}

function detectIdentityChange(client, existing) {
  if (!existing || existing.requestCount === 0) {
    return { score: 0, reasons: [], threats: [] };
  }

  const reasons = [];
  const threats = [];
  let score = 0;

  if (client.ip && existing.ips?.length && !existing.ips.includes(client.ip)) {
    score += 15;
    threats.push('identity_ip_change');
    reasons.push(`new_ip_for_client_${client.ip}`);
  }

  if (client.userAgent && existing.userAgents?.length && !existing.userAgents.includes(client.userAgent)) {
    score += 20;
    threats.push('identity_user_agent_change');
    reasons.push('new_user_agent_for_client');
  }

  if (client.fingerprint && existing.fingerprints?.length && !existing.fingerprints.includes(client.fingerprint)) {
    score += 25;
    threats.push('identity_fingerprint_change');
    reasons.push('new_fingerprint_for_known_client');
  }

  return { score, reasons, threats };
}

function getTestingOverride(req, config) {
  if (!config.testing?.allowClientOverrides) return {};
  const body = req.body?.__iri || req.body?.iriShieldTest || {};
  const output = {
    ip: req.headers['x-iri-test-ip'] || body.ip,
    userAgent: req.headers['x-iri-test-user-agent'] || body.userAgent,
    cookie: req.headers['x-iri-test-cookie'] || body.cookie,
    sessionId: req.headers['x-iri-test-session-id'] || body.sessionId,
    userId: req.headers['x-iri-test-user-id'] || body.userId,
    deviceId: req.headers['x-iri-test-device-id'] || body.deviceId,
    clientId: req.headers['x-iri-test-client-id'] || body.clientId
  };
  output.used = Object.values(output).some(Boolean);
  return output;
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) return forwarded.split(',')[0].trim();
  return req.ip || req.socket?.remoteAddress || req.connection?.remoteAddress || 'unknown';
}

function readCookie(cookieHeader, name) {
  return String(cookieHeader || '').split(';').map((item) => item.trim()).reduce((value, item) => {
    const splitAt = item.indexOf('=');
    if (splitAt === -1) return value;
    const key = decodeURIComponent(item.slice(0, splitAt));
    return key === name ? decodeURIComponent(item.slice(splitAt + 1)) : value;
  }, '');
}

function normalizeIpFamily(ip) {
  const value = String(ip || '');
  if (value.includes(':')) return value.split(':').slice(0, 4).join(':');
  return value.split('.').slice(0, 3).join('.');
}

function sha256(value) {
  return createHash('sha256').update(String(value)).digest('hex').slice(0, 24);
}

module.exports = { buildClientContext, detectIdentityChange };
