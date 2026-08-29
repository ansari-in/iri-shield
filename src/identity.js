'use strict';

const { createHash, randomUUID } = require('crypto');

/**
 * Build a rich client context from the incoming request.
 * Supports testing overrides via headers or req.body.__iri when config.testing.enabled = true.
 */
function buildClientContext(req, res, config) {
  const testingEnabled = config.testing?.enabled === true;
  const override = testingEnabled ? getTestingOverride(req, config) : {};

  // --- IP Resolution ---
  const realIp = getClientIp(req);
  const ip = override.ip || realIp;

  // --- User Agent ---
  const realUserAgent = req.headers['user-agent'] || '';
  const userAgent = override.userAgent || realUserAgent;

  // --- Cookie ---
  const cookie = override.cookie || req.headers.cookie || '';

  // --- Session ---
  const sessionId =
    override.sessionId ||
    req.headers['x-session-id'] ||
    readCookie(cookie, 'connect.sid') ||
    readCookie(cookie, 'express.sid') ||
    '';

  // --- Declared User ---
  const declaredUserId =
    override.userId ||
    req.headers['x-user-id'] ||
    req.body?.userId ||
    req.query?.userId ||
    '';

  // --- Device ID ---
  const deviceId = override.deviceId || req.headers['x-device-id'] || '';

  // --- Client ID (persistent cookie-based) ---
  const existingClientId =
    override.clientId ||
    req.headers['x-iri-client-id'] ||
    readCookie(cookie, 'iri_shield_uid');
  const clientId = existingClientId || randomUUID();

  // Set persistent client cookie if new
  if (!existingClientId && res && !res.headersSent) {
    res.setHeader(
      'Set-Cookie',
      `iri_shield_uid=${clientId}; HttpOnly; SameSite=Lax; Path=/; Max-Age=31536000`
    );
  }

  // --- Browser Signal Headers ---
  const acceptLanguage = req.headers['accept-language'] || '';
  const acceptEncoding = req.headers['accept-encoding'] || '';
  const accept = req.headers['accept'] || '';
  const dnt = req.headers['dnt'] || req.headers['sec-gpc'] || '';
  const connection = req.headers['connection'] || '';
  const referer = req.headers['referer'] || req.headers['referrer'] || '';

  // --- Client Hints (modern browsers) ---
  const secChUa = req.headers['sec-ch-ua'] || '';
  const secChUaMobile = req.headers['sec-ch-ua-mobile'] || '';
  const secChUaPlatform = req.headers['sec-ch-ua-platform'] || '';
  const secChUaArch = req.headers['sec-ch-ua-arch'] || '';

  // --- Fetch Metadata ---
  const secFetchSite = req.headers['sec-fetch-site'] || '';
  const secFetchMode = req.headers['sec-fetch-mode'] || '';
  const secFetchDest = req.headers['sec-fetch-dest'] || '';
  const secFetchUser = req.headers['sec-fetch-user'] || '';

  // --- Network info ---
  const xForwardedProto = req.headers['x-forwarded-proto'] || '';
  const xRealIp = req.headers['x-real-ip'] || '';
  const cfRay = req.headers['cf-ray'] || '';             // Cloudflare
  const cfConnectingIp = req.headers['cf-connecting-ip'] || '';

  // --- Header presence anomaly signals ---
  const headerSignals = buildHeaderSignals(req, userAgent);

  // --- Fingerprint (stable multi-signal hash) ---
  const fingerprintSource = [
    declaredUserId,
    deviceId,
    sessionId,
    normalizeUa(userAgent),
    normalizeIpFamily(ip),
    acceptLanguage.slice(0, 20),
    secChUaPlatform,
    secChUaMobile
  ]
    .filter(Boolean)
    .join('|');

  // --- Browser fingerprint (volatile signals for anomaly, not for stable ID) ---
  const browserFingerprint = buildBrowserFingerprint({
    userAgent,
    acceptLanguage,
    acceptEncoding,
    accept,
    dnt,
    connection,
    secChUa,
    secChUaMobile,
    secChUaPlatform,
    secFetchSite,
    secFetchMode
  });

  return {
    clientId,
    userId: declaredUserId || clientId,
    ip,
    realIp,
    userAgent,
    cookie,
    sessionId,
    deviceId,
    referer,
    fingerprint: sha256(fingerprintSource || clientId),
    browserFingerprint,
    acceptLanguage,
    secChUa,
    secChUaPlatform,
    secFetchSite,
    secFetchMode,
    secFetchDest,
    headerSignals,
    isTestingOverride: Boolean(override.used),
    timestamp: new Date().toISOString()
  };
}

/**
 * Detect suspicious identity changes for a returning client.
 */
function detectIdentityChange(client, existing) {
  if (!existing || existing.requestCount === 0) {
    return { score: 0, reasons: [], threats: [] };
  }

  const reasons = [];
  const threats = [];
  let score = 0;

  // IP change
  if (client.ip && existing.ips?.length && !existing.ips.includes(client.ip)) {
    score += 15;
    threats.push('identity_ip_change');
    reasons.push(`new_ip_for_client_${client.ip}`);
  }

  // User-Agent change
  if (client.userAgent && existing.userAgents?.length && !existing.userAgents.includes(client.userAgent)) {
    score += 20;
    threats.push('identity_user_agent_change');
    reasons.push('new_user_agent_for_client');
  }

  // Fingerprint change (strong signal)
  if (client.fingerprint && existing.fingerprints?.length && !existing.fingerprints.includes(client.fingerprint)) {
    score += 25;
    threats.push('identity_fingerprint_change');
    reasons.push('new_fingerprint_for_known_client');
  }

  // Platform change (Client Hints — very reliable in modern browsers)
  if (
    client.secChUaPlatform &&
    existing.platforms?.length &&
    !existing.platforms.includes(client.secChUaPlatform)
  ) {
    score += 10;
    threats.push('identity_platform_change');
    reasons.push(`new_platform_${client.secChUaPlatform}`);
  }

  return { score, reasons, threats };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
  // Trust proxy chain
  const cfIp = req.headers['cf-connecting-ip'];
  if (cfIp) return cfIp.trim();

  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) {
    return forwarded.split(',')[0].trim();
  }

  const realIp = req.headers['x-real-ip'];
  if (realIp) return realIp.trim();

  return req.ip || req.socket?.remoteAddress || req.connection?.remoteAddress || 'unknown';
}

function readCookie(cookieHeader, name) {
  return String(cookieHeader || '')
    .split(';')
    .map((item) => item.trim())
    .reduce((value, item) => {
      const splitAt = item.indexOf('=');
      if (splitAt === -1) return value;
      const key = decodeURIComponent(item.slice(0, splitAt));
      return key === name ? decodeURIComponent(item.slice(splitAt + 1)) : value;
    }, '');
}

function normalizeIpFamily(ip) {
  const value = String(ip || '');
  // IPv6: keep first 4 groups (network prefix)
  if (value.includes(':')) return value.split(':').slice(0, 4).join(':');
  // IPv4: keep first 3 octets (subnet)
  return value.split('.').slice(0, 3).join('.');
}

function normalizeUa(ua) {
  // Strip version numbers for stable comparison
  return String(ua || '')
    .replace(/[\d.]+/g, 'X')
    .slice(0, 80);
}

/**
 * Build a secondary browser-signal fingerprint for anomaly detection.
 * This is more volatile and used to detect spoofing.
 */
function buildBrowserFingerprint(signals) {
  const parts = Object.values(signals).filter(Boolean).join('|');
  return sha256(parts || 'empty');
}

/**
 * Analyze header presence for anomaly detection.
 * Real browsers send specific combinations of headers.
 */
function buildHeaderSignals(req, userAgent) {
  const ua = String(userAgent || '').toLowerCase();
  const isBrowserLike =
    ua.includes('mozilla') || ua.includes('chrome') || ua.includes('safari') || ua.includes('firefox');

  const hasAccept = Boolean(req.headers['accept']);
  const hasAcceptLang = Boolean(req.headers['accept-language']);
  const hasAcceptEncoding = Boolean(req.headers['accept-encoding']);
  const hasSecFetch = Boolean(req.headers['sec-fetch-site']);
  const hasSecChUa = Boolean(req.headers['sec-ch-ua']);

  // Real browsers (Chrome/Edge) always send sec-fetch-* and sec-ch-ua
  const missingBrowserHeaders =
    isBrowserLike && (!hasAccept || !hasAcceptLang || !hasAcceptEncoding);

  // Modern browsers almost always send sec-fetch headers
  const claimsModernBrowser =
    isBrowserLike && (ua.includes('chrome') || ua.includes('edge'));
  const missingModernHeaders = claimsModernBrowser && !hasSecFetch && !hasSecChUa;

  return {
    hasAccept,
    hasAcceptLang,
    hasAcceptEncoding,
    hasSecFetch,
    hasSecChUa,
    isBrowserLike,
    missingBrowserHeaders,
    missingModernHeaders
  };
}

function sha256(value) {
  return createHash('sha256').update(String(value)).digest('hex').slice(0, 24);
}

module.exports = { buildClientContext, detectIdentityChange, getClientIp };
