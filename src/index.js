'use strict';

const bcrypt = require('bcryptjs');
const cors = require('cors');
const crypto = require('crypto');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const pino = require('pino');
const { randomUUID } = crypto;
const { createDashboardRouter } = require('./dashboard');
const { MemoryStorage } = require('./storage');
const { SQLiteStorage } = require('./sqlite-storage');
const { MongoStorage } = require('./mongodb-storage');
const { analyzeRequest, riskFromScore, actionFromRisk } = require('./threats');
const { redactPayload, redactRequestBody } = require('./redactor');
const { buildClientContext, detectIdentityChange, getClientIp } = require('./identity');
const { applyCustomRules } = require('./rules');
const { recordBehaviour, getBehaviourDeviation } = require('./behaviour');
const { recordSequence, detectCorrelation } = require('./correlation');

// ---------------------------------------------------------------------------
// Security mode presets
// ---------------------------------------------------------------------------

const SECURITY_MODE_PRESETS = {
  low: {
    rateLimit: { max: 300, windowMs: 60 * 1000 },
    block: { threshold: 90, durationMs: 6 * 60 * 60 * 1000 },
    anomaly: { mediumThreshold: 45, highThreshold: 75, criticalThreshold: 92 }
  },
  medium: {
    rateLimit: { max: 120, windowMs: 60 * 1000 },
    block: { threshold: 80, durationMs: 24 * 60 * 60 * 1000 },
    anomaly: { mediumThreshold: 35, highThreshold: 65, criticalThreshold: 90 }
  },
  high: {
    rateLimit: { max: 30, windowMs: 60 * 1000 },
    block: { threshold: 60, durationMs: 7 * 24 * 60 * 60 * 1000 },
    anomaly: { mediumThreshold: 25, highThreshold: 50, criticalThreshold: 80 }
  }
};

// ---------------------------------------------------------------------------
// Default configuration
// ---------------------------------------------------------------------------

const defaultConfig = {
  appName: 'iri-shield',
  security: 'medium',
  trustProxy: false,
  failureMode: 'fail-open',   // 'fail-open' | 'fail-closed'
  helmet: {
    enabled: true,
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
  },
  cors: false,
  logger: true,
  requestIdHeader: 'x-iri-request-id',
  testing: {
    enabled: false,
    allowClientOverrides: false
  },
  rateLimit: {
    enabled: true,
    windowMs: 60 * 1000,
    max: 120
  },
  block: {
    enabled: true,
    threshold: 80,
    durationMs: 24 * 60 * 60 * 1000
  },
  alert: {
    enabled: true,
    threshold: 35
  },
  anomaly: {
    mediumThreshold: 35,
    highThreshold: 65,
    criticalThreshold: 90,
    singleEndpointMax: 80,
    failedAuthMax: 5,
    allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    sensitiveEndpoints: ['/admin', '/internal', '/debug', '/.env', '/config']
  },
  rules: {
    sqlInjection: true,
    xss: true,
    pathTraversal: true,
    commandInjection: true,
    ssti: true,
    nosqlInjection: true,
    ldapInjection: true,
    xxe: true,
    openRedirect: true,
    base64Payload: true,
    headerInjection: true,
    secretProbe: true,
    scannerDetection: true,
    headerAnomaly: true,
    customRules: []
  },
  redaction: {
    enabled: true,
    mask: '[REDACTED]',
    fields: [
      'password', 'token', 'accessToken', 'refreshToken',
      'authorization', 'apiKey', 'secret', 'ssn',
      'aadhaar', 'email', 'phone', 'creditCard', 'cvv'
    ]
  },
  privacy: {
    hashIp: false,
    retainRawIp: true,
    retentionDays: 30
  },
  dashboard: {
    enabled: true,
    path: '/iri-shield',
    username: 'admin',
    password: 'admin',
    refreshMs: 5 * 60 * 1000
  },
  storage: {
    mode: 'memory',
    sqliteFile: './data/iri-shield.sqlite',
    mongoUrl: 'mongodb://localhost:27017/iri-shield'
  }
};

// ---------------------------------------------------------------------------
// Config helpers
// ---------------------------------------------------------------------------

function mergeConfig(base, override) {
  const output = Object.assign({}, base);
  for (const [key, value] of Object.entries(override || {})) {
    if (
      value &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      base[key] &&
      typeof base[key] === 'object'
    ) {
      output[key] = mergeConfig(base[key], value);
    } else {
      output[key] = value;
    }
  }
  return output;
}

function applySecurityMode(config, userOptions) {
  const mode = config.security || 'medium';
  const preset = SECURITY_MODE_PRESETS[mode] || SECURITY_MODE_PRESETS.medium;
  if (!userOptions.rateLimit || !userOptions.rateLimit.max) config.rateLimit.max = preset.rateLimit.max;
  if (!userOptions.rateLimit || !userOptions.rateLimit.windowMs) config.rateLimit.windowMs = preset.rateLimit.windowMs;
  if (!userOptions.block || !userOptions.block.threshold) config.block.threshold = preset.block.threshold;
  if (!userOptions.block || !userOptions.block.durationMs) config.block.durationMs = preset.block.durationMs;
  if (!userOptions.anomaly || !userOptions.anomaly.mediumThreshold) config.anomaly.mediumThreshold = preset.anomaly.mediumThreshold;
  if (!userOptions.anomaly || !userOptions.anomaly.highThreshold) config.anomaly.highThreshold = preset.anomaly.highThreshold;
  if (!userOptions.anomaly || !userOptions.anomaly.criticalThreshold) config.anomaly.criticalThreshold = preset.anomaly.criticalThreshold;
  return config;
}

/**
 * Hash an IP address for privacy mode
 */
function hashIp(ip) {
  return 'sha256:' + crypto.createHash('sha256').update(ip || '').digest('hex').slice(0, 16);
}

// ---------------------------------------------------------------------------
// Main factory
// ---------------------------------------------------------------------------

function createShield(options = {}) {
  let config = mergeConfig(defaultConfig, options);
  config = applySecurityMode(config, options);

  const storage =
    options.storage && typeof options.storage.getBlock === 'function'
      ? options.storage
      : (options._storage || createStorage(config.storage));
  const logger = options._logger || (config.logger ? pino({ name: config.appName }) : null);

  // --- Base middlewares ---
  const baseMiddlewares = [];
  if (config.helmet) {
    const helmetOptions =
      typeof config.helmet === 'object'
        ? Object.assign({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }, config.helmet)
        : { contentSecurityPolicy: false, crossOriginEmbedderPolicy: false };
    if (helmetOptions.enabled !== false) {
      delete helmetOptions.enabled;
      baseMiddlewares.push(helmet(helmetOptions));
    }
  }
  if (config.cors) {
    baseMiddlewares.push(cors(typeof config.cors === 'object' ? config.cors : undefined));
  }

  // --- Core middleware ---
  const middleware = async function iriShield(req, res, next) {
    const start = process.hrtime.bigint();
    const requestId = req.headers[config.requestIdHeader] || randomUUID();
    res.setHeader(config.requestIdHeader, requestId);

    try {
      // Skip dashboard routes
      const reqPath = String(req.originalUrl || req.url);
      if (
        config.dashboard && config.dashboard.enabled &&
        config.dashboard.path &&
        reqPath.startsWith(config.dashboard.path)
      ) {
        return next();
      }

      // Build client context
      const client = buildClientContext(req, res, config);
      req.iriShieldClient = client;
      const rawIp = client.ip;

      // Privacy: optionally hash IP for storage
      const storageIp = config.privacy && config.privacy.hashIp ? hashIp(rawIp) : rawIp;

      // Find existing client record for identity change detection
      const knownClient = (storage.clients && storage.clients.get) ? storage.clients.get(client.clientId) : null;
      const sameUserClients =
        typeof storage.findClientsByUserId === 'function'
          ? storage.findClientsByUserId(client.userId)
          : [];
      const identityChange = detectIdentityChange(client, knownClient || sameUserClients[0]);

      // --- Check active block (always use rawIp for blocking enforcement) ---
      const activeBlock = storage.getBlock(rawIp);
      if (activeBlock) {
        const event = buildEvent(req, {
          requestId,
          threat: 'blocked_ip',
          riskLevel: 'critical',
          riskScore: activeBlock.score || config.block.threshold,
          action: 'blocked',
          reason: activeBlock.reason || 'ip_block_active',
          storageIp
        });
        storage.recordEvent(event);
        storage.recordRequest(Object.assign({}, client, {
          ip: storageIp,
          blocked: true,
          endpoint: event.endpoint,
          method: req.method,
          statusCode: 403,
          durationMs: 0
        }));
        return res.status(403).json({ error: 'Request blocked by iri-shield', requestId });
      }

      // --- Rate limit ---
      const rateDecision = storage.hitRateLimit(rawIp, config.rateLimit);
      if (rateDecision.blocked) {
        const event = buildEvent(req, {
          requestId,
          threat: 'rate_limit_exceeded',
          riskLevel: 'medium',
          riskScore: 55,
          action: 'rate_limited',
          reason: 'rate_limit_' + config.rateLimit.max + '_per_' + config.rateLimit.windowMs + 'ms',
          storageIp
        });
        storage.recordEvent(event);
        storage.recordRequest(Object.assign({}, client, {
          ip: storageIp,
          blocked: true,
          endpoint: event.endpoint,
          method: req.method,
          statusCode: 429,
          durationMs: 0
        }));
        return res.status(429).json({
          error: 'Too many requests — rate limit exceeded',
          requestId,
          retryAfter: Math.ceil(config.rateLimit.windowMs / 1000)
        });
      }

      // --- Threat analysis ---
      const analysis = analyzeRequest(req, storage, config);

      // --- Custom rule engine ---
      const customResult = applyCustomRules(req, config);
      if (customResult.score > 0) {
        analysis.score = Math.min(100, analysis.score + customResult.score);
        analysis.threats.push(...customResult.threats);
        analysis.reasons.push(...customResult.reasons);
        analysis.breakdown.push(...customResult.breakdown);
        analysis.riskLevel = riskFromScore(analysis.score, config);
        analysis.action = actionFromRisk(analysis.riskLevel);
      }

      // --- Identity change penalty ---
      if (identityChange.score > 0) {
        analysis.score = Math.min(100, analysis.score + identityChange.score);
        analysis.threats.push(...identityChange.threats);
        analysis.reasons.push(...identityChange.reasons);
        if (identityChange.score > 0) {
          analysis.breakdown.push({
            rule: 'identity_drift',
            label: 'Identity / device change detected',
            points: identityChange.score,
            category: 'anomaly',
            confidence: 75
          });
        }
        analysis.riskLevel = riskFromScore(analysis.score, config);
        analysis.action = actionFromRisk(analysis.riskLevel);
      }

      // --- Behaviour baseline tracking ---
      if (storage.behaviourStore) {
        recordBehaviour(rawIp, req.originalUrl || req.url, req.method, 0, storage.behaviourStore);
        const deviation = getBehaviourDeviation(rawIp, storage.behaviourStore);
        if (deviation.deviationPercent >= 80) {
          const devPts = Math.round(deviation.deviationPercent * 0.2);
          analysis.score = Math.min(100, analysis.score + devPts);
          analysis.threats.push('behaviour_deviation');
          analysis.reasons.push('behaviour_deviation_' + deviation.deviationPercent + 'pct');
          analysis.breakdown.push({
            rule: 'behaviour_deviation',
            label: 'Behaviour deviation from baseline (' + deviation.deviationPercent + '% spike)',
            points: devPts,
            category: 'anomaly',
            confidence: 78,
            meta: deviation
          });
          analysis.riskLevel = riskFromScore(analysis.score, config);
          analysis.action = actionFromRisk(analysis.riskLevel);
        }
        analysis.behaviourDeviation = deviation;
      }

      // --- Attack sequence correlation ---
      if (storage.sequenceStore) {
        recordSequence(rawIp, req.originalUrl || req.url, analysis.threats, storage.sequenceStore);
        const correlation = detectCorrelation(rawIp, storage.sequenceStore);
        if (correlation) {
          analysis.score = Math.min(100, analysis.score + correlation.riskBonus);
          analysis.threats.push('correlated_attack_' + correlation.pattern);
          analysis.breakdown.push({
            rule: 'correlated_attack_' + correlation.pattern,
            label: correlation.label,
            points: correlation.riskBonus,
            category: 'correlation',
            confidence: correlation.confidence
          });
          analysis.correlatedAttack = correlation;
          analysis.riskLevel = riskFromScore(analysis.score, config);
          analysis.action = actionFromRisk(analysis.riskLevel);
        }
      }

      // Redact request body fields before storing in logs
      let safeBody = null;
      if (config.redaction && config.redaction.enabled && req.body) {
        const redacted = redactPayload(req.body, config.redaction);
        safeBody = redacted.value;
      }

      client.riskLevel = analysis.riskLevel;
      storage.recordClient(Object.assign({}, client, { ip: storageIp }));
      req.iriShield = { requestId, ip: rawIp, storageIp, client, analysis };

      // --- Auto block if score >= block threshold ---
      if (analysis.score >= config.block.threshold && config.block.enabled) {
        storage.blockIp(rawIp, {
          expiresAt: Date.now() + config.block.durationMs,
          reason: analysis.reasons.join(', '),
          score: analysis.score
        });
        const event = buildEvent(req, {
          requestId,
          threat: analysis.threats.join(', ') || 'blocked_threat',
          riskLevel: analysis.riskLevel,
          riskScore: analysis.score,
          action: 'blocked',
          reason: analysis.reasons.join('; '),
          breakdown: analysis.breakdown,
          confidence: analysis.confidence || 0,
          correlatedAttack: analysis.correlatedAttack || null,
          storageIp
        });
        storage.recordEvent(event);
        storage.recordRequest(Object.assign({}, client, {
          ip: storageIp,
          blocked: true,
          endpoint: req.originalUrl || req.url,
          method: req.method,
          statusCode: 403,
          durationMs: 0
        }));
        return res.status(403).json({
          error: 'Request blocked — threat detected by iri-shield',
          requestId,
          threat: analysis.threats.join(', ')
        });
      }

      // --- Alerts ---
      const alertThreshold = (config.alert && config.alert.threshold) || config.anomaly.mediumThreshold;
      if (
        config.alert && config.alert.enabled &&
        analysis.score >= alertThreshold &&
        analysis.score < config.block.threshold
      ) {
        storage.recordAlert(client.clientId, {
          score: analysis.score,
          riskLevel: analysis.riskLevel,
          ip: rawIp,
          threats: analysis.threats
        });
      }

      // --- Record security event ---
      if (analysis.score >= config.anomaly.mediumThreshold) {
        const event = buildEvent(req, {
          requestId,
          threat: analysis.threats.join(', ') || 'anomaly',
          riskLevel: analysis.riskLevel,
          riskScore: analysis.score,
          action: analysis.action,
          reason: analysis.reasons.join('; '),
          breakdown: analysis.breakdown,
          confidence: analysis.confidence || 0,
          correlatedAttack: analysis.correlatedAttack || null,
          storageIp
        });
        storage.recordEvent(event);
        logger && logger.warn(event, 'iri-shield security event');
      }

      // --- Block on critical score ---
      if (analysis.score >= config.anomaly.criticalThreshold) {
        storage.recordRequest(Object.assign({}, client, {
          ip: storageIp,
          blocked: true,
          endpoint: req.originalUrl || req.url,
          method: req.method,
          statusCode: 403,
          durationMs: 0
        }));
        return res.status(403).json({
          error: 'Request blocked — critical threat detected by iri-shield',
          requestId
        });
      }

      // --- Patch response for redaction ---
      patchResponse(res, storage, config);

      // --- Record on finish ---
      res.on('finish', function() {
        const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
        storage.recordRequest(Object.assign({}, client, {
          ip: storageIp,
          endpoint: (req.route && req.route.path) || req.originalUrl || req.url,
          method: req.method,
          statusCode: res.statusCode,
          durationMs,
          blocked: res.statusCode === 403 || res.statusCode === 429
        }));
        // Update behaviour store with real status code
        if (storage.behaviourStore) {
          recordBehaviour(rawIp, req.originalUrl || req.url, req.method, res.statusCode, storage.behaviourStore);
        }
      });

      return next();
    } catch (error) {
      logger && logger.error({ err: error, requestId }, 'iri-shield middleware failure');
      if (config.failureMode === 'fail-closed') {
        return res.status(503).json({ error: 'Security layer unavailable — request rejected', requestId });
      }
      return next(error); // fail-open: let traffic through on internal errors
    }
  };

  // Chain base middlewares then core
  const runBase = function iriShieldBase(req, res, next) {
    let index = 0;
    const step = function(err) {
      if (err || index >= baseMiddlewares.length) return err ? next(err) : middleware(req, res, next);
      return baseMiddlewares[index++](req, res, step);
    };
    return step();
  };

  return {
    config,
    storage,
    middleware: runBase,
    dashboard: createDashboardRouter({ storage, config }),
    getStats: function() { return storage.getStats(); },
    getConfig: function() { return sanitizeConfig(config); },
    updateConfig: function(patch) { return mergeInto(config, patch); },
    clear: function() { return storage.clear(); }
  };
}

// ---------------------------------------------------------------------------
// Storage factory
// ---------------------------------------------------------------------------

function createStorage(storageConfig) {
  storageConfig = storageConfig || {};
  const mode = storageConfig.mode || 'memory';
  if (mode === 'sqlite') {
    return new SQLiteStorage({
      file: storageConfig.sqliteFile || './data/iri-shield.sqlite',
      maxRequestRows: storageConfig.maxRequestRows,
      maxEventRows: storageConfig.maxEventRows,
      retentionDays: storageConfig.retentionDays
    });
  }
  if (mode === 'mongodb') {
    return new MongoStorage({
      mongoUrl: storageConfig.mongoUrl || 'mongodb://localhost:27017/iri-shield',
      dbName: storageConfig.dbName || 'iri-shield'
    });
  }
  return new MemoryStorage();
}

// ---------------------------------------------------------------------------
// Response redaction patch
// ---------------------------------------------------------------------------

function patchResponse(res, storage, config) {
  if (!config.redaction || !config.redaction.enabled || res.locals.iriShieldRedactionPatched) return;
  res.locals.iriShieldRedactionPatched = true;

  const originalJson = res.json.bind(res);
  const originalSend = res.send.bind(res);

  res.json = function(payload) {
    if (res.locals.iriShieldSkipRedaction) return originalJson(payload);
    const result = redactPayload(payload, config.redaction);
    if (result.redactions > 0) storage.recordRedaction(result.redactions);
    return originalJson(result.value);
  };

  res.send = function(payload) {
    if (res.locals.iriShieldSkipRedaction) return originalSend(payload);
    if (typeof payload !== 'string') return originalSend(payload);
    const result = redactPayload(payload, config.redaction);
    if (result.redactions > 0) storage.recordRedaction(result.redactions);
    return originalSend(result.value);
  };
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

function apiKeyAuth(validKeys, options) {
  options = options || {};
  const keys = new Set(Array.isArray(validKeys) ? validKeys : [validKeys].filter(Boolean));
  const headerName = (options.header || 'x-api-key').toLowerCase();
  return function iriShieldApiKeyAuth(req, res, next) {
    const key = req.headers[headerName];
    if (!key || !keys.has(key)) {
      return res.status(401).json({ error: 'Invalid or missing API key' });
    }
    return next();
  };
}

function signToken(payload, secret, options) {
  options = options || {};
  if (!secret) throw new Error('JWT secret is required');
  return jwt.sign(payload, secret, Object.assign({ expiresIn: '1h' }, options));
}

function jwtAuth(secret, options) {
  options = options || {};
  if (!secret) throw new Error('JWT secret is required');
  return function iriShieldJwtAuth(req, res, next) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing bearer token' });
    try {
      req.user = jwt.verify(token, secret, options.verify || {});
      return next();
    } catch (_) {
      return res.status(401).json({ error: 'Invalid bearer token' });
    }
  };
}

async function hashPassword(password, rounds) {
  rounds = rounds || 10;
  return bcrypt.hash(password, rounds);
}

async function comparePassword(password, hash) {
  return bcrypt.compare(password, hash);
}

// ---------------------------------------------------------------------------
// Internal utilities
// ---------------------------------------------------------------------------

function buildEvent(req, extra) {
  const client = req.iriShieldClient || {};
  return Object.assign({
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    ip: extra.storageIp || client.ip || getClientIp(req),
    clientId: client.clientId || null,
    userId: client.userId || null,
    sessionId: client.sessionId || null,
    deviceId: client.deviceId || null,
    fingerprint: client.fingerprint || null,
    platform: client.secChUaPlatform || null,
    method: req.method,
    endpoint: req.originalUrl || req.url,
    userAgent: client.userAgent || req.headers['user-agent'] || '',
    referer: client.referer || req.headers['referer'] || '',
    acceptLanguage: client.acceptLanguage || req.headers['accept-language'] || ''
  }, extra);
}

function mergeInto(target, patch) {
  for (const [key, value] of Object.entries(patch || {})) {
    if (
      value &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      target[key] &&
      typeof target[key] === 'object'
    ) {
      mergeInto(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return sanitizeConfig(target);
}

function sanitizeConfig(config) {
  const copy = JSON.parse(JSON.stringify(config));
  if (copy.dashboard && copy.dashboard.password) copy.dashboard.password = '';
  return copy;
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  createShield,
  MemoryStorage,
  SQLiteStorage,
  MongoStorage,
  redactPayload,
  analyzeRequest,
  apiKeyAuth,
  signToken,
  jwtAuth,
  hashPassword,
  comparePassword,
  SECURITY_MODE_PRESETS
};
