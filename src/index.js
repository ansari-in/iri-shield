'use strict';

const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const pino = require('pino');
const { randomUUID } = require('crypto');
const { createDashboardRouter } = require('./dashboard');
const { MemoryStorage } = require('./storage');
const { SQLiteStorage } = require('./sqlite-storage');
const { analyzeRequest } = require('./threats');
const { redactPayload } = require('./redactor');
const { buildClientContext, detectIdentityChange } = require('./identity');

const defaultConfig = {
  appName: 'iri-shield',
  trustProxy: false,
  helmet: {
    enabled: true,
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
  },
  cors: false,
  logger: true,
  requestIdHeader: 'x-iri-request-id',
  testing: {
    allowClientOverrides: true
  },
  rateLimit: {
    enabled: true,
    windowMs: 60 * 1000,
    max: 120
  },
  block: {
    enabled: true,
    threshold: 80,
    durationMs: 10 * 60 * 1000
  },
  anomaly: {
    mediumThreshold: 35,
    highThreshold: 65,
    criticalThreshold: 90,
    singleEndpointMax: 80,
    failedAuthMax: 5,
    allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    sensitiveEndpoints: ['/admin', '/internal', '/debug', '/.env']
  },
  redaction: {
    enabled: true,
    mask: '[REDACTED]',
    fields: [
      'password',
      'token',
      'accessToken',
      'refreshToken',
      'authorization',
      'apiKey',
      'secret',
      'ssn',
      'aadhaar',
      'email',
      'phone'
    ]
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
    sqliteFile: './data/iri-shield.sqlite'
  }
};

function mergeConfig(base, override) {
  const output = { ...base };
  for (const [key, value] of Object.entries(override || {})) {
    if (value && typeof value === 'object' && !Array.isArray(value) && base[key] && typeof base[key] === 'object') {
      output[key] = mergeConfig(base[key], value);
    } else {
      output[key] = value;
    }
  }
  return output;
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) {
    return forwarded.split(',')[0].trim();
  }
  return req.ip || req.socket?.remoteAddress || req.connection?.remoteAddress || 'unknown';
}

function buildEvent(req, extra) {
  return {
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    ip: getClientIp(req),
    method: req.method,
    endpoint: req.originalUrl || req.url,
    userAgent: req.headers['user-agent'] || '',
    ...extra
  };
}

function createShield(options = {}) {
  const config = mergeConfig(defaultConfig, options);
  const storage = options.storage || createStorage(config.storage);
  const logger = options.logger || (config.logger ? pino({ name: config.appName }) : null);

  const baseMiddlewares = [];
  if (config.helmet) {
    const helmetOptions = typeof config.helmet === 'object'
      ? {
          contentSecurityPolicy: false,
          crossOriginEmbedderPolicy: false,
          ...config.helmet
        }
      : {
          contentSecurityPolicy: false,
          crossOriginEmbedderPolicy: false
        };
    if (helmetOptions.enabled !== false) {
      delete helmetOptions.enabled;
      baseMiddlewares.push(helmet(helmetOptions));
    }
  }
  if (config.cors) baseMiddlewares.push(cors(typeof config.cors === 'object' ? config.cors : undefined));

  const middleware = async function iriShield(req, res, next) {
    const start = process.hrtime.bigint();
    const client = buildClientContext(req, res, config);
    const ip = client.ip;
    const requestId = req.headers[config.requestIdHeader] || randomUUID();
    res.setHeader(config.requestIdHeader, requestId);

    try {
      if (config.dashboard?.enabled && config.dashboard?.path && String(req.originalUrl || req.url).startsWith(config.dashboard.path)) {
        return next();
      }

      req.iriShieldClient = client;
      const knownClient = storage.clients?.get?.(client.clientId) || null;
      const sameUserClients = typeof storage.findClientsByUserId === 'function' ? storage.findClientsByUserId(client.userId) : [];
      const identityChange = detectIdentityChange(client, knownClient || sameUserClients[0]);
      const activeBlock = storage.getBlock(ip);
      if (activeBlock) {
        const event = buildEvent(req, {
          requestId,
          threat: 'blocked_ip',
          riskLevel: 'high',
          riskScore: activeBlock.score || config.block.threshold,
          action: 'blocked',
          reason: activeBlock.reason || 'temporary_ip_block'
        });
        storage.recordEvent(event);
        storage.recordRequest({ ...client, blocked: true, endpoint: event.endpoint, method: req.method, statusCode: 403, durationMs: 0 });
        return res.status(403).json({ error: 'Request blocked by iri-shield', requestId });
      }

      const rateDecision = storage.hitRateLimit(ip, config.rateLimit);
      if (rateDecision.blocked) {
        const event = buildEvent(req, {
          requestId,
          threat: 'rate_limit_exceeded',
          riskLevel: 'medium',
          riskScore: 55,
          action: 'rate_limited',
          reason: `request_limit_${config.rateLimit.max}_per_${config.rateLimit.windowMs}ms`
        });
        storage.recordEvent(event);
        storage.recordRequest({ ...client, blocked: true, endpoint: event.endpoint, method: req.method, statusCode: 429, durationMs: 0 });
        return res.status(429).json({ error: 'Too many requests', requestId });
      }

      const analysis = analyzeRequest(req, storage, config);
      if (identityChange.score > 0) {
        analysis.score = Math.min(100, analysis.score + identityChange.score);
        analysis.threats.push(...identityChange.threats);
        analysis.reasons.push(...identityChange.reasons);
        analysis.riskLevel = riskFromScore(analysis.score, config);
        analysis.action = actionFromRisk(analysis.riskLevel);
      }
      client.riskLevel = analysis.riskLevel;
      storage.recordClient(client);
      req.iriShield = { requestId, ip, client, analysis };

      if (analysis.score >= config.block.threshold && config.block.enabled) {
        storage.blockIp(ip, {
          expiresAt: Date.now() + config.block.durationMs,
          reason: analysis.reasons.join(', '),
          score: analysis.score
        });
      }

      if (analysis.score >= config.anomaly.mediumThreshold) {
        const event = buildEvent(req, {
          requestId,
          threat: analysis.threats.join(', ') || 'anomaly',
          riskLevel: analysis.riskLevel,
          riskScore: analysis.score,
          action: analysis.action,
          reason: analysis.reasons.join('; ')
        });
        storage.recordEvent(event);
        logger?.warn(event, 'iri-shield security event');
      }

      if (analysis.score >= config.anomaly.criticalThreshold) {
        storage.recordRequest({ ...client, blocked: true, endpoint: req.originalUrl || req.url, method: req.method, statusCode: 403, durationMs: 0 });
        return res.status(403).json({ error: 'Critical request blocked by iri-shield', requestId });
      }

      patchResponse(res, storage, config);

      res.on('finish', () => {
        const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
        storage.recordRequest({
          ...client,
          endpoint: req.route?.path || req.originalUrl || req.url,
          method: req.method,
          statusCode: res.statusCode,
          durationMs,
          blocked: res.statusCode === 403 || res.statusCode === 429
        });
      });

      return next();
    } catch (error) {
      logger?.error({ err: error, requestId }, 'iri-shield middleware failure');
      return next(error);
    }
  };

  const runBase = function iriShieldBase(req, res, next) {
    let index = 0;
    const step = (err) => {
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
    getStats: () => storage.getStats(),
    getConfig: () => sanitizeConfig(config),
    updateConfig: (patch) => mergeInto(config, patch),
    clear: () => storage.clear()
  };
}

function createStorage(storageConfig = {}) {
  if (storageConfig.mode === 'sqlite') {
    return new SQLiteStorage({ file: storageConfig.sqliteFile });
  }
  return new MemoryStorage();
}

function patchResponse(res, storage, config) {
  if (!config.redaction?.enabled || res.locals?.iriShieldRedactionPatched) return;
  res.locals.iriShieldRedactionPatched = true;

  const originalJson = res.json.bind(res);
  const originalSend = res.send.bind(res);

  res.json = (payload) => {
    const result = redactPayload(payload, config.redaction);
    if (result.redactions > 0) storage.recordRedaction(result.redactions);
    return originalJson(result.value);
  };

  res.send = (payload) => {
    if (typeof payload !== 'string') return originalSend(payload);
    const result = redactPayload(payload, config.redaction);
    if (result.redactions > 0) storage.recordRedaction(result.redactions);
    return originalSend(result.value);
  };
}

function apiKeyAuth(validKeys, options = {}) {
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

function signToken(payload, secret, options = {}) {
  if (!secret) throw new Error('JWT secret is required');
  return jwt.sign(payload, secret, { expiresIn: '1h', ...options });
}

function jwtAuth(secret, options = {}) {
  if (!secret) throw new Error('JWT secret is required');
  return function iriShieldJwtAuth(req, res, next) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing bearer token' });
    try {
      req.user = jwt.verify(token, secret, options.verify || {});
      return next();
    } catch {
      return res.status(401).json({ error: 'Invalid bearer token' });
    }
  };
}

async function hashPassword(password, rounds = 10) {
  return bcrypt.hash(password, rounds);
}

async function comparePassword(password, hash) {
  return bcrypt.compare(password, hash);
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

function mergeInto(target, patch) {
  for (const [key, value] of Object.entries(patch || {})) {
    if (value && typeof value === 'object' && !Array.isArray(value) && target[key] && typeof target[key] === 'object') {
      mergeInto(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return sanitizeConfig(target);
}

function sanitizeConfig(config) {
  const copy = JSON.parse(JSON.stringify(config));
  if (copy.dashboard?.password) copy.dashboard.password = '';
  return copy;
}

module.exports = {
  createShield,
  MemoryStorage,
  SQLiteStorage,
  redactPayload,
  analyzeRequest,
  apiKeyAuth,
  signToken,
  jwtAuth,
  hashPassword,
  comparePassword
};
