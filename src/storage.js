'use strict';

// ---------------------------------------------------------------------------
// MemoryStorage — in-process storage for iri-shield
// ---------------------------------------------------------------------------

class MemoryStorage {
  constructor(options = {}) {
    this.maxEvents = options.maxEvents || 500;
    this.maxRequests = options.maxRequests || 500;
    this.maxClients = options.maxClients || 1000;
    this.clear();
  }

  clear() {
    this.totalRequests = 0;
    this.blockedRequests = 0;
    this.totalLatencyMs = 0;
    this.redactions = 0;
    this.events = [];
    this.requests = [];
    this.clients = new Map();
    this.endpointStats = new Map();
    this.ipWindows = new Map();
    this.failedAuth = new Map();
    this.blocks = new Map();
    this.alerts = new Map();
    this.threatDistribution = new Map();
    this.behaviourStore = new Map();   // IP -> behaviour baseline record
    this.sequenceStore = new Map();    // IP -> request sequence[]
  }

  // -------------------------------------------------------------------------
  // Request recording
  // -------------------------------------------------------------------------

  recordRequest(request) {
    const row = {
      timestamp: new Date().toISOString(),
      ip: request.ip || 'unknown',
      clientId: request.clientId || null,
      fingerprint: request.fingerprint || null,
      userAgent: request.userAgent || '',
      cookie: request.cookie || '',
      sessionId: request.sessionId || '',
      endpoint: request.endpoint || '/',
      method: request.method || 'GET',
      statusCode: request.statusCode || 0,
      durationMs: request.durationMs || 0,
      blocked: Boolean(request.blocked)
    };

    this.requests.unshift(row);
    // Enforce size limit
    if (this.requests.length > this.maxRequests) {
      this.requests = this.requests.slice(0, this.maxRequests);
    }

    this.totalRequests += 1;
    if (request.blocked) this.blockedRequests += 1;
    this.totalLatencyMs += request.durationMs || 0;

    const key = `${request.method || 'GET'} ${request.endpoint || '/'}`;
    const current = this.endpointStats.get(key) || {
      endpoint: request.endpoint || '/',
      method: request.method || 'GET',
      count: 0,
      errors: 0,
      avgLatencyMs: 0
    };
    current.count += 1;
    current.errors += request.statusCode >= 400 ? 1 : 0;
    current.avgLatencyMs =
      (current.avgLatencyMs * (current.count - 1) + (request.durationMs || 0)) / current.count;
    this.endpointStats.set(key, current);
  }

  // -------------------------------------------------------------------------
  // Rate limiting
  // -------------------------------------------------------------------------

  hitRateLimit(ip, config) {
    if (!config?.enabled) return { blocked: false, count: 0 };
    const now = Date.now();
    const windowMs = config.windowMs || 60000;
    const max = config.max || 120;
    const window = this.ipWindows.get(ip) || { startedAt: now, count: 0, endpoints: new Map() };

    if (now - window.startedAt > windowMs) {
      window.startedAt = now;
      window.count = 0;
      window.endpoints = new Map();
    }

    window.count += 1;
    this.ipWindows.set(ip, window);
    return { blocked: window.count > max, count: window.count, remaining: Math.max(0, max - window.count) };
  }

  recordEndpointHit(ip, endpoint) {
    const window = this.ipWindows.get(ip);
    if (!window) return 0;
    const current = window.endpoints.get(endpoint) || 0;
    window.endpoints.set(endpoint, current + 1);
    return current + 1;
  }

  // -------------------------------------------------------------------------
  // Failed auth tracking
  // -------------------------------------------------------------------------

  recordFailedAuth(ip) {
    const current = this.failedAuth.get(ip) || { count: 0, startedAt: Date.now() };
    current.count += 1;
    this.failedAuth.set(ip, current);
    return current.count;
  }

  getFailedAuth(ip) {
    return this.failedAuth.get(ip)?.count || 0;
  }

  // -------------------------------------------------------------------------
  // Block management
  // -------------------------------------------------------------------------

  blockIp(ip, block) {
    this.blocks.set(ip, {
      ...block,
      blockedAt: block.blockedAt || new Date().toISOString(),
      manual: block.manual || false
    });
  }

  unblockIp(ip) {
    return this.blocks.delete(ip);
  }

  manualBlockIp(ip, { reason = 'manual_block', durationMs = 60 * 60 * 1000, score = 100 } = {}) {
    this.blockIp(ip, {
      expiresAt: durationMs > 0 ? Date.now() + durationMs : null, // null = permanent
      reason,
      score,
      manual: true,
      blockedAt: new Date().toISOString()
    });
  }

  getBlock(ip) {
    const block = this.blocks.get(ip);
    if (!block) return null;
    if (block.expiresAt && block.expiresAt <= Date.now()) {
      return null; // Expired, do not block incoming traffic
    }
    return block;
  }

  getBlockedIps({ page = 1, perPage = 20, status = 'all' } = {}) {
    const now = Date.now();
    let all = Array.from(this.blocks.entries()).map(([ip, block]) => {
      const isPermanent = !block.expiresAt;
      const isExpired = block.expiresAt ? block.expiresAt <= now : false;
      const itemStatus = isPermanent ? 'permanent' : (isExpired ? 'expired' : 'active');
      return {
        ip,
        reason: block.reason || '',
        score: block.score || 0,
        manual: Boolean(block.manual),
        status: itemStatus,
        isExpired,
        blockedAt: block.blockedAt || null,
        expiresAt: block.expiresAt ? new Date(block.expiresAt).toISOString() : null
      };
    });

    if (status === 'active') {
      all = all.filter((b) => !b.isExpired);
    } else if (status === 'expired') {
      all = all.filter((b) => b.isExpired);
    }

    all.sort((a, b) => {
      if (a.isExpired !== b.isExpired) return a.isExpired ? 1 : -1;
      return (b.blockedAt || '') > (a.blockedAt || '') ? 1 : -1;
    });

    return paginate(all, page, perPage);
  }

  // -------------------------------------------------------------------------
  // Events
  // -------------------------------------------------------------------------

  recordEvent(event) {
    const stored = Object.assign({}, event);
    // Ensure breakdown array is always present (may be undefined in old code paths)
    if (!Array.isArray(stored.breakdown)) stored.breakdown = [];
    if (stored.confidence == null) stored.confidence = 0;
    this.events.unshift(stored);
    if (this.events.length > this.maxEvents) {
      this.events = this.events.slice(0, this.maxEvents);
    }
    const threat = event.threat || 'unknown';
    this.threatDistribution.set(threat, (this.threatDistribution.get(threat) || 0) + 1);
  }

  getEvents({ page = 1, perPage = 20, riskLevel = null } = {}) {
    let filtered = this.events;
    if (riskLevel) filtered = filtered.filter((e) => e.riskLevel === riskLevel);
    return paginate(filtered, page, perPage);
  }

  // -------------------------------------------------------------------------
  // Client tracking
  // -------------------------------------------------------------------------

  recordClient(client) {
    const current = this.clients.get(client.clientId) || {
      clientId: client.clientId,
      userId: client.userId || client.clientId,
      firstSeenAt: client.timestamp,
      lastSeenAt: client.timestamp,
      requestCount: 0,
      ips: [],
      userAgents: [],
      fingerprints: [],
      platforms: [],
      changes: 0,
      lastRisk: 'none'
    };

    const beforeIps = new Set(current.ips);
    const beforeAgents = new Set(current.userAgents);
    const beforePrints = new Set(current.fingerprints);

    current.lastSeenAt = client.timestamp;
    current.requestCount += 1;
    current.lastIp = client.ip;
    current.lastUserAgent = client.userAgent;
    current.lastFingerprint = client.fingerprint;
    current.userId = client.userId || current.userId || client.clientId;
    current.lastRisk = client.riskLevel || current.lastRisk;

    pushUnique(current.ips, client.ip);
    pushUnique(current.userAgents, client.userAgent);
    pushUnique(current.fingerprints, client.fingerprint);
    if (client.secChUaPlatform) pushUnique(current.platforms, client.secChUaPlatform);

    if (
      (client.ip && !beforeIps.has(client.ip)) ||
      (client.userAgent && !beforeAgents.has(client.userAgent)) ||
      (client.fingerprint && !beforePrints.has(client.fingerprint))
    ) {
      current.changes += current.requestCount === 1 ? 0 : 1;
    }

    this.clients.set(client.clientId, current);

    // Enforce client map size limit (LRU-like: remove oldest by lastSeenAt)
    if (this.clients.size > this.maxClients) {
      pruneOldestClient(this.clients);
    }

    return current;
  }

  findClientsByUserId(userId) {
    if (!userId) return [];
    return Array.from(this.clients.values()).filter((c) => c.userId === userId);
  }

  getClients({ page = 1, perPage = 20 } = {}) {
    const all = Array.from(this.clients.values()).sort(
      (a, b) => b.requestCount - a.requestCount
    );
    return paginate(all, page, perPage);
  }

  // -------------------------------------------------------------------------
  // Alerts
  // -------------------------------------------------------------------------

  recordAlert(clientId, alertData) {
    const existing = this.alerts.get(clientId) || {
      clientId,
      firstAlertAt: new Date().toISOString(),
      count: 0,
      dismissed: false
    };
    existing.lastAlertAt = new Date().toISOString();
    existing.count += 1;
    existing.lastScore = alertData.score;
    existing.lastRisk = alertData.riskLevel;
    existing.lastIp = alertData.ip;
    existing.threats = alertData.threats || [];
    existing.dismissed = false; // re-activate on new alert
    this.alerts.set(clientId, existing);
  }

  dismissAlert(clientId) {
    const alert = this.alerts.get(clientId);
    if (alert) {
      alert.dismissed = true;
      this.alerts.set(clientId, alert);
      return true;
    }
    return false;
  }

  getAlerts({ page = 1, perPage = 20, dismissed = false } = {}) {
    const all = Array.from(this.alerts.values())
      .filter((a) => a.dismissed === dismissed)
      .sort((a, b) => (b.lastAlertAt > a.lastAlertAt ? 1 : -1));
    return paginate(all, page, perPage);
  }

  // -------------------------------------------------------------------------
  // Redaction
  // -------------------------------------------------------------------------

  recordRedaction(count) {
    this.redactions += count || 0;
  }

  // -------------------------------------------------------------------------
  // Stats
  // -------------------------------------------------------------------------

  getStats() {
    const activeBlocks = Array.from(this.blocks.entries()).filter(
      ([, block]) => !block.expiresAt || block.expiresAt > Date.now()
    );
    const activeAlerts = Array.from(this.alerts.values()).filter((a) => !a.dismissed);

    return {
      totalRequests: this.totalRequests,
      detectedThreats: this.events.length,
      blockedRequests: this.blockedRequests,
      anomalyEvents: this.events.filter((e) =>
        ['medium', 'high', 'critical'].includes(e.riskLevel)
      ).length,
      redactions: this.redactions,
      averageLatencyMs: this.totalRequests
        ? Number((this.totalLatencyMs / this.totalRequests).toFixed(2))
        : 0,
      storageMode: 'memory',
      activeAlerts: activeAlerts.length,
      blockedIps: activeBlocks.map(([ip, block]) => ({
        ip,
        reason: block.reason,
        score: block.score || 0,
        manual: Boolean(block.manual),
        blockedAt: block.blockedAt || null,
        expiresAt: block.expiresAt ? new Date(block.expiresAt).toISOString() : null
      })),
      endpoints: Array.from(this.endpointStats.values())
        .sort((a, b) => b.count - a.count)
        .slice(0, 20),
      recentEvents: this.events.slice(0, 50),
      threatDistribution: Array.from(this.threatDistribution.entries()).map(([name, count]) => ({
        name,
        count
      })),
      clients: Array.from(this.clients.values())
        .sort((a, b) => b.requestCount - a.requestCount)
        .slice(0, 50),
      recentRequests: this.requests.slice(0, 50)
    };
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function pushUnique(list, value) {
  if (!value || list.includes(value)) return;
  list.push(value);
  if (list.length > 10) list.shift();
}

function paginate(array, page, perPage) {
  const total = array.length;
  const totalPages = Math.ceil(total / perPage) || 1;
  const safePage = Math.max(1, Math.min(page, totalPages));
  const start = (safePage - 1) * perPage;
  const data = array.slice(start, start + perPage);
  return { data, total, page: safePage, perPage, totalPages };
}

function pruneOldestClient(clientsMap) {
  let oldestKey = null;
  let oldestTime = Infinity;
  for (const [key, client] of clientsMap.entries()) {
    const t = new Date(client.lastSeenAt || 0).getTime();
    if (t < oldestTime) {
      oldestTime = t;
      oldestKey = key;
    }
  }
  if (oldestKey) clientsMap.delete(oldestKey);
}

module.exports = { MemoryStorage, paginate };
