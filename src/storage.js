'use strict';

class MemoryStorage {
  constructor(options = {}) {
    this.maxEvents = options.maxEvents || 500;
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
    this.threatDistribution = new Map();
  }

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
    this.requests = this.requests.slice(0, 1000);
    this.totalRequests += 1;
    if (request.blocked) this.blockedRequests += 1;
    this.totalLatencyMs += request.durationMs || 0;

    const key = `${request.method || 'GET'} ${request.endpoint || '/'}`;
    const current = this.endpointStats.get(key) || { endpoint: request.endpoint || '/', method: request.method || 'GET', count: 0, errors: 0, avgLatencyMs: 0 };
    current.count += 1;
    current.errors += request.statusCode >= 400 ? 1 : 0;
    current.avgLatencyMs = ((current.avgLatencyMs * (current.count - 1)) + (request.durationMs || 0)) / current.count;
    this.endpointStats.set(key, current);
  }

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

  recordFailedAuth(ip) {
    const current = this.failedAuth.get(ip) || { count: 0, startedAt: Date.now() };
    current.count += 1;
    this.failedAuth.set(ip, current);
    return current.count;
  }

  getFailedAuth(ip) {
    return this.failedAuth.get(ip)?.count || 0;
  }

  blockIp(ip, block) {
    this.blocks.set(ip, block);
  }

  getBlock(ip) {
    const block = this.blocks.get(ip);
    if (!block) return null;
    if (block.expiresAt && block.expiresAt <= Date.now()) {
      this.blocks.delete(ip);
      return null;
    }
    return block;
  }

  recordEvent(event) {
    this.events.unshift(event);
    this.events = this.events.slice(0, this.maxEvents);
    const threat = event.threat || 'unknown';
    this.threatDistribution.set(threat, (this.threatDistribution.get(threat) || 0) + 1);
  }

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
    if ((client.ip && !beforeIps.has(client.ip)) || (client.userAgent && !beforeAgents.has(client.userAgent)) || (client.fingerprint && !beforePrints.has(client.fingerprint))) {
      current.changes += current.requestCount === 1 ? 0 : 1;
    }
    this.clients.set(client.clientId, current);
    return current;
  }

  findClientsByUserId(userId) {
    if (!userId) return [];
    return Array.from(this.clients.values()).filter((client) => client.userId === userId);
  }

  recordRedaction(count) {
    this.redactions += count || 0;
  }

  getStats() {
    const threats = this.events.length;
    return {
      totalRequests: this.totalRequests,
      detectedThreats: threats,
      blockedRequests: this.blockedRequests,
      anomalyEvents: this.events.filter((event) => ['medium', 'high', 'critical'].includes(event.riskLevel)).length,
      redactions: this.redactions,
      averageLatencyMs: this.totalRequests ? Number((this.totalLatencyMs / this.totalRequests).toFixed(2)) : 0,
      storageMode: 'memory',
      blockedIps: Array.from(this.blocks.entries())
        .filter(([, block]) => !block.expiresAt || block.expiresAt > Date.now())
        .map(([ip, block]) => ({ ip, reason: block.reason, expiresAt: block.expiresAt ? new Date(block.expiresAt).toISOString() : null })),
      endpoints: Array.from(this.endpointStats.values()).sort((a, b) => b.count - a.count).slice(0, 20),
      recentEvents: this.events.slice(0, 50),
      threatDistribution: Array.from(this.threatDistribution.entries()).map(([name, count]) => ({ name, count })),
      clients: Array.from(this.clients.values()).sort((a, b) => b.requestCount - a.requestCount).slice(0, 50),
      recentRequests: this.requests.slice(0, 50)
    };
  }
}

function pushUnique(list, value) {
  if (!value || list.includes(value)) return;
  list.push(value);
  if (list.length > 10) list.shift();
}

module.exports = { MemoryStorage };
