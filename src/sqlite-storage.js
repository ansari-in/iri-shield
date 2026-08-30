'use strict';

const { dirname } = require('path');
const { mkdirSync } = require('fs');
const { DatabaseSync } = require('node:sqlite');
const { MemoryStorage, paginate } = require('./storage');

// Max rows before cleanup (FIFO — oldest rows deleted first)
const DEFAULT_MAX_REQUEST_ROWS = 50_000;
const DEFAULT_MAX_EVENT_ROWS   = 10_000;
const CLEANUP_RATIO             = 0.1; // delete 10% oldest when limit exceeded

class SQLiteStorage extends MemoryStorage {
  constructor(options = {}) {
    super(options);
    this.file = options.file || options.filename || './data/iri-shield.sqlite';
    this.maxRequestRows = options.maxRequestRows || DEFAULT_MAX_REQUEST_ROWS;
    this.maxEventRows   = options.maxEventRows   || DEFAULT_MAX_EVENT_ROWS;
    this.retentionDays  = options.retentionDays  || 0;

    mkdirSync(dirname(this.file), { recursive: true });
    this.db = new DatabaseSync(this.file);
    this._initSchema();
    this._loadAllPersistentData();
  }

  // ---------------------------------------------------------------------------
  // Schema & Migration
  // ---------------------------------------------------------------------------

  _initSchema() {
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = NORMAL;

      CREATE TABLE IF NOT EXISTS iri_requests (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   TEXT,
        ip          TEXT,
        client_id   TEXT,
        fingerprint TEXT,
        user_agent  TEXT,
        session_id  TEXT,
        endpoint    TEXT,
        method      TEXT,
        status_code INTEGER,
        duration_ms REAL,
        blocked     INTEGER
      );

      CREATE TABLE IF NOT EXISTS iri_events (
        id         TEXT PRIMARY KEY,
        timestamp  TEXT,
        ip         TEXT,
        method     TEXT,
        endpoint   TEXT,
        user_agent TEXT,
        request_id TEXT,
        threat     TEXT,
        risk_level TEXT,
        risk_score INTEGER,
        action     TEXT,
        reason     TEXT,
        data       TEXT
      );

      CREATE TABLE IF NOT EXISTS iri_clients (
        client_id TEXT PRIMARY KEY,
        data      TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS iri_blocks (
        ip         TEXT PRIMARY KEY,
        reason     TEXT,
        score      INTEGER,
        manual     INTEGER DEFAULT 0,
        blocked_at TEXT,
        expires_at INTEGER
      );

      CREATE TABLE IF NOT EXISTS iri_alerts (
        client_id      TEXT PRIMARY KEY,
        first_alert_at TEXT,
        last_alert_at  TEXT,
        count          INTEGER DEFAULT 0,
        last_score     INTEGER,
        last_risk      TEXT,
        last_ip        TEXT,
        threats        TEXT,
        dismissed      INTEGER DEFAULT 0
      );

      CREATE INDEX IF NOT EXISTS idx_req_ip ON iri_requests (ip);
      CREATE INDEX IF NOT EXISTS idx_req_ts ON iri_requests (timestamp);
      CREATE INDEX IF NOT EXISTS idx_evt_risk ON iri_events (risk_level);
      CREATE INDEX IF NOT EXISTS idx_evt_ts  ON iri_events (timestamp);
      CREATE INDEX IF NOT EXISTS idx_blk_exp ON iri_blocks (expires_at);
    `);

    // Automatic migration for existing tables
    try {
      const eventCols = this.db.prepare('PRAGMA table_info(iri_events)').all().map((c) => c.name);
      if (eventCols.length && !eventCols.includes('data')) {
        this.db.exec('ALTER TABLE iri_events ADD COLUMN data TEXT;');
      }
      if (eventCols.length && !eventCols.includes('breakdown')) {
        this.db.exec('ALTER TABLE iri_events ADD COLUMN breakdown TEXT;');
      }
      if (eventCols.length && !eventCols.includes('confidence')) {
        this.db.exec('ALTER TABLE iri_events ADD COLUMN confidence INTEGER DEFAULT 0;');
      }
      if (eventCols.length && !eventCols.includes('correlated_attack')) {
        this.db.exec('ALTER TABLE iri_events ADD COLUMN correlated_attack TEXT;');
      }
      const blockCols = this.db.prepare('PRAGMA table_info(iri_blocks)').all().map((c) => c.name);
      if (blockCols.length && !blockCols.includes('blocked_at')) {
        this.db.exec('ALTER TABLE iri_blocks ADD COLUMN blocked_at TEXT;');
      }
      if (blockCols.length && !blockCols.includes('manual')) {
        this.db.exec('ALTER TABLE iri_blocks ADD COLUMN manual INTEGER DEFAULT 0;');
      }
    } catch { /* table is fresh */ }

    // Retention purge: remove old rows older than retentionDays
    if (this.retentionDays && this.retentionDays > 0) {
      const cutoff = new Date(Date.now() - this.retentionDays * 24 * 60 * 60 * 1000).toISOString();
      try {
        this.db.prepare('DELETE FROM iri_requests WHERE timestamp < ?').run(cutoff);
        this.db.prepare('DELETE FROM iri_events WHERE timestamp < ?').run(cutoff);
      } catch (_) { /* ignore */ }
    }
  }

  // ---------------------------------------------------------------------------
  // Load All Persistent Data from SQLite on Startup / Restart
  // ---------------------------------------------------------------------------

  _loadAllPersistentData() {
    this._loadPersistentBlocks();
    this._loadPersistentClients();
    this._loadPersistentAlerts();
    this._loadPersistentEvents();
    this._loadPersistentRequests();
  }

  _loadPersistentBlocks() {
    try {
      const rows = this.db.prepare('SELECT * FROM iri_blocks').all();
      for (const row of rows) {
        this.blocks.set(row.ip, {
          reason: row.reason || '',
          score: row.score || 0,
          manual: Boolean(row.manual),
          blockedAt: row.blocked_at || null,
          expiresAt: row.expires_at || null
        });
      }
    } catch { /* ignore */ }
  }

  _loadPersistentClients() {
    try {
      const rows = this.db.prepare('SELECT data FROM iri_clients').all();
      for (const row of rows) {
        if (row.data) {
          try {
            const client = JSON.parse(row.data);
            if (client && client.clientId) {
              this.clients.set(client.clientId, client);
            }
          } catch { /* ignore bad row */ }
        }
      }
    } catch { /* ignore */ }
  }

  _loadPersistentAlerts() {
    try {
      const rows = this.db.prepare('SELECT * FROM iri_alerts').all();
      for (const row of rows) {
        let threats = [];
        try { threats = JSON.parse(row.threats || '[]'); } catch { /* ignore */ }
        this.alerts.set(row.client_id, {
          clientId: row.client_id,
          firstAlertAt: row.first_alert_at,
          lastAlertAt: row.last_alert_at,
          count: row.count || 1,
          lastScore: row.last_score || 0,
          lastRisk: row.last_risk || 'medium',
          lastIp: row.last_ip || '',
          threats,
          dismissed: Boolean(row.dismissed)
        });
      }
    } catch { /* ignore */ }
  }

  _loadPersistentEvents() {
    try {
      const rows = this.db
        .prepare('SELECT * FROM iri_events ORDER BY rowid DESC LIMIT ?')
        .all(this.maxEvents);

      this.events = [];
      this.threatDistribution = new Map();

      for (const row of rows) {
        let eventObj = null;
        if (row.data) {
          try { eventObj = JSON.parse(row.data); } catch { /* ignore */ }
        }
        if (!eventObj) {
          eventObj = {
            id: row.id,
            timestamp: row.timestamp,
            ip: row.ip,
            method: row.method,
            endpoint: row.endpoint,
            userAgent: row.user_agent,
            requestId: row.request_id,
            threat: row.threat,
            riskLevel: row.risk_level,
            riskScore: row.risk_score,
            action: row.action,
            reason: row.reason
          };
        }
        this.events.push(eventObj);
        const threat = eventObj.threat || row.threat || 'unknown';
        this.threatDistribution.set(threat, (this.threatDistribution.get(threat) || 0) + 1);
      }
    } catch { /* ignore */ }
  }

  _loadPersistentRequests() {
    try {
      // Aggregates for totals
      const { total_count, blocked_count, sum_lat } =
        this.db.prepare(`
          SELECT
            COUNT(*) as total_count,
            SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked_count,
            SUM(duration_ms) as sum_lat
          FROM iri_requests
        `).get() || {};

      this.totalRequests = total_count || 0;
      this.blockedRequests = blocked_count || 0;
      this.totalLatencyMs = sum_lat || 0;

      // Endpoint stats aggregation
      const epRows = this.db.prepare(`
        SELECT
          method,
          endpoint,
          COUNT(*) as count,
          SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as errors,
          AVG(duration_ms) as avgLatencyMs
        FROM iri_requests
        GROUP BY method, endpoint
        ORDER BY count DESC
        LIMIT 50
      `).all();

      this.endpointStats = new Map();
      for (const row of epRows) {
        const key = `${row.method || 'GET'} ${row.endpoint || '/'}`;
        this.endpointStats.set(key, {
          endpoint: row.endpoint || '/',
          method: row.method || 'GET',
          count: row.count || 0,
          errors: row.errors || 0,
          avgLatencyMs: row.avgLatencyMs || 0
        });
      }

      // Recent requests list
      const reqRows = this.db
        .prepare('SELECT * FROM iri_requests ORDER BY id DESC LIMIT ?')
        .all(this.maxRequests);

      this.requests = reqRows.map((r) => ({
        timestamp: r.timestamp,
        ip: r.ip,
        clientId: r.client_id,
        fingerprint: r.fingerprint,
        userAgent: r.user_agent,
        sessionId: r.session_id,
        endpoint: r.endpoint,
        method: r.method,
        statusCode: r.status_code,
        durationMs: r.duration_ms,
        blocked: Boolean(r.blocked)
      }));
    } catch { /* ignore */ }
  }

  // ---------------------------------------------------------------------------
  // Clear
  // ---------------------------------------------------------------------------

  clear() {
    super.clear();
    if (this.db) {
      this.db.exec(
        'DELETE FROM iri_requests; DELETE FROM iri_events; DELETE FROM iri_clients; DELETE FROM iri_blocks; DELETE FROM iri_alerts;'
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Requests
  // ---------------------------------------------------------------------------

  recordRequest(request) {
    super.recordRequest(request);
    this.db
      .prepare(
        `INSERT INTO iri_requests
          (timestamp, ip, client_id, fingerprint, user_agent, session_id, endpoint, method, status_code, duration_ms, blocked)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        new Date().toISOString(),
        request.ip || 'unknown',
        request.clientId || null,
        request.fingerprint || null,
        request.userAgent || '',
        request.sessionId || '',
        request.endpoint || '/',
        request.method || 'GET',
        request.statusCode || 0,
        request.durationMs || 0,
        request.blocked ? 1 : 0
      );

    this._maybeCleanRequests();
  }

  _maybeCleanRequests() {
    const { count } = this.db.prepare('SELECT COUNT(*) as count FROM iri_requests').get() || {};
    if (count > this.maxRequestRows) {
      const deleteCount = Math.ceil(this.maxRequestRows * CLEANUP_RATIO);
      this.db.exec(
        `DELETE FROM iri_requests WHERE id IN (SELECT id FROM iri_requests ORDER BY id ASC LIMIT ${deleteCount})`
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Events
  // ---------------------------------------------------------------------------

  recordEvent(event) {
    super.recordEvent(event);
    this.db
      .prepare(
        `INSERT OR REPLACE INTO iri_events
          (id, timestamp, ip, method, endpoint, user_agent, request_id, threat, risk_level, risk_score, action, reason, breakdown, confidence, correlated_attack, data)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        event.id,
        event.timestamp,
        event.ip,
        event.method,
        event.endpoint,
        event.userAgent,
        event.requestId || '',
        event.threat || '',
        event.riskLevel || '',
        event.riskScore || 0,
        event.action || '',
        event.reason || '',
        event.breakdown ? JSON.stringify(event.breakdown) : '[]',
        event.confidence || 0,
        event.correlatedAttack ? JSON.stringify(event.correlatedAttack) : null,
        JSON.stringify(event)
      );

    this._maybeCleanEvents();
  }

  _maybeCleanEvents() {
    const { count } = this.db.prepare('SELECT COUNT(*) as count FROM iri_events').get() || {};
    if (count > this.maxEventRows) {
      const deleteCount = Math.ceil(this.maxEventRows * CLEANUP_RATIO);
      this.db.exec(
        `DELETE FROM iri_events WHERE id IN (SELECT id FROM iri_events ORDER BY rowid ASC LIMIT ${deleteCount})`
      );
    }
  }

  getEvents({ page = 1, perPage = 20, riskLevel = null } = {}) {
    try {
      const offset = (Math.max(1, page) - 1) * perPage;
      let rows;
      let total;

      if (riskLevel) {
        total = this.db.prepare('SELECT COUNT(*) as total FROM iri_events WHERE risk_level = ?').get(riskLevel)?.total || 0;
        rows = this.db.prepare('SELECT * FROM iri_events WHERE risk_level = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?').all(riskLevel, perPage, offset);
      } else {
        total = this.db.prepare('SELECT COUNT(*) as total FROM iri_events').get()?.total || 0;
        rows = this.db.prepare('SELECT * FROM iri_events ORDER BY timestamp DESC LIMIT ? OFFSET ?').all(perPage, offset);
      }

      const data = rows.map((row) => {
        if (row.data) {
          try { return JSON.parse(row.data); } catch { /* ignore */ }
        }
        return {
          id: row.id,
          timestamp: row.timestamp,
          ip: row.ip,
          method: row.method,
          endpoint: row.endpoint,
          userAgent: row.user_agent,
          requestId: row.request_id,
          threat: row.threat,
          riskLevel: row.risk_level,
          riskScore: row.risk_score,
          action: row.action,
          reason: row.reason
        };
      });

      const totalPages = Math.ceil(total / perPage) || 1;
      return { data, total, page: Math.max(1, page), perPage, totalPages };
    } catch {
      return super.getEvents({ page, perPage, riskLevel });
    }
  }

  // ---------------------------------------------------------------------------
  // Clients
  // ---------------------------------------------------------------------------

  recordClient(client) {
    const row = super.recordClient(client);
    row.userId = client.userId || row.userId;
    this.db
      .prepare('INSERT OR REPLACE INTO iri_clients (client_id, data) VALUES (?, ?)')
      .run(row.clientId, JSON.stringify(row));
    return row;
  }

  getClients({ page = 1, perPage = 20 } = {}) {
    try {
      const offset = (Math.max(1, page) - 1) * perPage;
      const { total } = this.db.prepare('SELECT COUNT(*) as total FROM iri_clients').get() || { total: 0 };
      const rows = this.db.prepare('SELECT data FROM iri_clients LIMIT ? OFFSET ?').all(perPage, offset);

      const clients = rows.map((r) => {
        try { return JSON.parse(r.data); } catch { return null; }
      }).filter(Boolean);

      clients.sort((a, b) => (b.requestCount || 0) - (a.requestCount || 0));
      const totalPages = Math.ceil(total / perPage) || 1;
      return { data: clients, total, page: Math.max(1, page), perPage, totalPages };
    } catch {
      return super.getClients({ page, perPage });
    }
  }

  // ---------------------------------------------------------------------------
  // Blocks (Persistent & History Retained)
  // ---------------------------------------------------------------------------

  blockIp(ip, block) {
    const fullBlock = {
      ...block,
      blockedAt: block.blockedAt || new Date().toISOString(),
      manual: Boolean(block.manual)
    };
    super.blockIp(ip, fullBlock);
    this.db
      .prepare(
        `INSERT OR REPLACE INTO iri_blocks (ip, reason, score, manual, blocked_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)`
      )
      .run(
        ip,
        fullBlock.reason || '',
        fullBlock.score || 0,
        fullBlock.manual ? 1 : 0,
        fullBlock.blockedAt,
        fullBlock.expiresAt || null
      );
  }

  unblockIp(ip) {
    const result = super.unblockIp(ip);
    this.db.prepare('DELETE FROM iri_blocks WHERE ip = ?').run(ip);
    return result;
  }

  manualBlockIp(ip, options = {}) {
    const duration = options.durationMs !== undefined ? options.durationMs : 24 * 60 * 60 * 1000;
    const fullBlock = {
      expiresAt: duration > 0 ? Date.now() + duration : null,
      reason: options.reason || 'manual_block',
      score: options.score !== undefined ? options.score : 100,
      manual: true,
      blockedAt: new Date().toISOString()
    };
    super.blockIp(ip, fullBlock);
    this.db
      .prepare(
        `INSERT OR REPLACE INTO iri_blocks (ip, reason, score, manual, blocked_at, expires_at)
         VALUES (?, ?, ?, 1, ?, ?)`
      )
      .run(ip, fullBlock.reason, fullBlock.score, fullBlock.blockedAt, fullBlock.expiresAt);
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
    try {
      const now = Date.now();
      let query;
      let countQuery;
      let params = [];

      if (status === 'active') {
        countQuery = 'SELECT COUNT(*) as total FROM iri_blocks WHERE expires_at IS NULL OR expires_at > ?';
        query = 'SELECT * FROM iri_blocks WHERE expires_at IS NULL OR expires_at > ? ORDER BY blocked_at DESC LIMIT ? OFFSET ?';
        params = [now];
      } else if (status === 'expired') {
        countQuery = 'SELECT COUNT(*) as total FROM iri_blocks WHERE expires_at IS NOT NULL AND expires_at <= ?';
        query = 'SELECT * FROM iri_blocks WHERE expires_at IS NOT NULL AND expires_at <= ? ORDER BY blocked_at DESC LIMIT ? OFFSET ?';
        params = [now];
      } else {
        // 'all' — show active/permanent first, then expired
        countQuery = 'SELECT COUNT(*) as total FROM iri_blocks';
        query = 'SELECT *, (CASE WHEN expires_at IS NULL OR expires_at > ? THEN 0 ELSE 1 END) as is_exp FROM iri_blocks ORDER BY is_exp ASC, blocked_at DESC LIMIT ? OFFSET ?';
        params = [now];
      }

      const total = this.db.prepare(countQuery).get(...(status !== 'all' ? params : []))?.total || 0;
      const offset = (Math.max(1, page) - 1) * perPage;
      const queryParams = [...params, perPage, offset];
      const rows = this.db.prepare(query).all(...queryParams);

      const formatted = rows.map((row) => {
        const isPermanent = !row.expires_at;
        const isExpired = row.expires_at ? row.expires_at <= now : false;
        const itemStatus = isPermanent ? 'permanent' : (isExpired ? 'expired' : 'active');
        return {
          ip: row.ip,
          reason: row.reason || '',
          score: row.score || 0,
          manual: Boolean(row.manual),
          status: itemStatus,
          isExpired,
          blockedAt: row.blocked_at || null,
          expiresAt: row.expires_at ? new Date(row.expires_at).toISOString() : null
        };
      });

      const totalPages = Math.ceil(total / perPage) || 1;
      return { data: formatted, total, page: Math.max(1, page), perPage, totalPages };
    } catch {
      return super.getBlockedIps({ page, perPage, status });
    }
  }

  // ---------------------------------------------------------------------------
  // Alerts (Persistent)
  // ---------------------------------------------------------------------------

  recordAlert(clientId, alertData) {
    super.recordAlert(clientId, alertData);
    const a = this.alerts.get(clientId);
    if (!a) return;
    this.db
      .prepare(
        `INSERT OR REPLACE INTO iri_alerts
          (client_id, first_alert_at, last_alert_at, count, last_score, last_risk, last_ip, threats, dismissed)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        a.clientId,
        a.firstAlertAt,
        a.lastAlertAt,
        a.count,
        a.lastScore || 0,
        a.lastRisk || '',
        a.lastIp || '',
        JSON.stringify(a.threats || []),
        a.dismissed ? 1 : 0
      );
  }

  dismissAlert(clientId) {
    const result = super.dismissAlert(clientId);
    this.db
      .prepare('UPDATE iri_alerts SET dismissed = 1 WHERE client_id = ?')
      .run(clientId);
    return result;
  }

  getAlerts({ page = 1, perPage = 20, dismissed = false } = {}) {
    try {
      const offset = (Math.max(1, page) - 1) * perPage;
      const { total } = this.db.prepare('SELECT COUNT(*) as total FROM iri_alerts WHERE dismissed = ?').get(dismissed ? 1 : 0) || { total: 0 };
      const rows = this.db.prepare('SELECT * FROM iri_alerts WHERE dismissed = ? ORDER BY last_alert_at DESC LIMIT ? OFFSET ?').all(dismissed ? 1 : 0, perPage, offset);

      const data = rows.map((r) => {
        let threats = [];
        try { threats = JSON.parse(r.threats || '[]'); } catch { /* ignore */ }
        return {
          clientId: r.client_id,
          firstAlertAt: r.first_alert_at,
          lastAlertAt: r.last_alert_at,
          count: r.count || 1,
          lastScore: r.last_score || 0,
          lastRisk: r.last_risk || 'medium',
          lastIp: r.last_ip || '',
          threats,
          dismissed: Boolean(r.dismissed)
        };
      });

      const totalPages = Math.ceil(total / perPage) || 1;
      return { data, total, page: Math.max(1, page), perPage, totalPages };
    } catch {
      return super.getAlerts({ page, perPage, dismissed });
    }
  }

  // ---------------------------------------------------------------------------
  // Real-time Database Stats (Accurate after restarts)
  // ---------------------------------------------------------------------------

  getStats() {
    const now = Date.now();

    // Active blocks list (for stats)
    const activeBlocks = this.db
      .prepare(
        'SELECT * FROM iri_blocks WHERE expires_at IS NULL OR expires_at > ? ORDER BY blocked_at DESC'
      )
      .all(now)
      .map((row) => ({
        ip: row.ip,
        reason: row.reason || '',
        score: row.score || 0,
        manual: Boolean(row.manual),
        status: row.expires_at ? 'active' : 'permanent',
        isExpired: false,
        blockedAt: row.blocked_at || null,
        expiresAt: row.expires_at ? new Date(row.expires_at).toISOString() : null
      }));

    // Request metrics directly from SQLite
    const { total_req, blocked_req, avg_lat } =
      this.db.prepare(`
        SELECT
          COUNT(*) as total_req,
          SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked_req,
          AVG(duration_ms) as avg_lat
        FROM iri_requests
      `).get() || {};

    // Event metrics directly from SQLite
    const { total_evt, anomaly_evt } =
      this.db.prepare(`
        SELECT
          COUNT(*) as total_evt,
          SUM(CASE WHEN risk_level IN ('medium', 'high', 'critical') THEN 1 ELSE 0 END) as anomaly_evt
        FROM iri_events
      `).get() || {};

    // Threat distribution aggregated directly from SQLite
    const threatDistribution = this.db.prepare(`
      SELECT threat as name, COUNT(*) as count
      FROM iri_events
      WHERE threat IS NOT NULL AND threat != ''
      GROUP BY threat
      ORDER BY count DESC
    `).all();

    // Top endpoints aggregated directly from SQLite
    const endpoints = this.db.prepare(`
      SELECT
        endpoint,
        method,
        COUNT(*) as count,
        SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as errors,
        AVG(duration_ms) as avgLatencyMs
      FROM iri_requests
      GROUP BY method, endpoint
      ORDER BY count DESC
      LIMIT 20
    `).all();

    // Client counts
    const { total_clients } =
      this.db.prepare('SELECT COUNT(*) as total_clients FROM iri_clients').get() || {};

    // Active alerts count
    const activeAlerts =
      this.db.prepare('SELECT COUNT(*) as cnt FROM iri_alerts WHERE dismissed = 0').get()?.cnt || 0;

    // Recent events list (latest 50)
    const recentEvents = this.db
      .prepare('SELECT * FROM iri_events ORDER BY timestamp DESC LIMIT 50')
      .all()
      .map((row) => {
        if (row.data) {
          try { return JSON.parse(row.data); } catch { /* ignore */ }
        }
        return {
          id: row.id,
          timestamp: row.timestamp,
          ip: row.ip,
          method: row.method,
          endpoint: row.endpoint,
          userAgent: row.user_agent,
          requestId: row.request_id,
          threat: row.threat,
          riskLevel: row.risk_level,
          riskScore: row.risk_score,
          action: row.action,
          reason: row.reason
        };
      });

    // Recent requests list (latest 50)
    const recentRequests = this.db
      .prepare('SELECT * FROM iri_requests ORDER BY id DESC LIMIT 50')
      .all()
      .map((r) => ({
        timestamp: r.timestamp,
        ip: r.ip,
        clientId: r.client_id,
        fingerprint: r.fingerprint,
        userAgent: r.user_agent,
        sessionId: r.session_id,
        endpoint: r.endpoint,
        method: r.method,
        statusCode: r.status_code,
        durationMs: r.duration_ms,
        blocked: Boolean(r.blocked)
      }));

    // Clients list (top 50)
    const clients = this.db
      .prepare('SELECT data FROM iri_clients LIMIT 50')
      .all()
      .map((r) => {
        try { return JSON.parse(r.data); } catch { return null; }
      })
      .filter(Boolean);

    clients.sort((a, b) => (b.requestCount || 0) - (a.requestCount || 0));

    return {
      totalRequests: total_req || 0,
      detectedThreats: total_evt || 0,
      blockedRequests: blocked_req || 0,
      anomalyEvents: anomaly_evt || 0,
      redactions: this.redactions || 0,
      averageLatencyMs: avg_lat ? Number(Number(avg_lat).toFixed(2)) : 0,
      storageMode: 'sqlite',
      sqliteFile: this.file,
      activeAlerts,
      blockedIps: activeBlocks,
      endpoints,
      threatDistribution,
      recentEvents,
      recentRequests,
      clients,
      dbStats: {
        totalRequestRows: total_req || 0,
        maxRequestRows: this.maxRequestRows,
        totalEventRows: total_evt || 0,
        maxEventRows: this.maxEventRows,
        totalClientRows: total_clients || 0
      }
    };
  }
}

module.exports = { SQLiteStorage };
