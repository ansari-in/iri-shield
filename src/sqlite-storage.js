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

    mkdirSync(dirname(this.file), { recursive: true });
    this.db = new DatabaseSync(this.file);
    this._initSchema();
    this._cleanupExpiredBlocks();
    this._loadPersistentBlocks();
  }

  // ---------------------------------------------------------------------------
  // Schema
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
      const eventCols = this.db.prepare('PRAGMA table_info(iri_events)').all().map(c => c.name);
      if (eventCols.length && !eventCols.includes('data')) {
        this.db.exec('ALTER TABLE iri_events ADD COLUMN data TEXT;');
      }
      const blockCols = this.db.prepare('PRAGMA table_info(iri_blocks)').all().map(c => c.name);
      if (blockCols.length && !blockCols.includes('blocked_at')) {
        this.db.exec('ALTER TABLE iri_blocks ADD COLUMN blocked_at TEXT;');
      }
      if (blockCols.length && !blockCols.includes('manual')) {
        this.db.exec('ALTER TABLE iri_blocks ADD COLUMN manual INTEGER DEFAULT 0;');
      }
    } catch { /* table might be fresh */ }
  }

  // ---------------------------------------------------------------------------
  // Persistent blocks
  // ---------------------------------------------------------------------------

  _cleanupExpiredBlocks() {
    this.db
      .prepare('DELETE FROM iri_blocks WHERE expires_at IS NOT NULL AND expires_at <= ?')
      .run(Date.now());
  }

  _loadPersistentBlocks() {
    const rows = this.db.prepare('SELECT * FROM iri_blocks').all();
    for (const row of rows) {
      if (!row.expires_at || row.expires_at > Date.now()) {
        this.blocks.set(row.ip, {
          reason: row.reason || '',
          score: row.score || 0,
          manual: Boolean(row.manual),
          blockedAt: row.blocked_at || null,
          expiresAt: row.expires_at || null
        });
      }
    }
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

    // FIFO cleanup to keep DB size manageable
    this._maybeCleanRequests();
  }

  _maybeCleanRequests() {
    const { count } = this.db.prepare('SELECT COUNT(*) as count FROM iri_requests').get();
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
          (id, timestamp, ip, method, endpoint, user_agent, request_id, threat, risk_level, risk_score, action, reason, data)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
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
        JSON.stringify(event)
      );

    this._maybeCleanEvents();
  }

  _maybeCleanEvents() {
    const { count } = this.db.prepare('SELECT COUNT(*) as count FROM iri_events').get();
    if (count > this.maxEventRows) {
      const deleteCount = Math.ceil(this.maxEventRows * CLEANUP_RATIO);
      this.db.exec(
        `DELETE FROM iri_events WHERE id IN (SELECT id FROM iri_events ORDER BY timestamp ASC LIMIT ${deleteCount})`
      );
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

  // ---------------------------------------------------------------------------
  // Blocks (persistent)
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
    const duration = options.durationMs !== undefined ? options.durationMs : 60 * 60 * 1000;
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

  getBlockedIps({ page = 1, perPage = 20 } = {}) {
    this._cleanupExpiredBlocks();
    const now = Date.now();
    const rows = this.db
      .prepare(
        'SELECT * FROM iri_blocks WHERE expires_at IS NULL OR expires_at > ? ORDER BY blocked_at DESC'
      )
      .all(now);

    const formatted = rows.map((row) => ({
      ip: row.ip,
      reason: row.reason || '',
      score: row.score || 0,
      manual: Boolean(row.manual),
      blockedAt: row.blocked_at || null,
      expiresAt: row.expires_at ? new Date(row.expires_at).toISOString() : null
    }));

    // Keep in-memory cache in sync
    this.blocks.clear();
    for (const item of rows) {
      this.blocks.set(item.ip, {
        reason: item.reason,
        score: item.score,
        manual: Boolean(item.manual),
        blockedAt: item.blocked_at,
        expiresAt: item.expires_at
      });
    }

    return paginate(formatted, page, perPage);
  }

  // ---------------------------------------------------------------------------
  // Alerts (persistent)
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

  // ---------------------------------------------------------------------------
  // Stats
  // ---------------------------------------------------------------------------

  getStats() {
    this._cleanupExpiredBlocks();
    const now = Date.now();
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
        blockedAt: row.blocked_at || null,
        expiresAt: row.expires_at ? new Date(row.expires_at).toISOString() : null
      }));

    const { total_req } =
      this.db.prepare('SELECT COUNT(*) as total_req FROM iri_requests').get() || {};
    const { total_evt } =
      this.db.prepare('SELECT COUNT(*) as total_evt FROM iri_events').get() || {};
    const { total_clients } =
      this.db.prepare('SELECT COUNT(*) as total_clients FROM iri_clients').get() || {};

    const activeAlerts =
      this.db.prepare('SELECT COUNT(*) as cnt FROM iri_alerts WHERE dismissed = 0').get()?.cnt || 0;

    return {
      ...super.getStats(),
      storageMode: 'sqlite',
      sqliteFile: this.file,
      blockedIps: activeBlocks,
      activeAlerts: activeAlerts || (super.getStats().activeAlerts || 0),
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
