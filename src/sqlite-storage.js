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
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp  TEXT,
        ip         TEXT,
        client_id  TEXT,
        fingerprint TEXT,
        user_agent TEXT,
        session_id TEXT,
        endpoint   TEXT,
        method     TEXT,
        status_code INTEGER,
        duration_ms REAL,
        blocked    INTEGER
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
        reason     TEXT
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
    `);
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
      this.blocks.set(row.ip, {
        reason: row.reason || '',
        score: row.score || 0,
        manual: Boolean(row.manual),
        blockedAt: row.blocked_at || null,
        expiresAt: row.expires_at || null
      });
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
          (id, timestamp, ip, method, endpoint, user_agent, request_id, threat, risk_level, risk_score, action, reason)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
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
        event.reason || ''
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
    super.blockIp(ip, block);
    this.db
      .prepare(
        `INSERT OR REPLACE INTO iri_blocks (ip, reason, score, manual, blocked_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)`
      )
      .run(
        ip,
        block.reason || '',
        block.score || 0,
        block.manual ? 1 : 0,
        block.blockedAt || new Date().toISOString(),
        block.expiresAt || null
      );
  }

  unblockIp(ip) {
    const result = super.unblockIp(ip);
    this.db.prepare('DELETE FROM iri_blocks WHERE ip = ?').run(ip);
    return result;
  }

  manualBlockIp(ip, options = {}) {
    super.manualBlockIp(ip, options);
    const block = this.blocks.get(ip);
    if (block) {
      this.db
        .prepare(
          `INSERT OR REPLACE INTO iri_blocks (ip, reason, score, manual, blocked_at, expires_at)
           VALUES (?, ?, ?, 1, ?, ?)`
        )
        .run(ip, block.reason, block.score || 100, block.blockedAt, block.expiresAt || null);
    }
  }

  getBlockedIps({ page = 1, perPage = 20 } = {}) {
    // Sync expired from DB first
    this._cleanupExpiredBlocks();
    return super.getBlockedIps({ page, perPage });
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
    const { total_req } = this.db
      .prepare('SELECT COUNT(*) as total_req FROM iri_requests')
      .get() || {};
    const { total_evt } = this.db
      .prepare('SELECT COUNT(*) as total_evt FROM iri_events')
      .get() || {};
    const { total_clients } = this.db
      .prepare('SELECT COUNT(*) as total_clients FROM iri_clients')
      .get() || {};

    return {
      ...super.getStats(),
      storageMode: 'sqlite',
      sqliteFile: this.file,
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
