'use strict';

const { dirname } = require('path');
const { mkdirSync } = require('fs');
const { DatabaseSync } = require('node:sqlite');
const { MemoryStorage } = require('./storage');

class SQLiteStorage extends MemoryStorage {
  constructor(options = {}) {
    super(options);
    this.file = options.file || options.filename || './data/iri-shield.sqlite';
    mkdirSync(dirname(this.file), { recursive: true });
    this.db = new DatabaseSync(this.file);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS iri_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        ip TEXT,
        client_id TEXT,
        fingerprint TEXT,
        user_agent TEXT,
        cookie TEXT,
        session_id TEXT,
        endpoint TEXT,
        method TEXT,
        status_code INTEGER,
        duration_ms REAL,
        blocked INTEGER
      );
      CREATE TABLE IF NOT EXISTS iri_events (
        id TEXT PRIMARY KEY,
        timestamp TEXT,
        ip TEXT,
        method TEXT,
        endpoint TEXT,
        user_agent TEXT,
        request_id TEXT,
        threat TEXT,
        risk_level TEXT,
        risk_score INTEGER,
        action TEXT,
        reason TEXT
      );
      CREATE TABLE IF NOT EXISTS iri_clients (
        client_id TEXT PRIMARY KEY,
        data TEXT NOT NULL
      );
    `);
  }

  clear() {
    super.clear();
    if (this.db) {
      this.db.exec('DELETE FROM iri_requests; DELETE FROM iri_events; DELETE FROM iri_clients;');
    }
  }

  recordRequest(request) {
    super.recordRequest(request);
    this.db.prepare(`INSERT INTO iri_requests (timestamp, ip, client_id, fingerprint, user_agent, cookie, session_id, endpoint, method, status_code, duration_ms, blocked)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      new Date().toISOString(),
      request.ip || 'unknown',
      request.clientId || null,
      request.fingerprint || null,
      request.userAgent || '',
      request.cookie || '',
      request.sessionId || '',
      request.endpoint || '/',
      request.method || 'GET',
      request.statusCode || 0,
      request.durationMs || 0,
      request.blocked ? 1 : 0
    );
  }

  recordEvent(event) {
    super.recordEvent(event);
    this.db.prepare(`INSERT OR REPLACE INTO iri_events (id, timestamp, ip, method, endpoint, user_agent, request_id, threat, risk_level, risk_score, action, reason)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
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
  }

  recordClient(client) {
    const row = super.recordClient(client);
    row.userId = client.userId || row.userId;
    this.db.prepare('INSERT OR REPLACE INTO iri_clients (client_id, data) VALUES (?, ?)').run(row.clientId, JSON.stringify(row));
    return row;
  }

  getStats() {
    return { ...super.getStats(), storageMode: 'sqlite', sqliteFile: this.file };
  }
}

module.exports = { SQLiteStorage };
