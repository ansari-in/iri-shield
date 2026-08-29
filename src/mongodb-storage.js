'use strict';

const { MemoryStorage } = require('./storage');

/**
 * MongoStorage — MongoDB-backed storage for iri-shield.
 *
 * Graceful fallback: if MongoDB is not available (connection fails within 3s),
 * the class silently falls back to pure in-memory operation.
 * No error is thrown — the server continues running normally.
 */
class MongoStorage extends MemoryStorage {
  constructor(options = {}) {
    super(options);
    this.mongoUrl = options.mongoUrl || 'mongodb://localhost:27017/iri-shield';
    this.dbName = options.dbName || 'iri-shield';
    this.connected = false;
    this.client = null;
    this.db = null;
    this._cols = {};

    // Start connection asynchronously — does not block constructor
    this._connect();
  }

  async _connect() {
    try {
      let MongoClient;
      try {
        ({ MongoClient } = require('mongodb'));
      } catch {
        // mongodb package not installed — silently use memory-only
        return;
      }

      const client = new MongoClient(this.mongoUrl, {
        serverSelectionTimeoutMS: 3000,
        connectTimeoutMS: 3000,
        socketTimeoutMS: 3000
      });

      await client.connect();
      this.client = client;
      this.db = client.db(this.dbName);
      this.connected = true;

      // Initialize collections and TTL indexes
      await this._initCollections();

      // Load persistent blocks into memory
      await this._loadPersistentBlocks();

      console.log('[iri-shield] MongoDB connected:', this.mongoUrl);
    } catch (err) {
      // Graceful fallback — not a fatal error
      console.warn('[iri-shield] MongoDB not available, using memory storage. Reason:', err.message);
      this.connected = false;
    }
  }

  async _initCollections() {
    const db = this.db;

    // Requests: TTL 7 days
    const requests = db.collection('iri_requests');
    await requests.createIndex({ createdAt: 1 }, { expireAfterSeconds: 7 * 24 * 60 * 60 });
    await requests.createIndex({ ip: 1 });

    // Events: TTL 30 days
    const events = db.collection('iri_events');
    await events.createIndex({ createdAt: 1 }, { expireAfterSeconds: 30 * 24 * 60 * 60 });
    await events.createIndex({ riskLevel: 1 });

    // Clients: no TTL
    const clients = db.collection('iri_clients');
    await clients.createIndex({ clientId: 1 }, { unique: true });

    // Blocks: no TTL (managed manually)
    const blocks = db.collection('iri_blocks');
    await blocks.createIndex({ ip: 1 }, { unique: true });

    // Alerts: no TTL
    const alerts = db.collection('iri_alerts');
    await alerts.createIndex({ clientId: 1 }, { unique: true });

    this._cols = { requests, events, clients, blocks, alerts };
  }

  async _loadPersistentBlocks() {
    if (!this.connected) return;
    try {
      const rows = await this._cols.blocks.find({}).toArray();
      for (const row of rows) {
        if (!row.expiresAt || row.expiresAt > Date.now()) {
          this.blocks.set(row.ip, {
            reason: row.reason || '',
            score: row.score || 0,
            manual: Boolean(row.manual),
            blockedAt: row.blockedAt || null,
            expiresAt: row.expiresAt || null
          });
        }
      }
    } catch { /* ignore */ }
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  _safe(fn) {
    // Fire-and-forget — never awaited, never throws
    if (!this.connected) return;
    Promise.resolve().then(fn).catch(() => {});
  }

  // ---------------------------------------------------------------------------
  // Request recording
  // ---------------------------------------------------------------------------

  recordRequest(request) {
    super.recordRequest(request);
    this._safe(() =>
      this._cols.requests.insertOne({
        ...request,
        createdAt: new Date(),
        blocked: Boolean(request.blocked)
      })
    );
  }

  // ---------------------------------------------------------------------------
  // Events
  // ---------------------------------------------------------------------------

  recordEvent(event) {
    super.recordEvent(event);
    this._safe(() =>
      this._cols.events.updateOne(
        { id: event.id },
        { $set: { ...event, createdAt: new Date() } },
        { upsert: true }
      )
    );
  }

  // ---------------------------------------------------------------------------
  // Clients
  // ---------------------------------------------------------------------------

  recordClient(client) {
    const row = super.recordClient(client);
    this._safe(() =>
      this._cols.clients.updateOne(
        { clientId: row.clientId },
        { $set: { ...row, updatedAt: new Date() } },
        { upsert: true }
      )
    );
    return row;
  }

  // ---------------------------------------------------------------------------
  // Blocks (persistent)
  // ---------------------------------------------------------------------------

  blockIp(ip, block) {
    super.blockIp(ip, block);
    this._safe(() =>
      this._cols.blocks.updateOne(
        { ip },
        { $set: { ip, ...block, updatedAt: new Date() } },
        { upsert: true }
      )
    );
  }

  unblockIp(ip) {
    const result = super.unblockIp(ip);
    this._safe(() => this._cols.blocks.deleteOne({ ip }));
    return result;
  }

  manualBlockIp(ip, options = {}) {
    super.manualBlockIp(ip, options);
    const block = this.blocks.get(ip);
    if (block) {
      this._safe(() =>
        this._cols.blocks.updateOne(
          { ip },
          { $set: { ip, ...block, manual: true, updatedAt: new Date() } },
          { upsert: true }
        )
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Alerts (persistent)
  // ---------------------------------------------------------------------------

  recordAlert(clientId, alertData) {
    super.recordAlert(clientId, alertData);
    const a = this.alerts.get(clientId);
    if (!a) return;
    this._safe(() =>
      this._cols.alerts.updateOne(
        { clientId },
        { $set: { ...a, updatedAt: new Date() } },
        { upsert: true }
      )
    );
  }

  dismissAlert(clientId) {
    const result = super.dismissAlert(clientId);
    this._safe(() =>
      this._cols.alerts.updateOne({ clientId }, { $set: { dismissed: true } })
    );
    return result;
  }

  // ---------------------------------------------------------------------------
  // Stats
  // ---------------------------------------------------------------------------

  getStats() {
    return {
      ...super.getStats(),
      storageMode: this.connected ? 'mongodb' : 'mongodb_fallback_memory',
      mongoUrl: this.mongoUrl,
      mongoConnected: this.connected
    };
  }
}

module.exports = { MongoStorage };
