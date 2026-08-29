'use strict';

const express = require('express');
const { randomBytes, timingSafeEqual } = require('crypto');

function createDashboardRouter({ storage, config }) {
  const router = express.Router();
  const auth = dashboardAuth(config.dashboard);

  router.use(express.urlencoded({ extended: false }));
  router.use(express.json({ limit: '50kb' }));

  // --- Auth routes ---
  router.get('/login', (req, res) => {
    if (auth.isAuthenticated(req)) return res.redirect(req.baseUrl || '/');
    res.type('html').send(renderLogin(config, false));
  });

  router.post('/login', (req, res) => {
    if (auth.canLogin(req.body?.username, req.body?.password)) {
      res.setHeader(
        'Set-Cookie',
        `iri_shield_session=${auth.token}; HttpOnly; SameSite=Lax; Path=${config.dashboard.path || '/iri-shield'}; Max-Age=86400`
      );
      return res.redirect(req.baseUrl || '/');
    }
    return res.status(401).type('html').send(renderLogin(config, true));
  });

  router.post('/logout', (req, res) => {
    res.setHeader(
      'Set-Cookie',
      `iri_shield_session=; HttpOnly; SameSite=Lax; Path=${config.dashboard.path || '/iri-shield'}; Max-Age=0`
    );
    return res.redirect(`${req.baseUrl || ''}/login`);
  });

  // --- Auth guard ---
  router.use((req, res, next) => {
    if (auth.isAuthenticated(req)) return next();
    if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
    return res.redirect(`${req.baseUrl || ''}/login`);
  });

  // =========================================================================
  // API endpoints
  // =========================================================================

  router.get('/api/stats', (req, res) => {
    res.json({ ...storage.getStats(), config: publicConfig(config) });
  });

  // Paginated events
  router.get('/api/events', (req, res) => {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const perPage = Math.min(100, Math.max(5, parseInt(req.query.perPage) || 20));
    const riskLevel = req.query.riskLevel || null;
    if (typeof storage.getEvents === 'function') {
      res.json(storage.getEvents({ page, perPage, riskLevel }));
    } else {
      const events = (storage.events || []).filter(e => !riskLevel || e.riskLevel === riskLevel);
      res.json(paginateArray(events, page, perPage));
    }
  });

  // Paginated clients
  router.get('/api/clients', (req, res) => {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const perPage = Math.min(100, Math.max(5, parseInt(req.query.perPage) || 20));
    if (typeof storage.getClients === 'function') {
      res.json(storage.getClients({ page, perPage }));
    } else {
      const clients = Array.from((storage.clients || new Map()).values())
        .sort((a, b) => b.requestCount - a.requestCount);
      res.json(paginateArray(clients, page, perPage));
    }
  });

  // Paginated blocked IPs
  router.get('/api/blocked', (req, res) => {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const perPage = Math.min(100, Math.max(5, parseInt(req.query.perPage) || 20));
    if (typeof storage.getBlockedIps === 'function') {
      res.json(storage.getBlockedIps({ page, perPage }));
    } else {
      const now = Date.now();
      const active = Array.from((storage.blocks || new Map()).entries())
        .filter(([, b]) => !b.expiresAt || b.expiresAt > now)
        .map(([ip, b]) => ({ ip, ...b, expiresAt: b.expiresAt ? new Date(b.expiresAt).toISOString() : null }));
      res.json(paginateArray(active, page, perPage));
    }
  });

  // Paginated alerts
  router.get('/api/alerts', (req, res) => {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const perPage = Math.min(100, Math.max(5, parseInt(req.query.perPage) || 20));
    const dismissed = req.query.dismissed === 'true';
    if (typeof storage.getAlerts === 'function') {
      res.json(storage.getAlerts({ page, perPage, dismissed }));
    } else {
      res.json(paginateArray([], page, perPage));
    }
  });

  // Unblock IP
  router.post('/api/unblock', (req, res) => {
    const { ip } = req.body || {};
    if (!ip) return res.status(400).json({ error: 'IP is required' });
    if (typeof storage.unblockIp === 'function') storage.unblockIp(ip);
    res.json({ ok: true, ip });
  });

  // Manual block IP
  router.post('/api/block', (req, res) => {
    const { ip, reason, durationMs } = req.body || {};
    if (!ip) return res.status(400).json({ error: 'IP is required' });
    const duration = Number(durationMs) || 60 * 60 * 1000;
    if (typeof storage.manualBlockIp === 'function') {
      storage.manualBlockIp(ip, { reason: reason || 'manual_block', durationMs: duration });
    } else {
      storage.blockIp(ip, {
        expiresAt: Date.now() + duration,
        reason: reason || 'manual_block',
        score: 100,
        manual: true,
        blockedAt: new Date().toISOString()
      });
    }
    res.json({ ok: true, ip, reason, durationMs: duration });
  });

  // Dismiss alert
  router.post('/api/alerts/:clientId/dismiss', (req, res) => {
    const { clientId } = req.params;
    if (!clientId) return res.status(400).json({ error: 'clientId is required' });
    const result = typeof storage.dismissAlert === 'function'
      ? storage.dismissAlert(clientId)
      : false;
    res.json({ ok: true, clientId, dismissed: result });
  });

  // Settings GET
  router.get('/api/settings', (req, res) => {
    res.json(publicConfig(config));
  });

  // Settings POST
  router.post('/api/settings', (req, res) => {
    applyDashboardSettings(config, req.body || {});
    res.json(publicConfig(config));
  });

  // --- Main dashboard page ---
  router.get('/', (req, res) => {
    res.type('html').send(renderDashboard(config, req.baseUrl || config.dashboard.path || '/iri-shield'));
  });

  return router;
}

// =============================================================================
// Dashboard HTML
// =============================================================================

function renderDashboard(config, baseUrl) {
  const base = String(baseUrl || '/iri-shield').replace(/\/$/, '');
  const refreshMs = Number(config.dashboard?.refreshMs || 300000);

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>iri-shield — Security Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    body { font-family: 'Inter', system-ui, sans-serif; }
    .nav-item { transition: background 0.15s, color 0.15s; }
    .nav-item.active { background: #eff6ff; color: #1d4ed8; font-weight: 600; }
    .nav-item.active .nav-icon { color: #1d4ed8; }
    .badge { display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 9999px; font-size: 11px; font-weight: 600; letter-spacing: 0.03em; }
    .badge-critical { background: #fef2f2; color: #b91c1c; }
    .badge-high { background: #fff7ed; color: #c2410c; }
    .badge-medium { background: #fefce8; color: #a16207; }
    .badge-low { background: #f0fdf4; color: #15803d; }
    .badge-none { background: #f8fafc; color: #64748b; }
    .badge-blue { background: #eff6ff; color: #1d4ed8; }
    .animate-pulse-once { animation: pulse 0.4s ease-in-out; }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.6} }
    table tbody tr:hover { background: #f8fafc; }
    .sidebar { width: 240px; min-width: 240px; }
    .stat-card { transition: box-shadow 0.15s; }
    .stat-card:hover { box-shadow: 0 4px 16px rgba(0,0,0,0.08); }
  </style>
</head>
<body class="bg-gray-50 text-gray-900 min-h-screen">

<!-- Layout -->
<div class="flex min-h-screen">

  <!-- Sidebar -->
  <aside class="sidebar bg-white border-r border-gray-200 flex flex-col shrink-0">
    <!-- Brand -->
    <div class="px-5 py-5 border-b border-gray-100">
      <div class="flex items-center gap-2.5">
        <div class="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center shrink-0">
          <svg class="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <div>
          <p class="text-xs text-gray-400 font-medium uppercase tracking-wider">Security</p>
          <h1 class="text-base font-bold text-gray-900 leading-none mt-0.5">iri-shield</h1>
        </div>
      </div>
      <div class="mt-3">
        <span id="sidebarMode" class="badge badge-blue text-xs">Mode: ${escapeHtml(config.security || 'medium')}</span>
      </div>
    </div>

    <!-- Nav -->
    <nav class="flex-1 px-3 py-4 space-y-0.5">
      ${navItem('overview', 'Overview', iconOverview())}
      ${navItem('alerts', 'Alerts', iconAlerts(), 'alertBadge')}
      ${navItem('events', 'Events', iconEvents())}
      ${navItem('clients', 'Clients', iconClients())}
      ${navItem('blocked', 'Blocked IPs', iconBlocked(), 'blockedBadge')}
      ${navItem('settings', 'Settings', iconSettings())}
    </nav>

    <!-- Footer info -->
    <div class="px-4 py-4 border-t border-gray-100 space-y-2">
      <div class="flex items-center justify-between text-xs text-gray-400">
        <span>Auto-refresh</span>
        <span id="refreshLabel" class="font-semibold text-gray-600">${Math.round(refreshMs / 1000)}s</span>
      </div>
      <div class="text-xs text-gray-400" id="updatedAt">Loading…</div>
      <form method="post" action="${escapeHtml(base)}/logout">
        <button class="w-full mt-1 rounded-md border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-50 hover:border-gray-300 transition-colors" type="submit">
          Sign out
        </button>
      </form>
    </div>
  </aside>

  <!-- Main content -->
  <main class="flex-1 overflow-auto">

    <!-- Page header -->
    <div class="bg-white border-b border-gray-200 px-8 py-4 sticky top-0 z-10">
      <div class="flex items-center justify-between">
        <h2 class="text-lg font-semibold text-gray-900" id="pageTitle">Overview</h2>
        <div class="flex items-center gap-3">
          <span class="text-xs text-gray-400" id="appName">${escapeHtml(config.appName || 'iri-shield')}</span>
          <div class="w-px h-4 bg-gray-200"></div>
          <span class="text-xs text-gray-500" id="storageMode">Loading…</span>
        </div>
      </div>
    </div>

    <div class="px-8 py-6">

    <!-- ===== OVERVIEW PANEL ===== -->
    <section class="panel" id="panel-overview">
      <!-- Stat cards -->
      <div class="grid grid-cols-2 xl:grid-cols-4 gap-4">
        ${statCard('totalRequests', 'Total Requests', iconReq(), 'text-gray-900', 'bg-gray-50')}
        ${statCard('detectedThreats', 'Threats Detected', iconThreat(), 'text-amber-700', 'bg-amber-50')}
        ${statCard('blockedCombined', 'Blocked', iconBlock(), 'text-red-700', 'bg-red-50')}
        ${statCard('activeAlerts', 'Active Alerts', iconAlert(), 'text-blue-700', 'bg-blue-50')}
      </div>

      <!-- Charts row -->
      <div class="mt-6 grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div class="bg-white rounded-xl border border-gray-200 p-5">
          <div class="flex items-center justify-between mb-4">
            <h3 class="font-semibold text-gray-900">Threat Distribution</h3>
            <span class="text-xs text-gray-400" id="redactionsLabel">0 redactions</span>
          </div>
          <canvas id="threatChart" height="160"></canvas>
        </div>
        <div class="bg-white rounded-xl border border-gray-200 p-5">
          <h3 class="font-semibold text-gray-900 mb-4">Top Endpoints</h3>
          <div class="overflow-x-auto">
            <table class="w-full text-sm">
              <thead><tr class="text-xs text-gray-400 uppercase tracking-wide border-b border-gray-100">
                <th class="pb-2 text-left font-medium">Endpoint</th>
                <th class="pb-2 text-right font-medium">Hits</th>
                <th class="pb-2 text-right font-medium">Errors</th>
                <th class="pb-2 text-right font-medium">Avg Latency</th>
              </tr></thead>
              <tbody id="endpointRows" class="divide-y divide-gray-50">
                <tr><td class="py-3 text-gray-400 text-sm" colspan="4">Loading…</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Quick stats row -->
      <div class="mt-6 grid grid-cols-2 xl:grid-cols-4 gap-4">
        ${miniStat('avgLatency', 'Avg Latency', 'ms')}
        ${miniStat('anomalyEvents', 'Anomaly Events', '')}
        ${miniStat('totalRedactions', 'Redactions', '')}
        ${miniStat('blockedIpsCount', 'Blocked IPs', '')}
      </div>
    </section>

    <!-- ===== ALERTS PANEL ===== -->
    <section class="panel hidden" id="panel-alerts">
      <div class="flex items-center justify-between mb-5">
        <div>
          <h3 class="font-semibold text-gray-900">Active Alerts</h3>
          <p class="text-sm text-gray-500 mt-0.5">Clients with elevated risk scores not yet blocked</p>
        </div>
        <button onclick="loadAlerts()" class="btn-secondary text-sm">Refresh</button>
      </div>
      <div class="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <table class="w-full text-sm">
          <thead><tr class="text-xs text-gray-400 uppercase tracking-wide border-b border-gray-100 bg-gray-50">
            <th class="px-4 py-3 text-left font-medium">Client ID</th>
            <th class="px-4 py-3 text-left font-medium">Last IP</th>
            <th class="px-4 py-3 text-left font-medium">Risk</th>
            <th class="px-4 py-3 text-left font-medium">Score</th>
            <th class="px-4 py-3 text-left font-medium">Threats</th>
            <th class="px-4 py-3 text-left font-medium">Last Alert</th>
            <th class="px-4 py-3 text-left font-medium">Count</th>
            <th class="px-4 py-3 text-left font-medium">Actions</th>
          </tr></thead>
          <tbody id="alertRows" class="divide-y divide-gray-100">
            <tr><td class="px-4 py-4 text-gray-400" colspan="8">Loading…</td></tr>
          </tbody>
        </table>
      </div>
      <div class="mt-4" id="alertPagination"></div>
    </section>

    <!-- ===== EVENTS PANEL ===== -->
    <section class="panel hidden" id="panel-events">
      <div class="flex items-center gap-3 mb-5 flex-wrap">
        <h3 class="font-semibold text-gray-900 mr-auto">Security Events</h3>
        <select id="eventRiskFilter" onchange="loadEvents(1)" class="border border-gray-200 rounded-lg px-3 py-1.5 text-sm text-gray-600 bg-white focus:outline-none focus:ring-2 focus:ring-blue-500">
          <option value="">All Risks</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <button onclick="loadEvents(1)" class="btn-secondary text-sm">Refresh</button>
      </div>
      <div class="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <table class="w-full text-sm">
          <thead><tr class="text-xs text-gray-400 uppercase tracking-wide border-b border-gray-100 bg-gray-50">
            <th class="px-4 py-3 text-left font-medium">Time</th>
            <th class="px-4 py-3 text-left font-medium">IP</th>
            <th class="px-4 py-3 text-left font-medium">Endpoint</th>
            <th class="px-4 py-3 text-left font-medium">Threat</th>
            <th class="px-4 py-3 text-left font-medium">Risk</th>
            <th class="px-4 py-3 text-right font-medium">Score</th>
            <th class="px-4 py-3 text-left font-medium">Action</th>
          </tr></thead>
          <tbody id="eventRows" class="divide-y divide-gray-100">
            <tr><td class="px-4 py-4 text-gray-400" colspan="7">Loading…</td></tr>
          </tbody>
        </table>
      </div>
      <div class="mt-4" id="eventPagination"></div>
    </section>

    <!-- ===== CLIENTS PANEL ===== -->
    <section class="panel hidden" id="panel-clients">
      <div class="flex items-center justify-between mb-5">
        <div>
          <h3 class="font-semibold text-gray-900">Client Identity Monitoring</h3>
          <p class="text-sm text-gray-500 mt-0.5">Unique clients tracked by fingerprint, IP, and device</p>
        </div>
        <button onclick="loadClients(1)" class="btn-secondary text-sm">Refresh</button>
      </div>
      <div class="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <table class="w-full text-sm">
          <thead><tr class="text-xs text-gray-400 uppercase tracking-wide border-b border-gray-100 bg-gray-50">
            <th class="px-4 py-3 text-left font-medium">Client ID</th>
            <th class="px-4 py-3 text-left font-medium">User ID</th>
            <th class="px-4 py-3 text-left font-medium">Last IP</th>
            <th class="px-4 py-3 text-right font-medium">Requests</th>
            <th class="px-4 py-3 text-right font-medium">IPs Used</th>
            <th class="px-4 py-3 text-right font-medium">Changes</th>
            <th class="px-4 py-3 text-right font-medium">Fingerprints</th>
            <th class="px-4 py-3 text-left font-medium">Last Risk</th>
            <th class="px-4 py-3 text-left font-medium">Last Seen</th>
          </tr></thead>
          <tbody id="clientRows" class="divide-y divide-gray-100">
            <tr><td class="px-4 py-4 text-gray-400" colspan="9">Loading…</td></tr>
          </tbody>
        </table>
      </div>
      <div class="mt-4" id="clientPagination"></div>
    </section>

    <!-- ===== BLOCKED IPs PANEL ===== -->
    <section class="panel hidden" id="panel-blocked">
      <div class="flex items-center justify-between mb-5 flex-wrap gap-3">
        <div>
          <h3 class="font-semibold text-gray-900">Blocked IPs</h3>
          <p class="text-sm text-gray-500 mt-0.5">Manage blocked IP addresses</p>
        </div>
        <button onclick="showBlockModal()" class="btn-primary text-sm flex items-center gap-1.5">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>
          Block IP
        </button>
      </div>
      <div class="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <table class="w-full text-sm">
          <thead><tr class="text-xs text-gray-400 uppercase tracking-wide border-b border-gray-100 bg-gray-50">
            <th class="px-4 py-3 text-left font-medium">IP Address</th>
            <th class="px-4 py-3 text-left font-medium">Reason</th>
            <th class="px-4 py-3 text-right font-medium">Score</th>
            <th class="px-4 py-3 text-left font-medium">Type</th>
            <th class="px-4 py-3 text-left font-medium">Blocked At</th>
            <th class="px-4 py-3 text-left font-medium">Expires At</th>
            <th class="px-4 py-3 text-left font-medium">Action</th>
          </tr></thead>
          <tbody id="blockedRows" class="divide-y divide-gray-100">
            <tr><td class="px-4 py-4 text-gray-400" colspan="7">Loading…</td></tr>
          </tbody>
        </table>
      </div>
      <div class="mt-4" id="blockedPagination"></div>
    </section>

    <!-- ===== SETTINGS PANEL ===== -->
    <section class="panel hidden" id="panel-settings">
      <form id="settingsForm">
        <!-- Security Mode -->
        <div class="bg-white rounded-xl border border-gray-200 p-5 mb-5">
          <h3 class="font-semibold text-gray-900 mb-4">Security Mode</h3>
          <div class="grid grid-cols-3 gap-3">
            ${modeCard('low', 'Low', 'Relaxed protection. 300 req/min, block at score 90.', config.security === 'low')}
            ${modeCard('medium', 'Medium', 'Balanced protection. 120 req/min, block at score 80.', (config.security || 'medium') === 'medium')}
            ${modeCard('high', 'High', 'Strict protection. 30 req/min, block at score 60.', config.security === 'high')}
          </div>
        </div>

        <!-- Rate Limiting -->
        <div class="bg-white rounded-xl border border-gray-200 p-5 mb-5">
          <h3 class="font-semibold text-gray-900 mb-4">Rate Limiting</h3>
          <div class="grid grid-cols-2 xl:grid-cols-3 gap-4">
            ${numInput('Max requests', 'rateLimit.max', config.rateLimit.max)}
            ${numInput('Window (ms)', 'rateLimit.windowMs', config.rateLimit.windowMs)}
            ${checkInput('Enable rate limiting', 'rateLimit.enabled', config.rateLimit.enabled)}
          </div>
        </div>

        <!-- Block Settings -->
        <div class="bg-white rounded-xl border border-gray-200 p-5 mb-5">
          <h3 class="font-semibold text-gray-900 mb-4">Block Settings</h3>
          <div class="grid grid-cols-2 xl:grid-cols-3 gap-4">
            ${numInput('Block threshold (score)', 'block.threshold', config.block.threshold)}
            ${numInput('Block duration (ms)', 'block.durationMs', config.block.durationMs)}
            ${checkInput('Enable auto-block', 'block.enabled', config.block.enabled)}
          </div>
        </div>

        <!-- Anomaly Thresholds -->
        <div class="bg-white rounded-xl border border-gray-200 p-5 mb-5">
          <h3 class="font-semibold text-gray-900 mb-4">Anomaly Thresholds</h3>
          <div class="grid grid-cols-2 xl:grid-cols-3 gap-4">
            ${numInput('Medium threshold', 'anomaly.mediumThreshold', config.anomaly.mediumThreshold)}
            ${numInput('High threshold', 'anomaly.highThreshold', config.anomaly.highThreshold)}
            ${numInput('Critical threshold', 'anomaly.criticalThreshold', config.anomaly.criticalThreshold)}
            ${numInput('Single endpoint max hits', 'anomaly.singleEndpointMax', config.anomaly.singleEndpointMax)}
            ${numInput('Failed auth max', 'anomaly.failedAuthMax', config.anomaly.failedAuthMax)}
            ${numInput('Alert threshold (score)', 'alert.threshold', config.alert?.threshold || 35)}
          </div>
        </div>

        <!-- Other Settings -->
        <div class="bg-white rounded-xl border border-gray-200 p-5 mb-5">
          <h3 class="font-semibold text-gray-900 mb-4">System</h3>
          <div class="grid grid-cols-2 xl:grid-cols-3 gap-4">
            ${numInput('Dashboard refresh (ms)', 'dashboard.refreshMs', config.dashboard?.refreshMs || 300000)}
            ${checkInput('Enable redaction', 'redaction.enabled', config.redaction.enabled)}
            ${checkInput('Testing mode', 'testing.enabled', config.testing?.enabled || false)}
            ${checkInput('Client overrides (testing)', 'testing.allowClientOverrides', config.testing?.allowClientOverrides || false)}
            ${checkInput('Helmet enabled', 'helmet.enabled', config.helmet?.enabled !== false)}
          </div>
          <div class="mt-4">
            <label class="block text-sm font-medium text-gray-700 mb-1.5">Redaction fields</label>
            <textarea class="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none" rows="2" name="redaction.fields">${escapeHtml((config.redaction?.fields || []).join(', '))}</textarea>
          </div>
        </div>

        <div class="flex items-center gap-4">
          <button class="btn-primary" type="submit">Save Settings</button>
          <span class="text-sm text-green-600 font-medium" id="settingsMsg"></span>
        </div>
      </form>
    </section>

    </div><!-- /px-8 py-6 -->
  </main>
</div>

<!-- Block IP Modal -->
<div id="blockModal" class="fixed inset-0 bg-black/40 z-50 hidden flex items-center justify-center p-4">
  <div class="bg-white rounded-2xl shadow-xl w-full max-w-md p-6">
    <h3 class="text-lg font-semibold text-gray-900 mb-4">Block IP Address</h3>
    <div class="space-y-3">
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-1">IP Address</label>
        <input id="blockIpInput" type="text" placeholder="e.g. 203.0.113.77" class="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
      </div>
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-1">Reason</label>
        <input id="blockReasonInput" type="text" placeholder="manual_block" class="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
      </div>
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-1">Duration</label>
        <select id="blockDurationInput" class="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
          <option value="3600000">1 hour</option>
          <option value="21600000">6 hours</option>
          <option value="86400000">24 hours</option>
          <option value="604800000">7 days</option>
          <option value="0">Permanent</option>
        </select>
      </div>
    </div>
    <div class="mt-5 flex gap-3">
      <button onclick="submitBlock()" class="btn-danger flex-1">Block IP</button>
      <button onclick="hideBlockModal()" class="btn-secondary flex-1">Cancel</button>
    </div>
  </div>
</div>

<style>
  .btn-primary { background: #2563eb; color: #fff; border-radius: 8px; padding: 7px 16px; font-size: 14px; font-weight: 500; border: none; cursor: pointer; transition: background 0.15s; }
  .btn-primary:hover { background: #1d4ed8; }
  .btn-secondary { background: #fff; color: #374151; border-radius: 8px; padding: 7px 16px; font-size: 14px; font-weight: 500; border: 1px solid #e5e7eb; cursor: pointer; transition: background 0.15s; }
  .btn-secondary:hover { background: #f9fafb; }
  .btn-danger { background: #dc2626; color: #fff; border-radius: 8px; padding: 7px 16px; font-size: 14px; font-weight: 500; border: none; cursor: pointer; transition: background 0.15s; }
  .btn-danger:hover { background: #b91c1c; }
  .btn-unblock { background: #fff; color: #059669; border: 1px solid #d1fae5; border-radius: 6px; padding: 3px 10px; font-size: 12px; font-weight: 500; cursor: pointer; transition: all 0.15s; }
  .btn-unblock:hover { background: #ecfdf5; border-color: #6ee7b7; }
  .btn-dismiss { background: #fff; color: #9ca3af; border: 1px solid #e5e7eb; border-radius: 6px; padding: 3px 10px; font-size: 12px; font-weight: 500; cursor: pointer; }
  .btn-dismiss:hover { background: #f9fafb; }
  .btn-block-small { background: #fff; color: #dc2626; border: 1px solid #fecaca; border-radius: 6px; padding: 3px 10px; font-size: 12px; font-weight: 500; cursor: pointer; }
  .btn-block-small:hover { background: #fef2f2; }
  .pagination { display: flex; gap: 6px; align-items: center; }
  .page-btn { background: #fff; border: 1px solid #e5e7eb; border-radius: 6px; padding: 4px 10px; font-size: 12px; cursor: pointer; transition: all 0.15s; }
  .page-btn:hover, .page-btn.active { background: #2563eb; color: #fff; border-color: #2563eb; }
  .mode-card { border: 2px solid #e5e7eb; border-radius: 12px; padding: 16px; cursor: pointer; transition: all 0.15s; }
  .mode-card.selected { border-color: #2563eb; background: #eff6ff; }
  .mode-card:hover:not(.selected) { border-color: #93c5fd; background: #f8fafc; }
</style>

<script>
const BASE = '${escapeJsString(base)}';
const fmt = new Intl.NumberFormat();
let refreshMs = ${refreshMs};
let timer;
let chart;
let currentPage = { events: 1, clients: 1, blocked: 1, alerts: 1 };

// -------------------------------------------------------------------------
// Navigation
// -------------------------------------------------------------------------

const PAGE_TITLES = { overview:'Overview', alerts:'Alerts', events:'Security Events', clients:'Clients', blocked:'Blocked IPs', settings:'Settings' };

function showPanel(id) {
  document.querySelectorAll('.panel').forEach(p => p.classList.add('hidden'));
  const panel = document.getElementById('panel-' + id);
  if (panel) panel.classList.remove('hidden');
  document.querySelectorAll('.nav-item').forEach(b => {
    b.classList.toggle('active', b.dataset.panel === id);
  });
  document.getElementById('pageTitle').textContent = PAGE_TITLES[id] || id;

  // Lazy load panel data
  if (id === 'events') loadEvents(1);
  if (id === 'clients') loadClients(1);
  if (id === 'blocked') loadBlocked(1);
  if (id === 'alerts') loadAlerts(1);
}

document.querySelectorAll('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => showPanel(btn.dataset.panel));
});

// -------------------------------------------------------------------------
// Stats (overview)
// -------------------------------------------------------------------------

async function loadStats() {
  try {
    const res = await fetch(BASE + '/api/stats');
    const data = await res.json();

    refreshMs = Number(data.config?.dashboard?.refreshMs || refreshMs);
    document.getElementById('refreshLabel').textContent = Math.round(refreshMs / 1000) + 's';
    document.getElementById('updatedAt').textContent = 'Updated ' + new Date().toLocaleTimeString();
    document.getElementById('storageMode').textContent = data.storageMode || 'memory';
    if (data.config?.security) {
      document.getElementById('sidebarMode').textContent = 'Mode: ' + data.config.security;
    }

    // Stat cards
    setText('totalRequests', fmt.format(data.totalRequests || 0));
    setText('detectedThreats', fmt.format(data.detectedThreats || 0));
    setText('blockedCombined', fmt.format(data.blockedRequests || 0) + ' req / ' + fmt.format((data.blockedIps || []).length) + ' IPs');
    setText('activeAlerts', fmt.format(data.activeAlerts || 0));

    // Mini stats
    setText('avgLatency', (data.averageLatencyMs || 0) + ' ms');
    setText('anomalyEvents', fmt.format(data.anomalyEvents || 0));
    setText('totalRedactions', fmt.format(data.redactions || 0));
    setText('blockedIpsCount', fmt.format((data.blockedIps || []).length));

    document.getElementById('redactionsLabel').textContent = fmt.format(data.redactions || 0) + ' redactions';

    // Badges
    const alertBadge = document.getElementById('alertBadge');
    if (alertBadge && data.activeAlerts > 0) {
      alertBadge.textContent = data.activeAlerts;
      alertBadge.classList.remove('hidden');
    } else if (alertBadge) {
      alertBadge.classList.add('hidden');
    }

    const blockedBadge = document.getElementById('blockedBadge');
    const bCount = (data.blockedIps || []).length;
    if (blockedBadge && bCount > 0) {
      blockedBadge.textContent = bCount;
      blockedBadge.classList.remove('hidden');
    } else if (blockedBadge) {
      blockedBadge.classList.add('hidden');
    }

    // Endpoints
    renderEndpoints(data.endpoints || []);
    // Chart
    renderChart(data.threatDistribution || []);
  } catch(e) { console.error('Stats error', e); }
  schedule();
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

// -------------------------------------------------------------------------
// Endpoints
// -------------------------------------------------------------------------

function renderEndpoints(rows) {
  const tbody = document.getElementById('endpointRows');
  if (!tbody) return;
  if (!rows.length) { tbody.innerHTML = '<tr><td class="py-3 text-gray-400 text-sm" colspan="4">No traffic yet</td></tr>'; return; }
  tbody.innerHTML = rows.map(r => \`<tr class="border-t border-gray-50 hover:bg-gray-50">
    <td class="py-2 pr-3 text-gray-700 text-xs font-mono">\${clean(r.method + ' ' + r.endpoint)}</td>
    <td class="py-2 pr-3 text-right text-gray-900">\${fmt.format(r.count)}</td>
    <td class="py-2 pr-3 text-right \${r.errors > 0 ? 'text-red-600' : 'text-gray-500'}">\${r.errors}</td>
    <td class="py-2 text-right text-gray-500">\${Number(r.avgLatencyMs||0).toFixed(1)} ms</td>
  </tr>\`).join('');
}

// -------------------------------------------------------------------------
// Events
// -------------------------------------------------------------------------

async function loadEvents(page) {
  currentPage.events = page || currentPage.events;
  const risk = document.getElementById('eventRiskFilter')?.value || '';
  try {
    const url = BASE + '/api/events?page=' + currentPage.events + '&perPage=20' + (risk ? '&riskLevel=' + risk : '');
    const res = await fetch(url);
    const data = await res.json();
    const tbody = document.getElementById('eventRows');
    if (!data.data?.length) {
      tbody.innerHTML = '<tr><td class="px-4 py-4 text-gray-400" colspan="7">No security events yet</td></tr>';
    } else {
      tbody.innerHTML = data.data.map(r => \`<tr>
        <td class="px-4 py-2.5 text-gray-400 text-xs whitespace-nowrap">\${clean(new Date(r.timestamp).toLocaleString())}</td>
        <td class="px-4 py-2.5 text-gray-700 font-mono text-xs">\${clean(r.ip)}</td>
        <td class="px-4 py-2.5 text-gray-600 text-xs">\${clean(r.method + ' ' + r.endpoint)}</td>
        <td class="px-4 py-2.5 text-amber-700 text-xs max-w-[180px] truncate">\${clean(r.threat)}</td>
        <td class="px-4 py-2.5"><span class="badge badge-\${r.riskLevel}">\${clean(r.riskLevel)}</span></td>
        <td class="px-4 py-2.5 text-right font-semibold text-gray-900">\${r.riskScore}</td>
        <td class="px-4 py-2.5 text-gray-500 text-xs">\${clean(r.action)}</td>
      </tr>\`).join('');
    }
    renderPagination('eventPagination', data, loadEvents);
  } catch(e) { console.error('Events error', e); }
}

// -------------------------------------------------------------------------
// Clients
// -------------------------------------------------------------------------

async function loadClients(page) {
  currentPage.clients = page || currentPage.clients;
  try {
    const res = await fetch(BASE + '/api/clients?page=' + currentPage.clients + '&perPage=20');
    const data = await res.json();
    const tbody = document.getElementById('clientRows');
    if (!data.data?.length) {
      tbody.innerHTML = '<tr><td class="px-4 py-4 text-gray-400" colspan="9">No clients yet</td></tr>';
    } else {
      tbody.innerHTML = data.data.map(r => \`<tr>
        <td class="px-4 py-2.5 font-mono text-xs text-gray-600 max-w-[130px] truncate" title="\${clean(r.clientId)}">\${clean(r.clientId)}</td>
        <td class="px-4 py-2.5 text-xs text-gray-600 max-w-[100px] truncate">\${clean(r.userId || '-')}</td>
        <td class="px-4 py-2.5 font-mono text-xs">\${clean(r.lastIp || '-')}</td>
        <td class="px-4 py-2.5 text-right text-gray-900">\${fmt.format(r.requestCount)}</td>
        <td class="px-4 py-2.5 text-right text-gray-500">\${(r.ips||[]).length}</td>
        <td class="px-4 py-2.5 text-right \${r.changes > 3 ? 'text-amber-600 font-semibold' : 'text-gray-500'}">\${r.changes}</td>
        <td class="px-4 py-2.5 text-right text-gray-500">\${(r.fingerprints||[]).length}</td>
        <td class="px-4 py-2.5"><span class="badge badge-\${r.lastRisk || 'none'}">\${clean(r.lastRisk||'none')}</span></td>
        <td class="px-4 py-2.5 text-xs text-gray-400 whitespace-nowrap">\${r.lastSeenAt ? clean(new Date(r.lastSeenAt).toLocaleTimeString()) : '-'}</td>
      </tr>\`).join('');
    }
    renderPagination('clientPagination', data, loadClients);
  } catch(e) { console.error('Clients error', e); }
}

// -------------------------------------------------------------------------
// Blocked IPs
// -------------------------------------------------------------------------

async function loadBlocked(page) {
  currentPage.blocked = page || currentPage.blocked;
  try {
    const res = await fetch(BASE + '/api/blocked?page=' + currentPage.blocked + '&perPage=20');
    const data = await res.json();
    const tbody = document.getElementById('blockedRows');
    if (!data.data?.length) {
      tbody.innerHTML = '<tr><td class="px-4 py-4 text-gray-400" colspan="7">No blocked IPs</td></tr>';
    } else {
      tbody.innerHTML = data.data.map(r => \`<tr>
        <td class="px-4 py-2.5 font-mono text-sm text-gray-900">\${clean(r.ip)}</td>
        <td class="px-4 py-2.5 text-xs text-gray-500 max-w-[180px] truncate">\${clean(r.reason || '-')}</td>
        <td class="px-4 py-2.5 text-right font-semibold \${(r.score||0) >= 80 ? 'text-red-600' : 'text-amber-600'}">\${r.score||0}</td>
        <td class="px-4 py-2.5"><span class="badge \${r.manual ? 'badge-blue' : 'badge-high'}">\${r.manual ? 'Manual' : 'Auto'}</span></td>
        <td class="px-4 py-2.5 text-xs text-gray-400">\${r.blockedAt ? clean(new Date(r.blockedAt).toLocaleString()) : '-'}</td>
        <td class="px-4 py-2.5 text-xs text-gray-400">\${r.expiresAt ? clean(new Date(r.expiresAt).toLocaleString()) : 'Permanent'}</td>
        <td class="px-4 py-2.5">
          <button class="btn-unblock" onclick="doUnblock('\${clean(r.ip)}')">Unblock</button>
        </td>
      </tr>\`).join('');
    }
    renderPagination('blockedPagination', data, loadBlocked);
  } catch(e) { console.error('Blocked error', e); }
}

async function doUnblock(ip) {
  if (!confirm('Unblock ' + ip + '?')) return;
  try {
    await fetch(BASE + '/api/unblock', { method: 'POST', headers: {'content-type':'application/json'}, body: JSON.stringify({ ip }) });
    loadBlocked(currentPage.blocked);
    loadStats();
  } catch(e) { console.error('Unblock error', e); }
}

// -------------------------------------------------------------------------
// Alerts
// -------------------------------------------------------------------------

async function loadAlerts(page) {
  currentPage.alerts = page || currentPage.alerts;
  try {
    const res = await fetch(BASE + '/api/alerts?page=' + currentPage.alerts + '&perPage=20');
    const data = await res.json();
    const tbody = document.getElementById('alertRows');
    if (!data.data?.length) {
      tbody.innerHTML = '<tr><td class="px-4 py-4 text-gray-400" colspan="8">No active alerts</td></tr>';
    } else {
      tbody.innerHTML = data.data.map(r => \`<tr>
        <td class="px-4 py-2.5 font-mono text-xs text-gray-600 max-w-[130px] truncate" title="\${clean(r.clientId)}">\${clean(r.clientId)}</td>
        <td class="px-4 py-2.5 font-mono text-xs">\${clean(r.lastIp || '-')}</td>
        <td class="px-4 py-2.5"><span class="badge badge-\${r.lastRisk||'medium'}">\${clean(r.lastRisk||'medium')}</span></td>
        <td class="px-4 py-2.5 font-semibold text-amber-700">\${r.lastScore||0}</td>
        <td class="px-4 py-2.5 text-xs text-gray-500 max-w-[200px] truncate">\${clean((r.threats||[]).join(', '))}</td>
        <td class="px-4 py-2.5 text-xs text-gray-400">\${r.lastAlertAt ? clean(new Date(r.lastAlertAt).toLocaleString()) : '-'}</td>
        <td class="px-4 py-2.5 text-gray-500">\${r.count||1}</td>
        <td class="px-4 py-2.5 flex gap-1.5">
          <button class="btn-block-small" onclick="doBlockFromAlert('\${clean(r.lastIp||'')}')">Block IP</button>
          <button class="btn-dismiss" onclick="doDismiss('\${clean(r.clientId)}')">Dismiss</button>
        </td>
      </tr>\`).join('');
    }
    renderPagination('alertPagination', data, loadAlerts);
  } catch(e) { console.error('Alerts error', e); }
}

async function doDismiss(clientId) {
  try {
    await fetch(BASE + '/api/alerts/' + encodeURIComponent(clientId) + '/dismiss', { method: 'POST' });
    loadAlerts(currentPage.alerts);
    loadStats();
  } catch(e) { console.error('Dismiss error', e); }
}

async function doBlockFromAlert(ip) {
  if (!ip || !confirm('Block IP ' + ip + ' for 1 hour?')) return;
  try {
    await fetch(BASE + '/api/block', { method: 'POST', headers: {'content-type':'application/json'}, body: JSON.stringify({ ip, reason: 'blocked_from_alert', durationMs: 3600000 }) });
    loadBlocked(1);
    loadStats();
  } catch(e) { console.error('Block from alert error', e); }
}

// -------------------------------------------------------------------------
// Block modal
// -------------------------------------------------------------------------

function showBlockModal() { document.getElementById('blockModal').classList.remove('hidden'); }
function hideBlockModal() { document.getElementById('blockModal').classList.add('hidden'); }

async function submitBlock() {
  const ip = document.getElementById('blockIpInput').value.trim();
  const reason = document.getElementById('blockReasonInput').value.trim() || 'manual_block';
  const durationMs = Number(document.getElementById('blockDurationInput').value) || 3600000;
  if (!ip) { alert('IP is required'); return; }
  try {
    await fetch(BASE + '/api/block', { method: 'POST', headers: {'content-type':'application/json'}, body: JSON.stringify({ ip, reason, durationMs }) });
    hideBlockModal();
    loadBlocked(1);
    loadStats();
  } catch(e) { console.error('Block error', e); }
}

// -------------------------------------------------------------------------
// Settings
// -------------------------------------------------------------------------

document.getElementById('settingsForm').addEventListener('submit', async function(e) {
  e.preventDefault();
  const fd = new FormData(e.target);
  const payload = {};
  for (const [key, value] of fd.entries()) setDeep(payload, key, value);
  // Handle unchecked checkboxes
  ['rateLimit.enabled','block.enabled','redaction.enabled','testing.enabled','testing.allowClientOverrides','helmet.enabled'].forEach(key => {
    if (!fd.has(key)) setDeep(payload, key, false);
  });
  // Handle security mode radio
  const modeEl = document.querySelector('input[name="security"]:checked');
  if (modeEl) payload.security = modeEl.value;

  try {
    const res = await fetch(BASE + '/api/settings', { method: 'POST', headers: {'content-type':'application/json'}, body: JSON.stringify(payload) });
    await res.json();
    const msg = document.getElementById('settingsMsg');
    msg.textContent = '✓ Settings saved';
    setTimeout(() => { msg.textContent = ''; }, 3000);
    loadStats();
  } catch(e) { console.error('Settings error', e); }
});

// -------------------------------------------------------------------------
// Chart
// -------------------------------------------------------------------------

function renderChart(rows) {
  const labels = rows.map(r => r.name);
  const values = rows.map(r => r.count);
  const colors = rows.map((_, i) => ['#3b82f6','#f59e0b','#ef4444','#10b981','#8b5cf6','#06b6d4','#f97316'][i % 7]);
  if (!chart) {
    chart = new Chart(document.getElementById('threatChart'), {
      type: 'bar',
      data: { labels, datasets: [{ label: 'Events', data: values, backgroundColor: colors, borderRadius: 4 }] },
      options: {
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#9ca3af', font: { size: 11 } }, grid: { color: '#f3f4f6' } },
          y: { ticks: { color: '#9ca3af', font: { size: 11 } }, grid: { color: '#f3f4f6' } }
        }
      }
    });
  } else {
    chart.data.labels = labels;
    chart.data.datasets[0].data = values;
    chart.data.datasets[0].backgroundColor = colors;
    chart.update('none');
  }
}

// -------------------------------------------------------------------------
// Pagination
// -------------------------------------------------------------------------

function renderPagination(containerId, pageData, loadFn) {
  const container = document.getElementById(containerId);
  if (!container || pageData.totalPages <= 1) { if (container) container.innerHTML = ''; return; }
  const { page, totalPages, total, perPage } = pageData;
  const start = (page - 1) * perPage + 1;
  const end = Math.min(page * perPage, total);
  let html = \`<div class="flex items-center gap-3 flex-wrap"><span class="text-sm text-gray-400">Showing \${start}-\${end} of \${fmt.format(total)}</span><div class="pagination">\`;
  if (page > 1) html += \`<button class="page-btn" onclick="(\${loadFn.name})(1)">«</button><button class="page-btn" onclick="(\${loadFn.name})(\${page - 1})">‹</button>\`;
  const start_p = Math.max(1, page - 2);
  const end_p = Math.min(totalPages, page + 2);
  for (let p = start_p; p <= end_p; p++) {
    html += \`<button class="page-btn \${p === page ? 'active' : ''}" onclick="(\${loadFn.name})(\${p})">\${p}</button>\`;
  }
  if (page < totalPages) html += \`<button class="page-btn" onclick="(\${loadFn.name})(\${page + 1})">›</button><button class="page-btn" onclick="(\${loadFn.name})(\${totalPages})">»</button>\`;
  html += '</div></div>';
  container.innerHTML = html;
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

function schedule() {
  clearTimeout(timer);
  timer = setTimeout(loadStats, Math.max(5000, refreshMs));
}

function clean(v) {
  return String(v || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
}

function setDeep(target, path, value) {
  const parts = path.split('.');
  let cur = target;
  while (parts.length > 1) { const p = parts.shift(); cur[p] = cur[p] || {}; cur = cur[p]; }
  cur[parts[0]] = value;
}

// -------------------------------------------------------------------------
// Init
// -------------------------------------------------------------------------

showPanel('overview');
loadStats();
</script>

</body>
</html>`;
}

// =============================================================================
// Login page
// =============================================================================

function renderLogin(config, failed) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>iri-shield — Login</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-gray-50 text-gray-900">
  <main class="flex min-h-screen items-center justify-center px-4">
    <div class="w-full max-w-sm">
      <div class="text-center mb-8">
        <div class="inline-flex w-12 h-12 rounded-xl bg-blue-600 items-center justify-center mb-3">
          <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <h1 class="text-2xl font-bold text-gray-900">iri-shield</h1>
        <p class="text-sm text-gray-500 mt-1">Security Dashboard</p>
      </div>
      <form method="post" action="${escapeHtml(config.dashboard?.path || '/iri-shield')}/login" class="bg-white rounded-2xl border border-gray-200 shadow-sm p-6">
        ${failed ? '<div class="mb-4 rounded-lg bg-red-50 border border-red-200 px-3 py-2 text-sm text-red-700">Invalid username or password.</div>' : ''}
        <label class="block text-sm font-medium text-gray-700 mb-1" for="username">Username</label>
        <input class="w-full rounded-lg border border-gray-200 px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 mb-4" id="username" name="username" autocomplete="username" required />
        <label class="block text-sm font-medium text-gray-700 mb-1" for="password">Password</label>
        <input class="w-full rounded-lg border border-gray-200 px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 mb-5" id="password" name="password" type="password" autocomplete="current-password" required />
        <button class="w-full rounded-lg bg-blue-600 px-4 py-2.5 font-semibold text-white hover:bg-blue-700 transition-colors" type="submit">Sign in</button>
      </form>
      <p class="text-center text-xs text-gray-400 mt-4">${escapeHtml(config.appName || 'iri-shield')} Security Platform</p>
    </div>
  </main>
</body>
</html>`;
}

// =============================================================================
// HTML helpers
// =============================================================================

function navItem(panel, label, icon, badgeId = null) {
  const badge = badgeId
    ? `<span id="${badgeId}" class="ml-auto text-xs font-semibold bg-red-100 text-red-600 rounded-full px-1.5 py-0.5 hidden"></span>`
    : '';
  return `<button class="nav-item w-full flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium text-gray-600 hover:bg-gray-50 hover:text-gray-900" data-panel="${panel}">
    <span class="nav-icon w-4 h-4 shrink-0 text-gray-400">${icon}</span>
    <span>${label}</span>
    ${badge}
  </button>`;
}

function statCard(id, label, icon, colorClass, bgClass) {
  return `<div class="stat-card bg-white rounded-xl border border-gray-200 p-5">
    <div class="flex items-start justify-between">
      <div>
        <p class="text-xs font-medium text-gray-500 uppercase tracking-wide">${label}</p>
        <p class="mt-2 text-2xl font-bold ${colorClass}" id="${id}">—</p>
      </div>
      <div class="w-9 h-9 ${bgClass} rounded-lg flex items-center justify-center shrink-0">${icon}</div>
    </div>
  </div>`;
}

function miniStat(id, label, suffix) {
  return `<div class="bg-white rounded-xl border border-gray-200 px-4 py-3 flex items-center justify-between">
    <span class="text-sm text-gray-500">${label}</span>
    <span class="text-sm font-semibold text-gray-900" id="${id}">—</span>
  </div>`;
}

function modeCard(value, title, desc, selected) {
  return `<label class="mode-card${selected ? ' selected' : ''} block cursor-pointer">
    <input type="radio" name="security" value="${value}" class="sr-only" ${selected ? 'checked' : ''} />
    <p class="font-semibold text-gray-900 text-sm">${title}</p>
    <p class="text-xs text-gray-500 mt-1">${desc}</p>
  </label>`;
}

function numInput(label, name, value) {
  return `<label class="block">
    <span class="text-sm font-medium text-gray-700">${label}</span>
    <input class="mt-1 w-full rounded-lg border border-gray-200 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" type="number" name="${name}" value="${escapeHtml(String(value ?? ''))}" />
  </label>`;
}

function checkInput(label, name, checked) {
  return `<label class="flex items-center gap-3 rounded-lg border border-gray-200 px-3 py-2.5 cursor-pointer hover:bg-gray-50">
    <input class="w-4 h-4 rounded accent-blue-600" type="checkbox" name="${name}" ${checked ? 'checked' : ''} />
    <span class="text-sm font-medium text-gray-700">${label}</span>
  </label>`;
}

// --- SVG Icons ---
function iconOverview() { return '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" class="w-4 h-4"><rect x="3" y="3" width="7" height="7" rx="1" stroke-width="2"/><rect x="14" y="3" width="7" height="7" rx="1" stroke-width="2"/><rect x="3" y="14" width="7" height="7" rx="1" stroke-width="2"/><rect x="14" y="14" width="7" height="7" rx="1" stroke-width="2"/></svg>'; }
function iconAlerts()   { return '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>'; }
function iconEvents()   { return '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>'; }
function iconClients()  { return '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/></svg>'; }
function iconBlocked()  { return '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" class="w-4 h-4"><circle cx="12" cy="12" r="10" stroke-width="2"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07" stroke-width="2" stroke-linecap="round"/></svg>'; }
function iconSettings() { return '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><circle cx="12" cy="12" r="3" stroke-width="2"/></svg>'; }
function iconReq()     { return '<svg class="w-5 h-5 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>'; }
function iconThreat()  { return '<svg class="w-5 h-5 text-amber-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>'; }
function iconBlock()   { return '<svg class="w-5 h-5 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" stroke-width="2"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07" stroke-width="2" stroke-linecap="round"/></svg>'; }
function iconAlert()   { return '<svg class="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/></svg>'; }

// =============================================================================
// Auth & settings helpers
// =============================================================================

function dashboardAuth(options = {}) {
  const username = options.username || 'admin';
  const password = options.password || 'admin';
  const token = randomBytes(32).toString('hex');
  return {
    token,
    canLogin(inputUser, inputPass) {
      return safeEqual(inputUser || '', username) && safeEqual(inputPass || '', password);
    },
    isAuthenticated(req) {
      return parseCookies(req.headers.cookie).iri_shield_session === token;
    }
  };
}

function applyDashboardSettings(config, body) {
  const numberFields = [
    ['rateLimit.max', 1, 100000],
    ['rateLimit.windowMs', 1000, 86400000],
    ['block.threshold', 1, 100],
    ['block.durationMs', 1000, 86400000 * 7],
    ['anomaly.mediumThreshold', 1, 100],
    ['anomaly.highThreshold', 1, 100],
    ['anomaly.criticalThreshold', 1, 100],
    ['anomaly.singleEndpointMax', 1, 100000],
    ['anomaly.failedAuthMax', 1, 100000],
    ['alert.threshold', 1, 100],
    ['dashboard.refreshMs', 5000, 3600000]
  ];
  for (const [path, min, max] of numberFields) {
    const value = getPath(body, path);
    if (value !== undefined && value !== '') setPath(config, path, clamp(Number(value), min, max));
  }

  const booleanFields = [
    'rateLimit.enabled', 'block.enabled', 'redaction.enabled',
    'testing.enabled', 'testing.allowClientOverrides',
    'helmet.enabled', 'helmet.contentSecurityPolicy', 'alert.enabled'
  ];
  for (const path of booleanFields) {
    const value = getPath(body, path);
    if (value !== undefined) setPath(config, path, value === true || value === 'true' || value === 'on');
  }

  if (body.security && ['low', 'medium', 'high'].includes(body.security)) {
    config.security = body.security;
  }

  if (typeof body['redaction.fields'] === 'string') {
    config.redaction.fields = body['redaction.fields'].split(',').map(f => f.trim()).filter(Boolean);
  }
  if (body.redaction?.fields && typeof body.redaction.fields === 'string') {
    config.redaction.fields = body.redaction.fields.split(',').map(f => f.trim()).filter(Boolean);
  }
}

function publicConfig(config) {
  const copy = JSON.parse(JSON.stringify(config));
  if (copy.dashboard?.password) copy.dashboard.password = '';
  return copy;
}

function paginateArray(array, page, perPage) {
  const total = array.length;
  const totalPages = Math.ceil(total / perPage) || 1;
  const safePage = Math.max(1, Math.min(page, totalPages));
  const start = (safePage - 1) * perPage;
  return { data: array.slice(start, start + perPage), total, page: safePage, perPage, totalPages };
}

function safeEqual(left, right) {
  const lb = Buffer.from(String(left));
  const rb = Buffer.from(String(right));
  if (lb.length !== rb.length) return false;
  return timingSafeEqual(lb, rb);
}

function parseCookies(cookieHeader = '') {
  return String(cookieHeader)
    .split(';')
    .reduce((cookies, pair) => {
      const [rawKey, ...rawValue] = pair.trim().split('=');
      if (!rawKey) return cookies;
      cookies[decodeURIComponent(rawKey)] = decodeURIComponent(rawValue.join('='));
      return cookies;
    }, {});
}

function getPath(object, path) {
  return path.split('.').reduce((cur, key) => cur?.[key], object);
}

function setPath(object, path, value) {
  const parts = path.split('.');
  let cur = object;
  while (parts.length > 1) { const k = parts.shift(); cur[k] = cur[k] || {}; cur = cur[k]; }
  cur[parts[0]] = value;
}

function clamp(value, min, max) {
  if (!Number.isFinite(value)) return min;
  return Math.max(min, Math.min(max, value));
}

function escapeHtml(value) {
  return String(value || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[c]));
}

function escapeJsString(value) {
  return String(value || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

module.exports = { createDashboardRouter };
