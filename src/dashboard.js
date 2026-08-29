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
      const events = (storage.events || []).filter((e) => !riskLevel || e.riskLevel === riskLevel);
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
      const clients = Array.from((storage.clients || new Map()).values()).sort(
        (a, b) => b.requestCount - a.requestCount
      );
      res.json(paginateArray(clients, page, perPage));
    }
  });

  // Paginated blocked IPs with status filter
  router.get('/api/blocked', (req, res) => {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const perPage = Math.min(100, Math.max(5, parseInt(req.query.perPage) || 20));
    const status = req.query.status || 'all';
    if (typeof storage.getBlockedIps === 'function') {
      res.json(storage.getBlockedIps({ page, perPage, status }));
    } else {
      res.json(storage.getBlockedIps({ page, perPage, status }));
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

  // Unblock / Delete Block for an IP
  router.post('/api/unblock', (req, res) => {
    const { ip } = req.body || {};
    if (!ip) return res.status(400).json({ error: 'IP is required' });
    if (typeof storage.unblockIp === 'function') storage.unblockIp(ip);
    res.json({ ok: true, ip });
  });

  // Manual block / Re-block IP
  router.post('/api/block', (req, res) => {
    const { ip, reason, durationMs } = req.body || {};
    if (!ip) return res.status(400).json({ error: 'IP is required' });
    const duration = durationMs !== undefined ? Number(durationMs) : 24 * 60 * 60 * 1000;
    if (typeof storage.manualBlockIp === 'function') {
      storage.manualBlockIp(ip, { reason: reason || 'manual_block', durationMs: duration });
    } else {
      storage.blockIp(ip, {
        expiresAt: duration > 0 ? Date.now() + duration : null,
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
    const result = typeof storage.dismissAlert === 'function' ? storage.dismissAlert(clientId) : false;
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
  <title>iri-shield — Enterprise Security Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    body { font-family: 'Inter', system-ui, -apple-system, sans-serif; }
    .nav-item { transition: background 0.15s, color 0.15s; }
    .nav-item.active { background: #eff6ff; color: #1d4ed8; font-weight: 600; }
    .nav-item.active .nav-icon { color: #1d4ed8; }
    .badge { display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 9999px; font-size: 11px; font-weight: 600; letter-spacing: 0.03em; }
    .badge-critical { background: #fef2f2; color: #b91c1c; border: 1px solid #fecaca; }
    .badge-high { background: #fff7ed; color: #c2410c; border: 1px solid #fed7aa; }
    .badge-medium { background: #fefce8; color: #a16207; border: 1px solid #fef08a; }
    .badge-low { background: #f0fdf4; color: #15803d; border: 1px solid #bbf7d0; }
    .badge-none { background: #f8fafc; color: #64748b; border: 1px solid #e2e8f0; }
    .badge-blue { background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; }
    .sidebar { width: 240px; min-width: 240px; }
    .stat-card { transition: box-shadow 0.15s, transform 0.15s; }
    .stat-card:hover { box-shadow: 0 4px 16px rgba(0,0,0,0.06); }
    
    /* Interactive mode card */
    .mode-card {
      border: 2px solid #e5e7eb;
      border-radius: 12px;
      padding: 16px;
      cursor: pointer;
      transition: all 0.2s ease;
      position: relative;
    }
    .mode-card:hover { border-color: #93c5fd; background: #f8fafc; }
    .mode-card.selected {
      border-color: #2563eb;
      background: #eff6ff;
      box-shadow: 0 0 0 1px #2563eb;
    }
    .mode-card.selected .mode-radio-icon {
      border-color: #2563eb;
      background: #2563eb;
    }

    /* Buttons */
    .btn-primary { background: #2563eb; color: #fff; border-radius: 8px; padding: 7px 16px; font-size: 14px; font-weight: 500; border: none; cursor: pointer; transition: background 0.15s; }
    .btn-primary:hover { background: #1d4ed8; }
    .btn-secondary { background: #fff; color: #374151; border-radius: 8px; padding: 7px 16px; font-size: 14px; font-weight: 500; border: 1px solid #e5e7eb; cursor: pointer; transition: background 0.15s; }
    .btn-secondary:hover { background: #f9fafb; border-color: #d1d5db; }
    .btn-danger { background: #dc2626; color: #fff; border-radius: 8px; padding: 7px 16px; font-size: 14px; font-weight: 500; border: none; cursor: pointer; transition: background 0.15s; }
    .btn-danger:hover { background: #b91c1c; }
    .btn-unblock { background: #fff; color: #059669; border: 1px solid #a7f3d0; border-radius: 6px; padding: 3px 10px; font-size: 12px; font-weight: 600; cursor: pointer; transition: all 0.15s; }
    .btn-unblock:hover { background: #ecfdf5; border-color: #34d399; }
    .btn-dismiss { background: #fff; color: #6b7280; border: 1px solid #e5e7eb; border-radius: 6px; padding: 4px 10px; font-size: 12px; font-weight: 500; cursor: pointer; transition: all 0.15s; }
    .btn-dismiss:hover { background: #f9fafb; color: #111827; }
    .btn-block-small { background: #fff; color: #dc2626; border: 1px solid #fecaca; border-radius: 6px; padding: 3px 10px; font-size: 12px; font-weight: 600; cursor: pointer; transition: all 0.15s; }
    .btn-block-small:hover { background: #fef2f2; border-color: #f87171; }
    
    /* Pagination */
    .pagination { display: flex; gap: 6px; align-items: center; }
    .page-btn { background: #fff; border: 1px solid #e5e7eb; border-radius: 6px; padding: 4px 10px; font-size: 12px; font-weight: 500; cursor: pointer; transition: all 0.15s; color: #374151; }
    .page-btn:hover { background: #f3f4f6; border-color: #d1d5db; }
    .page-btn.active { background: #2563eb; color: #fff; border-color: #2563eb; font-weight: 600; }
    
    /* Tooltip / Hint indicator */
    [title] { cursor: help; }
    .event-row { cursor: pointer; transition: background 0.15s; }
    .event-row:hover { background: #f1f5f9 !important; }
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
        <div class="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center shrink-0 shadow-sm">
          <svg class="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <div>
          <p class="text-xs text-gray-400 font-medium uppercase tracking-wider">Security</p>
          <h1 class="text-base font-bold text-gray-900 leading-none mt-0.5">iri-shield</h1>
          <img src="https://img.shields.io/badge/v-${escapeHtml(config.version || '1.0.0')}-blue?style=flat-square&logo=appveyor" alt="Version Badge" class="mt-1">
        </div>
      </div>
      <div class="mt-3 flex items-center gap-2">
        <span id="sidebarMode" class="badge badge-blue text-xs" title="Current security protection mode">Mode: ${escapeHtml(config.security || 'medium')}</span>
        <span class="text-xs text-emerald-600 font-medium flex items-center gap-1">
          <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span> Active
        </span>
      </div>
    </div>

    <!-- Nav -->
    <nav class="flex-1 px-3 py-4 space-y-0.5">
      ${navItem('overview', 'Overview', iconOverview())}
      ${navItem('alerts', 'Alerts', iconAlerts(), 'alertBadge')}
      ${navItem('events', 'Security Events', iconEvents())}
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
      <div class="text-xs text-gray-500 font-medium" id="updatedAt">Updating…</div>
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
    <div class="bg-white border-b border-gray-200 px-8 py-4 sticky top-0 z-10 shadow-xs">
      <div class="flex items-center justify-between">
        <div>
          <h2 class="text-lg font-semibold text-gray-900" id="pageTitle">Overview</h2>
          <p class="text-xs text-gray-400 mt-0.5" id="pageSubtitle">Real-time API traffic and threat monitoring</p>
        </div>
        <div class="flex items-center gap-3">
          <span class="text-xs font-mono text-gray-600 bg-gray-100 px-2.5 py-1 rounded font-medium" id="appName">${escapeHtml(config.appName || 'iri-shield')}</span>
          <div class="w-px h-4 bg-gray-200"></div>
          <span class="text-xs text-gray-600 font-medium" id="storageMode">Storage: ${escapeHtml(config.storage?.mode || 'sqlite')}</span>
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
        ${statCard('blockedCombined', 'Active Blocked', iconBlock(), 'text-red-700', 'bg-red-50')}
        ${statCard('activeAlerts', 'Active Alerts', iconAlert(), 'text-blue-700', 'bg-blue-50')}
      </div>

      <!-- Charts row -->
      <div class="mt-6 grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div class="bg-white rounded-xl border border-gray-200 p-5 shadow-xs">
          <div class="flex items-center justify-between mb-4">
            <div>
              <h3 class="font-semibold text-gray-900">Threat Distribution</h3>
              <p class="text-xs text-gray-400">Categorized security threats detected</p>
            </div>
            <span class="text-xs text-gray-400 font-medium" id="redactionsLabel">0 redactions</span>
          </div>
          <div class="relative" style="height: 220px;">
            <canvas id="threatChart"></canvas>
          </div>
        </div>
        <div class="bg-white rounded-xl border border-gray-200 p-5 shadow-xs">
          <div class="flex items-center justify-between mb-4">
            <div>
              <h3 class="font-semibold text-gray-900">Top Endpoints</h3>
              <p class="text-xs text-gray-400">Most active API paths and latency</p>
            </div>
          </div>
          <div class="overflow-x-auto max-h-[220px]">
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
        ${miniStat('totalRedactions', 'PII Redactions', '')}
        ${miniStat('blockedIpsCount', 'Active Blocked IPs', '')}
      </div>
    </section>

    <!-- ===== ALERTS PANEL ===== -->
    <section class="panel hidden" id="panel-alerts">
      <div class="flex items-center justify-between mb-5">
        <div>
          <h3 class="font-semibold text-gray-900 text-base">Suspicious Client Alerts</h3>
          <p class="text-sm text-gray-500 mt-0.5">Clients with elevated risk scores under observation (not yet automatically blocked)</p>
        </div>
        <button onclick="loadAlerts(currentPage.alerts)" class="btn-secondary text-sm flex items-center gap-1.5">
          <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
          Refresh Alerts
        </button>
      </div>
      <div class="bg-white rounded-xl border border-gray-200 overflow-hidden shadow-xs">
        <table class="w-full text-sm">
          <thead><tr class="text-xs text-gray-500 uppercase tracking-wide border-b border-gray-200 bg-gray-50">
            <th class="px-4 py-3 text-left font-medium">Client ID</th>
            <th class="px-4 py-3 text-left font-medium">Last IP</th>
            <th class="px-4 py-3 text-left font-medium">Risk</th>
            <th class="px-4 py-3 text-right font-medium">Score</th>
            <th class="px-4 py-3 text-left font-medium">Threats Detected</th>
            <th class="px-4 py-3 text-left font-medium">Last Alert</th>
            <th class="px-4 py-3 text-right font-medium">Alerts</th>
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
        <div>
          <h3 class="font-semibold text-gray-900 text-base">Security Events Log</h3>
          <p class="text-xs text-gray-500 mt-0.5">Click on any event row to expand complete details (User-Agent, Reasons, Client context)</p>
        </div>
        <div class="flex items-center gap-2 ml-auto">
          <select id="eventRiskFilter" onchange="loadEvents(1)" class="border border-gray-200 rounded-lg px-3 py-1.5 text-sm text-gray-700 bg-white focus:outline-none focus:ring-2 focus:ring-blue-500">
            <option value="">All Risk Levels</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <button onclick="loadEvents(currentPage.events)" class="btn-secondary text-sm flex items-center gap-1.5">
            <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
            Refresh
          </button>
        </div>
      </div>
      <div class="bg-white rounded-xl border border-gray-200 overflow-hidden shadow-xs">
        <table class="w-full text-sm">
          <thead><tr class="text-xs text-gray-500 uppercase tracking-wide border-b border-gray-200 bg-gray-50">
            <th class="px-4 py-3 text-left font-medium w-6"></th>
            <th class="px-4 py-3 text-left font-medium">Timestamp</th>
            <th class="px-4 py-3 text-left font-medium">IP Address</th>
            <th class="px-4 py-3 text-left font-medium">Endpoint</th>
            <th class="px-4 py-3 text-left font-medium">Threat Category</th>
            <th class="px-4 py-3 text-left font-medium">Risk</th>
            <th class="px-4 py-3 text-right font-medium">Score</th>
            <th class="px-4 py-3 text-left font-medium">Mitigation</th>
          </tr></thead>
          <tbody id="eventRows" class="divide-y divide-gray-100">
            <tr><td class="px-4 py-4 text-gray-400" colspan="8">Loading…</td></tr>
          </tbody>
        </table>
      </div>
      <div class="mt-4" id="eventPagination"></div>
    </section>

    <!-- ===== CLIENTS PANEL ===== -->
    <section class="panel hidden" id="panel-clients">
      <div class="flex items-center justify-between mb-5">
        <div>
          <h3 class="font-semibold text-gray-900 text-base">Client Identity Monitoring</h3>
          <p class="text-sm text-gray-500 mt-0.5">Unique clients fingerprinted across sessions, IPs, User-Agents and devices</p>
        </div>
        <button onclick="loadClients(currentPage.clients)" class="btn-secondary text-sm flex items-center gap-1.5">
          <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
          Refresh
        </button>
      </div>
      <div class="bg-white rounded-xl border border-gray-200 overflow-hidden shadow-xs">
        <table class="w-full text-sm">
          <thead><tr class="text-xs text-gray-500 uppercase tracking-wide border-b border-gray-200 bg-gray-50">
            <th class="px-4 py-3 text-left font-medium">Client ID</th>
            <th class="px-4 py-3 text-left font-medium">User ID</th>
            <th class="px-4 py-3 text-left font-medium">Last Known IP</th>
            <th class="px-4 py-3 text-right font-medium">Total Requests</th>
            <th class="px-4 py-3 text-right font-medium">IPs Used</th>
            <th class="px-4 py-3 text-right font-medium">Identity Drift</th>
            <th class="px-4 py-3 text-right font-medium">Fingerprints</th>
            <th class="px-4 py-3 text-left font-medium">Risk Status</th>
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
          <h3 class="font-semibold text-gray-900 text-base">Blocked IP Management</h3>
          <p class="text-sm text-gray-500 mt-0.5">Manage active and historical IP restrictions</p>
        </div>
        <div class="flex items-center gap-2">
          <select id="blockedStatusFilter" onchange="loadBlocked(1)" class="border border-gray-200 rounded-lg px-3 py-1.5 text-sm text-gray-700 bg-white focus:outline-none focus:ring-2 focus:ring-blue-500">
            <option value="all">All Blocks (Active & History)</option>
            <option value="active">Active Blocks Only</option>
            <option value="expired">Expired Blocks</option>
          </select>
          <button onclick="loadBlocked(currentPage.blocked)" class="btn-secondary text-sm flex items-center gap-1.5">
            <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
            Refresh
          </button>
          <button onclick="showBlockModal()" class="btn-primary text-sm flex items-center gap-1.5">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>
            Block IP Address
          </button>
        </div>
      </div>
      <div class="bg-white rounded-xl border border-gray-200 overflow-hidden shadow-xs">
        <table class="w-full text-sm">
          <thead><tr class="text-xs text-gray-500 uppercase tracking-wide border-b border-gray-200 bg-gray-50">
            <th class="px-4 py-3 text-left font-medium">IP Address</th>
            <th class="px-4 py-3 text-left font-medium">Block Reason</th>
            <th class="px-4 py-3 text-right font-medium">Risk Score</th>
            <th class="px-4 py-3 text-left font-medium">Type</th>
            <th class="px-4 py-3 text-left font-medium">Status</th>
            <th class="px-4 py-3 text-left font-medium">Blocked At</th>
            <th class="px-4 py-3 text-left font-medium">Expires At</th>
            <th class="px-4 py-3 text-left font-medium">Actions</th>
          </tr></thead>
          <tbody id="blockedRows" class="divide-y divide-gray-100">
            <tr><td class="px-4 py-4 text-gray-400" colspan="8">Loading…</td></tr>
          </tbody>
        </table>
      </div>
      <div class="mt-4" id="blockedPagination"></div>
    </section>

    <!-- ===== SETTINGS PANEL ===== -->
    <section class="panel hidden" id="panel-settings">
      <form id="settingsForm">
        <!-- Security Mode Selector -->
        <div class="bg-white rounded-xl border border-gray-200 p-6 mb-5 shadow-xs">
          <div class="mb-4">
            <h3 class="font-semibold text-gray-900 text-base">Security Mode</h3>
            <p class="text-xs text-gray-500 mt-0.5">Select protection preset. Mode applies immediately upon saving.</p>
          </div>
          <div class="grid grid-cols-1 md:grid-cols-3 gap-4" id="modeCardsContainer">
            ${modeCard('low', 'Low Mode', 'Relaxed protection. 300 req/min, auto-block score threshold 90.', config.security === 'low')}
            ${modeCard('medium', 'Medium Mode', 'Balanced enterprise protection. 120 req/min, block threshold 80.', (config.security || 'medium') === 'medium')}
            ${modeCard('high', 'High Mode', 'Strict protection. 30 req/min, block threshold 60, 1.3x threat multipliers.', config.security === 'high')}
          </div>
        </div>

        <!-- Rate Limiting -->
        <div class="bg-white rounded-xl border border-gray-200 p-6 mb-5 shadow-xs">
          <h3 class="font-semibold text-gray-900 text-base mb-4">Rate Limiting Parameters</h3>
          <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
            ${numInput('Max requests per window', 'rateLimit.max', config.rateLimit.max)}
            ${numInput('Window duration (ms)', 'rateLimit.windowMs', config.rateLimit.windowMs)}
            ${checkInput('Enable rate limiting', 'rateLimit.enabled', config.rateLimit.enabled)}
          </div>
        </div>

        <!-- Block Settings -->
        <div class="bg-white rounded-xl border border-gray-200 p-6 mb-5 shadow-xs">
          <h3 class="font-semibold text-gray-900 text-base mb-4">Automated IP Blocking</h3>
          <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
            ${numInput('Auto-block threshold score (0-100)', 'block.threshold', config.block.threshold)}
            ${numInput('Block duration (ms)', 'block.durationMs', config.block.durationMs)}
            ${checkInput('Enable automated IP blocking', 'block.enabled', config.block.enabled)}
          </div>
        </div>

        <!-- Anomaly Thresholds -->
        <div class="bg-white rounded-xl border border-gray-200 p-6 mb-5 shadow-xs">
          <h3 class="font-semibold text-gray-900 text-base mb-4">Anomaly Detection Thresholds</h3>
          <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
            ${numInput('Medium risk threshold', 'anomaly.mediumThreshold', config.anomaly.mediumThreshold)}
            ${numInput('High risk threshold', 'anomaly.highThreshold', config.anomaly.highThreshold)}
            ${numInput('Critical risk threshold', 'anomaly.criticalThreshold', config.anomaly.criticalThreshold)}
            ${numInput('Single endpoint flood max hits', 'anomaly.singleEndpointMax', config.anomaly.singleEndpointMax)}
            ${numInput('Failed auth attempts limit', 'anomaly.failedAuthMax', config.anomaly.failedAuthMax)}
            ${numInput('Alert threshold score', 'alert.threshold', config.alert?.threshold || 35)}
          </div>
        </div>

        <!-- System & Redaction -->
        <div class="bg-white rounded-xl border border-gray-200 p-6 mb-5 shadow-xs">
          <h3 class="font-semibold text-gray-900 text-base mb-4">System, Helmet & Redaction</h3>
          <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            ${numInput('Dashboard auto-refresh (ms)', 'dashboard.refreshMs', config.dashboard?.refreshMs || 300000)}
            ${checkInput('Enable response redaction', 'redaction.enabled', config.redaction.enabled)}
            ${checkInput('Enable Helmet security headers', 'helmet.enabled', config.helmet?.enabled !== false)}
            ${checkInput('Testing mode enabled', 'testing.enabled', config.testing?.enabled || false)}
            ${checkInput('Allow client test overrides', 'testing.allowClientOverrides', config.testing?.allowClientOverrides || false)}
            ${checkInput('Enable active alerts queue', 'alert.enabled', config.alert?.enabled !== false)}
          </div>
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1.5">Sensitive Redaction Fields (comma-separated)</label>
            <textarea class="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm font-mono text-gray-800 focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none" rows="2" name="redaction.fields">${escapeHtml((config.redaction?.fields || []).join(', '))}</textarea>
          </div>
        </div>

        <div class="flex items-center gap-4">
          <button class="btn-primary" type="submit">Save All Settings</button>
          <span class="text-sm text-emerald-600 font-medium" id="settingsMsg"></span>
        </div>
      </form>
    </section>

    </div><!-- /px-8 py-6 -->
  </main>
</div>

<!-- Block IP Modal -->
<div id="blockModal" class="fixed inset-0 bg-black/40 z-50 hidden flex items-center justify-center p-4">
  <div class="bg-white rounded-2xl shadow-xl w-full max-w-md p-6">
    <h3 class="text-lg font-semibold text-gray-900 mb-1">Manually Block IP Address</h3>
    <p class="text-xs text-gray-500 mb-4">Add an IP address to the persistent blocklist.</p>
    <div class="space-y-3">
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-1">IP Address</label>
        <input id="blockIpInput" type="text" placeholder="e.g. 203.0.113.77" class="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono" />
      </div>
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-1">Block Reason</label>
        <input id="blockReasonInput" type="text" placeholder="manual_admin_block" class="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
      </div>
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-1">Block Duration</label>
        <select id="blockDurationInput" class="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
          <option value="86400000" selected>24 hours</option>
          <option value="3600000">1 hour</option>
          <option value="21600000">6 hours</option>
          <option value="604800000">7 days</option>
          <option value="0">Permanent Block</option>
        </select>
      </div>
    </div>
    <div class="mt-5 flex gap-3">
      <button onclick="submitBlock()" class="btn-danger flex-1">Apply Block</button>
      <button onclick="hideBlockModal()" class="btn-secondary flex-1">Cancel</button>
    </div>
  </div>
</div>

<script>
const BASE = '${escapeJsString(base)}';
const fmt = new Intl.NumberFormat();
let refreshMs = ${refreshMs};
let timer;
let chart;
let rawEventsData = [];
let activeBlockedIps = new Set();
let currentPage = { events: 1, clients: 1, blocked: 1, alerts: 1 };

// Friendly shortened labels mapping for threat chart
const THREAT_SHORT_LABELS = {
  'sql_injection': 'SQL Inj',
  'sql_injection_pattern': 'SQL Inj',
  'xss_pattern': 'XSS',
  'path_traversal': 'Path Trav',
  'path_traversal_pattern': 'Path Trav',
  'command_injection': 'Cmd Inj',
  'ssti_pattern': 'SSTI',
  'nosql_injection': 'NoSQL Inj',
  'secret_probe': 'Secret Probe',
  'xxe_pattern': 'XXE',
  'open_redirect': 'Open Redir',
  'repeated_failed_auth': 'Auth Fail',
  'single_endpoint_flood': 'Flood',
  'sensitive_endpoint_access': 'Sens. Path',
  'header_anomaly_missing_browser_headers': 'Header Anom',
  'header_anomaly_missing_modern_headers': 'Modern Anom',
  'identity_ip_change': 'IP Drift',
  'identity_user_agent_change': 'UA Drift',
  'identity_fingerprint_change': 'Fp Drift',
  'scanner_ua_sqlmap': 'SQLMap',
  'scanner_ua_nikto': 'Nikto',
  'scanner_ua_masscan': 'Masscan',
  'scanner_ua_hydra': 'Hydra',
  'scanner_ua_headless_chrome': 'Headless',
  'scanner_ua_puppeteer': 'Puppeteer',
  'scanner_ua_python_requests': 'Py-Requests',
  'rate_limit_exceeded': 'Rate Limit',
  'blocked_ip': 'Blocked IP'
};

function formatThreatLabel(name) {
  if (!name) return 'Unknown';
  if (THREAT_SHORT_LABELS[name]) return THREAT_SHORT_LABELS[name];
  const cleaned = name.replace(/^scanner_ua_/, '').replace(/_/g, ' ');
  return cleaned.length > 12 ? cleaned.slice(0, 11) + '..' : cleaned;
}

// -------------------------------------------------------------------------
// Navigation & Panel Memory
// -------------------------------------------------------------------------

const PAGE_TITLES = {
  overview: { title: 'Overview', sub: 'Real-time API traffic and threat monitoring' },
  alerts: { title: 'Suspicious Alerts', sub: 'Active suspicious clients under observation' },
  events: { title: 'Security Events Log', sub: 'Click on any event row to expand complete details' },
  clients: { title: 'Client Identity Monitoring', sub: 'Client fingerprinting and identity drift history' },
  blocked: { title: 'Blocked IP Management', sub: 'Manage active and historical IP restrictions' },
  settings: { title: 'System Settings', sub: 'Configure security modes, thresholds, and redaction' }
};

function showPanel(id) {
  const targetId = id || 'overview';
  localStorage.setItem('iri_active_panel', targetId);

  document.querySelectorAll('.panel').forEach(p => p.classList.add('hidden'));
  const panel = document.getElementById('panel-' + targetId);
  if (panel) panel.classList.remove('hidden');

  document.querySelectorAll('.nav-item').forEach(b => {
    b.classList.toggle('active', b.dataset.panel === targetId);
  });

  const meta = PAGE_TITLES[targetId] || { title: targetId, sub: '' };
  document.getElementById('pageTitle').textContent = meta.title;
  document.getElementById('pageSubtitle').textContent = meta.sub;

  // Always load live stats in background so header, footer and badges are updated
  loadStats();

  if (targetId === 'events') loadEvents(currentPage.events);
  if (targetId === 'clients') loadClients(currentPage.clients);
  if (targetId === 'blocked') loadBlocked(currentPage.blocked);
  if (targetId === 'alerts') loadAlerts(currentPage.alerts);
  if (targetId === 'settings') loadSettings();
}

document.querySelectorAll('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => showPanel(btn.dataset.panel));
});

// -------------------------------------------------------------------------
// Security Mode Interactive UI
// -------------------------------------------------------------------------

function selectMode(mode) {
  const targetMode = mode || 'medium';
  document.querySelectorAll('.mode-card').forEach(card => {
    const input = card.querySelector('input[name="security"]');
    const isMatch = input && input.value === targetMode;
    if (input) input.checked = isMatch;
    card.classList.toggle('selected', isMatch);
  });
  const sidebar = document.getElementById('sidebarMode');
  if (sidebar) sidebar.textContent = 'Mode: ' + targetMode;
}

document.querySelectorAll('.mode-card').forEach(card => {
  card.addEventListener('click', () => {
    const input = card.querySelector('input[name="security"]');
    if (input) selectMode(input.value);
  });
});

// -------------------------------------------------------------------------
// Reactive Block / Unblock Helpers
// -------------------------------------------------------------------------

function renderIpAction(ip, reason = '') {
  if (!ip || ip === '-' || ip === 'unknown') return '';
  const isBlocked = activeBlockedIps.has(ip);
  if (isBlocked) {
    return \`<span class="inline-flex items-center gap-1.5" data-ip-ctrl="\${clean(ip)}">
      <span class="badge badge-critical text-[10px] font-semibold">Blocked</span>
      <button class="btn-unblock text-[11px]" onclick="event.stopPropagation(); doToggleBlock('\${clean(ip)}', false)">Unblock</button>
    </span>\`;
  } else {
    return \`<span class="inline-flex items-center gap-1.5" data-ip-ctrl="\${clean(ip)}">
      <button class="btn-block-small text-[11px]" onclick="event.stopPropagation(); doToggleBlock('\${clean(ip)}', true, '\${clean(reason)}')">Block IP</button>
    </span>\`;
  }
}

function updateIpControlsOnPage(ip, isBlocked) {
  document.querySelectorAll(\`[data-ip-ctrl="\${ip}"]\`).forEach(el => {
    if (isBlocked) {
      el.innerHTML = \`
        <span class="badge badge-critical text-[10px] font-semibold">Blocked</span>
        <button class="btn-unblock text-[11px]" onclick="event.stopPropagation(); doToggleBlock('\${clean(ip)}', false)">Unblock</button>
      \`;
    } else {
      el.innerHTML = \`
        <button class="btn-block-small text-[11px]" onclick="event.stopPropagation(); doToggleBlock('\${clean(ip)}', true)">Block IP</button>
      \`;
    }
  });
}

async function doToggleBlock(ip, shouldBlock, reason = 'manual_action', durationMs = 86400000) {
  if (!ip) return;
  const actionName = shouldBlock ? 'Block' : 'Unblock';
  if (!confirm(\`\${actionName} IP \${ip}?\`)) return;

  // Immediate optimistic update
  if (shouldBlock) {
    activeBlockedIps.add(ip);
  } else {
    activeBlockedIps.delete(ip);
  }
  updateIpControlsOnPage(ip, shouldBlock);

  try {
    if (shouldBlock) {
      await fetch(BASE + '/api/block', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ ip, reason: reason || 'manual_action', durationMs })
      });
    } else {
      await fetch(BASE + '/api/unblock', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ ip })
      });
    }

    // Refresh active panel data to reflect changes immediately
    const activeTab = localStorage.getItem('iri_active_panel') || 'overview';
    if (activeTab === 'blocked') loadBlocked(currentPage.blocked);
    if (activeTab === 'alerts') loadAlerts(currentPage.alerts);
    if (activeTab === 'events') loadEvents(currentPage.events);
    loadStats();
  } catch (e) {
    console.error('Toggle block error', e);
    if (shouldBlock) activeBlockedIps.delete(ip); else activeBlockedIps.add(ip);
    updateIpControlsOnPage(ip, !shouldBlock);
  }
}

// -------------------------------------------------------------------------
// Stats (Header, Footer, Badges & Overview)
// -------------------------------------------------------------------------

async function loadStats() {
  try {
    const res = await fetch(BASE + '/api/stats');
    const data = await res.json();

    refreshMs = Number(data.config?.dashboard?.refreshMs || refreshMs);
    document.getElementById('refreshLabel').textContent = Math.round(refreshMs / 1000) + 's';
    document.getElementById('updatedAt').textContent = 'Updated ' + new Date().toLocaleTimeString();
    document.getElementById('storageMode').textContent = data.storageMode ? 'Storage: ' + data.storageMode : 'Storage: memory';
    
    if (data.config?.security) {
      selectMode(data.config.security);
    }

    // Sync active blocked IPs set
    activeBlockedIps = new Set((data.blockedIps || []).map(b => b.ip));

    // Stat cards
    setText('totalRequests', fmt.format(data.totalRequests || 0));
    setText('detectedThreats', fmt.format(data.detectedThreats || 0));
    const activeBlockedCount = (data.blockedIps || []).length;
    setText('blockedCombined', fmt.format(data.blockedRequests || 0) + ' req / ' + fmt.format(activeBlockedCount) + ' active');
    setText('activeAlerts', fmt.format(data.activeAlerts || 0));

    // Mini stats
    setText('avgLatency', (data.averageLatencyMs || 0) + ' ms');
    setText('anomalyEvents', fmt.format(data.anomalyEvents || 0));
    setText('totalRedactions', fmt.format(data.redactions || 0));
    setText('blockedIpsCount', fmt.format(activeBlockedCount));

    document.getElementById('redactionsLabel').textContent = fmt.format(data.redactions || 0) + ' redactions';

    // Badges in sidebar
    const alertBadge = document.getElementById('alertBadge');
    if (alertBadge) {
      if (data.activeAlerts > 0) {
        alertBadge.textContent = data.activeAlerts;
        alertBadge.classList.remove('hidden');
      } else {
        alertBadge.classList.add('hidden');
      }
    }

    const blockedBadge = document.getElementById('blockedBadge');
    if (blockedBadge) {
      if (activeBlockedCount > 0) {
        blockedBadge.textContent = activeBlockedCount;
        blockedBadge.classList.remove('hidden');
      } else {
        blockedBadge.classList.add('hidden');
      }
    }

    const currentActive = localStorage.getItem('iri_active_panel') || 'overview';
    if (currentActive === 'overview') {
      renderEndpoints(data.endpoints || []);
      renderChart(data.threatDistribution || []);
    }
  } catch(e) { console.error('Stats error', e); }
  schedule();
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

// -------------------------------------------------------------------------
// Top Endpoints
// -------------------------------------------------------------------------

function renderEndpoints(rows) {
  const tbody = document.getElementById('endpointRows');
  if (!tbody) return;
  if (!rows.length) {
    tbody.innerHTML = '<tr><td class="py-3 text-gray-400 text-sm" colspan="4">No traffic recorded yet</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map(r => {
    const fullPath = (r.method || 'GET') + ' ' + (r.endpoint || '/');
    return \`<tr class="border-t border-gray-50 hover:bg-gray-50">
      <td class="py-2 pr-3 text-gray-700 text-xs font-mono max-w-[200px] truncate" title="\${clean(fullPath)}">\${clean(fullPath)}</td>
      <td class="py-2 pr-3 text-right text-gray-900 font-medium">\${fmt.format(r.count)}</td>
      <td class="py-2 pr-3 text-right \${r.errors > 0 ? 'text-red-600 font-semibold' : 'text-gray-500'}">\${r.errors}</td>
      <td class="py-2 text-right text-gray-500">\${Number(r.avgLatencyMs||0).toFixed(1)} ms</td>
    </tr>\`;
  }).join('');
}

// -------------------------------------------------------------------------
// Security Events (with interactive expand on click and reactive block button)
// -------------------------------------------------------------------------

async function loadEvents(page) {
  currentPage.events = page || currentPage.events;
  const risk = document.getElementById('eventRiskFilter')?.value || '';
  try {
    const url = BASE + '/api/events?page=' + currentPage.events + '&perPage=20' + (risk ? '&riskLevel=' + risk : '');
    const res = await fetch(url);
    const data = await res.json();
    rawEventsData = data.data || [];
    const tbody = document.getElementById('eventRows');
    if (!rawEventsData.length) {
      tbody.innerHTML = '<tr><td class="px-4 py-4 text-gray-400 text-center" colspan="8">No security events recorded</td></tr>';
    } else {
      tbody.innerHTML = rawEventsData.map((r, idx) => {
        const fullEndpoint = (r.method || '') + ' ' + (r.endpoint || '');
        const timeStr = r.timestamp ? new Date(r.timestamp).toLocaleString() : '-';

        return \`<tr class="event-row border-t border-gray-100 hover:bg-blue-50/40" onclick="toggleEventDetail('\${clean(r.id || idx)}')" id="row-\${clean(r.id || idx)}">
          <td class="px-3 py-2.5 text-gray-400 text-xs text-center">
            <span id="chevron-\${clean(r.id || idx)}" class="inline-block transition-transform duration-200">▶</span>
          </td>
          <td class="px-4 py-2.5 text-gray-500 text-xs whitespace-nowrap" title="\${clean(r.timestamp)}">\${clean(timeStr)}</td>
          <td class="px-4 py-2.5 text-gray-800 font-mono text-xs font-medium" title="\${clean(r.ip)}">\${clean(r.ip)}</td>
          <td class="px-4 py-2.5 text-gray-700 font-mono text-xs max-w-[160px] truncate" title="\${clean(fullEndpoint)}">\${clean(fullEndpoint)}</td>
          <td class="px-4 py-2.5 text-amber-800 text-xs font-medium max-w-[160px] truncate" title="\${clean(r.threat)}">\${clean(r.threat)}</td>
          <td class="px-4 py-2.5"><span class="badge badge-\${r.riskLevel}" title="Risk score: \${r.riskScore}">\${clean(r.riskLevel)}</span></td>
          <td class="px-4 py-2.5 text-right font-bold text-gray-900">\${r.riskScore}</td>
          <td class="px-4 py-2.5 text-gray-600 text-xs" title="\${clean(r.action)}">\${clean(r.action)}</td>
        </tr>
        <!-- Expandable details sub-row -->
        <tr id="detail-\${clean(r.id || idx)}" class="hidden bg-slate-50 border-b border-gray-200">
          <td colspan="8" class="px-6 py-4">
            <div class="rounded-lg bg-white border border-gray-200 p-4 space-y-3 text-xs">
              <div class="flex items-center justify-between border-b border-gray-100 pb-2">
                <span class="font-semibold text-gray-900 text-sm">Security Event Details</span>
                <span class="font-mono text-gray-400 text-xs">Request ID: \${clean(r.requestId || r.id || 'N/A')}</span>
              </div>
              <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                <div>
                  <span class="text-gray-400 block">IP Address:</span>
                  <div class="flex items-center gap-2 mt-0.5">
                    <span class="font-mono text-gray-900 font-semibold">\${clean(r.ip)}</span>
                    \${renderIpAction(r.ip, r.threat || r.reason)}
                  </div>
                </div>
                <div>
                  <span class="text-gray-400 block">Client ID:</span>
                  <span class="font-mono text-gray-800">\${clean(r.clientId || 'N/A')}</span>
                </div>
                <div>
                  <span class="text-gray-400 block">User ID:</span>
                  <span class="text-gray-800 font-medium">\${clean(r.userId || 'Anonymous / Unauthenticated')}</span>
                </div>
                <div>
                  <span class="text-gray-400 block">Session ID:</span>
                  <span class="font-mono text-gray-800">\${clean(r.sessionId || 'None')}</span>
                </div>
                <div>
                  <span class="text-gray-400 block">Device ID / Platform:</span>
                  <span class="text-gray-800">\${clean((r.deviceId || '') + (r.platform ? ' (' + r.platform + ')' : '')) || 'N/A'}</span>
                </div>
                <div>
                  <span class="text-gray-400 block">Hardware Fingerprint:</span>
                  <span class="font-mono text-gray-800">\${clean(r.fingerprint || 'N/A')}</span>
                </div>
              </div>
              <div class="border-t border-gray-100 pt-2">
                <span class="text-gray-400 block mb-0.5">User-Agent Header:</span>
                <p class="font-mono text-gray-700 bg-gray-50 p-2 rounded border border-gray-100 break-all select-all">\${clean(r.userAgent || 'None')}</p>
              </div>
              <div>
                <span class="text-gray-400 block mb-0.5">Detected Threat Rules & Trigger Reasons:</span>
                <p class="text-amber-900 bg-amber-50/70 p-2 rounded border border-amber-200 font-medium">\${clean(r.reason || r.threat || 'None')}</p>
              </div>
              <div class="flex items-center justify-between text-gray-400 text-[11px] pt-1">
                <span>Exact Time: \${clean(r.timestamp)}</span>
                <span>Mitigation Applied: <strong class="text-gray-700">\${clean(r.action)}</strong> (Risk Score: \${r.riskScore})</span>
              </div>
            </div>
          </td>
        </tr>\`;
      }).join('');
    }
    renderPagination('eventPagination', data, loadEvents);
  } catch(e) { console.error('Events error', e); }
}

function toggleEventDetail(id) {
  const detailRow = document.getElementById('detail-' + id);
  const chevron = document.getElementById('chevron-' + id);
  if (detailRow) {
    const isHidden = detailRow.classList.contains('hidden');
    detailRow.classList.toggle('hidden');
    if (chevron) chevron.style.transform = isHidden ? 'rotate(90deg)' : 'rotate(0deg)';
  }
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
      tbody.innerHTML = '<tr><td class="px-4 py-4 text-gray-400 text-center" colspan="9">No clients recorded</td></tr>';
    } else {
      tbody.innerHTML = data.data.map(r => {
        const fullIps = (r.ips || []).join(', ');
        const fullFps = (r.fingerprints || []).join(', ');
        return \`<tr>
          <td class="px-4 py-2.5 font-mono text-xs text-gray-800 max-w-[130px] truncate" title="\${clean(r.clientId)}">\${clean(r.clientId)}</td>
          <td class="px-4 py-2.5 text-xs text-gray-700 max-w-[100px] truncate" title="\${clean(r.userId || 'N/A')}">\${clean(r.userId || '-')}</td>
          <td class="px-4 py-2.5 font-mono text-xs text-gray-900" title="IPs used: \${clean(fullIps)}">\${clean(r.lastIp || '-')}</td>
          <td class="px-4 py-2.5 text-right font-semibold text-gray-900">\${fmt.format(r.requestCount)}</td>
          <td class="px-4 py-2.5 text-right text-gray-600" title="\${clean(fullIps)}">\${(r.ips||[]).length}</td>
          <td class="px-4 py-2.5 text-right \${r.changes > 2 ? 'text-amber-600 font-bold' : 'text-gray-500'}" title="Identity drift count: \${r.changes}">\${r.changes}</td>
          <td class="px-4 py-2.5 text-right text-gray-500 font-mono text-xs" title="\${clean(fullFps)}">\${(r.fingerprints||[]).length}</td>
          <td class="px-4 py-2.5"><span class="badge badge-\${r.lastRisk || 'none'}">\${clean(r.lastRisk||'none')}</span></td>
          <td class="px-4 py-2.5 text-xs text-gray-400 whitespace-nowrap" title="\${clean(r.lastSeenAt)}">\${r.lastSeenAt ? clean(new Date(r.lastSeenAt).toLocaleTimeString()) : '-'}</td>
        </tr>\`;
      }).join('');
    }
    renderPagination('clientPagination', data, loadClients);
  } catch(e) { console.error('Clients error', e); }
}

// -------------------------------------------------------------------------
// Blocked IPs (Persistent, History & Filterable)
// -------------------------------------------------------------------------

async function loadBlocked(page) {
  currentPage.blocked = page || currentPage.blocked;
  const status = document.getElementById('blockedStatusFilter')?.value || 'all';
  try {
    const res = await fetch(BASE + '/api/blocked?page=' + currentPage.blocked + '&perPage=20&status=' + status);
    const data = await res.json();
    const tbody = document.getElementById('blockedRows');
    if (!data.data?.length) {
      tbody.innerHTML = '<tr><td class="px-4 py-4 text-gray-400 text-center" colspan="8">No IP addresses recorded in blocklist</td></tr>';
    } else {
      tbody.innerHTML = data.data.map(r => {
        let statusBadge = '';
        if (r.status === 'permanent') {
          statusBadge = '<span class="badge badge-blue font-semibold">Permanent</span>';
        } else if (r.status === 'active' || !r.isExpired) {
          statusBadge = '<span class="badge badge-critical font-semibold">Active</span>';
        } else {
          statusBadge = '<span class="badge badge-none font-medium">Expired</span>';
        }

        let actionButtons = '';
        if (r.status === 'active' || r.status === 'permanent' || !r.isExpired) {
          actionButtons = \`<button class="btn-unblock" onclick="doToggleBlock('\${clean(r.ip)}', false)">Unblock IP</button>\`;
        } else {
          actionButtons = \`
            <div class="flex items-center gap-1.5">
              <button class="btn-primary text-xs py-1 px-2.5 rounded" onclick="doToggleBlock('\${clean(r.ip)}', true, '\${clean(r.reason)}')">Re-block</button>
              <button class="btn-dismiss text-xs py-1 px-2 rounded" onclick="doDeleteBlock('\${clean(r.ip)}')">Remove</button>
            </div>\`;
        }

        return \`<tr>
          <td class="px-4 py-2.5 font-mono text-sm text-gray-900 font-semibold" title="\${clean(r.ip)}">\${clean(r.ip)}</td>
          <td class="px-4 py-2.5 text-xs text-gray-600 max-w-[180px] truncate" title="\${clean(r.reason || 'None')}">\${clean(r.reason || '-')}</td>
          <td class="px-4 py-2.5 text-right font-bold \${(r.score||0) >= 80 ? 'text-red-600' : 'text-amber-600'}">\${r.score||0}</td>
          <td class="px-4 py-2.5"><span class="badge \${r.manual ? 'badge-blue' : 'badge-high'}">\${r.manual ? 'Manual' : 'Automated'}</span></td>
          <td class="px-4 py-2.5">\${statusBadge}</td>
          <td class="px-4 py-2.5 text-xs text-gray-500" title="\${clean(r.blockedAt)}">\${r.blockedAt ? clean(new Date(r.blockedAt).toLocaleString()) : '-'}</td>
          <td class="px-4 py-2.5 text-xs text-gray-500" title="\${clean(r.expiresAt)}">\${r.expiresAt ? clean(new Date(r.expiresAt).toLocaleString()) : '<span class="font-semibold text-gray-800">Permanent</span>'}</td>
          <td class="px-4 py-2.5">\${actionButtons}</td>
        </tr>\`;
      }).join('');
    }
    renderPagination('blockedPagination', data, loadBlocked);
  } catch(e) { console.error('Blocked error', e); }
}

async function doDeleteBlock(ip) {
  if (!confirm('Permanently remove IP ' + ip + ' from block history?')) return;
  try {
    await fetch(BASE + '/api/unblock', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ip })
    });
    activeBlockedIps.delete(ip);
    updateIpControlsOnPage(ip, false);
    loadBlocked(currentPage.blocked);
    loadStats();
  } catch(e) { console.error('Delete block error', e); }
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
      tbody.innerHTML = '<tr><td class="px-4 py-4 text-gray-400 text-center" colspan="8">No active alerts</td></tr>';
    } else {
      tbody.innerHTML = data.data.map(r => {
        const threatsStr = (r.threats || []).join(', ');
        return \`<tr>
          <td class="px-4 py-2.5 font-mono text-xs text-gray-800 max-w-[130px] truncate" title="\${clean(r.clientId)}">\${clean(r.clientId)}</td>
          <td class="px-4 py-2.5 font-mono text-xs text-gray-900" title="\${clean(r.lastIp)}">\${clean(r.lastIp || '-')}</td>
          <td class="px-4 py-2.5"><span class="badge badge-\${r.lastRisk||'medium'}">\${clean(r.lastRisk||'medium')}</span></td>
          <td class="px-4 py-2.5 text-right font-bold text-amber-700">\${r.lastScore||0}</td>
          <td class="px-4 py-2.5 text-xs text-gray-600 max-w-[220px] truncate" title="\${clean(threatsStr)}">\${clean(threatsStr || 'Anomaly')}</td>
          <td class="px-4 py-2.5 text-xs text-gray-500" title="\${clean(r.lastAlertAt)}">\${r.lastAlertAt ? clean(new Date(r.lastAlertAt).toLocaleString()) : '-'}</td>
          <td class="px-4 py-2.5 text-right text-gray-800 font-semibold">\${r.count||1}</td>
          <td class="px-4 py-2.5 flex items-center gap-1.5">
            \${renderIpAction(r.lastIp, 'alert_action')}
            <button class="btn-dismiss" onclick="doDismiss('\${clean(r.clientId)}')">Dismiss</button>
          </td>
        </tr>\`;
      }).join('');
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

// -------------------------------------------------------------------------
// Block Modal
// -------------------------------------------------------------------------

function showBlockModal() { document.getElementById('blockModal').classList.remove('hidden'); }
function hideBlockModal() { document.getElementById('blockModal').classList.add('hidden'); }

async function submitBlock() {
  const ip = document.getElementById('blockIpInput').value.trim();
  const reason = document.getElementById('blockReasonInput').value.trim() || 'manual_block';
  const durationMs = Number(document.getElementById('blockDurationInput').value);
  if (!ip) { alert('Please enter a valid IP address'); return; }
  hideBlockModal();
  document.getElementById('blockIpInput').value = '';
  document.getElementById('blockReasonInput').value = '';
  await doToggleBlock(ip, true, reason, isNaN(durationMs) ? 86400000 : durationMs);
}

// -------------------------------------------------------------------------
// Settings
// -------------------------------------------------------------------------

async function loadSettings() {
  try {
    const res = await fetch(BASE + '/api/settings');
    const data = await res.json();
    if (data.security) selectMode(data.security);
  } catch(e) { console.error('Load settings error', e); }
}

document.getElementById('settingsForm').addEventListener('submit', async function(e) {
  e.preventDefault();
  const fd = new FormData(e.target);
  const payload = {};
  for (const [key, value] of fd.entries()) setDeep(payload, key, value);

  // Handle unchecked checkboxes
  ['rateLimit.enabled','block.enabled','redaction.enabled','testing.enabled','testing.allowClientOverrides','helmet.enabled','alert.enabled'].forEach(key => {
    if (!fd.has(key)) setDeep(payload, key, false);
  });

  // Handle selected security mode radio
  const modeEl = document.querySelector('input[name="security"]:checked');
  if (modeEl) payload.security = modeEl.value;

  try {
    const res = await fetch(BASE + '/api/settings', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const updated = await res.json();
    if (updated.security) selectMode(updated.security);

    const msg = document.getElementById('settingsMsg');
    msg.textContent = '✓ Settings successfully saved and applied';
    setTimeout(() => { msg.textContent = ''; }, 3500);
    loadStats();
  } catch(e) { console.error('Settings error', e); }
});

// -------------------------------------------------------------------------
// Chart (Threat Distribution with short labels & full tooltips)
// -------------------------------------------------------------------------

function renderChart(rows) {
  const labels = rows.map(r => formatThreatLabel(r.name));
  const values = rows.map(r => r.count);
  const colors = rows.map((_, i) => ['#2563eb','#f59e0b','#ef4444','#10b981','#8b5cf6','#06b6d4','#f97316'][i % 7]);

  if (!chart) {
    const canvas = document.getElementById('threatChart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    chart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: 'Threat Count',
          data: values,
          backgroundColor: colors,
          borderRadius: 4,
          maxBarThickness: 32
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              title: function(items) {
                if (!items.length) return '';
                const idx = items[0].dataIndex;
                return rows[idx] ? rows[idx].name : items[0].label;
              },
              label: function(item) {
                return 'Detected count: ' + item.parsed.y;
              }
            }
          }
        },
        scales: {
          x: {
            ticks: {
              color: '#64748b',
              font: { size: 11, family: 'Inter' },
              maxRotation: 20,
              minRotation: 0
            },
            grid: { display: false }
          },
          y: {
            beginAtZero: true,
            ticks: {
              color: '#94a3b8',
              font: { size: 11, family: 'Inter' },
              precision: 0
            },
            grid: { color: '#f1f5f9' }
          }
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
// Pagination Helper
// -------------------------------------------------------------------------

function renderPagination(containerId, pageData, loadFn) {
  const container = document.getElementById(containerId);
  if (!container || pageData.totalPages <= 1) {
    if (container) container.innerHTML = '';
    return;
  }
  const { page, totalPages, total, perPage } = pageData;
  const start = (page - 1) * perPage + 1;
  const end = Math.min(page * perPage, total);
  let html = \`<div class="flex items-center justify-between gap-3 flex-wrap">
    <span class="text-xs text-gray-500 font-medium">Showing <strong>\${start}-\${end}</strong> of <strong>\${fmt.format(total)}</strong> records</span>
    <div class="pagination">\`;

  if (page > 1) {
    html += \`<button class="page-btn" onclick="(\${loadFn.name})(1)" title="First page">«</button>\`;
    html += \`<button class="page-btn" onclick="(\${loadFn.name})(\${page - 1})" title="Previous page">‹</button>\`;
  }

  const start_p = Math.max(1, page - 2);
  const end_p = Math.min(totalPages, page + 2);
  for (let p = start_p; p <= end_p; p++) {
    html += \`<button class="page-btn \${p === page ? 'active' : ''}" onclick="(\${loadFn.name})(\${p})">\${p}</button>\`;
  }

  if (page < totalPages) {
    html += \`<button class="page-btn" onclick="(\${loadFn.name})(\${page + 1})" title="Next page">›</button>\`;
    html += \`<button class="page-btn" onclick="(\${loadFn.name})(\${totalPages})" title="Last page">»</button>\`;
  }
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
  while (parts.length > 1) {
    const p = parts.shift();
    cur[p] = cur[p] || {};
    cur = cur[p];
  }
  cur[parts[0]] = value;
}

// -------------------------------------------------------------------------
// Initialization
// -------------------------------------------------------------------------

const savedPanel = localStorage.getItem('iri_active_panel') || 'overview';
showPanel(savedPanel);
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
        <div class="inline-flex w-12 h-12 rounded-xl bg-blue-600 items-center justify-center mb-3 shadow-md">
          <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <h1 class="text-2xl font-bold text-gray-900">iri-shield</h1>
        <p class="text-sm text-gray-500 mt-1">Enterprise Security Dashboard</p>
      </div>
      <form method="post" action="${escapeHtml(config.dashboard?.path || '/iri-shield')}/login" class="bg-white rounded-2xl border border-gray-200 shadow-sm p-6">
        ${failed ? '<div class="mb-4 rounded-lg bg-red-50 border border-red-200 px-3 py-2 text-sm text-red-700 font-medium">Invalid username or password.</div>' : ''}
        <label class="block text-sm font-medium text-gray-700 mb-1" for="username">Username</label>
        <input class="w-full rounded-lg border border-gray-200 px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 mb-4" id="username" name="username" autocomplete="username" required />
        <label class="block text-sm font-medium text-gray-700 mb-1" for="password">Password</label>
        <input class="w-full rounded-lg border border-gray-200 px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 mb-5" id="password" name="password" type="password" autocomplete="current-password" required />
        <button class="w-full rounded-lg bg-blue-600 px-4 py-2.5 font-semibold text-white hover:bg-blue-700 transition-colors shadow-sm" type="submit">Sign in</button>
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
    ? `<span id="${badgeId}" class="ml-auto text-xs font-bold bg-red-100 text-red-600 border border-red-200 rounded-full px-2 py-0.5 hidden"></span>`
    : '';
  return `<button class="nav-item w-full flex items-center gap-2.5 rounded-lg px-3 py-2.5 text-sm font-medium text-gray-600 hover:bg-gray-50 hover:text-gray-900" data-panel="${panel}">
    <span class="nav-icon w-4 h-4 shrink-0 text-gray-400">${icon}</span>
    <span>${label}</span>
    ${badge}
  </button>`;
}

function statCard(id, label, icon, colorClass, bgClass) {
  return `<div class="stat-card bg-white rounded-xl border border-gray-200 p-5 shadow-xs">
    <div class="flex items-start justify-between">
      <div>
        <p class="text-xs font-medium text-gray-500 uppercase tracking-wide">${label}</p>
        <p class="mt-2 text-2xl font-bold ${colorClass}" id="${id}">—</p>
      </div>
      <div class="w-9 h-9 ${bgClass} rounded-lg flex items-center justify-center shrink-0 border border-gray-100">${icon}</div>
    </div>
  </div>`;
}

function miniStat(id, label, suffix) {
  return `<div class="bg-white rounded-xl border border-gray-200 px-4 py-3 flex items-center justify-between shadow-xs">
    <span class="text-sm text-gray-500 font-medium">${label}</span>
    <span class="text-sm font-bold text-gray-900" id="${id}">—</span>
  </div>`;
}

function modeCard(value, title, desc, selected) {
  return `<label class="mode-card${selected ? ' selected' : ''} block" data-mode="${value}">
    <input type="radio" name="security" value="${value}" class="sr-only" ${selected ? 'checked' : ''} />
    <div class="flex items-center justify-between mb-1">
      <span class="font-semibold text-gray-900 text-sm">${title}</span>
      <span class="mode-radio-icon w-3.5 h-3.5 rounded-full border-2 border-gray-300 inline-block"></span>
    </div>
    <p class="text-xs text-gray-500 leading-relaxed">${desc}</p>
  </label>`;
}

function numInput(label, name, value) {
  return `<label class="block">
    <span class="text-sm font-medium text-gray-700">${label}</span>
    <input class="mt-1 w-full rounded-lg border border-gray-200 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-900" type="number" name="${name}" value="${escapeHtml(String(value ?? ''))}" />
  </label>`;
}

function checkInput(label, name, checked) {
  return `<label class="flex items-center gap-3 rounded-lg border border-gray-200 px-3 py-2.5 cursor-pointer hover:bg-gray-50 transition-colors">
    <input class="w-4 h-4 rounded accent-blue-600 cursor-pointer" type="checkbox" name="${name}" ${checked ? 'checked' : ''} />
    <span class="text-sm font-medium text-gray-700 select-none">${label}</span>
  </label>`;
}

// --- SVG Icons ---
function iconOverview() { return '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" class="w-4 h-4"><rect x="3" y="3" width="7" height="7" rx="1" stroke-width="2"/><rect x="14" y="3" width="7" height="7" rx="1" stroke-width="2"/><rect x="3" y="14" width="7" height="7" rx="1" stroke-width="2"/><rect x="14" y="14" width="7" height="7" rx="1" stroke-width="2"/></svg>'; }
function iconAlerts()   { return '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>'; }
function iconEvents()   { return '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>'; }
function iconClients()  { return '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/></svg>'; }
function iconBlocked()  { return '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" class="w-4 h-4"><circle cx="12" cy="12" r="10" stroke-width="2"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07" stroke-width="2" stroke-linecap="round"/></svg>'; }
function iconSettings() { return '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><circle cx="12" cy="12" r="3" stroke-width="2"/></svg>'; }
function iconReq()     { return '<svg class="w-5 h-5 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>'; }
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
    ['block.durationMs', 1000, 86400000 * 30],
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
    config.redaction.fields = body['redaction.fields'].split(',').map((f) => f.trim()).filter(Boolean);
  }
  if (body.redaction?.fields && typeof body.redaction.fields === 'string') {
    config.redaction.fields = body.redaction.fields.split(',').map((f) => f.trim()).filter(Boolean);
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
  return String(value || '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[c]));
}

function escapeJsString(value) {
  return String(value || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

module.exports = { createDashboardRouter };
