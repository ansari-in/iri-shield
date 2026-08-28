'use strict';

const express = require('express');
const { randomBytes, timingSafeEqual } = require('crypto');

function createDashboardRouter({ storage, config }) {
  const router = express.Router();
  const auth = dashboardAuth(config.dashboard);

  router.use(express.urlencoded({ extended: false }));
  router.use(express.json({ limit: '50kb' }));

  router.get('/login', (req, res) => {
    if (auth.isAuthenticated(req)) return res.redirect(req.baseUrl || '/');
    res.type('html').send(renderLogin(config, false));
  });

  router.post('/login', (req, res) => {
    if (auth.canLogin(req.body?.username, req.body?.password)) {
      res.setHeader('Set-Cookie', `iri_shield_session=${auth.token}; HttpOnly; SameSite=Lax; Path=${config.dashboard.path || '/iri-shield'}; Max-Age=86400`);
      return res.redirect(req.baseUrl || '/');
    }
    return res.status(401).type('html').send(renderLogin(config, true));
  });

  router.post('/logout', (req, res) => {
    res.setHeader('Set-Cookie', `iri_shield_session=; HttpOnly; SameSite=Lax; Path=${config.dashboard.path || '/iri-shield'}; Max-Age=0`);
    return res.redirect(`${req.baseUrl || ''}/login`);
  });

  router.use((req, res, next) => {
    if (auth.isAuthenticated(req)) return next();
    return res.redirect(`${req.baseUrl || ''}/login`);
  });

  router.get('/api/stats', (req, res) => {
    res.json({ ...storage.getStats(), config: publicConfig(config) });
  });

  router.get('/api/settings', (req, res) => {
    res.json(publicConfig(config));
  });

  router.post('/api/settings', (req, res) => {
    applyDashboardSettings(config, req.body || {});
    res.json(publicConfig(config));
  });

  router.get('/', (req, res) => {
    res.type('html').send(renderDashboard(config, req.baseUrl || config.dashboard.path || '/iri-shield'));
  });

  return router;
}

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
    ['block.durationMs', 1000, 86400000],
    ['anomaly.mediumThreshold', 1, 100],
    ['anomaly.highThreshold', 1, 100],
    ['anomaly.criticalThreshold', 1, 100],
    ['anomaly.singleEndpointMax', 1, 100000],
    ['anomaly.failedAuthMax', 1, 100000],
    ['dashboard.refreshMs', 5000, 3600000]
  ];

  for (const [path, min, max] of numberFields) {
    const value = getPath(body, path);
    if (value !== undefined) setPath(config, path, clamp(Number(value), min, max));
  }

  const booleanFields = [
    'rateLimit.enabled',
    'block.enabled',
    'redaction.enabled',
    'testing.allowClientOverrides',
    'helmet.enabled',
    'helmet.contentSecurityPolicy'
  ];

  for (const path of booleanFields) {
    const value = getPath(body, path);
    if (value !== undefined) setPath(config, path, value === true || value === 'true' || value === 'on');
  }

  if (typeof body.redaction?.fields === 'string') {
    config.redaction.fields = body.redaction.fields.split(',').map((field) => field.trim()).filter(Boolean);
  }
}

function renderDashboard(config, baseUrl) {
  const dashboardBaseUrl = String(baseUrl || '/iri-shield').replace(/\/$/, '');
  const refreshMs = Number(config.dashboard?.refreshMs || 300000);
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>iri-shield dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body class="min-h-screen bg-slate-50 text-slate-950">
  <div class="min-h-screen lg:grid lg:grid-cols-[260px_1fr]">
    <aside class="border-b border-slate-200 bg-white px-4 py-4 lg:min-h-screen lg:border-b-0 lg:border-r">
      <div class="flex items-center justify-between lg:block">
        <div>
          <p class="text-xs font-semibold uppercase tracking-wide text-emerald-700">${escapeHtml(config.appName)}</p>
          <h1 class="mt-1 text-2xl font-semibold">iri-shield</h1>
        </div>
        <form method="post" action="${escapeHtml(dashboardBaseUrl)}/logout">
          <button class="rounded-md border border-slate-300 px-3 py-2 text-sm hover:bg-slate-100" type="submit">Logout</button>
        </form>
      </div>
      <nav class="mt-6 grid grid-cols-2 gap-2 text-sm lg:grid-cols-1">
        <button class="nav rounded-md px-3 py-2 text-left font-medium text-slate-700 hover:bg-slate-100" data-panel="overview">Overview</button>
        <button class="nav rounded-md px-3 py-2 text-left font-medium text-slate-700 hover:bg-slate-100" data-panel="events">Events</button>
        <button class="nav rounded-md px-3 py-2 text-left font-medium text-slate-700 hover:bg-slate-100" data-panel="clients">Clients</button>
        <button class="nav rounded-md px-3 py-2 text-left font-medium text-slate-700 hover:bg-slate-100" data-panel="settings">Settings</button>
      </nav>
      <div class="mt-6 rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-slate-600">
        <p>Refresh interval</p>
        <p class="mt-1 font-semibold text-slate-950" id="refreshLabel">${Math.round(refreshMs / 1000)} sec</p>
      </div>
    </aside>

    <main class="px-4 py-6 sm:px-6 lg:px-8">
      <header class="flex flex-col gap-3 border-b border-slate-200 pb-5 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p class="text-sm text-slate-500">API security monitoring and research evaluation</p>
          <h2 class="mt-1 text-3xl font-semibold">Dashboard</h2>
        </div>
        <div class="text-sm text-slate-500" id="updatedAt">Loading</div>
      </header>

      <section class="panel mt-6" id="overview">
        <div class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          ${metricCard('Total API requests', 'totalRequests', 'text-slate-950')}
          ${metricCard('Detected threats', 'detectedThreats', 'text-amber-700')}
          ${metricCard('Blocked requests/IPs', 'blockedCombined', 'text-rose-700')}
          ${metricCard('Avg latency', 'latency', 'text-sky-700')}
        </div>
        <div class="mt-6 grid gap-6 xl:grid-cols-[1fr_1fr]">
          <div class="rounded-lg border border-slate-200 bg-white p-4">
            <div class="mb-4 flex items-center justify-between">
              <h3 class="text-lg font-semibold">Threat distribution</h3>
              <span class="text-sm text-slate-500" id="redactions">0 redactions</span>
            </div>
            <canvas id="threatChart" height="150"></canvas>
          </div>
          <div class="rounded-lg border border-slate-200 bg-white p-4">
            <h3 class="mb-4 text-lg font-semibold">Endpoint activity</h3>
            ${table(['Endpoint', 'Count', 'Errors', 'Latency'], 'endpointRows', 4)}
          </div>
        </div>
      </section>

      <section class="panel mt-6 hidden" id="events">
        <div class="rounded-lg border border-slate-200 bg-white p-4">
          <h3 class="mb-4 text-lg font-semibold">Recent security events</h3>
          ${table(['Time', 'IP', 'Endpoint', 'Threat', 'Risk', 'Action'], 'eventRows', 6)}
        </div>
      </section>

      <section class="panel mt-6 hidden" id="clients">
        <div class="rounded-lg border border-slate-200 bg-white p-4">
          <h3 class="mb-4 text-lg font-semibold">Client identity monitoring</h3>
          ${table(['Client', 'Last IP', 'Requests', 'Changes', 'Fingerprints'], 'clientRows', 5)}
        </div>
        <div class="mt-6 rounded-lg border border-slate-200 bg-white p-4">
          <h3 class="mb-4 text-lg font-semibold">Recent request dataset captured</h3>
          ${table(['Time', 'Client', 'IP', 'Endpoint', 'UA'], 'requestRows', 5)}
        </div>
      </section>

      <section class="panel mt-6 hidden" id="settings">
        <form id="settingsForm" class="grid gap-4 rounded-lg border border-slate-200 bg-white p-4 md:grid-cols-2 xl:grid-cols-3">
          ${numberInput('Rate limit max', 'rateLimit.max', config.rateLimit.max)}
          ${numberInput('Rate window ms', 'rateLimit.windowMs', config.rateLimit.windowMs)}
          ${numberInput('Block threshold', 'block.threshold', config.block.threshold)}
          ${numberInput('Block duration ms', 'block.durationMs', config.block.durationMs)}
          ${numberInput('Medium risk threshold', 'anomaly.mediumThreshold', config.anomaly.mediumThreshold)}
          ${numberInput('High risk threshold', 'anomaly.highThreshold', config.anomaly.highThreshold)}
          ${numberInput('Critical risk threshold', 'anomaly.criticalThreshold', config.anomaly.criticalThreshold)}
          ${numberInput('Single endpoint max', 'anomaly.singleEndpointMax', config.anomaly.singleEndpointMax)}
          ${numberInput('Failed auth max', 'anomaly.failedAuthMax', config.anomaly.failedAuthMax)}
          ${numberInput('Dashboard refresh ms', 'dashboard.refreshMs', refreshMs)}
          ${checkboxInput('Rate limit enabled', 'rateLimit.enabled', config.rateLimit.enabled)}
          ${checkboxInput('Temporary block enabled', 'block.enabled', config.block.enabled)}
          ${checkboxInput('Redaction enabled', 'redaction.enabled', config.redaction.enabled)}
          ${checkboxInput('Testing client overrides', 'testing.allowClientOverrides', config.testing.allowClientOverrides)}
          ${checkboxInput('Helmet enabled', 'helmet.enabled', config.helmet.enabled)}
          ${checkboxInput('CSP enabled', 'helmet.contentSecurityPolicy', config.helmet.contentSecurityPolicy)}
          <label class="md:col-span-2 xl:col-span-3">
            <span class="text-sm font-medium text-slate-700">Redaction fields</span>
            <textarea class="mt-2 h-24 w-full rounded-md border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500" name="redaction.fields">${escapeHtml(config.redaction.fields.join(', '))}</textarea>
          </label>
          <div class="md:col-span-2 xl:col-span-3">
            <button class="rounded-md bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-700" type="submit">Save settings</button>
            <span class="ml-3 text-sm text-slate-500" id="settingsMessage"></span>
          </div>
        </form>
      </section>
    </main>
  </div>

<script>
const baseUrl = '${escapeJsString(dashboardBaseUrl)}';
const statsUrl = baseUrl + '/api/stats';
const settingsUrl = baseUrl + '/api/settings';
let refreshMs = ${refreshMs};
let timer;
let chart;
const fmt = new Intl.NumberFormat();

document.querySelectorAll('.nav').forEach(button => {
  button.addEventListener('click', () => showPanel(button.dataset.panel));
});
document.getElementById('settingsForm').addEventListener('submit', saveSettings);

function showPanel(id) {
  document.querySelectorAll('.panel').forEach(panel => panel.classList.toggle('hidden', panel.id !== id));
  document.querySelectorAll('.nav').forEach(button => button.classList.toggle('bg-emerald-50', button.dataset.panel === id));
}

async function loadStats() {
  const res = await fetch(statsUrl);
  const data = await res.json();
  refreshMs = Number(data.config.dashboard.refreshMs || refreshMs);
  document.getElementById('updatedAt').textContent = 'Updated ' + new Date().toLocaleTimeString();
  document.getElementById('refreshLabel').textContent = Math.round(refreshMs / 1000) + ' sec';
  document.getElementById('totalRequests').textContent = fmt.format(data.totalRequests);
  document.getElementById('detectedThreats').textContent = fmt.format(data.detectedThreats);
  document.getElementById('blockedCombined').textContent = fmt.format(data.blockedRequests) + '/' + fmt.format(data.blockedIps.length);
  document.getElementById('latency').textContent = data.averageLatencyMs + ' ms';
  document.getElementById('redactions').textContent = fmt.format(data.redactions) + ' redactions';
  renderEndpoints(data.endpoints || []);
  renderEvents(data.recentEvents || []);
  renderClients(data.clients || []);
  renderRequests(data.recentRequests || []);
  renderChart(data.threatDistribution || []);
  schedule();
}

async function saveSettings(event) {
  event.preventDefault();
  const data = new FormData(event.target);
  const payload = {};
  for (const [key, value] of data.entries()) setDeep(payload, key, value);
  ['rateLimit.enabled','block.enabled','redaction.enabled','testing.allowClientOverrides','helmet.enabled','helmet.contentSecurityPolicy'].forEach(key => {
    if (!data.has(key)) setDeep(payload, key, false);
  });
  const res = await fetch(settingsUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) });
  const settings = await res.json();
  refreshMs = Number(settings.dashboard.refreshMs || refreshMs);
  document.getElementById('settingsMessage').textContent = 'Saved';
  schedule();
}

function schedule() {
  clearTimeout(timer);
  timer = setTimeout(loadStats, Math.max(5000, refreshMs));
}

function renderEndpoints(rows) {
  document.getElementById('endpointRows').innerHTML = rows.map(row => '<tr><td class="py-2 pr-3">' + clean(row.method + ' ' + row.endpoint) + '</td><td class="py-2 pr-3">' + row.count + '</td><td class="py-2 pr-3">' + row.errors + '</td><td class="py-2 pr-3">' + Number(row.avgLatencyMs || 0).toFixed(1) + ' ms</td></tr>').join('') || emptyRow(4, 'No traffic yet');
}
function renderEvents(rows) {
  document.getElementById('eventRows').innerHTML = rows.map(row => '<tr><td class="py-2 pr-3 text-slate-500">' + clean(new Date(row.timestamp).toLocaleTimeString()) + '</td><td class="py-2 pr-3">' + clean(row.ip) + '</td><td class="py-2 pr-3">' + clean(row.method + ' ' + row.endpoint) + '</td><td class="py-2 pr-3 text-amber-700">' + clean(row.threat) + '</td><td class="py-2 pr-3">' + clean(row.riskLevel) + ' (' + row.riskScore + ')</td><td class="py-2 pr-3">' + clean(row.action) + '</td></tr>').join('') || emptyRow(6, 'No security events yet');
}
function renderClients(rows) {
  document.getElementById('clientRows').innerHTML = rows.map(row => '<tr><td class="py-2 pr-3 font-mono text-xs">' + clean(row.clientId) + '</td><td class="py-2 pr-3">' + clean(row.lastIp) + '</td><td class="py-2 pr-3">' + row.requestCount + '</td><td class="py-2 pr-3">' + row.changes + '</td><td class="py-2 pr-3">' + (row.fingerprints || []).length + '</td></tr>').join('') || emptyRow(5, 'No clients yet');
}
function renderRequests(rows) {
  document.getElementById('requestRows').innerHTML = rows.map(row => '<tr><td class="py-2 pr-3 text-slate-500">' + clean(new Date(row.timestamp).toLocaleTimeString()) + '</td><td class="py-2 pr-3 font-mono text-xs">' + clean(row.clientId || '') + '</td><td class="py-2 pr-3">' + clean(row.ip) + '</td><td class="py-2 pr-3">' + clean(row.method + ' ' + row.endpoint) + '</td><td class="py-2 pr-3 max-w-md truncate">' + clean(row.userAgent) + '</td></tr>').join('') || emptyRow(5, 'No request capture yet');
}
function renderChart(rows) {
  const labels = rows.map(row => row.name);
  const values = rows.map(row => row.count);
  if (!chart) {
    chart = new Chart(document.getElementById('threatChart'), {
      type: 'bar',
      data: { labels, datasets: [{ label: 'Events', data: values, backgroundColor: '#059669' }] },
      options: { plugins: { legend: { display: false } }, scales: { x: { ticks: { color: '#475569' }, grid: { color: '#e2e8f0' } }, y: { ticks: { color: '#475569' }, grid: { color: '#e2e8f0' } } } }
    });
  } else {
    chart.data.labels = labels;
    chart.data.datasets[0].data = values;
    chart.update();
  }
}
function emptyRow(cols, label) {
  return '<tr><td class="py-4 text-slate-500" colspan="' + cols + '">' + label + '</td></tr>';
}
function setDeep(target, path, value) {
  const parts = path.split('.');
  let current = target;
  while (parts.length > 1) {
    const part = parts.shift();
    current[part] = current[part] || {};
    current = current[part];
  }
  current[parts[0]] = value;
}
function clean(value) {
  return String(value || '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[char]));
}
showPanel('overview');
loadStats();
</script>
</body>
</html>`;
}

function renderLogin(config, failed) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>iri-shield login</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-slate-50 text-slate-950">
  <main class="flex min-h-screen items-center justify-center px-4">
    <form method="post" action="${escapeHtml(config.dashboard.path || '/iri-shield')}/login" class="w-full max-w-sm rounded-lg border border-slate-200 bg-white p-6 shadow-sm">
      <p class="text-sm font-semibold uppercase tracking-wide text-emerald-700">${escapeHtml(config.appName)}</p>
      <h1 class="mt-1 text-2xl font-semibold">iri-shield dashboard</h1>
      ${failed ? '<p class="mt-4 rounded-md border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-700">Invalid username or password.</p>' : ''}
      <label class="mt-5 block text-sm font-medium text-slate-700" for="username">Username</label>
      <input class="mt-2 w-full rounded-md border border-slate-300 px-3 py-2 outline-none focus:border-emerald-500" id="username" name="username" autocomplete="username" required />
      <label class="mt-4 block text-sm font-medium text-slate-700" for="password">Password</label>
      <input class="mt-2 w-full rounded-md border border-slate-300 px-3 py-2 outline-none focus:border-emerald-500" id="password" name="password" type="password" autocomplete="current-password" required />
      <button class="mt-6 w-full rounded-md bg-emerald-600 px-4 py-2 font-medium text-white hover:bg-emerald-700" type="submit">Login</button>
    </form>
  </main>
</body>
</html>`;
}

function metricCard(label, id, colorClass) {
  return `<article class="rounded-lg border border-slate-200 bg-white p-4">
    <p class="text-sm text-slate-500">${label}</p>
    <p class="mt-2 text-3xl font-semibold ${colorClass}" id="${id}">0</p>
  </article>`;
}

function table(headers, id, cols) {
  return `<div class="overflow-x-auto">
    <table class="w-full text-left text-sm">
      <thead class="text-slate-500">
        <tr>${headers.map((header) => `<th class="pb-2 pr-3 font-medium">${header}</th>`).join('')}</tr>
      </thead>
      <tbody id="${id}" class="divide-y divide-slate-100">${emptyServerRow(cols)}</tbody>
    </table>
  </div>`;
}

function numberInput(label, name, value) {
  return `<label><span class="text-sm font-medium text-slate-700">${label}</span><input class="mt-2 w-full rounded-md border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500" type="number" name="${name}" value="${escapeHtml(value)}" /></label>`;
}

function checkboxInput(label, name, checked) {
  return `<label class="flex items-center gap-3 rounded-md border border-slate-200 px-3 py-2 text-sm font-medium text-slate-700"><input class="h-4 w-4 accent-emerald-600" type="checkbox" name="${name}" ${checked ? 'checked' : ''} />${label}</label>`;
}

function emptyServerRow(cols) {
  return `<tr><td class="py-4 text-slate-500" colspan="${cols}">Loading</td></tr>`;
}

function publicConfig(config) {
  const copy = JSON.parse(JSON.stringify(config));
  if (copy.dashboard?.password) copy.dashboard.password = '';
  return copy;
}

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(String(left));
  const rightBuffer = Buffer.from(String(right));
  if (leftBuffer.length !== rightBuffer.length) return false;
  return timingSafeEqual(leftBuffer, rightBuffer);
}

function parseCookies(cookieHeader = '') {
  return String(cookieHeader).split(';').reduce((cookies, pair) => {
    const [rawKey, ...rawValue] = pair.trim().split('=');
    if (!rawKey) return cookies;
    cookies[decodeURIComponent(rawKey)] = decodeURIComponent(rawValue.join('='));
    return cookies;
  }, {});
}

function getPath(object, path) {
  return path.split('.').reduce((current, key) => current?.[key], object);
}

function setPath(object, path, value) {
  const parts = path.split('.');
  let current = object;
  while (parts.length > 1) {
    const key = parts.shift();
    current[key] = current[key] || {};
    current = current[key];
  }
  current[parts[0]] = value;
}

function clamp(value, min, max) {
  if (!Number.isFinite(value)) return min;
  return Math.max(min, Math.min(max, value));
}

function escapeHtml(value) {
  return String(value || '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[char]));
}

function escapeJsString(value) {
  return String(value || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

module.exports = { createDashboardRouter };
