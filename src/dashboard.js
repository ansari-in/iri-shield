'use strict';

const express = require('express');
const { randomBytes, timingSafeEqual } = require('crypto');

function createDashboardRouter({ storage, config }) {
  const router = express.Router();
  const auth = dashboardAuth(config.dashboard);

  router.use(express.urlencoded({ extended: false }));

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
    res.json(storage.getStats());
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

function renderDashboard(config, baseUrl) {
  const dashboardBaseUrl = String(baseUrl || '/iri-shield').replace(/\/$/, '');
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>iri-shield dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body class="min-h-screen bg-zinc-950 text-zinc-100">
  <main class="mx-auto flex min-h-screen w-full max-w-7xl flex-col gap-6 px-4 py-6 sm:px-6 lg:px-8">
    <header class="flex flex-col gap-3 border-b border-zinc-800 pb-5 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <p class="text-sm font-medium uppercase tracking-wide text-emerald-300">${escapeHtml(config.appName)}</p>
        <h1 class="mt-1 text-3xl font-semibold text-white">iri-shield security dashboard</h1>
      </div>
      <div class="flex items-center gap-3">
        <div class="text-sm text-zinc-400" id="updatedAt">Loading</div>
        <form method="post" action="./logout">
          <button class="rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-200 hover:bg-zinc-800" type="submit">Logout</button>
        </form>
      </div>
    </header>

    <section class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <article class="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
        <p class="text-sm text-zinc-400">Total API requests</p>
        <p class="mt-2 text-3xl font-semibold" id="totalRequests">0</p>
      </article>
      <article class="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
        <p class="text-sm text-zinc-400">Detected threats</p>
        <p class="mt-2 text-3xl font-semibold text-amber-300" id="detectedThreats">0</p>
      </article>
      <article class="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
        <p class="text-sm text-zinc-400">Blocked requests/IPs</p>
        <p class="mt-2 text-3xl font-semibold text-rose-300"><span id="blockedRequests">0</span>/<span id="blockedIps">0</span></p>
      </article>
      <article class="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
        <p class="text-sm text-zinc-400">Avg latency</p>
        <p class="mt-2 text-3xl font-semibold text-sky-300"><span id="latency">0</span> ms</p>
      </article>
    </section>

    <section class="grid gap-6 lg:grid-cols-[1fr_1fr]">
      <div class="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
        <div class="mb-4 flex items-center justify-between">
          <h2 class="text-lg font-semibold">Threat distribution</h2>
          <span class="text-sm text-zinc-400" id="redactions">0 redactions</span>
        </div>
        <canvas id="threatChart" height="160"></canvas>
      </div>
      <div class="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
        <h2 class="mb-4 text-lg font-semibold">Endpoint activity</h2>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm">
            <thead class="text-zinc-400">
              <tr><th class="pb-2">Endpoint</th><th class="pb-2">Count</th><th class="pb-2">Errors</th><th class="pb-2">Latency</th></tr>
            </thead>
            <tbody id="endpointRows" class="divide-y divide-zinc-800"></tbody>
          </table>
        </div>
      </div>
    </section>

    <section class="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
      <h2 class="mb-4 text-lg font-semibold">Recent security events</h2>
      <div class="overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead class="text-zinc-400">
            <tr><th class="pb-2">Time</th><th class="pb-2">IP</th><th class="pb-2">Endpoint</th><th class="pb-2">Threat</th><th class="pb-2">Risk</th><th class="pb-2">Action</th></tr>
          </thead>
          <tbody id="eventRows" class="divide-y divide-zinc-800"></tbody>
        </table>
      </div>
    </section>
  </main>

<script>
const statsUrl = '${escapeJsString(dashboardBaseUrl)}/api/stats';
let chart;
const fmt = new Intl.NumberFormat();
async function loadStats() {
  const res = await fetch(statsUrl);
  const data = await res.json();
  document.getElementById('updatedAt').textContent = 'Updated ' + new Date().toLocaleTimeString();
  document.getElementById('totalRequests').textContent = fmt.format(data.totalRequests);
  document.getElementById('detectedThreats').textContent = fmt.format(data.detectedThreats);
  document.getElementById('blockedRequests').textContent = fmt.format(data.blockedRequests);
  document.getElementById('blockedIps').textContent = fmt.format(data.blockedIps.length);
  document.getElementById('latency').textContent = data.averageLatencyMs;
  document.getElementById('redactions').textContent = fmt.format(data.redactions) + ' redactions';
  renderEndpoints(data.endpoints);
  renderEvents(data.recentEvents);
  renderChart(data.threatDistribution);
}
function renderEndpoints(rows) {
  document.getElementById('endpointRows').innerHTML = rows.map(row => '<tr><td class="py-2 pr-3 text-zinc-200">' + clean(row.method + ' ' + row.endpoint) + '</td><td class="py-2 pr-3">' + row.count + '</td><td class="py-2 pr-3">' + row.errors + '</td><td class="py-2 pr-3">' + Number(row.avgLatencyMs || 0).toFixed(1) + ' ms</td></tr>').join('') || '<tr><td class="py-4 text-zinc-500" colspan="4">No traffic yet</td></tr>';
}
function renderEvents(rows) {
  document.getElementById('eventRows').innerHTML = rows.map(row => '<tr><td class="py-2 pr-3 text-zinc-400">' + clean(new Date(row.timestamp).toLocaleTimeString()) + '</td><td class="py-2 pr-3">' + clean(row.ip) + '</td><td class="py-2 pr-3">' + clean(row.method + ' ' + row.endpoint) + '</td><td class="py-2 pr-3 text-amber-200">' + clean(row.threat) + '</td><td class="py-2 pr-3">' + clean(row.riskLevel) + ' (' + row.riskScore + ')</td><td class="py-2 pr-3">' + clean(row.action) + '</td></tr>').join('') || '<tr><td class="py-4 text-zinc-500" colspan="6">No security events yet</td></tr>';
}
function renderChart(rows) {
  const labels = rows.map(row => row.name);
  const values = rows.map(row => row.count);
  if (!chart) {
    chart = new Chart(document.getElementById('threatChart'), {
      type: 'bar',
      data: { labels, datasets: [{ label: 'Events', data: values, backgroundColor: '#34d399' }] },
      options: { plugins: { legend: { display: false } }, scales: { x: { ticks: { color: '#a1a1aa' }, grid: { color: '#27272a' } }, y: { ticks: { color: '#a1a1aa' }, grid: { color: '#27272a' } } } }
    });
  } else {
    chart.data.labels = labels;
    chart.data.datasets[0].data = values;
    chart.update();
  }
}
function clean(value) {
  return String(value || '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[char]));
}
loadStats();
setInterval(loadStats, 5000);
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
<body class="min-h-screen bg-zinc-950 text-zinc-100">
  <main class="flex min-h-screen items-center justify-center px-4">
    <form method="post" action="./login" class="w-full max-w-sm rounded-lg border border-zinc-800 bg-zinc-900 p-6">
      <p class="text-sm font-medium uppercase tracking-wide text-emerald-300">${escapeHtml(config.appName)}</p>
      <h1 class="mt-1 text-2xl font-semibold text-white">iri-shield dashboard</h1>
      ${failed ? '<p class="mt-4 rounded-md border border-rose-800 bg-rose-950 px-3 py-2 text-sm text-rose-200">Invalid username or password.</p>' : ''}
      <label class="mt-5 block text-sm text-zinc-300" for="username">Username</label>
      <input class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-white outline-none focus:border-emerald-400" id="username" name="username" autocomplete="username" required />
      <label class="mt-4 block text-sm text-zinc-300" for="password">Password</label>
      <input class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-white outline-none focus:border-emerald-400" id="password" name="password" type="password" autocomplete="current-password" required />
      <button class="mt-6 w-full rounded-md bg-emerald-400 px-4 py-2 font-medium text-zinc-950 hover:bg-emerald-300" type="submit">Login</button>
    </form>
  </main>
</body>
</html>`;
}

function escapeHtml(value) {
  return String(value || '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[char]));
}

function escapeJsString(value) {
  return String(value || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

module.exports = { createDashboardRouter };
