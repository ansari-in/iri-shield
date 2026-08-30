'use strict';

const http = require('http');
const express = require('express');
const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');
const { createShield } = require('../src/index.js');

const NUM_REQUESTS = parseInt(process.env.BENCHMARK_REQUESTS || '1000', 10);
const CONCURRENCY = parseInt(process.env.BENCHMARK_CONCURRENCY || '20', 10);

const ATTACK_VECTORS = [
  { path: "/api/search?q=' OR 1=1--", expectedBlocked: true, name: "SQL Injection" },
  { path: "/api/comment?text=<script>alert(1)</script>", expectedBlocked: true, name: "XSS Pattern" },
  { path: "/api/files?file=../../../../etc/passwd", expectedBlocked: true, name: "Path Traversal" },
  { path: "/api/view?t={{7*7}}", expectedBlocked: true, name: "SSTI Template" },
  { path: "/api/users?user=admin", headers: { "user-agent": "sqlmap/1.7#stable" }, expectedBlocked: true, name: "Scanner Bot (sqlmap)" },
  { path: "/.env", expectedBlocked: true, name: "Secret Probe (.env)" }
];

const CLEAN_VECTORS = [
  { path: "/api/health", name: "Health Check" },
  { path: "/api/users/profile", name: "User Profile" },
  { path: "/api/items?category=electronics&page=1", name: "Catalog Search" },
  { path: "/api/articles/123", name: "Article Fetch" }
];

function createBaselineApp() {
  const app = express();
  app.use(express.json());
  app.get('/api/health', (req, res) => res.json({ status: 'ok' }));
  app.get('/api/users/profile', (req, res) => res.json({ user: 'john_doe', role: 'member' }));
  app.get('/api/items', (req, res) => res.json({ items: [{ id: 1, name: 'Item A' }] }));
  app.get('/api/articles/:id', (req, res) => res.json({ id: req.params.id, title: 'Sample' }));
  app.get('/api/search', (req, res) => res.json({ results: [] }));
  app.get('/api/comment', (req, res) => res.json({ status: 'saved' }));
  app.get('/api/files', (req, res) => res.json({ file: 'none' }));
  app.get('/api/view', (req, res) => res.json({ view: 'rendered' }));
  app.get('/.env', (req, res) => res.status(404).send('Not Found'));
  return app;
}

function createShieldApp() {
  const app = express();
  app.use(express.json());
  const shield = createShield({
    appName: 'benchmark-shield',
    security: 'medium',
    logger: false,
    dashboard: { enabled: false },
    rateLimit: { max: 500, windowMs: 60000 },
    storage: { mode: 'memory' }
  });
  app.use(shield.middleware);
  app.get('/api/health', (req, res) => res.json({ status: 'ok' }));
  app.get('/api/users/profile', (req, res) => res.json({ user: 'john_doe', role: 'member' }));
  app.get('/api/items', (req, res) => res.json({ items: [{ id: 1, name: 'Item A' }] }));
  app.get('/api/articles/:id', (req, res) => res.json({ id: req.params.id, title: 'Sample' }));
  app.get('/api/search', (req, res) => res.json({ results: [] }));
  app.get('/api/comment', (req, res) => res.json({ status: 'saved' }));
  app.get('/api/files', (req, res) => res.json({ file: 'none' }));
  app.get('/api/view', (req, res) => res.json({ view: 'rendered' }));
  app.get('/.env', (req, res) => res.status(404).send('Not Found'));
  return { app, shield };
}

function makeRequest(port, target) {
  return new Promise((resolve) => {
    const start = performance.now();
    const options = {
      hostname: '127.0.0.1',
      port,
      path: encodeURI(target.path),
      method: 'GET',
      headers: target.headers || { 'user-agent': 'BenchmarkClient/1.0' }
    };
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        const duration = performance.now() - start;
        resolve({
          statusCode: res.statusCode,
          duration,
          blocked: res.statusCode === 403 || res.statusCode === 429
        });
      });
    });
    req.on('error', () => {
      const duration = performance.now() - start;
      resolve({ statusCode: 500, duration, blocked: false });
    });
    req.end();
  });
}

async function runLoadTest(port, isShielded) {
  const latencies = [];
  let blockedCount = 0;
  let totalClean = 0;
  let falsePositives = 0;
  let totalAttacks = 0;
  let attacksBlocked = 0;

  const startHeap = process.memoryUsage().heapUsed;
  const overallStart = performance.now();

  let reqIndex = 0;
  async function worker() {
    while (reqIndex < NUM_REQUESTS) {
      const idx = reqIndex++;
      const isAttack = idx % 5 === 0;
      let target;
      if (isAttack) {
        target = ATTACK_VECTORS[idx % ATTACK_VECTORS.length];
        totalAttacks++;
      } else {
        target = CLEAN_VECTORS[idx % CLEAN_VECTORS.length];
        totalClean++;
      }
      const clientIp = `192.168.1.${(idx % 40) + 1}`;
      const headers = Object.assign({
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'accept-language': 'en-US,en;q=0.9',
        'x-forwarded-for': clientIp
      }, target.headers || {});

      const res = await makeRequest(port, { ...target, headers });
      latencies.push(res.duration);
      if (res.blocked) blockedCount++;
      if (isAttack && res.blocked) attacksBlocked++;
      if (!isAttack && res.blocked) falsePositives++;
    }
  }

  const workers = [];
  for (let i = 0; i < CONCURRENCY; i++) workers.push(worker());
  await Promise.all(workers);

  const overallDuration = (performance.now() - overallStart) / 1000;
  const endHeap = process.memoryUsage().heapUsed;

  latencies.sort((a, b) => a - b);
  const avgLatency = latencies.reduce((a, b) => a + b, 0) / latencies.length;
  const p50 = latencies[Math.floor(latencies.length * 0.50)] || 0;
  const p90 = latencies[Math.floor(latencies.length * 0.90)] || 0;
  const p95 = latencies[Math.floor(latencies.length * 0.95)] || 0;
  const p99 = latencies[Math.floor(latencies.length * 0.99)] || 0;
  const throughput = Math.round(NUM_REQUESTS / overallDuration);

  return {
    totalRequests: NUM_REQUESTS,
    durationSec: Number(overallDuration.toFixed(2)),
    throughputReqSec: throughput,
    latency: {
      avgMs: Number(avgLatency.toFixed(2)),
      p50Ms: Number(p50.toFixed(2)),
      p90Ms: Number(p90.toFixed(2)),
      p95Ms: Number(p95.toFixed(2)),
      p99Ms: Number(p99.toFixed(2))
    },
    memory: {
      heapUsedMbBefore: Number((startHeap / 1024 / 1024).toFixed(2)),
      heapUsedMbAfter: Number((endHeap / 1024 / 1024).toFixed(2)),
      diffMb: Number(((endHeap - startHeap) / 1024 / 1024).toFixed(2))
    },
    security: isShielded ? {
      totalAttacksSent: totalAttacks,
      attacksMitigated: attacksBlocked,
      detectionRatePct: totalAttacks > 0 ? Number(((attacksBlocked / totalAttacks) * 100).toFixed(1)) : 0,
      cleanRequestsSent: totalClean,
      falsePositives: falsePositives,
      falsePositiveRatePct: totalClean > 0 ? Number(((falsePositives / totalClean) * 100).toFixed(2)) : 0
    } : null
  };
}

async function main() {
  console.log("================================================================================");
  console.log("             iri-shield Built-in Automated Benchmark Suite                      ");
  console.log("================================================================================");
  console.log(`Requests: ${NUM_REQUESTS} | Concurrency: ${CONCURRENCY} workers\n`);

  const baselineApp = createBaselineApp();
  const baselineServer = baselineApp.listen(0);
  const baselinePort = baselineServer.address().port;

  const { app: shieldApp } = createShieldApp();
  const shieldServer = shieldApp.listen(0);
  const shieldPort = shieldServer.address().port;

  console.log(`[1/2] Benchmarking Baseline Express App on port ${baselinePort}...`);
  const baselineResults = await runLoadTest(baselinePort, false);
  console.log(`  -> Completed in ${baselineResults.durationSec}s (${baselineResults.throughputReqSec} req/s, avg ${baselineResults.latency.avgMs}ms)`);

  console.log(`[2/2] Benchmarking iri-shield Middleware on port ${shieldPort}...`);
  const shieldResults = await runLoadTest(shieldPort, true);
  console.log(`  -> Completed in ${shieldResults.durationSec}s (${shieldResults.throughputReqSec} req/s, avg ${shieldResults.latency.avgMs}ms)`);

  baselineServer.close();
  shieldServer.close();

  const overheadMs = Number((shieldResults.latency.avgMs - baselineResults.latency.avgMs).toFixed(2));
  const throughputImpactPct = Number((((baselineResults.throughputReqSec - shieldResults.throughputReqSec) / baselineResults.throughputReqSec) * 100).toFixed(1));

  const comparison = {
    timestamp: new Date().toISOString(),
    benchmarkConfig: { requests: NUM_REQUESTS, concurrency: CONCURRENCY },
    overheadSummary: {
      latencyOverheadAvgMs: overheadMs,
      throughputImpactPercent: throughputImpactPct,
      attackDetectionRate: `${shieldResults.security.detectionRatePct}%`,
      falsePositiveRate: `${shieldResults.security.falsePositiveRatePct}%`
    },
    baseline: baselineResults,
    shield: shieldResults
  };

  const resultsDir = path.join(__dirname, '../results');
  if (!fs.existsSync(resultsDir)) fs.mkdirSync(resultsDir, { recursive: true });

  fs.writeFileSync(path.join(resultsDir, 'baseline.json'), JSON.stringify(baselineResults, null, 2));
  fs.writeFileSync(path.join(resultsDir, 'shield.json'), JSON.stringify(shieldResults, null, 2));
  fs.writeFileSync(path.join(resultsDir, 'comparison.json'), JSON.stringify(comparison, null, 2));

  console.log("\n================================================================================");
  console.log("                           BENCHMARK COMPARISON RESULTS                         ");
  console.log("================================================================================");
  console.log(`Metric                   | Baseline       | iri-shield     | Delta / Overhead   `);
  console.log(`-------------------------|----------------|----------------|--------------------`);
  console.log(`Throughput               | ${String(baselineResults.throughputReqSec).padEnd(14)} | ${String(shieldResults.throughputReqSec).padEnd(14)} | -${throughputImpactPct}% throughput`);
  console.log(`Avg Latency              | ${String(baselineResults.latency.avgMs + ' ms').padEnd(14)} | ${String(shieldResults.latency.avgMs + ' ms').padEnd(14)} | +${overheadMs} ms overhead`);
  console.log(`p50 Latency              | ${String(baselineResults.latency.p50Ms + ' ms').padEnd(14)} | ${String(shieldResults.latency.p50Ms + ' ms').padEnd(14)} | +${Number((shieldResults.latency.p50Ms - baselineResults.latency.p50Ms).toFixed(2))} ms`);
  console.log(`p95 Latency              | ${String(baselineResults.latency.p95Ms + ' ms').padEnd(14)} | ${String(shieldResults.latency.p95Ms + ' ms').padEnd(14)} | +${Number((shieldResults.latency.p95Ms - baselineResults.latency.p95Ms).toFixed(2))} ms`);
  console.log(`p99 Latency              | ${String(baselineResults.latency.p99Ms + ' ms').padEnd(14)} | ${String(shieldResults.latency.p99Ms + ' ms').padEnd(14)} | +${Number((shieldResults.latency.p99Ms - baselineResults.latency.p99Ms).toFixed(2))} ms`);
  console.log(`Memory Delta             | ${String(baselineResults.memory.diffMb + ' MB').padEnd(14)} | ${String(shieldResults.memory.diffMb + ' MB').padEnd(14)} | +${Number((shieldResults.memory.diffMb - baselineResults.memory.diffMb).toFixed(2))} MB`);
  console.log(`Detection Rate           | N/A            | ${String(shieldResults.security.detectionRatePct + '%').padEnd(14)} | Mitigated ${shieldResults.security.attacksMitigated}/${shieldResults.security.totalAttacksSent} attacks`);
  console.log(`False Positive Rate      | N/A            | ${String(shieldResults.security.falsePositiveRatePct + '%').padEnd(14)} | ${shieldResults.security.falsePositives} false alarms`);
  console.log("================================================================================");
  console.log(`Results saved to:`);
  console.log(`  - results/baseline.json`);
  console.log(`  - results/shield.json`);
  console.log(`  - results/comparison.json\n`);
}

main().catch(console.error);
