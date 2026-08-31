'use strict';

const http = require('http');
const express = require('express');
const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');
const { createShield } = require('../src/index.js');

const RESULTS_DIR = path.join(__dirname, '..', 'results');
if (!fs.existsSync(RESULTS_DIR)) fs.mkdirSync(RESULTS_DIR, { recursive: true });

// Configurable workload configurations or matrix
const MATRIX_REQUESTS = process.env.BENCHMARK_REQUESTS_LIST
  ? process.env.BENCHMARK_REQUESTS_LIST.split(',').map(n => parseInt(n.trim(), 10))
  : [500, 1000, 2000];

const MATRIX_CONCURRENCY = process.env.BENCHMARK_CONCURRENCY_LIST
  ? process.env.BENCHMARK_CONCURRENCY_LIST.split(',').map(n => parseInt(n.trim(), 10))
  : [5, 15, 30];

const REPEATED_TRIALS = parseInt(process.env.BENCHMARK_TRIALS || '3', 10);
const WARMUP_REQUESTS = 150;

const ENDPOINTS = [
  { path: "/api/health", method: "GET" },
  { path: "/api/users/profile", method: "GET" },
  { path: "/api/items?category=electronics&page=1", method: "GET" },
  { path: "/api/articles/123", method: "GET" },
  { path: "/api/search?q=wireless%20headphones", method: "GET" }
];

function createBaselineApp() {
  const app = express();
  app.use(express.json());
  app.get('/api/health', (req, res) => res.json({ status: 'ok' }));
  app.get('/api/users/profile', (req, res) => res.json({ user: 'john_doe', role: 'member' }));
  app.get('/api/items', (req, res) => res.json({ items: [{ id: 1, name: 'Item A' }] }));
  app.get('/api/articles/:id', (req, res) => res.json({ id: req.params.id, title: 'Sample' }));
  app.get('/api/search', (req, res) => res.json({ results: [] }));
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
    rateLimit: { max: 100000, windowMs: 60000 },
    storage: { mode: 'memory' }
  });
  app.use(shield.middleware);
  app.get('/api/health', (req, res) => res.json({ status: 'ok' }));
  app.get('/api/users/profile', (req, res) => res.json({ user: 'john_doe', role: 'member' }));
  app.get('/api/items', (req, res) => res.json({ items: [{ id: 1, name: 'Item A' }] }));
  app.get('/api/articles/:id', (req, res) => res.json({ id: req.params.id, title: 'Sample' }));
  app.get('/api/search', (req, res) => res.json({ results: [] }));
  return { app, shield };
}

function makeRequest(port, idx) {
  return new Promise((resolve) => {
    const start = performance.now();
    const target = ENDPOINTS[idx % ENDPOINTS.length];
    const options = {
      hostname: '127.0.0.1',
      port,
      path: encodeURI(target.path),
      method: target.method,
      headers: {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 BenchmarkClient/1.0',
        'x-forwarded-for': `10.0.${(idx % 100) + 1}.${(Math.floor(idx / 100) % 250) + 1}`,
        'accept': 'application/json'
      }
    };
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        const duration = performance.now() - start;
        resolve({ statusCode: res.statusCode, duration });
      });
    });
    req.on('error', () => {
      resolve({ statusCode: 500, duration: performance.now() - start });
    });
    req.end();
  });
}

async function sendWarmup(port, count) {
  const promises = [];
  for (let i = 0; i < count; i++) {
    promises.push(makeRequest(port, i));
  }
  await Promise.all(promises);
}

async function executeLoadTrial(port, numRequests, concurrency) {
  const latencies = [];
  const startCpu = process.cpuUsage();
  const startHeap = process.memoryUsage().heapUsed;
  const overallStart = performance.now();

  let reqIndex = 0;
  async function worker() {
    while (reqIndex < numRequests) {
      const idx = reqIndex++;
      const res = await makeRequest(port, idx);
      latencies.push(res.duration);
    }
  }

  const workers = [];
  for (let i = 0; i < concurrency; i++) workers.push(worker());
  await Promise.all(workers);

  const durationSec = (performance.now() - overallStart) / 1000;
  const endHeap = process.memoryUsage().heapUsed;
  const cpuDiff = process.cpuUsage(startCpu);
  const totalCpuMicroseconds = cpuDiff.user + cpuDiff.system;
  
  const os = require('os');
  const numCores = os.cpus().length || 1;
  const coresUtilized = Number((totalCpuMicroseconds / (durationSec * 1000000)).toFixed(2));
  const normalizedCpuPercent = Number(((coresUtilized / numCores) * 100).toFixed(1));
  const processLoadPercent = Number((coresUtilized * 100).toFixed(1));

  latencies.sort((a, b) => a - b);
  const sum = latencies.reduce((a, b) => a + b, 0);
  const avg = sum / latencies.length;
  const median = latencies[Math.floor(latencies.length * 0.50)] || 0;
  const p90 = latencies[Math.floor(latencies.length * 0.90)] || 0;
  const p95 = latencies[Math.floor(latencies.length * 0.95)] || 0;
  const p99 = latencies[Math.floor(latencies.length * 0.99)] || 0;

  // Compute Standard Deviation (sigma)
  const variance = latencies.reduce((acc, val) => acc + Math.pow(val - avg, 2), 0) / latencies.length;
  const stdDev = Math.sqrt(variance);

  return {
    requests: numRequests,
    concurrency,
    durationSec: Number(durationSec.toFixed(3)),
    throughput: Math.round(numRequests / durationSec),
    coresUtilized,
    normalizedCpuPercent,
    cpuPercent: normalizedCpuPercent, // Standard system-normalized CPU
    processLoadPercent,               // Multi-core process load (where 100% = 1 core)
    heapDeltaMb: Number(((endHeap - startHeap) / 1024 / 1024).toFixed(2)),
    latency: {
      avg: Number(avg.toFixed(2)),
      median: Number(median.toFixed(2)),
      stdDev: Number(stdDev.toFixed(2)),
      p90: Number(p90.toFixed(2)),
      p95: Number(p95.toFixed(2)),
      p99: Number(p99.toFixed(2))
    }
  };
}

function aggregateTrials(trials) {
  const n = trials.length;
  const avgThroughput = Math.round(trials.reduce((sum, t) => sum + t.throughput, 0) / n);
  const avgLatency = Number((trials.reduce((sum, t) => sum + t.latency.avg, 0) / n).toFixed(2));
  const avgMedian = Number((trials.reduce((sum, t) => sum + t.latency.median, 0) / n).toFixed(2));
  const avgStdDev = Number((trials.reduce((sum, t) => sum + t.latency.stdDev, 0) / n).toFixed(2));
  const avgP95 = Number((trials.reduce((sum, t) => sum + t.latency.p95, 0) / n).toFixed(2));
  const avgP99 = Number((trials.reduce((sum, t) => sum + t.latency.p99, 0) / n).toFixed(2));
  const avgCores = Number((trials.reduce((sum, t) => sum + t.coresUtilized, 0) / n).toFixed(2));
  const avgCpu = Number((trials.reduce((sum, t) => sum + t.normalizedCpuPercent, 0) / n).toFixed(1));
  const avgProcessLoad = Number((trials.reduce((sum, t) => sum + t.processLoadPercent, 0) / n).toFixed(1));
  const avgHeapDelta = Number((trials.reduce((sum, t) => sum + t.heapDeltaMb, 0) / n).toFixed(2));

  return {
    throughput: avgThroughput,
    coresUtilized: avgCores,
    normalizedCpuPercent: avgCpu,
    cpuPercent: avgCpu,
    processLoadPercent: avgProcessLoad,
    heapDeltaMb: avgHeapDelta,
    latency: {
      avg: avgLatency,
      median: avgMedian,
      stdDev: avgStdDev,
      p95: avgP95,
      p99: avgP99
    }
  };
}

async function runPerformanceBenchmark() {
  console.log("================================================================================");
  console.log("       iri-shield Multi-Workload Scientific Performance Benchmark Matrix        ");
  console.log("================================================================================");
  console.log(`Workloads Matrix : Requests ${JSON.stringify(MATRIX_REQUESTS)} × Concurrency ${JSON.stringify(MATRIX_CONCURRENCY)}`);
  console.log(`Repeated Trials  : ${REPEATED_TRIALS} runs per configuration (computing Mean, Median, StdDev, p95, p99)`);
  console.log(`Warm-up Phase    : ${WARMUP_REQUESTS} initial requests per server to stabilize V8 JIT\n`);

  // Start Baseline App
  const baselineApp = createBaselineApp();
  const baselineServer = baselineApp.listen(0);
  const baselinePort = baselineServer.address().port;

  // Start Shield App
  const { app: shieldApp } = createShieldApp();
  const shieldServer = shieldApp.listen(0);
  const shieldPort = shieldServer.address().port;

  console.log(`[Warm-up] Warming up V8 JIT compiler on baseline (port ${baselinePort}) and shield (port ${shieldPort})...`);
  await sendWarmup(baselinePort, WARMUP_REQUESTS);
  await sendWarmup(shieldPort, WARMUP_REQUESTS);
  console.log(`[Warm-up] Warmup completed. Beginning measured matrix execution.\n`);

  const matrixResults = [];
  const csvRows = [
    [
      'Requests', 'Concurrency', 'Trials',
      'Baseline_Throughput_ReqSec', 'Shield_Throughput_ReqSec', 'Throughput_Delta_Pct',
      'Baseline_Avg_Latency_ms', 'Shield_Avg_Latency_ms', 'Latency_Overhead_ms',
      'Baseline_Median_ms', 'Shield_Median_ms',
      'Baseline_StdDev_ms', 'Shield_StdDev_ms',
      'Baseline_p95_ms', 'Shield_p95_ms',
      'Baseline_p99_ms', 'Shield_p99_ms',
      'Baseline_Cores_Utilized', 'Shield_Cores_Utilized',
      'Baseline_Normalized_CPU_Pct', 'Shield_Normalized_CPU_Pct',
      'Baseline_Heap_MB', 'Shield_Heap_MB'
    ]
  ];

  for (const reqCount of MATRIX_REQUESTS) {
    for (const concurrency of MATRIX_CONCURRENCY) {
      process.stdout.write(`Benchmarking Workload: ${reqCount} reqs @ ${concurrency} workers (${REPEATED_TRIALS} trials)... `);

      const baselineTrials = [];
      const shieldTrials = [];

      for (let t = 0; t < REPEATED_TRIALS; t++) {
        const bRes = await executeLoadTrial(baselinePort, reqCount, concurrency);
        baselineTrials.push(bRes);
        const sRes = await executeLoadTrial(shieldPort, reqCount, concurrency);
        shieldTrials.push(sRes);
      }

      const baselineAgg = aggregateTrials(baselineTrials);
      const shieldAgg = aggregateTrials(shieldTrials);

      const latencyOverhead = Number((shieldAgg.latency.avg - baselineAgg.latency.avg).toFixed(2));
      const throughputImpact = Number((((baselineAgg.throughput - shieldAgg.throughput) / baselineAgg.throughput) * 100).toFixed(1));

      const entry = {
        requests: reqCount,
        concurrency,
        trials: REPEATED_TRIALS,
        baseline: baselineAgg,
        shield: shieldAgg,
        comparison: {
          throughputImpactPercent: throughputImpact,
          latencyOverheadAvgMs: latencyOverhead,
          p95DeltaMs: Number((shieldAgg.latency.p95 - baselineAgg.latency.p95).toFixed(2)),
          p99DeltaMs: Number((shieldAgg.latency.p99 - baselineAgg.latency.p99).toFixed(2)),
          cpuOverheadPercent: Number((shieldAgg.normalizedCpuPercent - baselineAgg.normalizedCpuPercent).toFixed(1))
        }
      };

      matrixResults.push(entry);

      csvRows.push([
        reqCount, concurrency, REPEATED_TRIALS,
        baselineAgg.throughput, shieldAgg.throughput, `${throughputImpact}%`,
        baselineAgg.latency.avg, shieldAgg.latency.avg, latencyOverhead,
        baselineAgg.latency.median, shieldAgg.latency.median,
        baselineAgg.latency.stdDev, shieldAgg.latency.stdDev,
        baselineAgg.latency.p95, shieldAgg.latency.p95,
        baselineAgg.latency.p99, shieldAgg.latency.p99,
        baselineAgg.coresUtilized, shieldAgg.coresUtilized,
        `${baselineAgg.normalizedCpuPercent}%`, `${shieldAgg.normalizedCpuPercent}%`,
        baselineAgg.heapDeltaMb, shieldAgg.heapDeltaMb
      ]);

      console.log(`Done! [Overhead: +${latencyOverhead}ms, Throughput: ${baselineAgg.throughput} vs ${shieldAgg.throughput} req/s]`);
    }
  }

  baselineServer.close();
  shieldServer.close();

  console.log("\n================================================================================");
  console.log("               SCIENTIFIC PERFORMANCE EVALUATION SUMMARY MATRIX                 ");
  console.log("================================================================================");
  console.log("Workload       | Throughput (Req/s)    | Avg Latency (ms)      | p95 Latency (ms)     | Host CPU (%)  | Cores Utilized");
  console.log("Reqs @ Concurr | Baseline   | Shield   | Baseline  | Shield    | Baseline  | Shield   | Base | Shield | Base  | Shield");
  console.log("---------------|------------|----------|-----------|-----------|-----------|----------|------|--------|-------|-------");

  for (const m of matrixResults) {
    const wl = `${m.requests} @ c=${m.concurrency}`.padEnd(14);
    const bt = String(m.baseline.throughput).padEnd(10);
    const st = String(m.shield.throughput).padEnd(8);
    const bl = String(m.baseline.latency.avg + ' ms').padEnd(9);
    const sl = String(m.shield.latency.avg + ' ms').padEnd(9);
    const bp95 = String(m.baseline.latency.p95 + ' ms').padEnd(9);
    const sp95 = String(m.shield.latency.p95 + ' ms').padEnd(8);
    const bcpu = String(m.baseline.normalizedCpuPercent + '%').padEnd(4);
    const scpu = String(m.shield.normalizedCpuPercent + '%').padEnd(6);
    const bcores = String(m.baseline.coresUtilized).padEnd(5);
    const scores = String(m.shield.coresUtilized).padEnd(6);
    console.log(`${wl} | ${bt} | ${st} | ${bl} | ${sl} | ${bp95} | ${sp95} | ${bcpu} | ${scpu} | ${bcores} | ${scores}`);
  }

  console.log("================================================================================");
  console.log("Note: Host CPU % is normalized against host logical cores (" + (require('os').cpus().length || 1) + " cores).");
  console.log("      Cores Utilized represents total multi-threaded v8/libuv process core saturation.");

  // Write CSV
  const csvContent = csvRows.map(r => r.join(',')).join('\n');
  fs.writeFileSync(path.join(RESULTS_DIR, 'performance.csv'), csvContent);

  // Write JSON
  const summaryJson = {
    timestamp: new Date().toISOString(),
    configurations: {
      requests: MATRIX_REQUESTS,
      concurrency: MATRIX_CONCURRENCY,
      trials: REPEATED_TRIALS,
      warmupRequests: WARMUP_REQUESTS
    },
    results: matrixResults
  };

  fs.writeFileSync(path.join(RESULTS_DIR, 'comparison.json'), JSON.stringify(summaryJson, null, 2));

  console.log(`Reports saved to:`);
  console.log(`  - results/performance.csv`);
  console.log(`  - results/comparison.json\n`);

  return summaryJson;
}

if (require.main === module) {
  runPerformanceBenchmark().catch(console.error);
}

module.exports = { runPerformanceBenchmark };
