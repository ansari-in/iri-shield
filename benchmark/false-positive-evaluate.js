'use strict';

const http = require('http');
const express = require('express');
const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');
const { createShield } = require('../src/index.js');

const RESULTS_DIR = path.join(__dirname, '..', 'results');
if (!fs.existsSync(RESULTS_DIR)) fs.mkdirSync(RESULTS_DIR, { recursive: true });

const NUM_LEGIT_REQUESTS = parseInt(process.env.FP_REQUESTS || '10000', 10);
const CONCURRENCY = parseInt(process.env.FP_CONCURRENCY || '25', 10);

const LEGIT_ENDPOINTS = [
  { path: "/api/products?page=1&limit=20&sort=price_asc", method: "GET" },
  { path: "/api/search?q=men%27s%20leather%20jackets", method: "GET" }, // contains legitimate apostrophe: men's
  { path: "/api/books?author=O%27Reilly%20Media", method: "GET" },      // contains legitimate apostrophe: O'Reilly
  { path: "/api/users/profile", method: "GET" },
  { path: "/api/cart/items", method: "GET" },
  { path: "/api/comments", method: "POST", body: { name: "Alice", comment: "This is a great tutorial! I'm really enjoying it." } },
  { path: "/api/feedback", method: "POST", body: { rating: 5, feedback: "Fast delivery & nice packaging, 10/10 recommended." } },
  { path: "/api/articles/4921", method: "GET" },
  { path: "/api/category/electronics/laptops?brand=Dell&ram=16GB", method: "GET" },
  { path: "/api/support/tickets", method: "POST", body: { subject: "Invoice question", details: "Can you send the invoice for order #54321?" } }
];

const LEGIT_USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
  "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
];

function startTestServer() {
  const app = express();
  app.use(express.json());

  const shield = createShield({
    appName: 'fp-eval-shield',
    security: 'medium',
    logger: false,
    dashboard: { enabled: false },
    rateLimit: { max: 100000, windowMs: 60000 }, // High limit so rate-limiting doesn't count as false positive threat detection
    storage: { mode: 'memory' }
  });

  app.use(shield.middleware);
  app.use((req, res) => res.status(200).json({ status: 'ok', endpoint: req.url }));

  const server = app.listen(0);
  const port = server.address().port;
  return { server, port, shield };
}

function makeRequest(port, testIndex) {
  return new Promise((resolve) => {
    const template = LEGIT_ENDPOINTS[testIndex % LEGIT_ENDPOINTS.length];
    const userAgent = LEGIT_USER_AGENTS[testIndex % LEGIT_USER_AGENTS.length];
    const clientIp = `10.10.${(testIndex % 200) + 1}.${(Math.floor(testIndex / 200) % 250) + 1}`;
    const bodyData = template.body ? JSON.stringify(template.body) : null;

    const headers = {
      'user-agent': userAgent,
      'x-forwarded-for': clientIp,
      'accept-language': 'en-US,en;q=0.9',
      'accept': 'application/json, text/plain, */*'
    };

    if (template.method === 'POST' && bodyData) {
      headers['content-type'] = 'application/json';
      headers['content-length'] = Buffer.byteLength(bodyData);
    }

    const options = {
      hostname: '127.0.0.1',
      port,
      path: encodeURI(template.path),
      method: template.method || 'GET',
      headers,
      timeout: 3000
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          isFalsePositive: res.statusCode === 403 || res.statusCode === 429
        });
      });
    });

    req.on('error', () => {
      resolve({ statusCode: 500, isFalsePositive: false });
    });

    if (bodyData) req.write(bodyData);
    req.end();
  });
}

async function runFalsePositiveEvaluation() {
  console.log("================================================================================");
  console.log("        iri-shield Large-Scale False Positive Rate (FPR) Evaluation             ");
  console.log("================================================================================");
  console.log(`Evaluating ${NUM_LEGIT_REQUESTS.toLocaleString()} legitimate production-style requests...`);
  console.log(`Concurrency: ${CONCURRENCY} workers | Rotating IPs across 10.10.x.x pool\n`);

  const { server, port, shield } = startTestServer();
  const overallStart = performance.now();

  let reqIndex = 0;
  let falsePositiveCount = 0;
  let passedCount = 0;

  async function worker() {
    while (reqIndex < NUM_LEGIT_REQUESTS) {
      const idx = reqIndex++;
      const res = await makeRequest(port, idx);
      if (res.isFalsePositive) {
        falsePositiveCount++;
      } else {
        passedCount++;
      }
    }
  }

  const workers = [];
  for (let i = 0; i < CONCURRENCY; i++) workers.push(worker());
  await Promise.all(workers);

  const durationSec = Number(((performance.now() - overallStart) / 1000).toFixed(2));
  server.close();

  const fprPct = Number(((falsePositiveCount / NUM_LEGIT_REQUESTS) * 100).toFixed(4));
  const throughput = Math.round(NUM_LEGIT_REQUESTS / durationSec);

  console.log("================================================================================");
  console.log("                       FALSE POSITIVE EVALUATION RESULTS                        ");
  console.log("================================================================================");
  console.log(`Total Legitimate Requests : ${NUM_LEGIT_REQUESTS.toLocaleString()}`);
  console.log(`Successfully Allowed (TN) : ${passedCount.toLocaleString()} (${(100 - fprPct).toFixed(2)}%)`);
  console.log(`False Positives (FP)      : ${falsePositiveCount}`);
  console.log(`False Positive Rate (FPR) : ${fprPct}%`);
  console.log(`Evaluation Duration       : ${durationSec}s (${throughput} req/s)`);
  console.log("================================================================================");

  // Write CSV
  const csvContent = [
    'Metric,Value',
    `Total_Legitimate_Requests,${NUM_LEGIT_REQUESTS}`,
    `True_Negatives_Passed,${passedCount}`,
    `False_Positives_Blocked,${falsePositiveCount}`,
    `False_Positive_Rate_Pct,${fprPct}`,
    `Throughput_Req_Sec,${throughput}`,
    `Duration_Sec,${durationSec}`
  ].join('\n');

  fs.writeFileSync(path.join(RESULTS_DIR, 'false_positives.csv'), csvContent);

  const jsonSummary = {
    timestamp: new Date().toISOString(),
    totalRequests: NUM_LEGIT_REQUESTS,
    passedCount,
    falsePositiveCount,
    falsePositiveRatePct: fprPct,
    durationSec,
    throughputReqSec: throughput
  };

  fs.writeFileSync(path.join(RESULTS_DIR, 'false_positives.json'), JSON.stringify(jsonSummary, null, 2));

  console.log(`Reports saved to:`);
  console.log(`  - results/false_positives.csv`);
  console.log(`  - results/false_positives.json\n`);

  return jsonSummary;
}

if (require.main === module) {
  runFalsePositiveEvaluation().catch(console.error);
}

module.exports = { runFalsePositiveEvaluation };
