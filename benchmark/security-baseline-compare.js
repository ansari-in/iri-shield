'use strict';

const http = require('http');
const express = require('express');
const fs = require('fs');
const path = require('path');
const { createShield } = require('../src/index.js');

const DATASET_PATH = path.join(__dirname, 'datasets', 'attacks.json');
const RESULTS_DIR = path.join(__dirname, '..', 'results');

if (!fs.existsSync(RESULTS_DIR)) fs.mkdirSync(RESULTS_DIR, { recursive: true });

function startUnprotectedServer() {
  const app = express();
  app.use(express.json());
  app.use(express.text({ type: ['text/*', 'application/xml', '*/*'] }));

  app.use((req, res) => {
    res.status(200).json({
      status: 'success',
      receivedUrl: req.url,
      method: req.method,
      body: req.body || null
    });
  });

  // Express error handler
  app.use((err, req, res, next) => {
    res.status(400).json({ error: 'invalid_payload' });
  });

  const server = app.listen(0);
  const port = server.address().port;
  return { server, port };
}

function startShieldServer() {
  const app = express();
  app.use(express.json());
  app.use(express.text({ type: ['text/*', 'application/xml', '*/*'] }));

  const shield = createShield({
    appName: 'security-eval-shield',
    security: 'medium',
    logger: false,
    dashboard: { enabled: false },
    block: { threshold: 60, enabled: true },
    rateLimit: { max: 5000, windowMs: 60000 },
    storage: { mode: 'memory' }
  });

  app.use(shield.middleware);

  app.use((req, res) => {
    res.status(200).json({
      status: 'success',
      receivedUrl: req.url,
      method: req.method,
      body: req.body || null
    });
  });

  // Express error handler
  app.use((err, req, res, next) => {
    res.status(400).json({ error: 'invalid_payload' });
  });

  const server = app.listen(0);
  const port = server.address().port;
  return { server, port, shield };
}

function sendAttack(port, testCase) {
  return new Promise((resolve) => {
    const isStringBody = typeof testCase.body === 'string';
    const bodyData = isStringBody ? testCase.body : (testCase.body ? JSON.stringify(testCase.body) : null);
    const headers = Object.assign({}, testCase.headers || { 'user-agent': 'SecurityBaselineTester/1.0' });

    if (bodyData) {
      headers['content-type'] = isStringBody ? 'application/xml' : 'application/json';
      headers['content-length'] = Buffer.byteLength(bodyData);
    }

    let parsedPath = testCase.url;
    try {
      parsedPath = encodeURI(testCase.url);
    } catch (_) {
      parsedPath = testCase.url;
    }

    const options = {
      hostname: '127.0.0.1',
      port,
      path: parsedPath,
      method: testCase.method || 'GET',
      headers,
      timeout: 3000
    };

    let req;
    try {
      req = http.request(options, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          const isBlocked = res.statusCode === 403 || res.statusCode === 429;
          resolve({
            id: testCase.id,
            category: testCase.category,
            statusCode: res.statusCode,
            mitigated: isBlocked
          });
        });
      });
    } catch (_) {
      return resolve({
        id: testCase.id,
        category: testCase.category,
        statusCode: 400,
        mitigated: false
      });
    }

    req.on('error', () => {
      resolve({
        id: testCase.id,
        category: testCase.category,
        statusCode: 500,
        mitigated: false
      });
    });

    if (bodyData) req.write(bodyData);
    req.end();
  });
}

async function runSecurityBaselineComparison() {
  console.log("================================================================================");
  console.log("   iri-shield Security Baseline Comparison (Vanilla Express vs. Express + Shield)");
  console.log("================================================================================");

  const attacks = JSON.parse(fs.readFileSync(DATASET_PATH, 'utf8'));
  console.log(`Evaluating ${attacks.length} attack vectors across both server configurations...\n`);

  const unprot = startUnprotectedServer();
  const shld = startShieldServer();

  const baselineResults = [];
  const shieldResults = [];

  for (const atk of attacks) {
    const bRes = await sendAttack(unprot.port, atk);
    baselineResults.push(bRes);
    const sRes = await sendAttack(shld.port, atk);
    shieldResults.push(sRes);
  }

  unprot.server.close();
  shld.server.close();

  // Aggregate category-wise comparison
  const categories = {};
  for (let i = 0; i < attacks.length; i++) {
    const atk = attacks[i];
    const b = baselineResults[i];
    const s = shieldResults[i];

    if (!categories[atk.category]) {
      categories[atk.category] = { total: 0, baselineMitigated: 0, shieldMitigated: 0 };
    }
    categories[atk.category].total += 1;
    if (b.mitigated) categories[atk.category].baselineMitigated += 1;
    if (s.mitigated) categories[atk.category].shieldMitigated += 1;
  }

  console.log("================================================================================");
  console.log("                 SECURITY BASELINE COMPARISON MATRIX                            ");
  console.log("================================================================================");
  console.log(`Threat Category      | Test Cases | Vanilla Express | Express + iri-shield | Delta (Defense Gain) `);
  console.log(`---------------------|------------|-----------------|----------------------|----------------------`);

  const csvRows = [
    ['Threat_Category', 'Total_Cases', 'Vanilla_Express_Mitigated_Pct', 'iri_shield_Mitigated_Pct', 'Defense_Gain_Pct']
  ];

  let totalAttacks = attacks.length;
  let totalBaseMitigated = 0;
  let totalShieldMitigated = 0;

  for (const [cat, stat] of Object.entries(categories)) {
    const basePct = Number(((stat.baselineMitigated / stat.total) * 100).toFixed(1));
    const shieldPct = Number(((stat.shieldMitigated / stat.total) * 100).toFixed(1));
    const gainPct = Number((shieldPct - basePct).toFixed(1));

    totalBaseMitigated += stat.baselineMitigated;
    totalShieldMitigated += stat.shieldMitigated;

    console.log(
      `${cat.padEnd(20)} | ${String(stat.total).padEnd(10)} | ${String(basePct + '% (' + stat.baselineMitigated + ')').padEnd(15)} | ${String(shieldPct + '% (' + stat.shieldMitigated + ')').padEnd(20)} | +${gainPct}%`
    );

    csvRows.push([cat, stat.total, `${basePct}%`, `${shieldPct}%`, `+${gainPct}%`]);
  }

  const totalBasePct = Number(((totalBaseMitigated / totalAttacks) * 100).toFixed(1));
  const totalShieldPct = Number(((totalShieldMitigated / totalAttacks) * 100).toFixed(1));
  const totalGainPct = Number((totalShieldPct - totalBasePct).toFixed(1));

  console.log("================================================================================");
  console.log(`OVERALL COMPARISON   | ${String(totalAttacks).padEnd(10)} | ${String(totalBasePct + '% (' + totalBaseMitigated + ')').padEnd(15)} | ${String(totalShieldPct + '% (' + totalShieldMitigated + ')').padEnd(20)} | +${totalGainPct}%`);
  console.log("================================================================================");

  // Write CSV
  const csvContent = csvRows.map(r => r.join(',')).join('\n');
  fs.writeFileSync(path.join(RESULTS_DIR, 'security_baseline_comparison.csv'), csvContent);

  const jsonSummary = {
    timestamp: new Date().toISOString(),
    totalAttacks,
    vanillaExpress: { totalMitigated: totalBaseMitigated, mitigationRatePct: totalBasePct },
    iriShield: { totalMitigated: totalShieldMitigated, mitigationRatePct: totalShieldPct },
    netDefenseGainPct: totalGainPct,
    categories
  };

  fs.writeFileSync(path.join(RESULTS_DIR, 'security_baseline_comparison.json'), JSON.stringify(jsonSummary, null, 2));

  console.log(`Reports saved to:`);
  console.log(`  - results/security_baseline_comparison.csv`);
  console.log(`  - results/security_baseline_comparison.json\n`);

  return jsonSummary;
}

if (require.main === module) {
  runSecurityBaselineComparison().catch(console.error);
}

module.exports = { runSecurityBaselineComparison };
