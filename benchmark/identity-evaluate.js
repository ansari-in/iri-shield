'use strict';

const fs = require('fs');
const path = require('path');
const { createShield } = require('../src/index.js');
const { buildClientContext, detectIdentityChange } = require('../src/identity.js');

const DATASET_PATH = path.join(__dirname, 'datasets', 'identity-scenarios.json');
const RESULTS_DIR = path.join(__dirname, '..', 'results');

if (!fs.existsSync(RESULTS_DIR)) fs.mkdirSync(RESULTS_DIR, { recursive: true });

async function runIdentityEvaluation() {
  console.log("================================================================================");
  console.log("     iri-shield Multi-Signal Identity Continuity & Drift Evaluation             ");
  console.log("================================================================================");

  if (!fs.existsSync(DATASET_PATH)) {
    console.error(`Dataset not found at ${DATASET_PATH}.`);
    process.exit(1);
  }

  const dataset = JSON.parse(fs.readFileSync(DATASET_PATH, 'utf8'));
  console.log(`Evaluating ${dataset.length} controlled identity state-machine scenarios...\n`);

  const shield = createShield({
    appName: 'identity-eval-shield',
    security: 'medium',
    logger: false,
    dashboard: { enabled: false },
    testing: { enabled: true, allowClientOverrides: true },
    storage: { mode: 'memory' }
  });

  const typeStats = {};
  let totalEvaluated = dataset.length;
  let correctlyEvaluated = 0;
  let totalDriftsDetected = 0;
  let falseDriftCount = 0;

  const results = [];

  for (const scenario of dataset) {
    if (!typeStats[scenario.type]) {
      typeStats[scenario.type] = { total: 0, correctlyIdentified: 0, avgPenalty: 0, totalPenalty: 0 };
    }
    typeStats[scenario.type].total += 1;

    // Construct request mock
    const reqMock = {
      headers: {
        'user-agent': scenario.userAgent,
        'x-forwarded-for': scenario.ip,
        'x-iri-test-user-id': scenario.userId,
        'x-iri-test-client-id': scenario.clientId,
        'x-iri-test-device-id': scenario.deviceId
      },
      cookies: {},
      ip: scenario.ip,
      url: scenario.url,
      method: 'GET'
    };

    const resMock = { setHeader: () => {}, getHeader: () => null };
    const client = buildClientContext(reqMock, resMock, shield.config);
    const knownClient = shield.storage.clients.get(client.clientId) || null;
    const sameUserClients = shield.storage.findClientsByUserId(client.userId);
    const identityChange = detectIdentityChange(client, knownClient || sameUserClients[0]);

    // Record client in storage
    shield.storage.recordClient(client);

    const hasDrift = identityChange.score > 0;
    const isCorrect = scenario.expectedDrift ? hasDrift : !hasDrift;

    if (isCorrect) correctlyEvaluated += 1;
    if (hasDrift) totalDriftsDetected += 1;
    if (!scenario.expectedDrift && hasDrift) falseDriftCount += 1;

    typeStats[scenario.type].totalPenalty += identityChange.score;
    if (isCorrect) typeStats[scenario.type].correctlyIdentified += 1;

    results.push({
      id: scenario.id,
      type: scenario.type,
      userId: scenario.userId,
      expectedDrift: scenario.expectedDrift,
      detectedDrift: hasDrift,
      penaltyAssigned: identityChange.score,
      threats: identityChange.threats.join('; ')
    });
  }

  console.log("================================================================================");
  console.log("                     IDENTITY CONTINUITY EVALUATION MATRIX                      ");
  console.log("================================================================================");
  console.log(`Scenario Type         | Test Cases | Correct  | Avg Penalty Assigned | Accuracy % `);
  console.log(`----------------------|------------|----------|----------------------|------------`);

  const csvRows = [
    ['Scenario_Type', 'Total_Cases', 'Correctly_Identified', 'Avg_Penalty_Assigned', 'Accuracy_Pct']
  ];

  for (const [type, stat] of Object.entries(typeStats)) {
    const accuracy = Number(((stat.correctlyIdentified / stat.total) * 100).toFixed(1));
    const avgPenalty = Number((stat.totalPenalty / stat.total).toFixed(1));
    console.log(
      `${type.padEnd(21)} | ${String(stat.total).padEnd(10)} | ${String(stat.correctlyIdentified).padEnd(8)} | ${String(avgPenalty + ' pts').padEnd(20)} | ${String(accuracy + '%').padEnd(10)}`
    );
    csvRows.push([type, stat.total, stat.correctlyIdentified, avgPenalty, accuracy]);
  }

  const overallAccuracyPct = Number(((correctlyEvaluated / totalEvaluated) * 100).toFixed(1));
  const falseDriftPct = Number(((falseDriftCount / (typeStats['BASELINE_NORMAL'] ? typeStats['BASELINE_NORMAL'].total : 1)) * 100).toFixed(2));

  console.log("================================================================================");
  console.log(`Total Identity Scenarios : ${totalEvaluated}`);
  console.log(`Correctly Profiled       : ${correctlyEvaluated}`);
  console.log(`Overall Identity Accuracy: ${overallAccuracyPct}%`);
  console.log(`False Drift Alert Rate   : ${falseDriftPct}%`);
  console.log("================================================================================");

  // Write CSV
  const csvContent = csvRows.map(row => row.join(',')).join('\n');
  fs.writeFileSync(path.join(RESULTS_DIR, 'identity.csv'), csvContent);

  const jsonSummary = {
    timestamp: new Date().toISOString(),
    totalEvaluated,
    correctlyEvaluated,
    overallAccuracyPct,
    falseDriftPct,
    typeStats,
    resultsSample: results.slice(0, 50)
  };

  fs.writeFileSync(path.join(RESULTS_DIR, 'identity.json'), JSON.stringify(jsonSummary, null, 2));

  console.log(`Reports saved to:`);
  console.log(`  - results/identity.csv`);
  console.log(`  - results/identity.json\n`);

  return jsonSummary;
}

if (require.main === module) {
  runIdentityEvaluation().catch(console.error);
}

module.exports = { runIdentityEvaluation };
