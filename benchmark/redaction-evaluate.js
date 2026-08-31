'use strict';

const fs = require('fs');
const path = require('path');
const { redactPayload } = require('../src/redactor.js');

const DATASET_PATH = path.join(__dirname, 'datasets', 'redaction-samples.json');
const RESULTS_DIR = path.join(__dirname, '..', 'results');

if (!fs.existsSync(RESULTS_DIR)) fs.mkdirSync(RESULTS_DIR, { recursive: true });

async function runRedactionEvaluation() {
  console.log("================================================================================");
  console.log("     iri-shield Sensitive Data & PII Automated Redaction Evaluation             ");
  console.log("================================================================================");

  if (!fs.existsSync(DATASET_PATH)) {
    console.error(`Dataset not found at ${DATASET_PATH}.`);
    process.exit(1);
  }

  const dataset = JSON.parse(fs.readFileSync(DATASET_PATH, 'utf8'));
  console.log(`Evaluating ${dataset.length} sensitive PII & token response payloads...\n`);

  const categoryStats = {};
  let totalEvaluated = dataset.length;
  let totalCorrect = 0;
  let totalExpectedRedactions = 0;
  let totalActualRedactions = 0;
  let falseRedactionCount = 0;

  const redactionOptions = {
    mask: '[REDACTED]',
    fields: [
      'password', 'token', 'accessToken', 'refreshToken',
      'authorization', 'apiKey', 'secret', 'ssn',
      'aadhaar', 'email', 'contactEmail', 'phone', 'customerPhone', 'creditCard', 'cvv'
    ]
  };

  const results = [];

  for (const sample of dataset) {
    if (!categoryStats[sample.category]) {
      categoryStats[sample.category] = {
        total: 0,
        correct: 0,
        expectedRedactions: 0,
        actualRedactions: 0,
        overMasked: 0
      };
    }
    categoryStats[sample.category].total += 1;
    categoryStats[sample.category].expectedRedactions += sample.expectedRedactions;
    totalExpectedRedactions += sample.expectedRedactions;

    const result = redactPayload(sample.payload, redactionOptions);
    categoryStats[sample.category].actualRedactions += result.redactions;
    totalActualRedactions += result.redactions;

    // Check if clean control was over-masked
    if (sample.category === 'CLEAN_CONTROL' && result.redactions > 0) {
      falseRedactionCount += 1;
      categoryStats[sample.category].overMasked += 1;
    }

    // Accurate if all expected sensitive items were masked and clean controls unmasked
    const isAccurate = sample.category === 'CLEAN_CONTROL'
      ? result.redactions === 0
      : result.redactions >= sample.expectedRedactions;

    if (isAccurate) {
      totalCorrect += 1;
      categoryStats[sample.category].correct += 1;
    }

    results.push({
      id: sample.id,
      category: sample.category,
      expectedRedactions: sample.expectedRedactions,
      actualRedactions: result.redactions,
      isAccurate
    });
  }

  console.log("================================================================================");
  console.log("                     SENSITIVE DATA REDACTION MATRIX                            ");
  console.log("================================================================================");
  console.log(`Category             | Test Cases | Correct  | Expected Redact | Actual Redact | Accuracy % `);
  console.log(`---------------------|------------|----------|-----------------|---------------|------------`);

  const csvRows = [
    ['Category', 'Total_Cases', 'Correct', 'Expected_Redactions', 'Actual_Redactions', 'Accuracy_Pct']
  ];

  for (const [cat, stat] of Object.entries(categoryStats)) {
    const accuracy = Number(((stat.correct / stat.total) * 100).toFixed(1));
    console.log(
      `${cat.padEnd(20)} | ${String(stat.total).padEnd(10)} | ${String(stat.correct).padEnd(8)} | ${String(stat.expectedRedactions).padEnd(15)} | ${String(stat.actualRedactions).padEnd(13)} | ${String(accuracy + '%').padEnd(10)}`
    );
    csvRows.push([cat, stat.total, stat.correct, stat.expectedRedactions, stat.actualRedactions, accuracy]);
  }

  const overallAccuracyPct = Number(((totalCorrect / totalEvaluated) * 100).toFixed(1));
  const cleanTotal = categoryStats['CLEAN_CONTROL'] ? categoryStats['CLEAN_CONTROL'].total : 1;
  const falseRedactionRatePct = Number(((falseRedactionCount / cleanTotal) * 100).toFixed(2));

  console.log("================================================================================");
  console.log(`Total Payloads Evaluated : ${totalEvaluated}`);
  console.log(`Accurately Masked / Kept : ${totalCorrect}`);
  console.log(`Overall Redaction Accuracy: ${overallAccuracyPct}%`);
  console.log(`False Redaction (Overmask): ${falseRedactionRatePct}%`);
  console.log("================================================================================");

  // Write CSV
  const csvContent = csvRows.map(row => row.join(',')).join('\n');
  fs.writeFileSync(path.join(RESULTS_DIR, 'redaction.csv'), csvContent);

  const jsonSummary = {
    timestamp: new Date().toISOString(),
    totalEvaluated,
    totalCorrect,
    overallAccuracyPct,
    falseRedactionRatePct,
    categoryStats
  };

  fs.writeFileSync(path.join(RESULTS_DIR, 'redaction.json'), JSON.stringify(jsonSummary, null, 2));

  console.log(`Reports saved to:`);
  console.log(`  - results/redaction.csv`);
  console.log(`  - results/redaction.json\n`);

  return jsonSummary;
}

if (require.main === module) {
  runRedactionEvaluation().catch(console.error);
}

module.exports = { runRedactionEvaluation };
