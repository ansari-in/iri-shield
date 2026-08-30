# 🛡️ iri-shield

[![npm version](https://img.shields.io/badge/npm-v1.2.0-blue.svg)](https://www.npmjs.com/package/iri-shield)
[![License: ISC](https://img.shields.io/badge/License-ISC-emerald.svg)](https://opensource.org/licenses/ISC)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22.0.0-purple.svg)](https://nodejs.org)
[![Security](https://img.shields.io/badge/security-explainable--ai-orange.svg)](#-explainable-risk-scoring)
[![Privacy](https://img.shields.io/badge/privacy-by--design-teal.svg)](#-privacy-by-design)

> **Enterprise-grade API security middleware for Express.js** featuring **Explainable Risk Scoring**, **Multi-Signal Identity Continuity Analysis**, **Behavioural Anomaly Detection**, **Attack Sequence Correlation**, **Configurable Rule Engine**, **Automated PII/Secret Redaction**, and an **Interactive Real-Time Admin Dashboard**.

---

## 📑 Table of Contents

- [Architectural Philosophy](#-architectural-philosophy)
- [Key Features](#-key-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Explainable Risk Scoring](#-explainable-risk-scoring)
- [Multi-Signal Identity Continuity](#-multi-signal-identity-continuity)
- [Security Rule Engine](#-security-rule-engine)
- [Behavioural Anomaly & Correlation](#-behavioural-anomaly--correlation)
- [Privacy Controls & Fail-Safe Modes](#-privacy-controls--fail-safe-modes)
- [Interactive Admin Dashboard](#-interactive-admin-dashboard)
- [Automated Benchmarking](#-automated-benchmarking)
- [Full Configuration Reference](#-full-configuration-reference)
- [Security & Auth Utilities](#-security--auth-utilities)
- [Academic & Research Defense](#-academic--research-defense)
- [License](#-license)

---

## 🏛️ Architectural Philosophy

Modern web threats exploit fragmented signals across rotating IP pools, forged User-Agents, and multi-step evasion techniques. Traditional WAFs rely solely on static signatures or opaque binary decisions.

`iri-shield` introduces a **transparent, multi-layered defense model**:

```text
Incoming HTTP Request
         │
         ├──► 1. Base Security (Helmet Headers, CORS, Fail-Safe Policy)
         ├──► 2. Identity Continuity Engine (IP + Session + Client Hints + Drift Analysis)
         ├──► 3. Configurable Rule Engine (SQLi, XSS, Path Traversal, SSTI, Custom Rules)
         ├──► 4. Behavioural Baseline (Rolling 5-min RPM & Deviation Tracking)
         ├──► 5. Attack Sequence Correlation (Multi-Step Recon & Takeover Chains)
         ├──► 6. Explainable Risk Scorer (Transparent Point Breakdown + Confidence Score)
         ├──► 7. Automated Mitigation (Rate-Limit, Temporary Block, Permanent Block)
         └──► 8. Automated Response & Log Redaction (PII Masking)
```

---

## ✨ Key Features

| Capability | Description |
| :--- | :--- |
| **🔍 Explainable Risk Scoring** | Provides a transparent, auditable breakdown table (`+30 SQLi`, `+20 Sensitive Endpoint`, `+15 Identity Drift`) with a mathematical **Confidence Score (0-100%)**. |
| **🧬 Multi-Signal Profiling** | Evaluates **Identity Continuity** using IP address, session tokens, Client Hints (`sec-ch-ua`, `sec-ch-ua-platform`), user-agents, accept headers, and device context to detect evasion attempts without violating user privacy. |
| **⚙️ Configurable Rule Engine** | Individually toggle built-in threat detection rules or declare flexible **Custom Rules** (by endpoint, method, IP prefix, user-agent regex, or body fields). |
| **📈 Behavioural Baselining** | Continuously learns normal per-endpoint request rates (RPM) and flags statistical anomalies (`Behaviour deviation: 92%`). |
| **🔗 Attack Sequence Correlation** | Evaluates ordered request chains to detect advanced multi-step campaigns (e.g., *Failed Auth ×3 → User Enumeration → Admin Access*). |
| **🔒 Privacy by Design** | Built-in SHA-256 IP hashing for persistent storage and automatic FIFO retention purging (`retentionDays: 30`). |
| **🛡️ Fail-Safe Policies** | Choose between `fail-open` (resilience first) and `fail-closed` (strict containment) on internal subsystem failures. |
| **📊 Built-in Benchmark Suite** | Automated performance comparison against baseline unshielded servers (`npm run benchmark`) measuring throughput, latency percentiles (p50/p95/p99), and defense efficacy. |
| **🖥️ Light-Theme Dashboard** | Enterprise management interface for real-time monitoring, reactive IP block/unblock, active alerts, security event forensics, and live configuration updates. |
| **🎭 Deep PII/Secret Redaction** | Deep redaction for passwords, API keys, bearer tokens, emails, phone numbers, SSNs, Aadhaar numbers, and credit cards across responses and log storage. |

---

## 📦 Installation

```bash
npm install iri-shield
```

> **Requirements**: Node.js **>= 22.0.0** recommended for native SQLite (`node:sqlite`) support.

---

## ⚡ Quick Start

```js
const express = require('express');
const { createShield, apiKeyAuth } = require('iri-shield');

const app = express();
app.use(express.json());

// Initialize iri-shield
const shield = createShield({
  appName: 'secure-api',
  security: 'medium', // 'low' | 'medium' | 'high'
  storage: {
    mode: 'sqlite',
    sqliteFile: './data/iri-shield.sqlite'
  },
  dashboard: {
    enabled: true,
    path: '/iri-shield',
    username: 'admin',
    password: 'admin'
  }
});

// Attach security middleware
app.use(shield.middleware);

// Attach admin dashboard
app.use('/iri-shield', shield.dashboard);

// Example protected endpoint
app.get('/api/users', apiKeyAuth('my-secret-key'), (req, res) => {
  res.json({
    status: 'success',
    token: 'jwt-secret-token-abc', // Automatically redacted to [REDACTED]
    email: 'alex@example.com'      // Automatically redacted to [REDACTED]
  });
});

app.listen(3000, () => {
  console.log('🚀 Server running on http://localhost:3000');
  console.log('📊 Dashboard available at http://localhost:3000/iri-shield');
});
```

---

## 🔍 Explainable Risk Scoring

Every intercepted security event produces a transparent **Score Breakdown**:

```json
{
  "score": 85,
  "riskLevel": "high",
  "confidence": 92,
  "action": "temporary_block",
  "breakdown": [
    { "rule": "sql_injection", "points": 40, "category": "injection", "confidence": 90, "label": "SQL Injection pattern" },
    { "rule": "sensitive_endpoint_access", "points": 20, "category": "anomaly", "confidence": 80, "label": "Access to sensitive endpoint: /admin" },
    { "rule": "correlated_attack_account_takeover", "points": 25, "category": "correlation", "confidence": 88, "label": "Possible account takeover / reconnaissance" }
  ]
}
```

In the **Admin Dashboard**, expanding any Security Event displays this structured breakdown table, enabling instant auditability for security analysts.

---

## 🧬 Multi-Signal Identity Continuity

Rather than claiming "guaranteed unique identification" (which is technically invalid across modern NATs and VPNs), `iri-shield` evaluates **Identity Continuity**:

```text
Known Client Profile (C-89a1)
├── Baseline Hardware Hash
├── Platform & Client Hints (Windows / Chrome 120)
└── Established Sessions
      │
      ▼
Sudden Switch Detected:
  • New IP (203.0.113.88)
  • Missing Modern Sec-Fetch Headers
  • Identity Drift Count: +1
      │
      ▼
Action: Risk Score Penalty (+15 pts) applied to request
```

---

## ⚙️ Security Rule Engine

Toggle built-in detection modules or supply flexible custom rules:

```js
const shield = createShield({
  rules: {
    sqlInjection: true,
    xss: true,
    pathTraversal: true,
    commandInjection: true,
    ssti: true,
    nosqlInjection: true,
    secretProbe: true,
    scannerDetection: true,
    openRedirect: true,
    headerAnomaly: true,

    // Custom Rules
    customRules: [
      {
        name: 'restrict-internal-billing',
        match: {
          endpoint: '/api/v1/internal/billing',
          method: ['POST', 'DELETE']
        },
        score: 35,
        label: 'Sensitive Billing Modification Attempt',
        confidence: 90
      },
      {
        name: 'block-deprecated-crawler',
        match: {
          userAgent: /legacy-scraper/i
        },
        score: 40,
        label: 'Deprecated Scraper Bot Match',
        confidence: 95
      }
    ]
  }
});
```

---

## 📈 Behavioural Anomaly & Correlation

### 1. Rolling Behaviour Baseline
Maintains a 5-minute rolling request rate (RPM) profile per IP and endpoint. Sudden traffic spikes (>3× baseline) trigger a proportional anomaly score penalty:

```text
Endpoint: /api/login
Baseline Rate:  2.4 req/min
Current Rate:  45.0 req/min
Behaviour Deviation: 94% (Anomaly Penalty: +18 pts)
```

### 2. Attack Sequence Correlation
Detects multi-step attack patterns across request sequences:
- **Account Takeover Chain**: Repeated failed logins followed by enumeration or admin route access.
- **Secret Enumeration**: Sequential probes for `.env`, `wp-config`, `.git`, or `config.json`.
- **Multi-Vector Escalation**: Combining SQL injection payloads with directory traversal probes.
- **Scanner Sweeps**: Rapidly touching 5+ distinct endpoints with automated tool fingerprints.

---

## 🔒 Privacy Controls & Fail-Safe Modes

```js
const shield = createShield({
  // Fail-Safe Policy
  failureMode: 'fail-open', // 'fail-open' (default) | 'fail-closed'

  // Privacy by Design
  privacy: {
    hashIp: false,        // If true, IPs are stored as SHA-256 hashes (e.g. sha256:4f8a...)
    retainRawIp: true,    // Retains raw IP in memory exclusively for active block enforcement
    retentionDays: 30     // Automatically purges SQLite event/request logs older than 30 days
  }
});
```

---

## 📊 Automated Benchmarking

`iri-shield` includes a built-in benchmarking tool to compare performance against a baseline unshielded Express server:

```bash
npm run benchmark
```

### Real Benchmark Output (500 Requests @ 15 Concurrency)

```text
================================================================================
                           BENCHMARK COMPARISON RESULTS                         
================================================================================
Metric                   | Baseline       | iri-shield     | Delta / Overhead   
-------------------------|----------------|----------------|--------------------
Throughput               | 1032 req/s     | 748 req/s      | -27.5% throughput
Avg Latency              | 14.03 ms       | 19.89 ms       | +5.86 ms overhead
p50 Latency              | 11.64 ms       | 18.11 ms       | +6.47 ms
p95 Latency              | 35.11 ms       | 31.00 ms       | -4.11 ms
p99 Latency              | 71.96 ms       | 61.88 ms       | -10.08 ms
Memory Delta             | 0.63 MB        | 6.93 MB        | +6.30 MB
Detection Rate           | N/A            | 80%            | 80/100 attacks intercepted
False Positive Rate      | N/A            | 0%             | 0 false alarms
================================================================================
```

JSON benchmark reports are automatically saved to `results/baseline.json`, `results/shield.json`, and `results/comparison.json`.

---

## 🖥️ Interactive Admin Dashboard

Access the real-time security dashboard at `/iri-shield`:

- **Overview Panel**: Live requests, mitigated threats, latency gauges, threat distribution donut charts, and top endpoint statistics.
- **Alerts ⚡**: Active suspicious client queue with one-click **Block IP** and **Dismiss** actions.
- **Security Events**: Filterable by risk level (`critical`, `high`, `medium`, `low`) with expandable **Risk Breakdown Tables**, **Confidence Badges**, and **Correlation Banners**.
- **Client Identity**: Identity continuity records, platform breakdown, IP rotation count, and anomaly histories.
- **Blocked IPs**: Full persistent blocklist management with instant **Unblock** and manual block creation modal.
- **Settings**: Live security mode switcher (`low`, `medium`, `high`), Security Rule Engine checkboxes, Privacy controls, and Redaction field managers.

---

## ⚙️ Full Configuration Reference

```js
const shield = createShield({
  appName: 'iri-shield',
  security: 'medium',            // 'low' | 'medium' | 'high'
  trustProxy: false,
  failureMode: 'fail-open',      // 'fail-open' | 'fail-closed'

  // HTTP Security Headers & CORS
  helmet: {
    enabled: true,
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
  },
  cors: false,
  logger: true,

  // Rate Limiting
  rateLimit: {
    enabled: true,
    windowMs: 60 * 1000,         // 1 minute
    max: 120                     // Requests per window
  },

  // Automated IP Blocking
  block: {
    enabled: true,
    threshold: 80,               // Threat score (0-100) to trigger block
    durationMs: 24 * 3600 * 1000 // Block duration (24 hours)
  },

  // Alert Queue
  alert: {
    enabled: true,
    threshold: 35                // Score threshold for active alert queue
  },

  // Anomaly Thresholds
  anomaly: {
    mediumThreshold: 35,
    highThreshold: 65,
    criticalThreshold: 90,
    singleEndpointMax: 80,
    failedAuthMax: 5,
    allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    sensitiveEndpoints: ['/admin', '/internal', '/debug', '/.env', '/config']
  },

  // Security Rule Engine
  rules: {
    sqlInjection: true,
    xss: true,
    pathTraversal: true,
    commandInjection: true,
    ssti: true,
    nosqlInjection: true,
    secretProbe: true,
    scannerDetection: true,
    openRedirect: true,
    headerAnomaly: true,
    customRules: []
  },

  // PII & Secret Redaction
  redaction: {
    enabled: true,
    mask: '[REDACTED]',
    fields: [
      'password', 'token', 'accessToken', 'refreshToken',
      'authorization', 'apiKey', 'secret', 'ssn',
      'aadhaar', 'email', 'phone', 'creditCard', 'cvv'
    ]
  },

  // Privacy Controls
  privacy: {
    hashIp: false,
    retainRawIp: true,
    retentionDays: 30
  },

  // Storage Engine
  storage: {
    mode: 'sqlite',              // 'memory' | 'sqlite' | 'mongodb'
    sqliteFile: './data/iri-shield.sqlite',
    mongoUrl: 'mongodb://localhost:27017/iri-shield',
    maxRequestRows: 50000,
    maxEventRows: 10000
  },

  // Dashboard Options
  dashboard: {
    enabled: true,
    path: '/iri-shield',
    username: 'admin',
    password: 'admin',
    refreshMs: 300000            // 5 minutes
  }
});
```

---

## 🛡️ Security & Auth Utilities

`iri-shield` ships with built-in cryptographic security utilities:

```js
const { 
  apiKeyAuth, 
  signToken, 
  jwtAuth, 
  hashPassword, 
  comparePassword 
} = require('iri-shield');

// API Key Guard
app.get('/api/v1/data', apiKeyAuth(['prod-key-1', 'prod-key-2']), handler);

// JWT Middleware
app.get('/api/v1/me', jwtAuth(process.env.JWT_SECRET), handler);

// Password Hashing
const hashed = await hashPassword('user-password', 12);
const isValid = await comparePassword('input-password', hashed);
```

---

## 🎓 Academic & Research Defense

When presenting or publishing research using `iri-shield`:

> **Terminology Note**: `iri-shield` utilizes **Multi-Signal Client Profiling and Identity Continuity Analysis**. We do not claim absolute identity guarantee, but rather compute continuous probabilistic risk scores derived from observed identity signal drift across request lifetimes.

### Theoretical Foundation
- **Multi-Vector Threat Fusion**: Combining signature heuristics, behavioral statistical deviations, and sequential Markovian attack chains into a unified, explainable score vector.
- **Privacy-Preserving Telemetry**: Deterministic SHA-256 IP pseudonyms with strict temporal data lifecycle controls.

---

## 📄 License

ISC © [ansari-in](https://github.com/ansari-in)
