# iri-shield

[![npm version](https://img.shields.io/badge/npm-v1.2.2-blue.svg)](https://www.npmjs.com/package/iri-shield)
[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22.0.0-purple.svg)](https://nodejs.org)
[![Security](https://img.shields.io/badge/security-risk--scoring-orange.svg)](#explainable-risk-scoring)
[![Privacy](https://img.shields.io/badge/privacy-by--design-teal.svg)](#privacy-controls--fail-safe-modes)

<p align="center">
  <img src="./img/iri-shield-home.jpg" alt="Iri Shield" width="500">
</p>

> **Open-source API security middleware for Express.js** with explainable risk scoring, multi-signal identity continuity analysis, behavioural anomaly detection, attack sequence correlation, configurable threat rules, recursive PII/secret redaction, and a real-time admin dashboard.

---

## Table of Contents

- [iri-shield](#iri-shield)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Key Features](#key-features)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
  - [Security Rule Engine](#security-rule-engine)
  - [Configuration Reference](#configuration-reference)
  - [Security \& Auth Utilities](#security--auth-utilities)
- [Guide for `Vercel`](#guide-for-vercel)
  - [Production Deployment](#production-deployment)
    - [Disable Testing Mode](#disable-testing-mode)
    - [Reverse Proxy \& Client IP](#reverse-proxy--client-ip)
    - [Storage on Serverless Platforms](#storage-on-serverless-platforms)
    - [Secure Dashboard Credentials](#secure-dashboard-credentials)
    - [Production Configuration](#production-configuration)
  - [Vercel Deployment](#vercel-deployment)
    - [1. Install Dependencies](#1-install-dependencies)
    - [2. Recommended Vercel Storage](#2-recommended-vercel-storage)
    - [3. Serverless Express Entry Point](#3-serverless-express-entry-point)
    - [4. Environment Variables](#4-environment-variables)
    - [5. Vercel Deployment Checklist](#5-vercel-deployment-checklist)
  - [Research \& Benchmarking](#research--benchmarking)
    - [Comprehensive Research Evaluation Summary (v1.2.0-research)](#comprehensive-research-evaluation-summary-v120-research)
    - [Multi-Workload Performance \& Latency Matrix](#multi-workload-performance--latency-matrix)
  - [Admin Dashboard](#admin-dashboard)
  - [Explainable Risk Scoring](#explainable-risk-scoring)
  - [Multi-Signal Identity Continuity](#multi-signal-identity-continuity)
  - [Behavioural Anomaly \& Attack Correlation](#behavioural-anomaly--attack-correlation)
    - [1. Rolling Behaviour Baseline](#1-rolling-behaviour-baseline)
    - [2. Attack Sequence Correlation](#2-attack-sequence-correlation)
  - [Privacy Controls \& Fail-Safe Modes](#privacy-controls--fail-safe-modes)
  - [Academic \& Research Defense](#academic--research-defense)
    - [Theoretical Foundation](#theoretical-foundation)
  - [License](#license)

---

## Overview

`iri-shield` is a security middleware layer for Express.js applications. It combines multiple security signals instead of relying on a single rule or signature. Requests can be evaluated using identity continuity, static attack detection, behavioural anomalies, sequence correlation, and explainable risk scoring before automated mitigation is applied.

The package is designed for **local development, security testing, research evaluation, and production-oriented Express.js deployments**. Storage can be configured for memory, SQLite, or MongoDB depending on the deployment environment.

> **Important:** Client profiling is probabilistic. `iri-shield` does not claim to provide authentication or guaranteed unique device identification.

---

## Key Features

| Capability | Description |
| :--- | :--- |
| **Explainable Risk Scoring** | Provides a transparent, auditable breakdown table (`+30 SQLi`, `+20 Sensitive Endpoint`, `+15 Identity Drift`) with a mathematical **Confidence Score (0-100%)**. |
| **Multi-Signal Profiling** | Evaluates **Identity Continuity** using IP address, session tokens, Client Hints (`sec-ch-ua`, `sec-ch-ua-platform`), user-agents, accept headers, and device context to detect evasion attempts without violating user privacy. |
| **Configurable Rule Engine** | Individually toggle built-in threat detection rules or declare flexible **Custom Rules** (by endpoint, method, IP prefix, user-agent regex, or body fields). |
| **Behavioural Baselining** | Continuously learns normal per-endpoint request rates (RPM) and flags statistical anomalies (`Behaviour deviation: 92%`). |
| **Attack Sequence Correlation** | Evaluates ordered request chains to detect advanced multi-step campaigns (e.g., *Failed Auth ×3 → User Enumeration → Admin Access*). |
| **Privacy by Design** | Built-in SHA-256 IP hashing for persistent storage and automatic FIFO retention purging (`retentionDays: 30`). |
| **Fail-Safe Policies** | Choose between `fail-open` (resilience first) and `fail-closed` (strict containment) on internal subsystem failures. |
| **Built-in Benchmark Suite** | Automated performance comparison against baseline unshielded servers (`npm run benchmark`) measuring throughput, latency percentiles (p50/p95/p99), and defense efficacy. |
| **Light-Theme Dashboard** | Enterprise management interface for real-time monitoring, reactive IP block/unblock, active alerts, security event forensics, and live configuration updates. |
| **Deep PII/Secret Redaction** | Deep redaction for passwords, API keys, bearer tokens, emails, phone numbers, SSNs, Aadhaar numbers, and credit cards across responses and log storage. |

---


## Installation

```bash
npm install iri-shield
```

> **Requirements:** Node.js **>= 22.0.0** is recommended, especially when using the native SQLite (`node:sqlite`) storage engine.

---

## Quick Start

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
    username: process.env.SHIELD_ADMIN_USER || 'admin',
    password: process.env.SHIELD_ADMIN_PASSWORD || 'admin' // development only
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
  console.log('Server running on http://localhost:3000');
  console.log(' Dashboard available at http://localhost:3000/iri-shield');
});
```

---

## Security Rule Engine

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

## Configuration Reference

```js
const shield = createShield({
  appName: 'iri-shield',
  security: 'medium',            // 'low' | 'medium' | 'high'
  trustProxy: false,             // Set true if behind Cloudflare, Nginx, or AWS ALB
  failureMode: 'fail-open',      // 'fail-open' | 'fail-closed'

  // Testing Mode (False by default — enables header/body overrides for testing)
  testing: {
    enabled: false,              // Keep FALSE in production
    allowClientOverrides: false
  },

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

## Security & Auth Utilities

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

# Guide for `Vercel`

This guide shows how to deploy an Express.js app protected by `iri-shield` on Vercel.

Vercel can deploy an Express server from a root `server.js` file with no extra routing config. `iri-shield` can use SQLite on Vercel too, but the SQLite file must be stored in `/tmp` because Vercel's deployed filesystem is read-only.

## Production Deployment

`iri-shield` can be used with production Express.js applications, but deployment-specific settings should be applied carefully.

### Disable Testing Mode

Testing mode is intended for benchmark replay and controlled security testing. It allows client identity overrides through `x-iri-test-*` headers.

> [!WARNING]
> **Never enable testing mode on a public production API.** Clients could spoof the test identity signals used for evaluation.

```js
testing: {
  enabled: false,
  allowClientOverrides: false
}
```

### Reverse Proxy & Client IP

If the application runs behind a reverse proxy, load balancer, or CDN, configure Express and `iri-shield` to trust the proxy appropriately.

```js
const app = express();

app.set('trust proxy', true);

const shield = createShield({
  appName: 'my-production-api',
  trustProxy: true
});
```

Use this only when the deployment topology is actually trusted and configured to forward client IP information correctly.

### Storage on Serverless Platforms

Storage choice depends on the runtime:

| Storage | Recommended Use | Persistence |
| :--- | :--- | :--- |
| `memory` | Tests, demos, temporary state | Instance memory only |
| `sqlite` | Local development / traditional Node.js servers | Local writable disk |
| `mongodb` | Serverless / distributed production deployments | External persistent database |

For Vercel or similar serverless platforms, **do not use `./data/...` as the SQLite path**. A writable `/tmp` location can be used for short-lived demos, but it should not be treated as permanent storage.

```js
const isVercel = Boolean(process.env.VERCEL);

const shield = createShield({
  appName: 'my-api',
  storage: {
    mode: process.env.IRI_STORAGE_MODE || (isVercel ? 'memory' : 'sqlite'),
    sqliteFile:
      process.env.IRI_SQLITE_FILE ||
      (isVercel ? '/tmp/iri-shield.sqlite' : './data/iri-shield.sqlite'),
    mongoUrl: process.env.IRI_MONGO_URL
  }
});
```

> **Recommendation:** For persistent production telemetry, block history, and analytics on serverless infrastructure, use `mongodb` or another external datastore.

### Secure Dashboard Credentials

Do not commit dashboard credentials to source control.

```js
dashboard: {
  enabled: true,
  path: '/iri-shield',
  username: process.env.SHIELD_ADMIN_USER,
  password: process.env.SHIELD_ADMIN_PASSWORD,
  refreshMs: 60 * 1000
}
```

### Production Configuration

```js
const express = require('express');
const { createShield } = require('iri-shield');

const app = express();
const isProd = process.env.NODE_ENV === 'production';
const isVercel = Boolean(process.env.VERCEL);

if (isProd) {
  app.set('trust proxy', true);
}

const shield = createShield({
  appName: process.env.APP_NAME || 'my-api',
  security: isProd ? 'high' : 'medium',
  trustProxy: isProd,
  failureMode: 'fail-open',

  testing: {
    enabled: false,
    allowClientOverrides: false
  },

  storage: {
    mode: process.env.IRI_STORAGE_MODE || (isVercel ? 'memory' : 'sqlite'),
    sqliteFile:
      process.env.IRI_SQLITE_FILE ||
      (isVercel ? '/tmp/iri-shield.sqlite' : './data/iri-shield.sqlite'),
    mongoUrl: process.env.IRI_MONGO_URL
  },

  dashboard: {
    enabled: true,
    path: '/iri-shield',
    username: process.env.SHIELD_ADMIN_USER,
    password: process.env.SHIELD_ADMIN_PASSWORD
  }
});

app.use(shield.middleware);
app.use('/iri-shield', shield.dashboard);
```


## Vercel Deployment

This section covers deploying an Express.js application protected by `iri-shield` to Vercel.

### 1. Install Dependencies

```bash
npm install express iri-shield
```

Use Node.js **22 or newer** when using the native SQLite storage engine.

### 2. Recommended Vercel Storage

For a simple Vercel smoke test, use `memory` storage:

```js
storage: {
  mode: process.env.IRI_STORAGE_MODE || 'memory'
}
```

This avoids filesystem initialization errors and is suitable for testing the middleware, dashboard, detection rules, and API behaviour.

If you explicitly want SQLite for a short-lived demo, use `/tmp`:

```js
storage: {
  mode: 'sqlite',
  sqliteFile: '/tmp/iri-shield.sqlite'
}
```

Do **not** use:

```js
sqliteFile: './data/iri-shield.sqlite'
```

on Vercel. A deployment can fail when the package attempts to create that directory in the serverless filesystem.

> **Persistence note:** `/tmp` is temporary function-instance storage. It should not be used as the long-term source of truth for production analytics or block history.

### 3. Serverless Express Entry Point

For a Vercel deployment, export the Express application instead of relying on a long-running local server.

```js
'use strict';

const express = require('express');
const { createShield } = require('iri-shield');

const app = express();

app.use(express.json({ limit: '200kb' }));

const shield = createShield({
  appName: process.env.APP_NAME || 'my-api',
  security: 'high',
  trustProxy: true,

  storage: {
    mode: process.env.IRI_STORAGE_MODE || 'memory',
    sqliteFile: process.env.IRI_SQLITE_FILE || '/tmp/iri-shield.sqlite',
    mongoUrl: process.env.IRI_MONGO_URL
  },

  testing: {
    enabled: false,
    allowClientOverrides: false
  },

  dashboard: {
    enabled: true,
    path: '/iri-shield',
    username: process.env.SHIELD_ADMIN_USER,
    password: process.env.SHIELD_ADMIN_PASSWORD,
    refreshMs: 60 * 1000
  }
});

app.use(shield.middleware);
app.use('/iri-shield', shield.dashboard);

app.get('/', (req, res) => {
  res.json({
    ok: true,
    name: process.env.APP_NAME || 'my-api',
    package: 'iri-shield',
    dashboard: '/iri-shield'
  });
});

app.get('/metrics', (req, res) => {
  res.json(shield.getStats());
});

module.exports = app;
```

> **Local development:** If you also want `node server.js` locally, wrap `app.listen(...)` in `if (require.main === module)` so importing the app for serverless execution does not start a second listener.

### 4. Environment Variables

Add these in **Vercel → Settings → Environment Variables**:

```bash
NODE_ENV=production
APP_NAME=my-api
SHIELD_ADMIN_USER=admin
SHIELD_ADMIN_PASSWORD=replace-with-a-strong-secret
IRI_STORAGE_MODE=memory
```

For a short-lived SQLite demo instead:

```bash
IRI_STORAGE_MODE=sqlite
IRI_SQLITE_FILE=/tmp/iri-shield.sqlite
```

For persistent production storage:

```bash
IRI_STORAGE_MODE=mongodb
IRI_MONGO_URL=mongodb+srv://user:password@cluster.example.mongodb.net/iri-shield
```

### 5. Vercel Deployment Checklist

- [x] Use `memory` for the simplest serverless smoke test.
- [x] Use `/tmp` only when explicitly testing SQLite.
- [x] Disable `testing.enabled` in production.
- [x] Disable `allowClientOverrides` in production.
- [x] Use strong dashboard credentials from environment variables.
- [x] Use MongoDB or another external datastore for persistent production state.
- [x] Export the Express app for serverless execution.


## Research & Benchmarking

`iri-shield` includes a built-in automated evaluation suite to benchmark performance, threat detection efficacy, false positives, identity continuity, and data redaction against baseline Express.js:

```bash
# Run comprehensive multi-experiment research evaluation suite
npm run research:evaluate

# Or run individual benchmark modules:
npm run benchmark           # Multi-workload latency/throughput matrix
npm run security:evaluate   # 220-vector category threat detection
npm run security:compare    # Vanilla Express vs iri-shield defense comparison
npm run fp:evaluate         # 2,000 legitimate queries false positive evaluation
npm run identity:evaluate   # 500-scenario identity continuity & drift evaluation
npm run redaction:evaluate  # 500-sample recursive PII masking evaluation
```

### Comprehensive Research Evaluation Summary (v1.2.0-research)

| Evaluation Dimension | Workload / Dataset | Success Metric | Value | Baseline Comparison |
| :--- | :--- | :--- | :--- | :--- |
| **Threat Detection** | 220 Attack Payloads (14 Categories) | Overall Mitigation Rate | **97.3%** (214/220) | Vanilla Express: 0.0% blocked in the separate baseline comparison |
| **False Positive Rate** | 2,000 Legitimate Queries | False Positive Rate | **0.00% FPR** | Zero business disruption on clean traffic |
| **Identity Continuity** | 500 State Transitions | Profiling Accuracy | **100.0%** (0% False Drift) | Accurately flags IP/UA/Fingerprint drift |
| **PII Data Redaction** | 500 Structured Payloads | Redaction Precision | **100.0%** (0% Overmask) | 5-level nested JSON & unstructured logs |
| **Low-Load Overhead** | 300 Requests @ Concurrency 5 | Average Latency Delta | **+1.99 ms** | 2.97 ms (Base) vs 4.96 ms (Shield) |

### Multi-Workload Performance & Latency Matrix

| Workload Configuration | Baseline Req/s | Shield Req/s | Throughput Impact | Base Latency (Avg) | Shield Latency (Avg) | Overhead (Δ) | Shield p95 | Shield p99 | Host CPU (Base vs Shield) | Cores Utilized (Base vs Shield) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **300 req @ c=5**  | 1,904 req/s | 997 req/s | -47.6% | 2.97 ms | 4.96 ms | **+1.99 ms** | 7.80 ms | 9.77 ms | 17.6% vs 13.6% | 1.41 vs 1.09 cores |
| **300 req @ c=15** | 2,404 req/s | 706 req/s | -70.6% | 6.28 ms | 21.49 ms | **+15.21 ms** | 34.24 ms | 35.73 ms | 12.8% vs 14.7% | 1.02 vs 1.17 cores |
| **500 req @ c=5**  | 2,669 req/s | 630 req/s | -76.4% | 1.86 ms | 7.92 ms | **+6.06 ms** | 12.16 ms | 16.58 ms | 14.9% vs 13.1% | 1.19 vs 1.05 cores |
| **500 req @ c=15** | 3,097 req/s | 730 req/s | -76.4% | 4.79 ms | 20.44 ms | **+15.65 ms** | 29.80 ms | 33.06 ms | 15.2% vs 14.9% | 1.21 vs 1.19 cores |

> **CPU Metric Definitions:**
> - **Host Normalized CPU %**: Percentage of entire multi-core host compute bandwidth consumed ($\frac{\Delta \text{CPU}_{\mu s}}{\text{Duration}_s \times 10^6 \times N_{\text{cores}}} \times 100\%$).
> - **Cores Utilized**: Total saturated CPU cores consumed by the V8 runtime / libuv thread pool ($\frac{\Delta \text{CPU}_{\mu s}}{\text{Duration}_s \times 10^6}$, where 1.0 = 1 full CPU core).

JSON and CSV benchmark artifacts are automatically recorded in `results/`, `final-results/`, and `research-results/`.

---

## Admin Dashboard

Access the real-time security dashboard at `/iri-shield`:

- **Overview Panel**: Live requests, mitigated threats, latency gauges, threat distribution donut charts, and top endpoint statistics.
- **Alerts**: Active suspicious client queue with one-click **Block IP** and **Dismiss** actions.
- **Security Events**: Filterable by risk level (`critical`, `high`, `medium`, `low`) with expandable **Risk Breakdown Tables**, **Confidence Badges**, and **Correlation Banners**.
- **Client Identity**: Identity continuity records, platform breakdown, IP rotation count, and anomaly histories.
- **Blocked IPs**: Full persistent blocklist management with instant **Unblock** and manual block creation modal.
- **Settings**: Live security mode switcher (`low`, `medium`, `high`), Security Rule Engine checkboxes, Privacy controls, and Redaction field managers.


---

## Explainable Risk Scoring

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

## Multi-Signal Identity Continuity

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

## Behavioural Anomaly & Attack Correlation

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

## Privacy Controls & Fail-Safe Modes

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

## Academic & Research Defense

When presenting or publishing research using `iri-shield`:

> **Terminology Note**: `iri-shield` utilizes **Multi-Signal Client Profiling and Identity Continuity Analysis**. We do not claim absolute identity guarantee, but rather compute continuous probabilistic risk scores derived from observed identity signal drift across request lifetimes.

### Theoretical Foundation
- **Multi-Vector Threat Fusion**: Combining signature heuristics, behavioral statistical deviations, and sequential Markovian attack chains into a unified, explainable score vector.
- **Privacy-Preserving Telemetry**: Deterministic SHA-256 IP pseudonyms with strict temporal data lifecycle controls.

---

## License

MIT License © [ansari-in](https://github.com/ansari-in/iri-shield/blob/main/LICENSE)
