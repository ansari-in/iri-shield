# iri-shield

[![npm version](https://img.shields.io/badge/npm-v1.2.2-blue.svg)](https://www.npmjs.com/package/iri-shield)
[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22.0.0-purple.svg)](https://nodejs.org)
[![Security](https://img.shields.io/badge/security-risk--scoring-orange.svg)](#-explainable-risk-scoring)
[![Privacy](https://img.shields.io/badge/privacy-by--design-teal.svg)](#-privacy-by-design)

<p align="center">
  <img src="./img/iri-shield-home.jpg" alt="Iri Shield Logo" width="500">
</p>


> **Open-source API security middleware for Express.js** featuring **Explainable Risk Scoring**, **Multi-Signal Identity Continuity Analysis**, **Behavioural Anomaly Detection**, **Attack Sequence Correlation**, **Configurable Rule Engine**, **Automated PII/Secret Redaction**, and an **Interactive Real-Time Admin Dashboard**.

---

## Table of Contents

- [iri-shield](#iri-shield)
  - [Table of Contents](#table-of-contents)
  - [Key Features](#key-features)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
  - [Security Rule Engine](#security-rule-engine)
  - [Real-World \& Production Deployment Guide](#real-world--production-deployment-guide)
    - [1. Disabling Testing Mode for Real Traffic](#1-disabling-testing-mode-for-real-traffic)
    - [2. Reverse Proxy \& Real Client IP (`trustProxy`)](#2-reverse-proxy--real-client-ip-trustproxy)
    - [3. Storage on Vercel and Serverless Platforms](#3-storage-on-vercel-and-serverless-platforms)
    - [4. Securing Admin Dashboard Credentials](#4-securing-admin-dashboard-credentials)
    - [5. Production Ready Configuration Example](#5-production-ready-configuration-example)
  - [Full Configuration Reference](#full-configuration-reference)
  - [Security \& Auth Utilities](#security--auth-utilities)
- [Deploy on `Vercel`](#deploy-on-vercel)
  - [1. Install iri-shield](#1-install-iri-shield)
  - [2. Create server.js](#2-create-serverjs)
  - [3. Why /tmp is required for SQLite on Vercel](#3-why-tmp-is-required-for-sqlite-on-vercel)
  - [4. Add environment variables in Vercel](#4-add-environment-variables-in-vercel)
  - [5. Recommended production settings](#5-recommended-production-settings)
  - [Automated Benchmarking \& Research Evaluation](#automated-benchmarking--research-evaluation)
    - [Comprehensive Research Evaluation Summary (v1.2.0-research)](#comprehensive-research-evaluation-summary-v120-research)
    - [Multi-Workload Performance \& Latency Matrix](#multi-workload-performance--latency-matrix)
  - [Interactive Admin Dashboard](#interactive-admin-dashboard)
  - [Architectural Philosophy](#architectural-philosophy)
  - [Explainable Risk Scoring](#explainable-risk-scoring)
  - [Multi-Signal Identity Continuity](#multi-signal-identity-continuity)
  - [Behavioural Anomaly \& Correlation](#behavioural-anomaly--correlation)
    - [1. Rolling Behaviour Baseline](#1-rolling-behaviour-baseline)
    - [2. Attack Sequence Correlation](#2-attack-sequence-correlation)
  - [Privacy Controls \& Fail-Safe Modes](#privacy-controls--fail-safe-modes)
  - [Academic \& Research Defense](#academic--research-defense)
    - [Theoretical Foundation](#theoretical-foundation)
  - [License](#license)


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

> **Requirements**: Node.js **>= 22.0.0** recommended for native SQLite (`node:sqlite`) support.

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



## Real-World & Production Deployment Guide

`iri-shield` is built to protect production Express.js APIs against real-world threats. When moving from local testing or dataset benchmarks to production, follow these steps:

### 1. Disabling Testing Mode for Real Traffic
By default in `iri-shield`, **testing mode is already disabled** (`enabled: false`). However, if you enabled it during local simulation or integration testing, ensure it is set to `false` or removed in production.

> [!WARNING]
> When `testing.enabled: true`, clients can spoof their IP, User-Agent, and Session ID via custom headers (`x-iri-test-ip`, `x-iri-test-user-agent`, etc.) for benchmark replay. **Never enable testing mode in production environments!**

```js
const shield = createShield({
  appName: 'my-production-api',
  // Ensure testing mode is off (or simply omit the testing property)
  testing: {
    enabled: false,
    allowClientOverrides: false
  },
  // ...
});
```

### 2. Reverse Proxy & Real Client IP (`trustProxy`)
If your application runs behind a reverse proxy, load balancer, or CDN (such as **Nginx**, **Cloudflare**, **AWS ALB**, or **Heroku**):
- Set `trustProxy: true` (or express `app.set('trust-proxy', 1)`) so `iri-shield` reads real client IPs from `CF-Connecting-IP`, `X-Forwarded-For`, or `X-Real-IP`.

```js
const app = express();
app.set('trust proxy', true);

const shield = createShield({
  appName: 'my-production-api',
  trustProxy: true,
  // ...
});
```

### 3. Storage on Vercel and Serverless Platforms

`iri-shield` defaults to `memory` storage if you do not pass a storage config. For demos that should exercise SQLite on Vercel, keep `mode: 'sqlite'` and point the database file at `/tmp`.

If you explicitly enable SQLite, do not point it at `./data` on Vercel. Vercel Functions have a read-only deployment filesystem and only expose `/tmp` as writable scratch space: [Vercel Functions runtime docs](https://vercel.com/docs/functions/runtimes#file-system-support).

Recommended serverless demo configuration:

```js
const isVercel = Boolean(process.env.VERCEL);

const shield = createShield({
  appName: 'my-api',
  storage: {
    mode: process.env.IRI_STORAGE_MODE || 'sqlite',
    sqliteFile: process.env.IRI_SQLITE_FILE || (isVercel ? '/tmp/iri-shield.sqlite' : './data/iri-shield.sqlite')
  }
});
```

Storage guidance:

- Use `sqlite` with `/tmp/iri-shield.sqlite` for quick Vercel demos and smoke tests.
- Use `sqlite` with `./data/iri-shield.sqlite` for local development or traditional servers with writable disk.
- Use `memory` only when you do not need a database file. Data resets when the function instance is recycled.
- Use `mongodb` or another external datastore for production persistence on serverless platforms.

### 4. Securing Admin Dashboard Credentials
Never hardcode default credentials in production code. Load admin username and password from environment variables:

```js
dashboard: {
  enabled: true,
  path: '/iri-shield',
  username: process.env.SHIELD_ADMIN_USER || 'admin',
  password: process.env.SHIELD_ADMIN_PASSWORD, // enforce strong secret via .env
  refreshMs: 60 * 1000
}
```

### 5. Production Ready Configuration Example

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
  security: isProd ? 'high' : 'medium', // 'low' | 'medium' | 'high'
  trustProxy: isProd,
  failureMode: 'fail-open', // resilient: won't bring down app on errors

  // Testing mode — automatically OFF in production
  testing: {
    enabled: !isProd,
    allowClientOverrides: !isProd
  },

  // Persistent storage for production blocks and analytics
  storage: {
    mode: process.env.IRI_STORAGE_MODE || 'sqlite', // 'memory', 'sqlite', or 'mongodb'
    sqliteFile: process.env.IRI_SQLITE_FILE || (isVercel ? '/tmp/iri-shield.sqlite' : './data/iri-shield.sqlite'),
    mongoUrl: process.env.IRI_MONGO_URL
  },

  // Secure Dashboard
  dashboard: {
    enabled: true,
    path: '/iri-shield',
    username: process.env.SHIELD_ADMIN_USER || 'admin',
    password: process.env.SHIELD_ADMIN_PASSWORD || 'ChangeThisSecret123!'
  }
});

app.use(shield.middleware);
app.use('/iri-shield', shield.dashboard);
```

---

## Full Configuration Reference

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

##  Security & Auth Utilities

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

# Deploy on `Vercel`

This guide shows how to deploy an Express.js app protected by `iri-shield` on Vercel.

Vercel can deploy an Express server from a root `server.js` file with no extra routing config. `iri-shield` can use SQLite on Vercel too, but the SQLite file must be stored in `/tmp` because Vercel's deployed filesystem is read-only.

## 1. Install iri-shield

```bash
npm install express iri-shield
```

`iri-shield` uses Node's native `node:sqlite` module for SQLite storage, so use Node.js 22 or newer.

In `package.json`, add an engine so Vercel uses a compatible Node version:

```json
{
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "express": "^5.0.0",
    "iri-shield": "^1.2.2"
  }
}
```

## 2. Create server.js

Create `server.js` in the project root:

```js
'use strict';

const express = require('express');
const { createShield } = require('iri-shield');

const app = express();
const port = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';
const isVercel = Boolean(process.env.VERCEL);

app.use(express.json({ limit: '200kb' }));

if (isProd) {
  app.set('trust proxy', true);
}

const shield = createShield({
  appName: process.env.APP_NAME || 'my-api',
  security: isProd ? 'high' : 'medium',
  trustProxy: isProd,
  failureMode: 'fail-open',

  storage: {
    mode: process.env.IRI_STORAGE_MODE || 'sqlite',
    sqliteFile: process.env.IRI_SQLITE_FILE || (isVercel ? '/tmp/iri-shield.sqlite' : './data/iri-shield.sqlite'),
    mongoUrl: process.env.IRI_MONGO_URL
  },

  testing: {
    enabled: !isProd,
    allowClientOverrides: !isProd
  },

  dashboard: {
    enabled: true,
    path: '/iri-shield',
    username: process.env.SHIELD_ADMIN_USER || 'admin',
    password: process.env.SHIELD_ADMIN_PASSWORD || 'ChangeThisSecret123!',
    refreshMs: 60 * 1000
  }
});

app.use(shield.middleware);
app.use('/iri-shield', shield.dashboard);

app.get('/', (req, res) => {
  res.json({
    ok: true,
    name: 'my-api',
    package: 'iri-shield',
    dashboard: '/iri-shield'
  });
});

app.get('/api/public', (req, res) => {
  res.json({
    ok: true,
    message: 'This route is protected by iri-shield',
    time: new Date().toISOString()
  });
});

app.get('/metrics', (req, res) => {
  res.json(shield.getStats());
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
  console.log(`iri-shield dashboard: http://localhost:${port}/iri-shield`);
  console.log(`iri-shield storage: ${shield.getStats().storageMode}`);
});
```

## 3. Why /tmp is required for SQLite on Vercel

Do not use this SQLite path on Vercel:

```js
sqliteFile: './data/iri-shield.sqlite'
```

That can fail with:

```text
Error: ENOENT: no such file or directory, mkdir './data'
```

Use this instead:

```js
sqliteFile: '/tmp/iri-shield.sqlite'
```

The `/tmp` directory is writable inside a Vercel Function. It is good for demos, smoke tests, and short-lived dashboard data. It is not permanent storage. Vercel can recycle function instances, so `/tmp/iri-shield.sqlite` can disappear between cold starts or deployments.

For production analytics, block history, or long-term dashboard data, use an external database such as MongoDB.

## 4. Add environment variables in Vercel

In your Vercel project:

1. Open the project dashboard.
2. Go to `Settings` -> `Environment Variables`.
3. Add these variables.

Recommended:

```bash
NODE_ENV=production
APP_NAME=my-api
SHIELD_ADMIN_USER=admin
SHIELD_ADMIN_PASSWORD=replace-with-a-strong-password
```

SQLite demo/default:

```bash
IRI_STORAGE_MODE=sqlite
IRI_SQLITE_FILE=/tmp/iri-shield.sqlite
```

MongoDB production option:

```bash
IRI_STORAGE_MODE=mongodb
IRI_MONGO_URL=mongodb+srv://user:password@cluster.example.mongodb.net/iri-shield
```


## 5. Recommended production settings

For a real public API:

- Keep `testing.enabled` and `testing.allowClientOverrides` disabled in production.
- Set `trustProxy: true` on Vercel so client IP detection works behind the platform proxy.
- Use strong dashboard credentials from environment variables.
- Use `failureMode: 'fail-open'` if availability is more important than blocking traffic when the security layer has an internal error.
- Use MongoDB or another external database if you need persistent logs, block history, and dashboard data.

Minimal production-safe config:

```js
const isProd = process.env.NODE_ENV === 'production';
const isVercel = Boolean(process.env.VERCEL);

const shield = createShield({
  appName: process.env.APP_NAME || 'my-api',
  security: 'high',
  trustProxy: true,
  failureMode: 'fail-open',
  testing: {
    enabled: false,
    allowClientOverrides: false
  },
  storage: {
    mode: process.env.IRI_STORAGE_MODE || 'sqlite',
    sqliteFile: process.env.IRI_SQLITE_FILE || (isVercel ? '/tmp/iri-shield.sqlite' : './data/iri-shield.sqlite'),
    mongoUrl: process.env.IRI_MONGO_URL
  },
  dashboard: {
    enabled: true,
    path: '/iri-shield',
    username: process.env.SHIELD_ADMIN_USER,
    password: process.env.SHIELD_ADMIN_PASSWORD
  }
});
```

---
## Automated Benchmarking & Research Evaluation

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
| **Threat Detection** | 220 Attack Payloads (14 Categories) | Overall Mitigation Rate | **97.3%** (214/220) | Vanilla Express: 0.0% (+97.7% Net Gain) |
| **False Positive Rate** | 2,000 Legitimate Queries | True Negative Pass Rate | **100.00%** (0% FPR) | Zero business disruption on clean traffic |
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

## Interactive Admin Dashboard

Access the real-time security dashboard at `/iri-shield`:

- **Overview Panel**: Live requests, mitigated threats, latency gauges, threat distribution donut charts, and top endpoint statistics.
- **Alerts**: Active suspicious client queue with one-click **Block IP** and **Dismiss** actions.
- **Security Events**: Filterable by risk level (`critical`, `high`, `medium`, `low`) with expandable **Risk Breakdown Tables**, **Confidence Badges**, and **Correlation Banners**.
- **Client Identity**: Identity continuity records, platform breakdown, IP rotation count, and anomaly histories.
- **Blocked IPs**: Full persistent blocklist management with instant **Unblock** and manual block creation modal.
- **Settings**: Live security mode switcher (`low`, `medium`, `high`), Security Rule Engine checkboxes, Privacy controls, and Redaction field managers.


---

##  Architectural Philosophy

`iri-shield` follows a **transparent, multi-layered security architecture**.
Instead of relying on a single detection mechanism, it combines identity signals, configurable security rules, behavioural analysis, attack correlation, explainable risk scoring, and automated mitigation.

```mermaid
flowchart TD
    A[Incoming HTTP Request] --> B[Base Security<br/>Helmet • CORS • Fail-Safe Policy]
    B --> C[Identity Continuity<br/>IP • Session • Client Hints • Drift Analysis]
    C --> D[Security Rule Engine<br/>SQLi • XSS • SSTI • Path Traversal • Custom Rules]
    D --> E[Behavioural Analysis<br/>Rolling Baseline • Anomaly Detection]
    E --> F[Attack Sequence Correlation<br/>Multi-Step Attack Detection]
    F --> G[Explainable Risk Scoring<br/>Risk Score • Confidence • Breakdown]
    G --> H[Automated Mitigation<br/>Rate Limit • Temporary/Permanent Block]
    H --> I[Secure Response & Redaction<br/>PII • Secrets • Sensitive Logs]
```
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

## Behavioural Anomaly & Correlation

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
