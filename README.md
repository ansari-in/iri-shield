# iri-shield

`iri-shield` is an enterprise-grade Express.js security middleware package designed for API security monitoring, real-time threat detection, identity fingerprinting, automated anomaly mitigation, sensitive data redaction, and centralized dashboard administration.

---

## 🚀 Key Features

- **Multi-signal Identity Fingerprinting**: Identifies clients using IP, session, cookies, Client Hints (`sec-ch-ua`, `sec-ch-ua-platform`), user-agent, accept headers, and device context to assign consistent IDs and track suspicious bypasses.
- **Deep Threat & Scanner Detection**:
  - SQL Injection, XSS, Path Traversal, SSTI (`{{7*7}}`), NoSQL Injection (`$gt`, `$ne`), Command Injection, XXE, Open Redirects, and Secret Probing (`.env`, `wp-config`, `.git`).
  - Automated Scanner & Bot detection (`sqlmap`, `nikto`, `masscan`, `zgrab`, `hydra`, Headless Chrome, Puppeteer).
  - Header anomaly detection (browser-like claims missing standard headers).
- **Security Modes**:
  - `low`: Relaxed protection (300 req/min, block score 90).
  - `medium` (default): Balanced protection (120 req/min, block score 80).
  - `high`: Strict enterprise protection (30 req/min, block score 60).
- **Storage Options**:
  - `memory`: High-performance in-memory ring-buffer storage.
  - `sqlite`: Built-in Node.js SQLite with WAL mode, persistent blocks, persistent alerts, and automatic FIFO storage cleanup (50k rows default limit).
  - `mongodb`: MongoDB storage with TTL auto-cleanup and graceful fallback to memory if MongoDB is unavailable.
- **Interactive Light-Theme Enterprise Dashboard**:
  - **Overview**: Real-time traffic, detected threats, latency metrics, threat distribution chart, and endpoint statistics.
  - **Alerts ⚡**: Active suspicious client tracking with one-click Block IP and Dismiss actions.
  - **Security Events**: Filterable by risk level (`critical`, `high`, `medium`, `low`) with server-side pagination.
  - **Clients**: Client identity history, platform tracking, IP switches, and anomaly counts.
  - **Blocked IPs**: Full management table with instant **Unblock** and **Manual Block** modal.
  - **Settings**: Live security mode switcher, rate limiters, block thresholds, redaction fields, and testing toggles.
- **Automated PII & Secret Redaction**: Intercepts JSON/Text responses to mask passwords, API keys, tokens, emails, phone numbers, SSNs, and Aadhaar numbers.
- **Production vs. Testing Modes**: Configurable `testing.enabled` flag allowing test suites to simulate varied devices and IPs via headers/body overrides while ensuring strict real-IP validation in production.

---

## 📦 Installation

```bash
npm install iri-shield
```

*(Node.js >= 22.0.0 is recommended for built-in SQLite support)*

---

## ⚡ Quick Start

```js
const express = require('express');
const { createShield, apiKeyAuth } = require('iri-shield');

const app = express();
app.use(express.json());

const shield = createShield({
  appName: 'my-secure-api',
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

// Attach shield security middleware
app.use(shield.middleware);

// Attach dashboard
app.use('/iri-shield', shield.dashboard);

// Example protected endpoint
app.get('/api/secure-data', apiKeyAuth('my-secret-api-key'), (req, res) => {
  res.json({
    status: 'ok',
    token: 'sensitive-token-12345', // Automatically redacted
    email: 'user@example.com'       // Automatically redacted
  });
});

app.listen(3000, () => {
  console.log('App running on http://localhost:3000');
  console.log('Dashboard: http://localhost:3000/iri-shield');
});
```

---

## ⚙️ Configuration Reference

```js
const shield = createShield({
  appName: 'iri-shield',
  security: 'medium', // 'low' | 'medium' | 'high'
  trustProxy: false,
  
  // Rate Limiting
  rateLimit: {
    enabled: true,
    windowMs: 60 * 1000,
    max: 120
  },

  // IP Blocking
  block: {
    enabled: true,
    threshold: 80,             // Threat score to trigger auto-block (0-100)
    durationMs: 10 * 60 * 1000 // 10 minutes
  },

  // Alert Queue
  alert: {
    enabled: true,
    threshold: 35              // Score to add client to dashboard alerts
  },

  // Anomaly Thresholds
  anomaly: {
    mediumThreshold: 35,
    highThreshold: 65,
    criticalThreshold: 90,
    singleEndpointMax: 80,
    failedAuthMax: 5,
    allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    sensitiveEndpoints: ['/admin', '/internal', '/debug', '/.env']
  },

  // Sensitive Field Redaction
  redaction: {
    enabled: true,
    mask: '[REDACTED]',
    fields: ['password', 'token', 'accessToken', 'apiKey', 'secret', 'email', 'phone']
  },

  // Storage
  storage: {
    mode: 'sqlite', // 'memory' | 'sqlite' | 'mongodb'
    sqliteFile: './data/iri-shield.sqlite',
    mongoUrl: 'mongodb://localhost:27017/iri-shield', // Used if mode: 'mongodb'
    maxRequestRows: 50000, // FIFO cleanup threshold
    maxEventRows: 10000
  },

  // Testing Overrides
  testing: {
    enabled: false,             // Set true only in development/testing
    allowClientOverrides: false
  }
});
```

---

## 🧪 Testing Overrides

When `testing.enabled: true` and `testing.allowClientOverrides: true`, test scripts can simulate multiple client devices and remote IPs using custom headers:

```text
x-iri-test-ip: 203.0.113.77
x-iri-test-user-agent: Mozilla/5.0 (Android 14) Chrome/120
x-iri-test-user-id: student-001
x-iri-test-client-id: client-device-a
x-iri-test-device-id: mobile-01
x-iri-test-session-id: sess-xyz
x-iri-test-cookie: connect.sid=sess-xyz
```

Or through request body (`req.body.__iri`):
```json
{
  "__iri": {
    "ip": "203.0.113.77",
    "userAgent": "sqlmap/1.8"
  }
}
```

---

## 🛡️ Auth & Security Utilities

`iri-shield` includes built-in security utilities:

```js
const { 
  apiKeyAuth, 
  signToken, 
  jwtAuth, 
  hashPassword, 
  comparePassword 
} = require('iri-shield');

// API Key Guard
app.get('/api/protected', apiKeyAuth(['key1', 'key2']), handler);

// JWT Guard
app.get('/api/profile', jwtAuth(process.env.JWT_SECRET), handler);

// Password Hashing
const hash = await hashPassword('plain-password');
const isValid = await comparePassword('input-password', hash);
```

---

## 📄 License

ISC © [ansari-in](https://github.com/ansari-in)
