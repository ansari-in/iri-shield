# iri-shield

`iri-shield` is a research-oriented Express middleware package for API security monitoring, anomaly detection, threat mitigation, sensitive-data redaction, structured logging and dashboard visibility.

It is built from the API security project proposal in this workspace and targets the prototype features needed for the `iri-test` demo app.

## Install

```bash
npm install iri-shield
```

For local development from this workspace:

```bash
npm install ../iri-shield
```

## Quick Start

```js
const express = require('express');
const { createShield, apiKeyAuth } = require('iri-shield');

const app = express();
app.use(express.json());

const shield = createShield({
  storage: {
    mode: 'sqlite',
    sqliteFile: './data/iri-shield.sqlite'
  },
  // CSP is off by default so CDN dashboards and user apps do not break.
  // Enable it only when your app has a tested CSP policy.
  helmet: {
    enabled: true,
    contentSecurityPolicy: false
  },
  dashboard: {
    username: 'admin',
    password: 'admin'
  }
});

app.use(shield.middleware);
app.use('/iri-shield', shield.dashboard);

app.get('/api/private', apiKeyAuth('demo-key'), (req, res) => {
  res.json({ ok: true, token: 'secret-token', email: 'user@example.com' });
});

app.listen(3000);
```

Open `http://localhost:3000/iri-shield` and sign in with:

```text
username: admin
password: admin
```

## Features

- Request and endpoint monitoring: IP, method, endpoint, user-agent, cookie/session metadata, status code and latency.
- Client identity monitoring: client id, user id, session id, cookie, user-agent, IP history and request fingerprint.
- Rule-based anomaly detection for suspicious input, unusual methods, repeated auth attempts and sensitive endpoint access.
- Bypass-change detection when a known user/client suddenly changes IP, user-agent or fingerprint.
- Mitigation through rate limiting and temporary IP blocking.
- Sensitive-data redaction for configured response fields and common token/email/phone patterns.
- Structured security events with in-memory or SQLite storage.
- Tailwind-based light dashboard with totals, threats, blocked IPs, endpoint activity, clients, recent events and editable settings.
- Auth helpers for API keys, JWTs and bcrypt password hashing.
- Browser-friendly default security headers: Helmet is enabled, but CSP is disabled by default so external CSS/JS CDNs do not break consuming apps.

## Testing Different Users and IPs

For research/testing, `iri-shield` accepts override headers when `testing.allowClientOverrides` is enabled:

```text
x-iri-test-ip
x-iri-test-user-agent
x-iri-test-user-id
x-iri-test-client-id
x-iri-test-device-id
x-iri-test-session-id
x-iri-test-cookie
```

This lets `iri-test/client_requests.json` simulate different clients, devices and attackers from one local machine.

## Dashboard Settings

The dashboard can update runtime values such as rate-limit max/window, block threshold/duration, anomaly thresholds, dashboard refresh interval, redaction fields, testing overrides, Helmet and CSP toggles.

## API

### `createShield(options)`

Returns:

- `middleware`: Express middleware.
- `dashboard`: Express router for dashboard and stats API.
- `storage`: active storage adapter.
- `getStats()`: dashboard/evaluation metrics.
- `clear()`: reset in-memory state.

### `apiKeyAuth(keys, options)`

Protects a route using the `x-api-key` header by default.

### `signToken(payload, secret, options)` and `jwtAuth(secret, options)`

Create and verify bearer JWTs.

### `hashPassword(password)` and `comparePassword(password, hash)`

Small bcrypt helpers for application auth flows.

## Research Mapping

This package covers the proposal objectives:

- Monitoring API request behaviour.
- Detecting selected anomalous and suspicious activity.
- Applying configurable mitigation.
- Redacting selected sensitive response data.
- Maintaining structured security logs.
- Supporting standalone storage and a future database adapter boundary.
- Providing dashboard metrics for experimental evaluation.

## Notes

The package includes `MemoryStorage` and `SQLiteStorage`. MongoDB can be added later by implementing the same storage methods.
