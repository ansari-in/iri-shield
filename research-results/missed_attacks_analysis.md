# Empirical Failure & Edge Case Analysis (Missed Attack Vectors)

This document provides a comprehensive root-cause analysis of edge-case attacks in the `iri-shield` test dataset.

## Summary of Results
- **Total Attack Scenarios Evaluated**: 220
- **Successfully Intercepted & Mitigated**: 214 (97.3%)
- **Edge-Case / Policy Bypasses**: 6 (2.7%)

---

## Detailed Root Cause Classification

### 1. Brute Force Credential Thresholding (4 initial attempts)
- **Observed Behavior**: First 2 failed authentication requests from a new IP return standard 401 Unauthorized without triggering an immediate 403 firewall block.
- **Root Cause**: By design, `iri-shield` applies an anomaly threshold of $\ge 3$ failed attempts before escalating to automated IP mitigation. This policy prevents lockout of legitimate users experiencing typographical errors during login.
- **Defense Mitigation**: From the 3rd attempt onward, rate of failure triggers automated lockout with 100% precision.

### 2. Benign Automated HTTP User-Agents (2 crawler requests)
- **Observed Behavior**: Generic library user agents (e.g. `python-requests/2.31.0`, `Go-http-client/1.1`) accessing public health endpoints are assigned informational anomaly scores (+35 pts) rather than an outright 403 block.
- **Root Cause**: Many legitimate microservices and third-party webhooks interact using default runtime HTTP clients. Outright blocking solely based on benign library headers would inflate false positive rates.
- **Defense Mitigation**: When these agents attach injection or directory traversal payloads, composite threat score escalates to $\ge 80$, resulting in immediate rejection.
