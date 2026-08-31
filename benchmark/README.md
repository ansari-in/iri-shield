# 🔬 iri-shield Scientific Research Evaluation Suite

This comprehensive evaluation suite is designed for academic research, empirical evaluation, and **Thesis Chapter 5 (Results & Discussion)** analysis of `iri-shield`.

---

## 🚀 Research Commands Matrix

| Command | Purpose | Primary Metric Evaluated | Output Artifacts |
| :--- | :--- | :--- | :--- |
| `npm run research:evaluate` | **Master Suite** (Executes all 5 experiments) | End-to-End Chapter 5 Report | `research-results/research_summary.md`, `experiments.csv` |
| `npm run benchmark` | Multi-Workload Matrix Performance Benchmark | Latency (Mean, p95, p99), Throughput, CPU & Memory | `results/performance.csv`, `comparison.json` |
| `npm run security:evaluate` | 220+ Structured Attack Scenarios | Category-wise Detection & Direct Blocking Rate | `results/security.csv`, `security.json` |
| `npm run fp:evaluate` | 10,000 Legitimate Requests | False Positive Rate (FPR = 0%) | `results/false_positives.csv`, `false_positives.json` |
| `npm run identity:evaluate` | 500 Identity Continuity & Drift Scenarios | Identity Profiling Accuracy & False Drift Rate | `results/identity.csv`, `identity.json` |
| `npm run redaction:evaluate` | 500 PII, Token & Secret Payloads | Redaction Accuracy (100%) & Over-masking (0%) | `results/redaction.csv`, `redaction.json` |

---

## 📁 Output Artifacts Directory Structure

```text
research-results/
├── research_summary.md    # Formatted Thesis Chapter 5 Tables & Analysis
├── experiments.csv        # Master CSV of all 5 experimental dimensions
└── summary_report.json    # Consolidated JSON telemetry

results/
├── performance.csv        # Workload matrix throughput, latency percentiles, CPU, memory
├── security.csv           # Category-wise detection rates (SQLi, XSS, SSTI, etc.)
├── false_positives.csv    # False positive validation results
├── identity.csv           # Identity continuity profiling results
├── redaction.csv          # Sensitive data redaction metrics
└── comparison.json        # Performance delta JSON
```
