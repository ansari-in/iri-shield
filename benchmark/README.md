# 📊 iri-shield Benchmark Suite

This automated benchmark evaluates the performance overhead, throughput capacity, memory footprint, and threat detection efficacy of `iri-shield` versus a baseline Express.js server.

---

## 🚀 Running the Benchmark

Run the automated suite using npm:

```bash
npm run benchmark
```

### Custom Benchmark Parameters

You can customize the number of requests and concurrent workers via environment variables:

```bash
# 2,000 requests across 30 concurrent workers
BENCHMARK_REQUESTS=2000 BENCHMARK_CONCURRENCY=30 npm run benchmark
```

---

## 📈 Evaluation Metrics

The suite automatically measures and generates comparative metrics across five dimensions:

1. **Throughput (req/s)**: Total request handling rate under concurrent load.
2. **Latency Distribution**:
   - Average latency (`avg`)
   - Median latency (`p50`)
   - 90th percentile (`p90`)
   - 95th percentile (`p95`)
   - 99th percentile (`p99`)
3. **Memory Consumption**: Node.js V8 heap allocation before vs after the run.
4. **Attack Detection & Mitigation**: Percentage of malicious vectors (SQLi, XSS, Path Traversal, SSTI, scanner bots) intercepted.
5. **False Positive Rate**: Verification that 100% of legitimate API traffic passes through without impedance.

---

## 📁 Output Artifacts

All runs generate machine-readable JSON reports in the `results/` directory:

```text
results/
├── baseline.json       # Raw metrics from unshielded Express server
├── shield.json         # Raw metrics from iri-shield protected server
└── comparison.json     # Delta metrics, overhead summary, and defense efficacy
```
