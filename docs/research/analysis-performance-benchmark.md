---
type: report
title: Web Header Analyzer Performance Benchmark (Sample Headers)
created: 2026-02-18
tags:
  - performance
  - backend
  - benchmark
related:
  - "[[SpecKit-web-header-analyzer-Phase-09-Polish]]"
---

## Scope
Benchmark the full analysis runtime for `backend/tests/fixtures/sample_headers.txt` using the default backend analyzer configuration. Capture per-scanner timings to identify the slowest scanners.

## Environment
Local run on Windows PowerShell in repository root (`D:\dev2\decode-spam-headers`).

## Method
1. Load `backend/tests/fixtures/sample_headers.txt` into `AnalysisRequest` with default `AnalysisConfig`.
2. Run `HeaderAnalyzer.analyze(...)` once and record wall-clock runtime.
3. Run a per-scanner timing pass using the same parsed headers and `HeaderAnalyzer._run_scanner(...)` to match real execution behavior, including per-test timeouts.

## Results
- Full analysis runtime: 0.3396 seconds (metadata elapsed: 339.58 ms)
- Total scanners executed: 106
- Threshold requirement: under 10 seconds (met)

Top 10 scanners by runtime (single pass):
- 239.33 ms | Test 17 | Domain Impersonation
- 31.22 ms | Test 1 | Received - Mail Servers Flow
- 29.09 ms | Test 86 | Suspicious Words in Headers
- 2.19 ms | Test 3 | Extracted Domains
- 1.53 ms | Test 78 | Security Appliances Spotted
- 0.87 ms | Test 79 | Email Providers Infrastructure Clues
- 0.43 ms | Test 18 | SpamAssassin Spam Status
- 0.38 ms | Test 2 | Extracted IP addresses
- 0.38 ms | Test 12 | X-Forefront-Antispam-Report
- 0.37 ms | Test 7 | Authentication-Results

Scanners at or above 25 ms:
- 239.33 ms | Test 17 | Domain Impersonation
- 31.22 ms | Test 1 | Received - Mail Servers Flow
- 29.09 ms | Test 86 | Suspicious Words in Headers

## Notes
- No optimization required; runtime is well within the 10 second threshold.
- If regressions occur later, prioritize profiling Test 17, then Test 1 and Test 86.
