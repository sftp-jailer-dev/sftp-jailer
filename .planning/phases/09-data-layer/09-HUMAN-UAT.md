---
status: partial
phase: 09-data-layer
source: [09-VERIFICATION.md]
started: 2026-05-04T07:25:00Z
updated: 2026-05-04T07:25:00Z
---

## Current Test

[awaiting human testing]

## Tests

### 1. Lab UAT P2-B - real-DB EXPLAIN QUERY PLAN on ubuntu-wifi (192.168.1.187)
expected: EXPLAIN QUERY PLAN of dedup query on production observations DB (>=10k rows) contains "USING COVERING INDEX idx_observations_dedup"; query wall time <100ms.
result: [pending]

### 2. Lab UAT P2-D - migration latency on ubuntu-wifi (192.168.1.187)
expected: First-launch wall time on Ubuntu 24.04 lab host (>=10k observations row count) <= 1.5s; PRAGMA user_version reports 4 post-migration; observations row count delta = 0 (D-26 invariant).
result: [pending]

## Summary

total: 2
passed: 0
issues: 0
pending: 2
skipped: 0
blocked: 0

## Gaps
