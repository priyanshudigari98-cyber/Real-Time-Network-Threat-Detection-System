# C-Sentinel

A DSA-driven network intrusion detection and threat analysis system.

Unlike a firewall, which only allows or blocks traffic using fixed rules, C-Sentinel analyses traffic patterns over time to detect floods, port scans and brute-force attempts.

## Data structures used
- HashMap: per-IP tracking
- Sliding Window: request counts in the last 10 seconds
- Graph: IP-to-port connections for scan detection
- Priority Queue: ranks threats by severity

## How to run
Requires Python 3 (no extra libraries).

    python csentinel_engine.py
    python test_engine.py

## Status
Phase 2: detection engine and unit tests complete (simulated traffic).
Next: Scapy live capture, Flask API, SQLite database, dashboard.

Team Sentinel
