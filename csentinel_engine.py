"""
C-Sentinel: DSA-driven Network Intrusion Detection (Backend Engine - Phase 2)

Data structures used:
  1. HashMap (Python dict)   -> per-IP tracking, O(1) lookup
  2. Sliding Window (deque)  -> count requests only in the last N seconds
  3. Graph (adjacency dict)  -> who connected to whom, on which ports
  4. Priority Queue (heapq)  -> most dangerous threat comes out first

Run:  python csentinel_engine.py
(No admin rights or extra libraries needed. Traffic is simulated for now;
 live packet capture with Scapy comes in the next phase.)
"""

import heapq
import itertools
import json
import random
from collections import deque

# ---------------- Settings (easy to change) ----------------
WINDOW_SECONDS = 10      # sliding window size
FLOOD_LIMIT = 100        # packets from one IP in one window = flood
LOGIN_FAIL_LIMIT = 5     # failed logins from one IP in one window = brute force
SCAN_PORT_LIMIT = 15     # distinct ports on one target = port scan


# ---------------- DSA 1: Sliding Window ----------------
class SlidingWindow:
    """Remembers only the timestamps from the last `seconds` seconds."""

    def __init__(self, seconds):
        self.seconds = seconds
        self.times = deque()          # deque = fast add at one end, remove at other

    def add(self, t):
        self.times.append(t)                              # newest event goes in
        while self.times and self.times[0] <= t - self.seconds:
            self.times.popleft()                          # old events fall out
        return len(self.times)                            # events inside window


# ---------------- DSA 2: Graph ----------------
class ConnectionGraph:
    """Nodes = IP addresses. Edge src -> dst stores the set of ports used."""

    def __init__(self):
        self.edges = {}   # {src_ip: {dst_ip: {port, port, ...}}}

    def add_connection(self, src, dst, port):
        self.edges.setdefault(src, {}).setdefault(dst, set()).add(port)

    def max_ports_on_one_target(self, src):
        targets = self.edges.get(src, {})
        return max((len(ports) for ports in targets.values()), default=0)


# ---------------- DSA 3: Priority Queue ----------------
class ThreatQueue:
    """Max-priority queue: highest severity score is popped first.
    heapq is a MIN-heap, so we store the score as a negative number."""

    def __init__(self):
        self.heap = []
        self.counter = itertools.count()   # tie-breaker so equal scores don't clash

    def push(self, alert):
        heapq.heappush(self.heap, (-alert["score"], next(self.counter), alert))

    def pop(self):
        return heapq.heappop(self.heap)[2]

    def __len__(self):
        return len(self.heap)


def severity_label(score):
    if score >= 8:
        return "high"
    if score >= 5:
        return "medium"
    return "low"


# ---------------- The Engine ----------------
class SentinelEngine:
    def __init__(self):
        self.traffic = {}          # DSA: HashMap  ip -> SlidingWindow (all packets)
        self.failed_logins = {}    # DSA: HashMap  ip -> SlidingWindow (failed logins)
        self.graph = ConnectionGraph()
        self.threats = ThreatQueue()
        self.last_alert = {}       # (ip, type) -> time, avoids repeating same alert
        self.packets_seen = 0

    def _raise_alert(self, t, ip, attack, score, detail):
        key = (ip, attack)
        if key in self.last_alert and t - self.last_alert[key] < WINDOW_SECONDS:
            return None                                   # already alerted recently
        self.last_alert[key] = t
        alert = {
            "time": round(t, 1), "ip": ip, "type": attack,
            "score": score, "severity": severity_label(score), "detail": detail,
        }
        self.threats.push(alert)
        return alert

    def process(self, pkt):
        """Look at ONE packet. Returns a list of new alerts (usually empty)."""
        self.packets_seen += 1
        t, ip = pkt["time"], pkt["src_ip"]
        alerts = []

        # 1) Flood check: HashMap + Sliding Window
        window = self.traffic.setdefault(ip, SlidingWindow(WINDOW_SECONDS))
        count = window.add(t)
        if count > FLOOD_LIMIT:
            score = min(10, 6 + (count - FLOOD_LIMIT) // 50)
            alerts.append(self._raise_alert(
                t, ip, "Traffic Flood", score,
                f"{count} packets in {WINDOW_SECONDS}s"))

        # 2) Port scan check: Graph
        self.graph.add_connection(ip, pkt["dst_ip"], pkt["dst_port"])
        ports = self.graph.max_ports_on_one_target(ip)
        if ports > SCAN_PORT_LIMIT:
            score = min(10, 5 + ports // 10)
            alerts.append(self._raise_alert(
                t, ip, "Port Scan", score,
                f"{ports} different ports probed on one target"))

        # 3) Brute-force check: HashMap + Sliding Window on failed logins
        if pkt.get("login_failed"):
            fw = self.failed_logins.setdefault(ip, SlidingWindow(WINDOW_SECONDS))
            fails = fw.add(t)
            if fails > LOGIN_FAIL_LIMIT:
                score = min(10, 3 + fails)
                alerts.append(self._raise_alert(
                    t, ip, "Brute Force", score,
                    f"{fails} failed logins in {WINDOW_SECONDS}s"))

        return [a for a in alerts if a]


# ---------------- Simulated traffic (replaced by Scapy later) ----------------
def generate_traffic(seed=42):
    random.seed(seed)
    packets = []

    def pkt(t, src, dst, port, failed=False):
        return {"time": t, "src_ip": src, "dst_ip": dst,
                "dst_port": port, "login_failed": failed}

    normal_ips = [f"192.168.1.{i}" for i in range(10, 15)]
    server = "192.168.1.1"

    for sec in range(60):                                   # normal users
        for _ in range(random.randint(3, 8)):
            packets.append(pkt(sec + random.random(), random.choice(normal_ips),
                               server, random.choice([80, 443, 53])))

    for sec in range(20, 30):                               # flood attacker
        for _ in range(30):
            packets.append(pkt(sec + random.random(), "10.0.0.99", server, 80))

    for i in range(40):                                     # port scanner
        packets.append(pkt(35 + i * 0.12, "10.0.0.50", "192.168.1.10", 1 + i))

    for i in range(10):                                     # brute-force attacker
        packets.append(pkt(45 + i * 0.4, "10.0.0.77", server, 22, failed=True))

    packets.sort(key=lambda p: p["time"])
    return packets


# ---------------- Main ----------------
def main():
    engine = SentinelEngine()
    print("C-Sentinel engine started...\n")

    for packet in generate_traffic():
        for alert in engine.process(packet):
            print(f"[ALERT t={alert['time']:>5}s] {alert['severity'].upper():<6} "
                  f"{alert['type']:<13} from {alert['ip']:<13} ({alert['detail']})")

    print(f"\nPackets analysed: {engine.packets_seen}")
    print(f"Monitored IPs   : {len(engine.traffic)}")
    print("\n--- Threat ranking (Priority Queue: most dangerous first) ---")

    ranked = []
    while len(engine.threats):
        ranked.append(engine.threats.pop())
    for i, a in enumerate(ranked, 1):
        print(f"{i}. score {a['score']:>2} | {a['type']:<13} | {a['ip']}")

    with open("threats.json", "w") as f:        # frontend/database will read this later
        json.dump(ranked, f, indent=2)
    print("\nSaved to threats.json")


if __name__ == "__main__":
    main()