import unittest
from csentinel_engine import (SlidingWindow, ConnectionGraph, ThreatQueue,
                              SentinelEngine, generate_traffic)


def make_pkt(t, src="1.1.1.1", dst="2.2.2.2", port=80, failed=False):
    return {"time": t, "src_ip": src, "dst_ip": dst,
            "dst_port": port, "login_failed": failed}


class TestDataStructures(unittest.TestCase):
    def test_sliding_window_drops_old_events(self):
        w = SlidingWindow(10)
        w.add(0)
        w.add(5)
        self.assertEqual(w.add(12), 2)     # event at t=0 has fallen out

    def test_graph_counts_ports(self):
        g = ConnectionGraph()
        for p in (1, 2, 3, 3):
            g.add_connection("a", "b", p)
        self.assertEqual(g.max_ports_on_one_target("a"), 3)

    def test_priority_queue_highest_first(self):
        q = ThreatQueue()
        q.push({"score": 3})
        q.push({"score": 9})
        q.push({"score": 6})
        self.assertEqual([q.pop()["score"] for _ in range(3)], [9, 6, 3])


class TestDetection(unittest.TestCase):
    def test_normal_traffic_no_alert(self):
        e = SentinelEngine()
        alerts = []
        for i in range(20):
            alerts += e.process(make_pkt(i))
        self.assertEqual(alerts, [])

    def test_flood_detected(self):
        e = SentinelEngine()
        alerts = []
        for i in range(150):
            alerts += e.process(make_pkt(i * 0.01))
        self.assertTrue(any(a["type"] == "Traffic Flood" for a in alerts))

    def test_port_scan_detected(self):
        e = SentinelEngine()
        alerts = []
        for p in range(1, 30):
            alerts += e.process(make_pkt(p * 0.1, port=p))
        self.assertTrue(any(a["type"] == "Port Scan" for a in alerts))

    def test_brute_force_detected(self):
        e = SentinelEngine()
        alerts = []
        for i in range(8):
            alerts += e.process(make_pkt(i * 0.5, port=22, failed=True))
        self.assertTrue(any(a["type"] == "Brute Force" for a in alerts))

    def test_full_simulation_finds_all_three_attackers(self):
        e = SentinelEngine()
        found = set()
        for p in generate_traffic():
            for a in e.process(p):
                found.add((a["ip"], a["type"]))
        self.assertIn(("10.0.0.99", "Traffic Flood"), found)
        self.assertIn(("10.0.0.50", "Port Scan"), found)
        self.assertIn(("10.0.0.77", "Brute Force"), found)

    def test_no_false_alarm_on_normal_users(self):
        e = SentinelEngine()
        for p in generate_traffic():
            for a in e.process(p):
                self.assertFalse(a["ip"].startswith("192.168.1."))


if __name__ == "__main__":
    unittest.main(verbosity=2)