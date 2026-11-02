#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_monitor_parser —— 沙箱事件解析纯函数测试"""
import unittest

from detector.executor.monitor_parser import (
    parse_event_log,
    parse_strace_text,
    parse_tcpdump_text,
)

STRACE = """
12345 execve("/usr/bin/python3", ["python3", "/app/server.py"], 0x7fff...) = 0
12345 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3
12345 connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0
"""

TCPDUMP = """
16:00:01.123456 IP 10.0.0.2.53001 > 10.0.0.1.53: 1234+ A? evil.example.com. (28)
16:00:02.000000 IP 192.168.1.2.52345 > 93.184.216.34.443: Flags [S], seq 1
"""


class TestParseStrace(unittest.TestCase):
    def test_execs_opens_connects(self):
        parsed = parse_strace_text(STRACE)
        self.assertEqual(parsed["execs"][0]["command"], "python3")
        self.assertEqual(parsed["execs"][0]["argv"], "python3 /app/server.py")
        self.assertIn("/etc/passwd", parsed["opens"])
        self.assertEqual(parsed["connects"], [("93.184.216.34", 443)])


class TestParseTcpdump(unittest.TestCase):
    def test_dns_tcp_honeypot(self):
        parsed = parse_tcpdump_text(
            TCPDUMP, honeypot_indicators=["honeypot_fake_key_do_not_use"])
        self.assertEqual(parsed["dns_queries"], ["evil.example.com"])
        # tcp_dsts 保留全部目的（含 DNS 的 53 端口，parse_event_log 里才过滤）
        self.assertEqual(parsed["tcp_dsts"],
                         [("10.0.0.1", 53), ("93.184.216.34", 443)])
        self.assertEqual(parsed["honeypot_hits"], [])

    def test_honeypot_hit_detected(self):
        text = TCPDUMP + "\npayload: honeypot_fake_key_do_not_use leaked\n"
        parsed = parse_tcpdump_text(
            text, honeypot_indicators=["honeypot_fake_key_do_not_use"])
        self.assertEqual(parsed["honeypot_hits"], ["honeypot_fake_key_do_not_use"])


class TestParseEventLog(unittest.TestCase):
    def test_behaviors(self):
        behaviors = parse_event_log(STRACE, TCPDUMP)
        cats = {b.category for b in behaviors}
        self.assertIn("subprocess", cats)
        self.assertIn("file_access", cats)   # /etc/passwd 属敏感路径
        self.assertIn("network", cats)
        # 回归：strace connect 必须转成 network 行为（曾被静默丢弃）
        nets = [b for b in behaviors if b.category == "network"]
        hosts = {(b.details.get("host"), b.details.get("port")) for b in nets}
        self.assertIn(("93.184.216.34", 443), hosts)

    def test_honeypot_payload_becomes_credential(self):
        text = TCPDUMP + "\npayload: honeypot_fake_key_do_not_use leaked\n"
        behaviors = parse_event_log(
            STRACE, text,
            honeypot_indicators=["honeypot_fake_key_do_not_use"])
        creds = [b for b in behaviors if b.category == "credential"]
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0].severity, "CRITICAL")


if __name__ == "__main__":
    unittest.main()
