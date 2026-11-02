#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_behavior_monitor —— 行为监控判定逻辑回归测试

覆盖两个曾经的真实 bug：
1. parse_event_log 丢弃 strace connect 数据（未声明网络连接检测失效）；
2. SIMULATE / FIXTURE 模式从不调用 report.stop()（判定永远 INCONCLUSIVE）。
"""
import json
import unittest
from pathlib import Path

from detector.tests.util import mktemp
from detector.executor.monitor_simulate import run_fixture

_DEMO_RULES = Path(__file__).resolve().parent.parent / "executor" / "fixtures" / "demo_rules.json"

STRACE = """
12345 execve("/usr/bin/python3", ["python3", "/app/server.py"], 0x7fff...) = 0
12345 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3
12345 connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0
"""


def _rules():
    return json.loads(_DEMO_RULES.read_text(encoding="utf-8"))


class TestRunFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = mktemp("mpv_test_mon_")
        self.strace = self.tmp / "a.log"
        self.strace.write_text(STRACE, encoding="utf-8")

    def test_verdict_is_determined_not_inconclusive(self):
        # 回归：fixture 模式必须调用 report.stop() 定格判定
        report = run_fixture(_rules(), str(self.strace), "")
        self.assertNotEqual(report.final_verdict, "INCONCLUSIVE")

    def test_strace_connect_becomes_network_behavior(self):
        # 回归：strace connect 必须转成 network 行为（曾被静默丢弃）
        report = run_fixture(_rules(), str(self.strace), "")
        nets = [b for b in report.behaviors if b.category == "network"]
        self.assertTrue(nets)
        self.assertEqual(nets[0].details["host"], "93.184.216.34")
        self.assertEqual(nets[0].details["port"], 443)

    def test_honeypot_payload_is_malicious(self):
        net = self.tmp / "n.txt"
        net.write_text("payload: honeypot_fake_key_do_not_use_sk_1234567890abcdef leaked\n",
                       encoding="utf-8")
        report = run_fixture(_rules(), str(self.strace), str(net))
        self.assertEqual(report.final_verdict, "MALICIOUS")
        self.assertTrue(report.review_requested)

    def test_clean_allowlisted_network_is_clean(self):
        # 网络端点命中 allowlist "*"、命令/路径产生 2 个违规（<3）→ CLEAN
        report = run_fixture(_rules(), str(self.strace), "")
        self.assertEqual(report.final_verdict, "CLEAN")


if __name__ == "__main__":
    unittest.main()
