#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_targets —— 目标清单生成测试"""
import unittest

from detector.tests.util import mktemp
from detector.targets import _include, from_dir, from_scan_summary


class TestTargets(unittest.TestCase):
    def setUp(self):
        self.tmp = mktemp("mpv_test_tgt_")

    def test_from_scan_summary_filters(self):
        p = self.tmp / "s.csv"
        p.write_text(
            "repo,verdict,CRITICAL,HIGH,hits,top_severity\n"
            "a/b,suspicious,0,0,0,NONE\n"
            "c/d,benign,0,3,3,HIGH\n"
            "e/f,benign,0,0,0,NONE\n"
            "g/h,benign,1,0,1,CRITICAL\n",
            encoding="utf-8")
        # 默认门槛 HIGH：suspicious / HIGH 命中 / CRITICAL 命中都入选
        got = [r[0] for r in from_scan_summary(p, min_severity="HIGH")]
        self.assertEqual(got, ["a_b", "g_h", "c_d"])

    def test_from_scan_summary_critical_only(self):
        p = self.tmp / "s.csv"
        p.write_text(
            "repo,verdict,CRITICAL,HIGH,hits,top_severity\n"
            "a/b,benign,0,3,3,HIGH\n"
            "g/h,benign,1,0,1,CRITICAL\n",
            encoding="utf-8")
        got = [r[0] for r in from_scan_summary(p, min_severity="CRITICAL")]
        self.assertEqual(got, ["g_h"])

    def test_from_scan_summary_min_hits(self):
        p = self.tmp / "s.csv"
        p.write_text(
            "repo,verdict,CRITICAL,HIGH,hits,top_severity\n"
            "a/b,benign,0,0,0,NONE\n"
            "c/d,benign,0,0,7,LOW\n",
            encoding="utf-8")
        got = [r[0] for r in from_scan_summary(p, min_severity="HIGH", min_hits=5)]
        self.assertEqual(got, ["c_d"])

    def test_include_logic(self):
        self.assertTrue(_include("suspicious", "NONE", 0, 1, 0))
        self.assertTrue(_include("benign", "CRITICAL", 0, 0, 0))   # 达到 CRITICAL 门槛
        self.assertTrue(_include("benign", "HIGH", 0, 1, 0))        # 达到 HIGH 门槛
        self.assertFalse(_include("benign", "HIGH", 0, 0, 0))       # CRITICAL 门槛不放行 HIGH
        self.assertFalse(_include("benign", "NONE", 0, 1, 0))       # 无命中
        self.assertTrue(_include("benign", "NONE", 3, 4, 2))        # hits 门槛

    def test_from_dir(self):
        (self.tmp / "a_b").mkdir()
        (self.tmp / "c_d").mkdir()
        (self.tmp / "no-sep").mkdir()
        (self.tmp / "_skip").mkdir()
        (self.tmp / "file.txt").write_text("x", encoding="utf-8")
        self.assertEqual(from_dir(self.tmp), ["a_b", "c_d"])


if __name__ == "__main__":
    unittest.main()
