#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_summary —— 扫描结果后处理（规范化/汇总）测试"""
import unittest

from detector.tests.util import mktemp
from detector.scanner.summary import aggregate, normalize, top_severity


def _result(repo="a_b", verdict="pending", files=3, hits=None):
    return {
        "repo": repo,
        "verdict": verdict,
        "files_scanned": files,
        "hits": hits if hits is not None else [],
        "fetch_method": "tarball",
        "confidence": 0.5,
        "reason": "x",
        "shadow_features": [],
    }


class TestSummary(unittest.TestCase):
    def setUp(self):
        self.tmp = mktemp("mpv_test_sum_")

    def test_top_severity(self):
        hits = [{"severity": "LOW"}, {"severity": "CRITICAL"}, {"severity": "HIGH"}]
        self.assertEqual(top_severity(hits), "CRITICAL")
        self.assertEqual(top_severity([]), "NONE")

    def test_aggregate_row_fields(self):
        hits = [{"severity": "CRITICAL", "pattern_id": "E2"},
                {"severity": "HIGH", "pattern_id": "E1"},
                {"severity": "HIGH", "pattern_id": "P1"}]
        rows = aggregate([(self.tmp / "a.json", _result(hits=hits))])
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["repo"], "a_b")
        self.assertEqual(row["hits"], 3)
        self.assertEqual(row["CRITICAL"], 1)
        self.assertEqual(row["HIGH"], 2)
        self.assertEqual(row["MEDIUM"], 0)
        self.assertEqual(row["top_severity"], "CRITICAL")

    def test_normalize_demotes_benign_without_files(self):
        data = _result(verdict="benign", files=0)
        demoted = normalize([(self.tmp / "a.json", data)])
        self.assertEqual(demoted, ["a_b"])
        self.assertEqual(data["verdict"], "not_scanned")

    def test_normalize_keeps_scanned_benign(self):
        data = _result(verdict="benign", files=5)
        demoted = normalize([(self.tmp / "a.json", data)])
        self.assertEqual(demoted, [])
        self.assertEqual(data["verdict"], "benign")


if __name__ == "__main__":
    unittest.main()
