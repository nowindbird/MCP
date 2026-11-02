#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_patterns —— 检测规则库完整性测试（改规则后跑一遍即可放心发布）"""
import re
import unittest

from detector.scanner.patterns import CONFIG_EXTS, PATTERNS

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


class TestPatterns(unittest.TestCase):
    def test_all_patterns_compile(self):
        for pid, label, sev, regex, flags in PATTERNS:
            with self.subTest(pattern=pid + ":" + label):
                cre = re.compile(regex, flags or 0)
                self.assertTrue(cre.pattern)

    def test_severities_valid(self):
        for pid, label, sev, regex, flags in PATTERNS:
            self.assertIn(sev, VALID_SEVERITIES, f"{pid}:{label} 非法严重性 {sev}")

    def test_ids_cover_paper_categories(self):
        ids = {p[0] for p in PATTERNS}
        # 论文 Table 9 的 14 模式 + MCP 补充 M1-M9
        for want in ("E1", "E2", "E3", "E4", "P1", "P2", "P3", "P4",
                     "PE1", "PE2", "PE3", "SC1", "SC2", "SC3",
                     "M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9"):
            self.assertIn(want, ids, f"缺少模式 {want}")

    def test_config_exts(self):
        self.assertIn(".json", CONFIG_EXTS)
        self.assertIn(".env", CONFIG_EXTS)


if __name__ == "__main__":
    unittest.main()
