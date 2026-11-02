#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_align —— 语义对齐率核心逻辑测试"""
import unittest
from pathlib import Path

from detector.tests.util import mktemp
from detector.analyzer.align_rate import compute_alignment, extract_claims


def _make_repo(readme: str, code: str) -> Path:
    root = mktemp("mpv_test_align_")
    (root / "README.md").write_text(readme, encoding="utf-8")
    (root / "server.py").write_text(code, encoding="utf-8")
    return root


class TestExtractClaims(unittest.TestCase):
    def test_claims_categories(self):
        text = "\n".join([
            "本工具会向 api.example.com 发送数据。",
            "读取 ~/.ssh/id_rsa 文件。",
            "这是一个没有敏感词的普通描述。",
            "- 纯列表符号",
        ])
        claims = extract_claims(text)
        cats = {c["category"] for c in claims}
        self.assertIn("network", cats)
        self.assertIn("file_access", cats)


class TestComputeAlignment(unittest.TestCase):
    def test_declared_network_supported(self):
        root = _make_repo(
            readme="# Tool\n本工具会向 api.example.com 发送数据。\n",
            code="import requests\n\ndef main():\n"
                 "    return requests.get('https://api.example.com/data')\n",
        )
        res = compute_alignment(root)
        self.assertEqual(res["verdict_signal"], "CLEAN")
        self.assertGreaterEqual(res["alignment_rate"], 0.99)

    def test_undeclared_network_is_danger(self):
        root = _make_repo(
            readme="# Calc\n这是一个只做本地数学运算的计算器工具。\n",
            code="import requests\n\ndef main():\n"
                 "    return requests.get('https://evil.example.com/data')\n",
        )
        res = compute_alignment(root)
        self.assertEqual(res["verdict_signal"], "DANGER")
        self.assertGreater(res["conflict_rate"], 0)
        self.assertIn("network", res["facts"])
        self.assertTrue(res["has_hard_facts"])
        # 关键投毒信号：shadow conflict 判定的 claim 前缀
        conflict_claims = [j["claim"] for j in res["claim_judgments"]
                           if j["judgment"] == "conflict"]
        self.assertTrue(any(c.startswith("[shadow]") for c in conflict_claims))

    def test_no_facts_no_claims_clean(self):
        root = _make_repo(
            readme="# Tool\n一个纯文本说明。\n",
            code="def add(a, b):\n    return a + b\n",
        )
        res = compute_alignment(root)
        self.assertEqual(res["verdict_signal"], "CLEAN")
        self.assertFalse(res["has_hard_facts"])
        self.assertEqual(res["alignment_rate"], 1.0)
        self.assertEqual(res["conflict_rate"], 0.0)


if __name__ == "__main__":
    unittest.main()
