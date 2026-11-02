#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_sandbox_rules —— 沙箱规则生成器测试"""
import unittest
from pathlib import Path

from detector.executor.sandbox_rules import extract_allowlist, generate_rules


def _align_result(verdict_signal="CLEAN", security_conflict_rate=0.0):
    return {
        "repo": "x",
        "facts": {
            "network": ["requests.get('https://evil.com/data')"],
            "file_access": [],
            "subprocess": ["subprocess.run['ls', '-la']"],
            "credential": ["os.getenv('API_KEY')"],
            "obfuscation": [],
        },
        "claims": [],
        "claim_judgments": [],
        "alignment_rate": 1.0,
        "conflict_rate": 0.0,
        "security_conflict_rate": security_conflict_rate,
        "verdict_signal": verdict_signal,
        "_claim_count": 0,
        "_judgment_counts": {"support": 0, "conflict": 0},
    }


class TestExtractAllowlist(unittest.TestCase):
    def test_extract_from_facts(self):
        al = extract_allowlist(_align_result()["facts"], Path("x"))
        self.assertEqual(al["network_endpoints"], ["evil.com"])
        self.assertEqual(al["commands"], ["ls"])
        self.assertEqual(al["env_vars"], ["API_KEY"])

    def test_star_fallback_when_no_endpoint(self):
        # 有网络事实但提取不出具体域名（如 socket 连接）→ 保守放行 "*" 并交人工审核
        facts = {"network": ["socket.connect(('evil.com', 80))"], "file_access": [],
                 "subprocess": [], "credential": [], "obfuscation": []}
        al = extract_allowlist(facts, Path("x"))
        self.assertEqual(al["network_endpoints"], ["*"])


class TestGenerateRules(unittest.TestCase):
    def test_basic_structure(self):
        rules = generate_rules(Path("x"), align_result=_align_result())
        self.assertEqual(rules["repo"], "x")
        self.assertIn("allowlist", rules)
        self.assertIn("blocklist", rules)
        self.assertIn("violation_actions", rules)
        self.assertIn("honeypot_indicators", rules["blocklist"])
        # 默认直接 block 的类别
        self.assertIn("credential", rules["violation_actions"]["auto_block_categories"])
        self.assertIn("obfuscation", rules["violation_actions"]["auto_block_categories"])

    def test_danger_signal_tightens_rules(self):
        rules = generate_rules(Path("x"),
                               align_result=_align_result(verdict_signal="DANGER"))
        va = rules["violation_actions"]
        self.assertIn("network", va["auto_block_categories"])
        self.assertEqual(rules["allowlist"]["network_endpoints"], [])

    def test_universal_blocklist_nonempty(self):
        rules = generate_rules(Path("x"), align_result=_align_result())
        self.assertTrue(rules["blocklist"]["dangerous_patterns"])


if __name__ == "__main__":
    unittest.main()
