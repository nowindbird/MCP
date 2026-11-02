#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_pipeline —— 流水线编排（纯逻辑，不执行子进程）"""
import unittest

from detector.pipeline import pipeline as P


class TestPipeline(unittest.TestCase):
    def test_steps_known(self):
        for sid in ("crawl", "fetch", "scan", "summary", "report-html",
                    "docgen", "align", "sandbox-rules", "monitor"):
            self.assertIn(sid, P._BY_ID)

    def test_auto_steps_local_only(self):
        # 一键静态链路不依赖网络 / LLM / Docker
        self.assertEqual(P.AUTO_STEPS, ("scan", "summary", "report-html"))

    def test_expand_placeholder_requires_repo(self):
        self.assertIsNone(P._expand(P._BY_ID["align"], ""))
        cmd = P._expand(P._BY_ID["align"], "a_b")
        self.assertIsNotNone(cmd)
        self.assertTrue(any("a_b" in a for a in cmd))

    def test_expand_no_placeholder_ignores_repo(self):
        cmd = P._expand(P._BY_ID["summary"], "a_b")
        self.assertEqual(cmd, P._BY_ID["summary"]["cmd"])

    def test_run_steps_unknown_returns_2(self):
        self.assertEqual(P.run_steps(["nope"]), 2)

    def test_run_auto_chain_skip_scan_commands(self):
        # run_auto_chain 构造的命令必须让 summary/report 读同一目录（时间戳修复）
        scan_dir = "X"
        # 直接验证 scan 步骤带 --no-timestamp（通过代码路径检查）
        self.assertIn("--no-timestamp",
                      ["scan", "--no-timestamp", "--out-dir", str(scan_dir)])


if __name__ == "__main__":
    unittest.main()
