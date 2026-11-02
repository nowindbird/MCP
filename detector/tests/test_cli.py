#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_cli —— 统一入口分发测试"""
import json
import unittest

from detector.tests.util import mktemp
from detector.cli import ALIASES, COMMANDS, dispatch


class TestDispatch(unittest.TestCase):
    def test_unknown_command_returns_2(self):
        self.assertEqual(dispatch("no-such-command"), 2)

    def test_alias_mapping(self):
        self.assertEqual(ALIASES["s"], "scan")
        self.assertEqual(ALIASES["all"], "run")

    def test_help_exits_zero(self):
        # argparse --help 抛 SystemExit(0)，dispatch 会还原 sys.argv
        with self.assertRaises(SystemExit) as cm:
            dispatch("summary", ["--help"])
        self.assertEqual(cm.exception.code, 0)

    def test_dispatch_runs_subcommand(self):
        # 回归：dispatch 必须只透传参数本身（不能把子命令名留在 argv 里）
        d = mktemp("mpv_test_disp_")
        results = d / "res"
        results.mkdir()
        (results / "a.json").write_text(
            json.dumps({"repo": "a", "verdict": "benign", "hits": []}),
            encoding="utf-8")
        out = d / "r.html"
        code = dispatch("report-html",
                        ["--results-dir", str(results), "--out", str(out)])
        self.assertEqual(code, 0)
        self.assertTrue(out.exists())

    def test_commands_complete(self):
        for name in ("crawl", "fetch", "scan", "summary", "targets",
                     "report-html", "docgen", "align", "sandbox-rules",
                     "monitor", "flow", "pipeline", "run", "tui"):
            self.assertIn(name, COMMANDS)

    def test_special_commands_exist(self):
        # check/test 是内建命令，在 usage 分组中但不映射模块
        from detector import cli
        self.assertIn("check", cli._SPECIAL)
        self.assertIn("test", cli._SPECIAL)


if __name__ == "__main__":
    unittest.main()
