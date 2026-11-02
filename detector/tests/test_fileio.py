#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_fileio —— 统一文件 IO 层测试"""
import unittest

from detector.tests.util import mktemp
from detector.fileio import (
    load_scan_summary,
    load_targets,
    normalize_repo_key,
    read_json,
    read_jsonl,
    read_text,
    write_csv,
    write_json,
    write_jsonl,
    write_text,
)


class TestTextJson(unittest.TestCase):
    def setUp(self):
        self.tmp = mktemp("mpv_test_io_")

    def test_write_read_text(self):
        p = write_text(self.tmp / "sub" / "a.txt", "你好, world")
        self.assertTrue(p.exists())
        self.assertEqual(read_text(p), "你好, world")

    def test_read_text_missing_returns_none(self):
        self.assertIsNone(read_text(self.tmp / "nope.txt"))

    def test_json_roundtrip(self):
        p = write_json(self.tmp / "a.json", {"k": "值", "n": 1})
        self.assertEqual(read_json(p), {"k": "值", "n": 1})

    def test_read_json_broken_returns_default(self):
        p = self.tmp / "bad.json"
        p.write_text("{not json", encoding="utf-8")
        self.assertEqual(read_json(p, default={}), {})

    def test_jsonl_roundtrip_skips_bad_lines(self):
        p = self.tmp / "a.jsonl"
        p.write_text('{"a": 1}\n\nnot-json\n{"b": 2}\n', encoding="utf-8")
        self.assertEqual(read_jsonl(p), [{"a": 1}, {"b": 2}])
        out = write_jsonl(self.tmp / "b.jsonl", [{"x": 1}, {"x": 2}])
        self.assertEqual(read_jsonl(out), [{"x": 1}, {"x": 2}])

    def test_write_csv_with_bom_and_fields(self):
        p = write_csv(self.tmp / "a.csv", [{"repo": "a/b", "n": 1}],
                      ["repo", "n"])
        raw = p.read_bytes()
        self.assertTrue(raw.startswith(b"\xef\xbb\xbf"))  # utf-8-sig BOM


class TestTargetsAndSummary(unittest.TestCase):
    def setUp(self):
        self.tmp = mktemp("mpv_test_tgt_")

    def test_load_targets_comments_and_blank(self):
        p = self.tmp / "t.txt"
        p.write_text("# 注释\n\n a_b \n c_d\n", encoding="utf-8")
        self.assertEqual(load_targets(p), ["a_b", "c_d"])

    def test_load_targets_missing_returns_empty(self):
        self.assertEqual(load_targets(self.tmp / "nope.txt"), [])

    def test_normalize_repo_key(self):
        self.assertEqual(normalize_repo_key("a/b"), "a_b")
        self.assertEqual(normalize_repo_key("a_b"), "a_b")

    def test_load_scan_summary(self):
        p = self.tmp / "s.csv"
        p.write_text("repo,verdict,CRITICAL,HIGH,hits\n"
                     "a/b,suspicious,1,2,7\n"
                     "c_d,benign,0,0,0\n", encoding="utf-8")
        got = load_scan_summary(p)
        self.assertEqual(got["a_b"], {"crit": 1, "high": 2, "hits": 7})
        self.assertEqual(got["c_d"], {"crit": 0, "high": 0, "hits": 0})


if __name__ == "__main__":
    unittest.main()
