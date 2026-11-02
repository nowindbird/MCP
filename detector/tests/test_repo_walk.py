#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_repo_walk —— 仓库遍历口径测试"""
import unittest

from detector.tests.util import mktemp
from detector.repo_walk import (
    detect_languages,
    is_scannable_file,
    iter_repo_files,
    read_readme,
    should_skip_dir,
)


class TestRepoWalk(unittest.TestCase):
    def setUp(self):
        self.root = mktemp("mpv_test_walk_")
        (self.root / ".git").mkdir()
        (self.root / "node_modules").mkdir()
        (self.root / "src").mkdir()
        (self.root / ".git" / "x.py").write_text("x", encoding="utf-8")
        (self.root / "node_modules" / "y.py").write_text("y", encoding="utf-8")
        (self.root / "src" / "main.py").write_text("print(1)", encoding="utf-8")
        (self.root / "README.md").write_text("# hi", encoding="utf-8")
        (self.root / "Dockerfile").write_text("FROM x", encoding="utf-8")
        (self.root / "big.txt").write_text("z" * 500, encoding="utf-8")

    def test_should_skip_dir(self):
        self.assertTrue(should_skip_dir(".git"))
        self.assertTrue(should_skip_dir("Node_Modules"))
        self.assertFalse(should_skip_dir("docs"))  # 扫描允许 docs 参与
        self.assertTrue(should_skip_dir("mydir", extra=["mydir"]))

    def test_is_scannable_file(self):
        self.assertTrue(is_scannable_file(self.root / "README.md"))
        self.assertTrue(is_scannable_file(self.root / "src" / "main.py"))
        self.assertTrue(is_scannable_file(self.root / "Dockerfile"))
        self.assertFalse(is_scannable_file(self.root / "a.exe"))
        self.assertFalse(is_scannable_file(self.root / "a.png"))

    def test_iter_repo_files_skips_noise_dirs(self):
        got = sorted(p.relative_to(self.root).as_posix()
                     for p in iter_repo_files(self.root))
        self.assertEqual(got, ["Dockerfile", "README.md", "big.txt", "src/main.py"])

    def test_iter_repo_files_max_bytes(self):
        got = list(iter_repo_files(self.root, max_bytes=100))
        names = sorted(p.relative_to(self.root).as_posix() for p in got)
        self.assertNotIn("big.txt", names)
        self.assertIn("src/main.py", names)

    def test_iter_repo_files_ext_filter(self):
        got = sorted(p.name for p in iter_repo_files(self.root, exts=(".py",)))
        self.assertEqual(got, ["main.py"])

    def test_read_readme(self):
        text = read_readme(self.root)
        self.assertEqual(text, "# hi")
        self.assertIsNone(read_readme(self.root / "src"))

    def test_detect_languages(self):
        self.assertEqual(detect_languages(self.root), ["python"])


if __name__ == "__main__":
    unittest.main()
