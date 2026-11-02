#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detector.selftest —— 单元测试入口
==================================
用标准库 unittest 跑 ``tests/`` 下的全部用例（零额外依赖）。

    python -m detector.cli test       # 完整输出
    python -m detector.cli test -q    # 只打印失败
    python -m detector.selftest       # 等价直接入口
"""
from __future__ import annotations

import unittest
from pathlib import Path

from detector.config import PROJECT_ROOT

TESTS_DIR = Path(__file__).resolve().parent / "tests"


def run_tests(verbosity: int = 2, pattern: str = "test_*.py") -> int:
    """发现并运行 tests/ 全部用例，返回退出码（0 = 全部通过）。"""
    if not TESTS_DIR.is_dir():
        print(f"[selftest] 未找到测试目录: {TESTS_DIR}")
        return 1
    # 保证 `import detector` 可用（仅在直接运行、包未安装时才注入路径）
    try:
        import detector  # noqa: F401
    except ImportError:
        import sys
        root = str(PROJECT_ROOT)
        if root not in sys.path:
            sys.path.insert(0, root)
    suite = unittest.defaultTestLoader.discover(str(TESTS_DIR), pattern=pattern)
    result = unittest.TextTestRunner(verbosity=verbosity).run(suite)
    print(f"\n[selftest] 用例 {result.testsRun} 个，"
          f"失败 {len(result.failures)}，错误 {len(result.errors)}")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    import sys

    sys.exit(run_tests(verbosity=0 if "-q" in sys.argv else 2))
