#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""detector.tests.util —— 测试辅助（工作区内临时目录）

测试临时目录统一落在 detector/tests/.tmp/ 下，便于集中清理、
不污染系统 TEMP，也方便沙箱受限环境（只允许写工作区）下运行。
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

_TMP_ROOT = Path(__file__).resolve().parent / ".tmp"


def mktemp(prefix: str = "mpv_test_") -> Path:
    """创建工作区内临时目录并返回 Path。"""
    _TMP_ROOT.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=str(_TMP_ROOT)))


def cleanup_all() -> None:
    """删除全部测试临时目录（可选，跑完测试后手动调用）。"""
    if _TMP_ROOT.is_dir():
        shutil.rmtree(_TMP_ROOT, ignore_errors=True)
