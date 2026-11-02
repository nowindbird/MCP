#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detector.paths —— 路径常量与基础路径工具
==========================================
从 deps.py 抽出，只放无外部依赖的路径/常量/简单工具函数。
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from detector.config import (
    CONFIG,
    LARGE_REPO_SOURCE,
    MEDIUM_REPO_META,
    SCAN_OUTPUT_DIR,
    STATIC_CONFIG,
)

# 路径
DATA_DIR: Path = LARGE_REPO_SOURCE       # 被检代码根（默认 dateset/）
METADATA_DIR: Path = MEDIUM_REPO_META    # 插件元数据根（默认 dateset/）

SCAN_SUMMARY_FIELDS: List[str] = list(CONFIG["scan_summary_fields"])

# 沙箱镜像资源目录（Dockerfile / entrypoint.sh / fixtures 所在）
SANDBOX_IMAGE_DIR: Path = Path(__file__).resolve().parent / "executor"

# 扫描口径：直接取自 config，杜绝各模块自己定义
SKIP_DIRS = frozenset(d.lower() for d in STATIC_CONFIG["SKIP_DIRS"])
DOC_SKIP_DIRS = frozenset(d.lower() for d in STATIC_CONFIG["DOC_SKIP_DIRS"])
SCAN_EXTS = frozenset(e.lower() for e in STATIC_CONFIG["SCAN_EXTS"])
SPECIAL_FILES = frozenset(f.lower() for f in STATIC_CONFIG["SPECIAL_FILES"])
CODE_EXTS = frozenset(e.lower() for e in STATIC_CONFIG["CODE_EXTS"])
MAX_FILE_SIZE_BYTES: int = STATIC_CONFIG["MAX_FILE_SIZE_BYTES"]
MAX_LINE_LENGTH: int = STATIC_CONFIG["MAX_LINE_LENGTH"]
EVAL_DENSITY_THRESHOLD: int = STATIC_CONFIG["EVAL_DENSITY_THRESHOLD"]

# 静态扫描允许 docs/ 参与（README 可能藏在 docs 下）；语义文档生成则跳过
_SKIP_DIRS_FOR_SCAN = SKIP_DIRS - {"docs"}


def ensure_dir(path: Path | str) -> Path:
    """创建目录（幂等）并返回 Path。"""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def repo_dir(repo: str, root: Optional[Path | str] = None) -> Path:
    """把 ``owner/repo`` 或 ``owner_repo`` 解析为本地仓库目录。"""
    base = Path(root) if root else DATA_DIR
    return base / str(repo).replace("/", "_")


def scan_result_path(repo: str, results_dir: Optional[Path | str] = None) -> Path:
    """单仓库扫描结果 JSON 路径（``<owner>__<repo>.json``）。"""
    base = Path(results_dir) if results_dir else SCAN_OUTPUT_DIR
    return base / (str(repo).replace("/", "__") + ".json")


def now_iso() -> str:
    """UTC ISO8601 时间戳（统一时区口径）。"""
    return datetime.now(timezone.utc).isoformat()


def ensure_utf8_stdio() -> None:
    """把 stdout/stderr 切到 UTF-8，避免 Windows GBK 控制台遇到 emoji 直接崩。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            continue
