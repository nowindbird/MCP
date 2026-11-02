#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detector.optional_deps —— 可选依赖探测与按需导入
=================================================
从 deps.py 抽出，离线功能不依赖 requests 等第三方库。
"""
from __future__ import annotations


class MissingDependency(RuntimeError):
    """缺少可选的第三方依赖时抛出（附带安装提示）。"""


def has_module(name: str) -> bool:
    """判断第三方模块是否可导入（不真正 import 其全部依赖）。"""
    import importlib.util
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def require_requests():
    """按需导入 requests；缺失时给出可执行的安装提示。"""
    try:
        import requests  # noqa: F401
        return requests
    except ImportError as e:
        raise MissingDependency(
            "缺少依赖 requests，请先执行: pip install -r requirements.txt"
        ) from e
