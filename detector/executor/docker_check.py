#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detector.executor.docker_check —— Docker 守护进程探测
=====================================================
从 deps.py 抽出，单独管理 Docker 相关探测逻辑。
"""
from __future__ import annotations

import shutil
import subprocess


def docker_available() -> bool:
    """探测 Docker 守护进程是否可用（CLI 存在 != 守护进程在跑）。"""
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(
            ["docker", "info"], capture_output=True, timeout=30
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False
