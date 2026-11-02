#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detector.log_config —— 统一日志配置
=====================================
用法::

    from detector.log_config import get_logger
    log = get_logger(__name__)
    log.info("...")

支持 -v / --verbose 调 DEBUG 级别。
"""
from __future__ import annotations

import logging
import sys

_CONFIGURED = False


def _configure() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    level = logging.DEBUG if "-v" in sys.argv or "--verbose" in sys.argv else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    _configure()
    return logging.getLogger(name)
