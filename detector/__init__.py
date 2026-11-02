#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MPV-Detector：MCP 插件生态投毒 / 恶意行为检测。

分层结构（按论文流水线）::

    crawl(采集) → fetch(获取) → scan(静态扫描) → docgen/align(语义对齐)
    → sandbox_rules/monitor(沙箱执行) → flow/pipeline(编排与汇总)

入口：``python -m detector.cli <子命令>``；依赖接口统一见 ``detector.deps``。
"""

__all__ = ["deps", "config"]

__version__ = "2.1.0"
