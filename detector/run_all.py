#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detector.run_all —— 一键静态链路（薄封装）
==========================================
依次跑：scan（扫 dateset/）→ summary（汇总）→ report-html（生成 HTML 报告）。

实际编排逻辑统一在 ``detector.pipeline.pipeline.run_auto_chain``，
与 ``python -m detector.cli pipeline --all`` 走同一条代码路径。

用法::

    python -m detector.cli run              # 一键跑完静态链路
    python -m detector.cli run --skip-scan  # 跳过扫描，直接用已有结果出报告
"""
from __future__ import annotations

import argparse

from detector.deps import REPORT_HTML, ensure_utf8_stdio
from detector.pipeline.pipeline import run_auto_chain


def main() -> int:
    ensure_utf8_stdio()
    ap = argparse.ArgumentParser(description="一键静态链路：scan → summary → report-html")
    ap.add_argument("--out-dir", default="", help="扫描结果目录（默认 config.SCAN_OUTPUT_DIR）")
    ap.add_argument("--report", default=str(REPORT_HTML), help="HTML 报告输出路径")
    ap.add_argument("--skip-scan", action="store_true",
                    help="跳过扫描，直接用已有结果生成报告")
    args = ap.parse_args()
    return run_auto_chain(scan_out=args.out_dir, report_out=args.report,
                          skip_scan=args.skip_scan)


if __name__ == "__main__":
    raise SystemExit(main())
