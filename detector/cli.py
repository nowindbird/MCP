#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MPV-Detector 统一命令行入口
============================
把分散在各层的检测模块收敛到一条命令下：

    python -m detector.cli <子命令> [该模块自己的参数...]

设计约定
--------
* 本入口只做「子命令 → 模块」的分发，参数原样透传给目标模块的 ``main()``，
  因此各模块仍可独立运行：``python -m detector.scanner.scanner --help``。
* 不做任何 ``sys.path`` 注入：项目以 ``detector`` 包形式导入，请在**项目根**执行
  （``pip install -e .`` 后则在任意目录均可）。
* 依赖统一走 ``detector.deps``，子命令清单只在这里维护。

示例::

    python -m detector.cli crawl --fetch-readme
    python -m detector.cli fetch --manifest output/scan_manifest.csv
    python -m detector.cli scan --manifest output/shard1.csv --out-dir output/scan_results
    python -m detector.cli summary --stage all
    python -m detector.cli docgen --backend openai
    python -m detector.cli align --repo-dir mcp插件/<owner>_<repo>
    python -m detector.cli sandbox-rules --repo-dir mcp插件/<owner>_<repo> --output rules.json
    python -m detector.cli monitor --rules rules.json --mode docker --repo-dir mcp插件/<owner>_<repo>
    python -m detector.cli flow --targets output/targets.txt --out-dir output/gen_docs
"""

import importlib
import sys

# 子命令 → 模块路径（点分，便于 importlib）
COMMANDS = {
    # ---- 数据采集层 ----
    "crawl": "detector.crawler.github_crawler",
    # ---- 代码获取层 ----
    "fetch": "detector.fetcher.fetch_repo",
    # ---- 静态扫描层 ----
    "scan": "detector.scanner.scanner",
    "summary": "detector.scanner.summary",
    # ---- 语义分析层 ----
    "docgen": "detector.analyzer.docgen",
    "align": "detector.analyzer.align_rate",
    "finetune-build": "detector.analyzer.finetune.build_dataset",
    "finetune-build2": "detector.analyzer.finetune.build_dataset_v2",
    "finetune-train": "detector.analyzer.finetune.train_lora",
    "finetune-infer": "detector.analyzer.finetune.infer_mcp_doc",
    # ---- 沙箱执行层 ----
    "sandbox-rules": "detector.executor.sandbox_rules",
    "monitor": "detector.executor.behavior_monitor",
    # ---- 编排层 ----
    "flow": "detector.pipeline.run_flow",
    "pipeline": "detector.pipeline.pipeline",
}


def _usage() -> str:
    lines = [__doc__.strip(), "", "可用子命令:"]
    width = max(len(k) for k in COMMANDS)
    for name, mod in COMMANDS.items():
        lines.append(f"  {name:<{width}}  →  {mod}")
    lines += ["", "查看某子命令参数: python -m detector.cli <子命令> --help"]
    return "\n".join(lines)


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print(_usage())
        return 0

    cmd = sys.argv[1]
    if cmd in ("-l", "--list"):
        for name in COMMANDS:
            print(name)
        return 0
    if cmd not in COMMANDS:
        print(f"[错误] 未知子命令: {cmd}\n可用命令: {', '.join(COMMANDS)}", file=sys.stderr)
        return 2

    mod = importlib.import_module(COMMANDS[cmd])
    # 把剩余参数透传给目标模块（保留 argv[0] 供 argparse 使用）
    sys.argv = [sys.argv[0]] + sys.argv[2:]
    return int(mod.main() or 0)


if __name__ == "__main__":
    sys.exit(main())
