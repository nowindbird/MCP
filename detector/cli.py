#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MPV-Detector 统一命令行入口
============================
参考论文 MaliciousAgentSkillsBench 的 helper.py 交互入口思想，把分散在各层的
检测模块收敛到一条命令下：`python -m detector.cli <子命令> [模块参数...]`。

用法示例:
  python -m detector.cli crawl --fetch-readme --output output
  python -m detector.cli organize
  python -m detector.cli scan --manifest output/shard1.csv --out-dir output/scan_results
  python -m detector.cli normalize
  python -m detector.cli aggregate
  python -m detector.cli report
  python -m detector.cli align --repo-dir <某仓库>
  python -m detector.cli sandbox-rules --repo-dir <某仓库> --output rules.json
  python -m detector.cli monitor --rules rules.json --mode docker --repo-dir <某仓库>
  python -m detector.cli docgen --backend openai
  python -m detector.cli finetune-build <repo_dir> -o dataset.jsonl

除子命令名外，其余参数原样透传给对应模块。
"""

import importlib
import sys
from pathlib import Path

# 确保 detector/ 可被 import（config 等模块依赖它）
sys.path.insert(0, str(Path(__file__).resolve().parent))


# 子命令 → 模块路径（点分，便于 importlib）
COMMANDS = {
    # ---- 数据采集层 ----
    "crawl":             "detector.crawler.github_crawler",
    "organize":          "detector.crawler.organize_plugins",
    # ---- 代码获取层 ----
    "fetch-api":         "detector.fetcher.fetch_api_selective",
    "fetch-small":       "detector.fetcher.fetch_small_repos",
    "fetch-tarballs":    "detector.fetcher.fetch_tarballs",
    "fetch-tarballs2":   "detector.fetcher.fetch_tarballs2",
    "fetch-retry":       "detector.fetcher.fetch_retry",
    "inventory":         "detector.fetcher.cache_inventory",
    # ---- 静态扫描层 ----
    "scan":              "detector.scanner.scanner",
    "normalize":         "detector.scanner.normalize",
    "aggregate":         "detector.scanner.aggregate",
    "report":            "detector.scanner.report",
    # ---- 语义分析层 ----
    "docgen":            "detector.analyzer.docgen",
    "align":             "detector.analyzer.align_rate",
    "finetune-build":    "detector.analyzer.finetune.build_dataset",
    "finetune-build2":   "detector.analyzer.finetune.build_dataset_v2",
    "finetune-train":    "detector.analyzer.finetune.train_lora",
    "finetune-infer":    "detector.analyzer.finetune.infer_mcp_doc",
    # ---- 沙箱执行层 ----
    "sandbox-rules":     "detector.executor.sandbox_rules",
    "monitor":           "detector.executor.behavior_monitor",
}


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print(__doc__)
        return 0

    cmd = sys.argv[1]
    if cmd not in COMMANDS:
        print(f"[错误] 未知子命令: {cmd}\n可用命令: {', '.join(COMMANDS)}", file=sys.stderr)
        return 2

    mod = importlib.import_module(COMMANDS[cmd])
    # 把剩余参数透传给目标模块（保留 argv[0] 为程序名，供 argparse 使用）
    sys.argv = [sys.argv[0]] + sys.argv[2:]
    return int(mod.main() or 0)


if __name__ == "__main__":
    sys.exit(main())
