#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MPV-Detector 端到端流水线编排
==============================
参考论文 MaliciousAgentSkillsBench/scripts/run_pipeline.sh 的思路，把
「抓取 → 落盘 → 获取 → 扫描 → 规范化 → 汇总 → 对齐率 → 沙箱规则 → 行为监控」
串成可复现的步骤流水线。每个 step 映射到 detector/cli.py 的对应子命令。

默认不执行（生产链路依赖网络 / LLM / Docker，需按需开启），用 --run 指定实际执行范围。
可复现命令清单见各 step 的 cmd。

用法:
  python -m detector.pipeline.pipeline            # 打印流水线步骤与命令
  python -m detector.pipeline.pipeline --run scan # 仅执行 scan 步骤
"""

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent  # 项目根


STEPS = [
    {
        "id": "crawl", "desc": "抓取 GitHub MCP 仓库元数据",
        "cmd": ["python", "-m", "detector.cli", "crawl", "--fetch-readme", "--output", "output"],
        "needs": "网络 / GITHUB_TOKEN",
    },
    {
        "id": "organize", "desc": "抓取结果落盘到 mcp插件/ 并生成路径清单",
        "cmd": ["python", "-m", "detector.cli", "organize"],
        "needs": "crawl 产物 output/mcp_repos_*.json",
    },
    {
        "id": "fetch", "desc": "多通道获取仓库代码到缓存（git clone / tarball / tree+raw）",
        "cmd": ["python", "-m", "detector.cli", "fetch-tarballs2"],
        "needs": "网络 / git",
    },
    {
        "id": "scan", "desc": "静态扫描（T2 候选），按分片产出 scan_results/*.json",
        "cmd": ["python", "-m", "detector.cli", "scan", "--manifest", "output/shard1.csv",
                "--out-dir", "output/scan_results"],
        "needs": "fetch 已落缓存",
    },
    {
        "id": "normalize", "desc": "判定规范化（files_scanned==0 的 benign → not_scanned）",
        "cmd": ["python", "-m", "detector.cli", "normalize"],
        "needs": "scan 产物",
    },
    {
        "id": "aggregate", "desc": "汇总扫描结果 → output/scan_summary.csv",
        "cmd": ["python", "-m", "detector.cli", "aggregate"],
        "needs": "normalize 产物",
    },
    {
        "id": "report", "desc": "输出报告统计（模式命中/severity/shadow/not_scanned）",
        "cmd": ["python", "-m", "detector.cli", "report"],
        "needs": "scan_results/*.json",
    },
    {
        "id": "docgen", "desc": "通用 LLM 生成语义文档（对齐率输入）",
        "cmd": ["python", "-m", "detector.cli", "docgen"],
        "needs": "本地 Ollama 或 LLM 后端",
    },
    {
        "id": "align", "desc": "语义对齐率：AST 硬事实 vs README/文档声明",
        "cmd": ["python", "-m", "detector.cli", "align", "--repo-dir", "<某仓库>"],
        "needs": "LLM（可选增强）",
    },
    {
        "id": "sandbox-rules", "desc": "由对齐率结果生成沙箱拦截规则",
        "cmd": ["python", "-m", "detector.cli", "sandbox-rules", "--repo-dir", "<某仓库>",
                "--output", "rules.json"],
        "needs": "align 产物",
    },
    {
        "id": "monitor", "desc": "沙箱运行时行为监控（T3 行为确认）",
        "cmd": ["python", "-m", "detector.cli", "monitor", "--rules", "rules.json",
                "--mode", "docker", "--repo-dir", "<某仓库>"],
        "needs": "Docker + sandbox 镜像",
    },
]

# 端到端默认执行顺序
DEFAULT_ORDER = ["crawl", "organize", "fetch", "scan", "normalize",
                 "aggregate", "report", "docgen", "align", "sandbox-rules", "monitor"]


def main() -> int:
    ap = argparse.ArgumentParser(description="MPV-Detector 流水线编排")
    ap.add_argument("--run", default="", help="要实际执行的 step id（默认只打印不执行）")
    args = ap.parse_args()

    if args.run:
        step = next((s for s in STEPS if s["id"] == args.run), None)
        if not step:
            print(f"[错误] 未知 step: {args.run}，可用: {', '.join(DEFAULT_ORDER)}", file=sys.stderr)
            return 2
        print(f"[流水线] 执行 {step['id']}: {step['desc']}")
        print(f"  $ {' '.join(step['cmd'])}")
        return subprocess.call(step["cmd"], cwd=str(ROOT))

    # 仅打印步骤清单（可复现命令）
    print(f"MPV-Detector 流水线（项目根: {ROOT}）\n")
    for i, sid in enumerate(DEFAULT_ORDER, 1):
        s = next(x for x in STEPS if x["id"] == sid)
        print(f"[{i:02d}] {s['id']:<14} {s['desc']}")
        print(f"      $ {' '.join(s['cmd'])}")
        print(f"      依赖: {s['needs']}\n")
    print("提示: 用 --run <step> 实际执行某一步；完整链路请按 01→11 顺序运行。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
