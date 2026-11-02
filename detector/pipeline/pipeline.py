#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MPV-Detector 端到端流水线编排
==============================
把「抓取 → 落地 → 获取 → 扫描 → 规范化/汇总 → 语义文档 → 对齐率 → 沙箱规则 → 行为监控」
串成可复现的步骤流水线。每个 step 唯一对应 ``detector.cli`` 的一个子命令，
因此单步命令可直接复制到终端重跑。

默认只打印步骤（生产链路依赖网络 / LLM / Docker，需显式执行）::

    python -m detector.pipeline.pipeline                 # 打印步骤与命令
    python -m detector.pipeline.pipeline --run scan      # 只执行 scan
    python -m detector.pipeline.pipeline --run crawl scan summary   # 按序执行多步
    python -m detector.pipeline.pipeline --all           # 跑完整默认顺序（跳过需占位参数的步骤）
"""

import argparse
import subprocess
import sys

from detector.deps import PROJECT_ROOT, ensure_utf8_stdio

# 每个 step: id / 说明 / 命令（相对项目根执行）/ 前置条件
STEPS = [
    {
        "id": "crawl",
        "desc": "抓取 GitHub MCP 仓库元数据（JSON/CSV）",
        "cmd": ["python", "-m", "detector.cli", "crawl", "--fetch-readme"],
        "needs": "网络 / 可选 GITHUB_TOKEN",
    },
    {
        "id": "fetch",
        "desc": "按清单获取仓库代码到缓存（tarball / tree+raw）",
        "cmd": ["python", "-m", "detector.cli", "fetch",
                "--manifest", "output/scan_manifest.csv"],
        "needs": "网络；清单需含 full_name 列",
    },
    {
        "id": "scan",
        "desc": "静态扫描（T2 候选），按分片产出 scan_results/*.json",
        "cmd": ["python", "-m", "detector.cli", "scan",
                "--manifest", "output/shard1.csv", "--out-dir", "output/scan_results"],
        "needs": "fetch 已落缓存",
    },
    {
        "id": "summary",
        "desc": "规范化 + 汇总 + 报告（scan_summary.csv）",
        "cmd": ["python", "-m", "detector.cli", "summary", "--stage", "all"],
        "needs": "scan 产物",
    },
    {
        "id": "docgen",
        "desc": "LLM 生成语义文档（对齐率输入）",
        "cmd": ["python", "-m", "detector.cli", "docgen",
                "--repo-list", "output/targets.txt", "--out-dir", "output/gen_docs"],
        "needs": "本地 Ollama 或 LLM 后端；目标清单",
    },
    {
        "id": "align",
        "desc": "语义对齐率：AST 硬事实 vs README 声明",
        "cmd": ["python", "-m", "detector.cli", "align",
                "--repo-dir", "mcp插件/<owner>_<repo>"],
        "needs": "本地仓库代码",
    },
    {
        "id": "sandbox-rules",
        "desc": "由对齐率结果生成沙箱拦截规则",
        "cmd": ["python", "-m", "detector.cli", "sandbox-rules",
                "--repo-dir", "mcp插件/<owner>_<repo>", "--output", "rules.json"],
        "needs": "align 可运行",
    },
    {
        "id": "monitor",
        "desc": "沙箱运行时行为监控（T3 行为确认）",
        "cmd": ["python", "-m", "detector.cli", "monitor",
                "--rules", "rules.json", "--mode", "docker",
                "--repo-dir", "mcp插件/<owner>_<repo>"],
        "needs": "Docker + 沙箱镜像",
    },
]

# 默认执行顺序
DEFAULT_ORDER = [s["id"] for s in STEPS]
# 需要占位参数、无法在 --all 中直接运行的步骤
PLACEHOLDER_STEPS = {"docgen", "align", "sandbox-rules", "monitor"}

_BY_ID = {s["id"]: s for s in STEPS}


def _run_step(step: dict) -> int:
    print(f"\n[流水线] 执行 {step['id']}: {step['desc']}")
    print(f"  $ {' '.join(step['cmd'])}")
    return subprocess.call(step["cmd"], cwd=str(PROJECT_ROOT))


def main() -> int:
    ensure_utf8_stdio()
    ap = argparse.ArgumentParser(description="MPV-Detector 流水线编排")
    ap.add_argument("--run", nargs="+", default=[], metavar="STEP",
                    help=f"要执行的 step（可多个，按给定顺序）：{', '.join(DEFAULT_ORDER)}")
    ap.add_argument("--all", action="store_true",
                    help="按默认顺序执行全部无需占位参数的步骤")
    args = ap.parse_args()

    if args.run or args.all:
        todo = args.all and [s for s in DEFAULT_ORDER if s not in PLACEHOLDER_STEPS]
        todo = args.run or todo
        unknown = [s for s in todo if s not in _BY_ID]
        if unknown:
            print(f"[错误] 未知 step: {', '.join(unknown)}\n"
                  f"可用: {', '.join(DEFAULT_ORDER)}", file=sys.stderr)
            return 2
        for sid in todo:
            code = _run_step(_BY_ID[sid])
            if code != 0:
                print(f"[流水线] {sid} 退出码 {code}，中止后续步骤", file=sys.stderr)
                return code
        print("\n[流水线] 全部选定步骤执行完成")
        return 0

    # 仅打印步骤清单（可复现命令）
    print(f"MPV-Detector 流水线（项目根: {PROJECT_ROOT}）\n")
    for i, sid in enumerate(DEFAULT_ORDER, 1):
        s = _BY_ID[sid]
        print(f"[{i:02d}] {s['id']:<14} {s['desc']}")
        print(f"      $ {' '.join(s['cmd'])}")
        print(f"      依赖: {s['needs']}\n")
    print("提示: --run <step> 执行指定步骤；--all 执行全链路（跳过需占位参数的步骤）。")
    print("      一键跑完（docgen→align→verdict→report）请用: "
          "python -m detector.cli flow --help")
    return 0


if __name__ == "__main__":
    sys.exit(main())
