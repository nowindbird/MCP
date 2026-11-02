#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MPV-Detector 端到端流水线编排
=============================
把「抓取 → 落地 → 获取 → 扫描 → 规范化/汇总 → 语义文档 → 对齐率 → 沙箱规则 → 行为监控」
串成可复现的步骤流水线。每个 step 唯一对应 ``detector.cli`` 的一个子命令，
打印出的单步命令可直接复制到终端重跑。

三条常用链路
------------
* ``run`` / ``pipeline --all`` : scan → summary → report-html
  （本地静态链路，无需网络 / LLM / Docker）
* ``flow``                     : docgen → align → verdict → report
  （语义链路，需本地 Ollama；见 ``detector.pipeline.run_flow``）
* ``sandbox-rules → monitor``  : 沙箱动态确认链路（需 Docker）

用法::

    python -m detector.pipeline.pipeline                 # 打印步骤与命令
    python -m detector.pipeline.pipeline --run scan      # 只执行 scan
    python -m detector.pipeline.pipeline --run scan summary   # 按序执行多步
    python -m detector.pipeline.pipeline --all           # 一键: scan → summary → report-html
    python -m detector.pipeline.pipeline --run align --repo owner_repo   # 代入占位参数
"""

import argparse
import subprocess
import sys
from pathlib import Path

from detector.deps import (
    DATA_DIR,
    PROJECT_ROOT,
    REPORT_HTML,
    SANDBOX_WORK_DIR,
    SCAN_OUTPUT_DIR,
    TARGETS_FILE,
    GEN_DOCS_DIR,
    ensure_utf8_stdio,
)
from detector.config import MANIFEST_SCAN, MANIFEST_SHARD1

# 每个 step: id / 说明 / 命令（相对项目根执行；{repo} 为占位参数）/ 前置条件
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
                "--manifest", str(MANIFEST_SCAN)],
        "needs": "网络；清单需含 full_name 列",
    },
    {
        "id": "scan",
        "desc": "静态扫描全部本地仓库（自动扫 dateset/，结果直接落 scan_results/）",
        "cmd": ["python", "-m", "detector.cli", "scan",
                "--no-timestamp", "--out-dir", str(SCAN_OUTPUT_DIR)],
        "needs": "dateset/ 下有仓库代码（或先跑 fetch）",
    },
    {
        "id": "summary",
        "desc": "规范化 + 汇总 + 报告（scan_summary.csv）",
        "cmd": ["python", "-m", "detector.cli", "summary", "--stage", "all"],
        "needs": "scan 产物",
    },
    {
        "id": "report-html",
        "desc": "生成 HTML 可视化报告",
        "cmd": ["python", "-m", "detector.cli", "report-html",
                "--results-dir", str(SCAN_OUTPUT_DIR), "--out", str(REPORT_HTML)],
        "needs": "scan + summary 产物",
    },
    {
        "id": "docgen",
        "desc": "LLM 生成语义文档（对齐率输入）",
        "cmd": ["python", "-m", "detector.cli", "docgen",
                "--repo-list", str(TARGETS_FILE), "--out-dir", str(GEN_DOCS_DIR)],
        "needs": "本地 Ollama 或 LLM 后端；目标清单 output/targets.txt",
    },
    {
        "id": "align",
        "desc": "语义对齐率：AST 硬事实 vs README 声明",
        "cmd": ["python", "-m", "detector.cli", "align",
                "--repo-dir", f"{DATA_DIR}/{{repo}}",
                "--output", f"{SANDBOX_WORK_DIR}/{{repo}}.align.json"],
        "needs": "本地仓库代码；占位参数 {repo}（--repo owner_repo）",
    },
    {
        "id": "sandbox-rules",
        "desc": "由对齐率结果生成沙箱拦截规则",
        "cmd": ["python", "-m", "detector.cli", "sandbox-rules",
                "--repo-dir", f"{DATA_DIR}/{{repo}}",
                "--output", f"{SANDBOX_WORK_DIR}/{{repo}}.rules.json"],
        "needs": "align 可运行；占位参数 {repo}",
    },
    {
        "id": "monitor",
        "desc": "沙箱运行时行为监控（T3 行为确认）",
        "cmd": ["python", "-m", "detector.cli", "monitor",
                "--rules", f"{SANDBOX_WORK_DIR}/{{repo}}.rules.json",
                "--mode", "docker", "--repo-dir", f"{DATA_DIR}/{{repo}}"],
        "needs": "Docker + 沙箱镜像；占位参数 {repo}",
    },
]

# 一键静态链路（python -m detector.cli run / pipeline --all 都走这里）
AUTO_STEPS = ("scan", "summary", "report-html")
# 需要占位参数、未提供 --repo 时无法运行的步骤
PLACEHOLDER_STEPS = {"align", "sandbox-rules", "monitor"}

_BY_ID = {s["id"]: s for s in STEPS}


def _expand(step: dict, repo: str = "") -> list | None:
    """把 {repo} 占位参数代入命令；缺占位值时返回 None。"""
    raw = " ".join(step["cmd"])
    if "{repo}" in raw and not repo:
        return None
    return [a.replace("{repo}", repo) for a in step["cmd"]]


def run_cmd(args: list, label: str = "") -> int:
    """以子进程执行一个 detector.cli 子命令（保持终端可复现）。"""
    cmd = [sys.executable, "-m", "detector.cli", *args]
    if label:
        print(f"\n[流水线] {label}")
    print(f"  $ {' '.join(cmd)}")
    return subprocess.call(cmd, cwd=str(PROJECT_ROOT))


def run_steps(ids, repo: str = "") -> int:
    """按顺序执行步骤（子进程）；某步失败即中止，返回退出码。"""
    unknown = [s for s in ids if s not in _BY_ID]
    if unknown:
        print(f"[错误] 未知 step: {', '.join(unknown)}\n"
              f"可用: {', '.join(_BY_ID)}", file=sys.stderr)
        return 2
    for sid in ids:
        step = _BY_ID[sid]
        cmd = _expand(step, repo)
        if cmd is None:
            print(f"[流水线] 跳过 {sid}：需要 --repo <owner_repo> 占位参数", file=sys.stderr)
            return 2
        print(f"\n[流水线] 执行 {sid}: {step['desc']}")
        code = subprocess.call(cmd, cwd=str(PROJECT_ROOT))
        if code != 0:
            print(f"[流水线] {sid} 退出码 {code}，中止后续步骤", file=sys.stderr)
            return code
    print("\n[流水线] 全部选定步骤执行完成")
    return 0


def run_auto_chain(scan_out: str = "", report_out: str = "",
                   skip_scan: bool = False) -> int:
    """一键静态链路 scan → summary → report-html（run / pipeline --all 共用）。

    scan 固定带 ``--no-timestamp`` 直落结果目录，保证 summary / report-html
    能读到同一批产物（时间戳子目录会让后两步读空目录）。
    """
    scan_dir = Path(scan_out) if scan_out else SCAN_OUTPUT_DIR
    report = Path(report_out) if report_out else REPORT_HTML

    steps = []
    if not skip_scan:
        steps.append(("静态扫描全部本地仓库",
                      ["scan", "--no-timestamp", "--out-dir", str(scan_dir)]))
    steps.append(("汇总 + 规范化 + 报告",
                  ["summary", "--stage", "all", "--results-dir", str(scan_dir)]))
    steps.append(("生成 HTML 报告",
                  ["report-html", "--results-dir", str(scan_dir), "--out", str(report)]))

    for i, (label, argv) in enumerate(steps, 1):
        print(f"===== [{i}/{len(steps)}] {label} =====")
        code = run_cmd(argv, label="")
        if code != 0:
            print(f"[流水线] 第 {i} 步退出码 {code}，中止", file=sys.stderr)
            return code
    print(f"\n[流水线] 完成。HTML 报告: {report}")
    return 0


def main() -> int:
    ensure_utf8_stdio()
    ap = argparse.ArgumentParser(description="MPV-Detector 流水线编排")
    ap.add_argument("--run", nargs="+", default=[], metavar="STEP",
                    help=f"要执行的 step（可多个，按给定顺序）：{', '.join(_BY_ID)}")
    ap.add_argument("--all", action="store_true",
                    help=f"一键静态链路：{' → '.join(AUTO_STEPS)}")
    ap.add_argument("--repo", default="",
                    help="占位参数 {repo} 的值（align / sandbox-rules / monitor 需要）")
    args = ap.parse_args()

    if args.all:
        return run_auto_chain()

    if args.run:
        return run_steps(args.run, repo=args.repo)

    # 默认：打印步骤清单（可复现命令）
    print(f"MPV-Detector 流水线（项目根: {PROJECT_ROOT}）\n")
    for i, sid in enumerate(_BY_ID, 1):
        s = _BY_ID[sid]
        tag = "一键" if sid in AUTO_STEPS else ("需 --repo" if sid in PLACEHOLDER_STEPS else "")
        print(f"[{i:02d}] {s['id']:<14} {s['desc']}  {tag}")
        print(f"      $ {' '.join(s['cmd'])}")
        print(f"      依赖: {s['needs']}\n")
    print(f"提示: --all 一键跑静态链路（{' → '.join(AUTO_STEPS)}）")
    print("      语义链路（docgen→align→verdict→report）请用: "
          "python -m detector.cli flow --help")
    print("      沙箱链路（sandbox-rules→monitor）: "
          "--run sandbox-rules monitor --repo <owner_repo>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
