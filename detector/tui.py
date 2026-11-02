#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detector.tui —— 交互式终端菜单
==============================
启动时先跑依赖检查，再进入主菜单。
不替代子命令，只是降低记忆成本。

用法::

    python -m detector.cli tui
"""
from __future__ import annotations

import importlib
import shutil
import sys
from pathlib import Path

try:
    from rich.console import Console
    from rich.prompt import Prompt
    from rich.table import Table
except Exception:
    print("rich 未安装，请先 pip install rich")
    raise SystemExit(1)

from detector.cli import COMMANDS, dispatch
from detector.deps import SCAN_OUTPUT_DIR, docker_available, ensure_dir
from detector.report_html import build_report

console = Console()


ACTIONS = [
    ("扫描单个仓库 (scan)", "scan"),
    ("扫描结果汇总 (summary)", "summary"),
    ("生成 HTML 报告 (report-html)", "report-html"),
    ("跑完整流程 (flow)", "flow"),
    ("查看所有子命令", "list"),
    ("退出", "quit"),
]


# ---- 依赖检查项 ----
REQUIRED_PY_DEPS = ["rich", "textual", "requests", "yaml"]
REQUIRED_DIRS = [
    ("dateset/", "被检代码根（1391 个 clone 仓库）"),
    ("output/scan_results/", "静态扫描结果目录（可空）"),
]
CONFIG_FILE = "config.yaml"


def check_dependencies() -> list[tuple[str, bool, str]]:
    """返回 [(项目, OK?, 备注)]，启动时展示。"""
    results: list[tuple[str, bool, str]] = []

    # Python 版本
    py_ok = sys.version_info >= (3, 9)
    results.append(("Python 版本", py_ok, f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"))

    # Python 依赖
    for mod in REQUIRED_PY_DEPS:
        try:
            importlib.import_module(mod)
            results.append((f"依赖 {mod}", True, "已安装"))
        except ImportError:
            results.append((f"依赖 {mod}", False, f"未装: pip install {mod}"))

    # Docker（可选，docker 模式才需要）
    docker_ok = docker_available()
    results.append(("Docker 守护进程（可选）", docker_ok,
                    "可用" if docker_ok else "未启动（docker 模式才需要，simulate 模式可跳过）"))

    # 关键目录
    for rel, desc in REQUIRED_DIRS:
        p = Path(rel)
        results.append((f"目录 {rel}", p.exists(), desc if not p.exists() else "存在"))

    # config.yaml
    cfg = Path(CONFIG_FILE)
    results.append((f"配置 {CONFIG_FILE}", cfg.exists(),
                    "用 config.yaml.example 复制一份改名" if not cfg.exists() else "存在"))

    return results


def show_check_and_pause() -> None:
    console.rule("[bold cyan]启动前依赖检查")
    rows = check_dependencies()
    t = Table(show_header=True, header_style="bold")
    t.add_column("项目")
    t.add_column("状态", justify="center")
    t.add_column("备注")
    missing = 0
    for name, ok, note in rows:
        t.add_row(name, "[green]✓ OK[/green]" if ok else "[red]✗ 缺失[/red]", note)
        if not ok:
            missing += 1
    console.print(t)
    if missing:
        console.print(f"[yellow]有 {missing} 项缺失。标红项如果要用对应功能请先装，否则可继续用其他功能。[/yellow]")
    Prompt.ask("按回车继续", default="")


def _run_cli(cmd: str, args: list[str]) -> int:
    """以给定参数调起子命令（走 cli.dispatch，不改全局 sys.argv）。"""
    return int(dispatch(cmd, args) or 0)


def main() -> int:
    show_check_and_pause()
    console.rule("[bold cyan]MPV-Detector 交互式菜单")
    while True:
        t = Table(show_header=False, box=None, padding=(0, 2))
        for i, (label, _) in enumerate(ACTIONS, 1):
            t.add_row(f"[cyan]{i}[/cyan]", label)
        console.print(t)
        choice = Prompt.ask("选择操作", default="6")
        try:
            idx = int(choice) - 1
        except ValueError:
            console.print("[red]请输入数字[/red]")
            continue
        if idx < 0 or idx >= len(ACTIONS):
            console.print("[red]无效选项[/red]")
            continue

        label, action = ACTIONS[idx]
        if action == "quit":
            console.print("再见")
            return 0
        if action == "list":
            console.print("\n[bold]全部子命令：[/bold]")
            for name, mod in COMMANDS.items():
                console.print(f"  [cyan]{name}[/cyan] → {mod}")
            print()
            continue

        if action == "scan":
            repo_dir = Prompt.ask("仓库目录（如 dateset/xxx_yyy）").strip().strip('"').strip("'")
            # 仓库名留空时从目录名推导：dateset/0GiS0_biznagafest-mcp → 0GiS0/biznagafest-mcp
            default_repo = ""
            name = Path(repo_dir).name
            if "_" in name:
                owner, repo = name.split("_", 1)
                default_repo = f"{owner}/{repo}"
            repo = Prompt.ask(f"仓库名（owner/repo，留空用 {default_repo or '自动推导'}）",
                               default=default_repo).strip().strip('"').strip("'")
            args = ["--repo-dir", repo_dir]
            if repo:
                args += ["--repo", repo]
            _run_cli("scan", args)
            # 扫完自动问是否生成 HTML 报告
            if Prompt.ask("扫描完成，是否生成 HTML 报告？", choices=["y", "n"], default="y") == "y":
                out = Prompt.ask("报告输出路径", default="output/report.html").strip().strip('"').strip("'")
                from pathlib import Path
                ensure_dir(Path(out).parent)
                stats = build_report(SCAN_OUTPUT_DIR, Path(out))
                console.print(f"[green]报告已生成: {out}[/green]")
                console.print(f"  仓库 {stats['total']}，verdict {stats['by_verdict']}")

        elif action == "summary":
            stage = Prompt.ask("stage (normalize/aggregate/report/all)", default="all")
            _run_cli("summary", ["--stage", stage])

        elif action == "report-html":
            out = Prompt.ask("输出 HTML 路径", default="output/report.html").strip().strip('"').strip("'")
            results_dir = Prompt.ask("扫描结果目录", default=str(SCAN_OUTPUT_DIR)).strip().strip('"').strip("'")
            from pathlib import Path
            ensure_dir(Path(out).parent)
            stats = build_report(Path(results_dir), Path(out))
            console.print(f"[green]报告已生成: {out}[/green]")
            console.print(f"  仓库 {stats['total']}，"
                          f"verdict {stats['by_verdict']}")

        elif action == "flow":
            targets = Prompt.ask("目标清单（每行 owner/repo）", default="output/targets.txt").strip().strip('"').strip("'")
            out_dir = Prompt.ask("输出目录", default="output/gen_docs").strip().strip('"').strip("'")
            _run_cli("flow", ["--targets", targets, "--out-dir", out_dir])

        print()


if __name__ == "__main__":
    raise SystemExit(main())
