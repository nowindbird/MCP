#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MPV-Detector 统一命令行入口
===========================
把分散在各层的检测模块收敛到一条命令下：

    python -m detector.cli <子命令> [该模块自己的参数...]

设计约定
--------
* 本入口只做「子命令 → 模块」的分发，参数原样透传给目标模块的 ``main()``，
  因此各模块仍可独立运行：``python -m detector.scanner.scanner --help``。
* 不做任何 ``sys.path`` 注入：项目以 ``detector`` 包形式导入，请在**项目根**执行
  （``pip install -e .`` 后则在任意目录均可）。
* 依赖统一走 ``detector.deps``，子命令清单只在这里维护。
* ``dispatch()`` 是可编程入口：tui / run_all / 测试都复用同一个分发逻辑，
  不再各自 hack ``sys.argv``。

示例::

    python -m detector.cli --list          # 列出所有子命令
    python -m detector.cli run             # 一键: scan → summary → report-html
    python -m detector.cli flow            # 一键: docgen → align → verdict → report
    python -m detector.cli check           # 环境自检（路径 / 导入 / 可选依赖）
    python -m detector.cli test            # 运行单元测试
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
    "targets": "detector.targets",
    "report-html": "detector.report_html",
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
    "run": "detector.run_all",
    # ---- 可视化 ----
    "tui": "detector.tui",
}

# 命令简写
ALIASES = {
    "s": "scan",
    "r": "report-html",
    "f": "flow",
    "sum": "summary",
    "rep": "report-html",
    "all": "run",
    "t": "test",
}

# usage 分组（决定展示顺序；check/test 是内建命令，不映射到模块）
_USAGE_GROUPS = [
    ("一键流程", ["run", "flow", "pipeline", "tui"]),
    ("数据采集", ["crawl", "fetch"]),
    ("静态扫描", ["scan", "summary", "targets", "report-html"]),
    ("语义分析", ["docgen", "align",
                  "finetune-build", "finetune-build2", "finetune-train", "finetune-infer"]),
    ("沙箱执行", ["sandbox-rules", "monitor"]),
    ("开发辅助", ["check", "test"]),
]


def _usage() -> str:
    lines = [__doc__.strip(), "", "可用子命令:"]
    width = max(len(c) for c in COMMANDS) + 1
    for group, names in _USAGE_GROUPS:
        lines.append(f"\n  [{group}]")
        for name in names:
            if name in COMMANDS:
                lines.append(f"    {name:<{width}} → {COMMANDS[name]}")
            else:
                lines.append(f"    {name:<{width}} → 内建命令")
    lines += ["", "查看某子命令参数: python -m detector.cli <子命令> --help"]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 内建命令（不映射到模块 main）
# ---------------------------------------------------------------------------
def _cmd_check(args) -> int:
    """环境自检：路径解析 / 子包导入 / 可选依赖。"""
    from detector.deps import _selfcheck

    return _selfcheck()


def _cmd_test(args) -> int:
    """运行单元测试（unittest discover tests/）。"""
    from detector.selftest import run_tests

    return run_tests(verbosity=0 if "-q" in args else 2)


_SPECIAL = {"check": _cmd_check, "test": _cmd_test}


def dispatch(cmd: str, args=()) -> int:
    """可编程分发入口：以给定参数执行子命令，返回退出码。

    供 ``main()`` 与 tui / run_all 等复用；对 ``sys.argv`` 的修改只在
    目标模块 ``main()`` 执行期间生效，随后立即还原。
    """
    args = list(args or [])
    if cmd in ALIASES:
        cmd = ALIASES[cmd]
    if cmd in _SPECIAL:
        return int(_SPECIAL[cmd](args) or 0)
    if cmd not in COMMANDS:
        print(f"[错误] 未知子命令: {cmd}\n可用命令: {', '.join(COMMANDS)}", file=sys.stderr)
        return 2

    mod = importlib.import_module(COMMANDS[cmd])
    old = sys.argv
    # 目标模块的 argparse 解析 sys.argv[1:]，因此只透传参数本身（去掉子命令名）
    sys.argv = [old[0], *args]
    try:
        return int(mod.main() or 0)
    finally:
        sys.argv = old


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print(_usage())
        return 0

    cmd = sys.argv[1]
    if cmd in ("-l", "--list"):
        for name in COMMANDS:
            print(name)
        return 0
    return dispatch(cmd, sys.argv[2:])


if __name__ == "__main__":
    sys.exit(main())
