#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detector.ui —— 终端可视化工具（rich 封装）
==========================================
提供彩色表格、进度条、严重性着色。所有函数在非 TTY 或 rich 未安装时
自动降级为纯文本，不破坏管道/日志。
"""
from __future__ import annotations

import sys
from typing import Iterable, Sequence

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    _console = Console()
    _HAS_RICH = True
except Exception:  # rich 未装或非 TTY
    _console = None
    _HAS_RICH = False


SEV_COLOR = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
}

VERDICT_COLOR = {
    "malicious": "bold red",
    "suspicious": "yellow",
    "pending": "cyan",
    "benign": "green",
    "not_scanned": "dim",
}


def print_hits_table(hits: Sequence[dict], title: str = "命中") -> None:
    """以表格展示 hits 列表；非 TTY 时降级为纯文本。"""
    if not hits:
        print(f"[{title}] 无命中")
        return
    if _HAS_RICH:
        t = Table(title=title, show_lines=False)
        t.add_column("严重度", style="bold")
        t.add_column("ID")
        t.add_column("说明")
        t.add_column("行", justify="right")
        t.add_column("证据", overflow="fold")
        for h in hits:
            sev = h.get("severity", "")
            color = SEV_COLOR.get(sev, "")
            t.add_row(
                f"[{color}]{sev}[/{color}]" if color else sev,
                h.get("pattern_id", ""),
                h.get("label", ""),
                str(h.get("line", "")),
                (h.get("evidence", "") or "")[:120],
            )
        _console.print(t)
    else:
        for h in hits:
            print(f"  [{h.get('severity','')}] {h.get('pattern_id','')} "
                  f"L{h.get('line','')} {h.get('label','')}: {h.get('evidence','')[:80]}")


def print_repo_row(repo: str, files: int, hits: int, sev_counts: dict) -> None:
    """批量扫描时每个仓库一行摘要。"""
    if _HAS_RICH:
        parts = [f"[bold]{repo}[/bold]", f"files={files}", f"hits={hits}"]
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            n = sev_counts.get(sev, 0)
            if n:
                color = SEV_COLOR.get(sev, "")
                parts.append(f"[{color}]{sev}={n}[/{color}]" if color else f"{sev}={n}")
        _console.print("  ".join(parts))
    else:
        print(f"[{repo}] files={files} hits={hits} {sev_counts}")


def print_summary_table(rows: Sequence[dict]) -> None:
    """汇总表格：verdict / files_scanned / hits / severity 分布。"""
    if not rows:
        print("[汇总] 无数据")
        return
    if _HAS_RICH:
        t = Table(title="扫描汇总", show_lines=True)
        for col in ("仓库", "verdict", "files", "hits", "CRIT", "HIGH", "MED", "LOW"):
            t.add_column(col, justify="right" if col not in ("仓库", "verdict") else "left")
        for r in rows:
            verdict = r.get("verdict", "")
            vcolor = VERDICT_COLOR.get(verdict, "")
            t.add_row(
                r.get("repo", ""),
                f"[{vcolor}]{verdict}[/{vcolor}]" if vcolor else verdict,
                str(r.get("files_scanned", 0)),
                str(r.get("hits", 0)),
                str(r.get("CRITICAL", 0)),
                str(r.get("HIGH", 0)),
                str(r.get("MEDIUM", 0)),
                str(r.get("LOW", 0)),
            )
        _console.print(t)
    else:
        for r in rows:
            print(f"  {r.get('repo','')} verdict={r.get('verdict','')} "
                  f"files={r.get('files_scanned',0)} hits={r.get('hits',0)}")


def progress_job(desc: str = "处理") -> Progress | None:
    """返回一个 rich Progress 上下文管理器；非 TTY 返回 None。"""
    if not _HAS_RICH:
        return None
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=_console,
    )
