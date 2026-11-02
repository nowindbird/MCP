#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detector.targets —— 生成语义分析目标清单
=========================================
``flow``（docgen → align → verdict → report）需要一份目标清单
（每行一个 ``owner_repo``）。本命令从两个来源自动生成，并默认写入
config 的 ``output/targets.txt``——与 flow 的默认读路径一致，形成闭环。

用法::

    # 从静态扫描汇总取可疑仓库（推荐：先跑 run / scan+summary）
    python -m detector.cli targets --from-scan-summary
    python -m detector.cli targets --from-scan-summary --min-severity CRITICAL

    # 从本地代码根枚举全部 <owner>_<repo> 目录
    python -m detector.cli targets --from-dir dateset

    # 指定输出（flow --targets 同一文件即可）
    python -m detector.cli targets --out my_targets.txt
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from detector.deps import (
    DATA_DIR,
    SCAN_SUMMARY_CSV,
    TARGETS_FILE,
    ensure_utf8_stdio,
    normalize_repo_key,
    read_text,
    write_text,
)

# verdict 越高越优先；severity 权重用于排序
_VERDICT_PRIORITY = {"malicious": 0, "suspicious": 1, "pending": 2, "benign": 3}
_SEV_PRIORITY = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}


def from_scan_summary(path: Path | str, min_severity: str = "HIGH",
                      min_hits: int = 0) -> list:
    """从 scan_summary.csv 筛选目标仓库，返回 [(owner_repo, verdict, hits)] 按风险排序。"""
    text = read_text(path)
    if text is None:
        return []
    sev_bar = _SEV_PRIORITY[min_severity]
    out = []
    for row in csv.DictReader(text.splitlines()):
        repo = normalize_repo_key(row.get("repo") or "")  # owner/repo → owner_repo
        verdict = (row.get("verdict") or "").strip()
        top = (row.get("top_severity") or "NONE").strip()
        if not repo:
            continue
        try:
            hits = int(row.get("hits") or 0)
        except ValueError:
            continue
        if not _include(verdict, top, hits, sev_bar, min_hits):
            continue
        out.append((repo, verdict, top, hits))
    out.sort(key=lambda r: (_VERDICT_PRIORITY.get(r[1], 9),
                            _SEV_PRIORITY.get(r[2], 9), -r[3]))
    return out


def _include(verdict: str, top_severity: str, hits: int,
             sev_bar: int, min_hits: int) -> bool:
    """目标筛选：可疑判定 / 达到严重性门槛 / 命中数门槛，任一满足即入选。"""
    if verdict in ("suspicious", "malicious", "pending"):
        return True
    if _SEV_PRIORITY.get(top_severity, 9) <= sev_bar:
        return True
    if min_hits and hits >= min_hits:
        return True
    return False


def from_dir(root: Path | str) -> list:
    """枚举本地代码根下全部 <owner>_<repo> 子目录，返回排序后的目录名列表。"""
    base = Path(root)
    if not base.is_dir():
        return []
    return sorted(d.name for d in base.iterdir()
                  if d.is_dir() and "_" in d.name and not d.name.startswith("_"))


def main() -> int:
    ensure_utf8_stdio()
    ap = argparse.ArgumentParser(description="生成语义分析目标清单（flow 的输入）")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--from-scan-summary", nargs="?", const=str(SCAN_SUMMARY_CSV),
                     metavar="CSV", default=None,
                     help=f"从扫描汇总取可疑仓库（缺省 {SCAN_SUMMARY_CSV}；不带本参数时默认）")
    src.add_argument("--from-dir", metavar="DIR", default=None,
                     help=f"枚举本地代码根全部 <owner>_<repo> 目录（缺省 {DATA_DIR}）")
    ap.add_argument("--out", "-o", default=str(TARGETS_FILE), help="输出清单路径")
    ap.add_argument("--min-severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    default="HIGH", help="严重性门槛（默认 HIGH）")
    ap.add_argument("--min-hits", type=int, default=0, help="最小命中数（默认 0=不限制）")
    args = ap.parse_args()

    out = Path(args.out)
    if args.from_dir is not None:
        names = from_dir(args.from_dir)
        source = f"本地目录 {args.from_dir}"
    else:
        csv_path = args.from_scan_summary or str(SCAN_SUMMARY_CSV)
        rows = from_scan_summary(csv_path, args.min_severity, args.min_hits)
        names = [r[0] for r in rows]
        source = f"扫描汇总 {csv_path}"
        if not rows:
            print(f"[错误] 扫描汇总为空或不存在: {csv_path}", file=sys.stderr)
            print("       请先跑静态链路: python -m detector.cli run", file=sys.stderr)
            print("       或枚举本地仓库: python -m detector.cli targets --from-dir", file=sys.stderr)
            return 1

    if not names:
        print(f"[错误] 没有可用目标（来源: {source}）", file=sys.stderr)
        return 1

    write_text(out, "\n".join(names) + "\n")
    print(f"[targets] {len(names)} 个目标（来源: {source}）")
    print(f"          已写入: {out}")
    print("          下一步: python -m detector.cli flow")
    return 0


if __name__ == "__main__":
    sys.exit(main())
