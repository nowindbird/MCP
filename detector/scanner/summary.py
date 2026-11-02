#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
扫描结果后处理：规范化 → 汇总 → 报告
=====================================
重构前这里有三个平级脚本（normalize / aggregate / report），各自重复
「拼 output/scan_results 路径 + 遍历 JSON + 跳过 ``_`` 汇总文件」，且汇总结论
存在两套列口径（run_flow 读 CRITICAL/HIGH/hits，aggregate 写 hit_count…）导致对接失败。

现在合并为一个模块、一套列口径（``deps.SCAN_SUMMARY_FIELDS``）：

1. **normalize** —— ``files_scanned == 0`` 却标 benign 的仓库降级为 ``not_scanned``
   （无代码即无静态审查依据），并校验 verdict 取值合法。
2. **aggregate** —— 汇总所有单仓库结果 → ``output/scan_summary.csv``。
3. **report** —— 打印模式分布 / 严重性分布 / 隐藏行为 / 未扫描清单。

用法::

    python -m detector.cli summary                      # 三步全跑
    python -m detector.cli summary --stage normalize    # 只规范化
    python -m detector.cli summary --stage aggregate --summary-out output/scan_summary.csv
    python -m detector.cli summary --results-dir output/scan_results_800
"""

import argparse
from collections import Counter
from pathlib import Path

from detector.deps import (
    SCAN_SUMMARY_CSV,
    SCAN_SUMMARY_FIELDS,
    SEVERITIES,
    iter_scan_results,
    now_iso,
    write_csv,
    write_json,
)

# 合法 verdict（pending 为静态扫描产出、等待语义复核的中间态）
VALID_VERDICTS = {"benign", "suspicious", "malicious", "not_scanned", "pending"}

# 严重性排序权重（越小越严重）
SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}

# verdict 排序权重（越靠前越需要关注）
VERDICT_ORDER = {"malicious": 0, "suspicious": 1, "pending": 2,
                 "benign": 3, "not_scanned": 4}

NOT_SCANNED_REASON = "缓存目录无可用源码/文本文件（代码获取未成功或为空），无静态审查依据"


# ---------------------------------------------------------------------------
# 1. 规范化
# ---------------------------------------------------------------------------
def normalize(results: list) -> list:
    """原地规范化 verdict 并写回 JSON；返回被降级的仓库列表。"""
    demoted = []
    for path, data in results:
        verdict = data.get("verdict")
        hits = data.get("hits") or []
        files_scanned = int(data.get("files_scanned") or 0)

        # benign 但一个文件都没扫到 → 没有审查依据
        if verdict == "benign" and files_scanned == 0 and not hits:
            data["verdict"] = "not_scanned"
            data["confidence"] = 0
            data["reason"] = NOT_SCANNED_REASON
            write_json(path, data)
            demoted.append(data.get("repo", path.stem))

        if data.get("verdict") not in VALID_VERDICTS:
            print(f"[警告] 非法 verdict={data.get('verdict')!r}，文件: {Path(path).name}")
    return demoted


# ---------------------------------------------------------------------------
# 2. 汇总
# ---------------------------------------------------------------------------
def top_severity(hits: list) -> str:
    """仓库内最严重等级（无命中 → NONE）。"""
    sev = "NONE"
    for h in hits:
        s = h.get("severity", "MEDIUM")
        if SEV_ORDER.get(s, 99) < SEV_ORDER.get(sev, 99):
            sev = s
    return sev


def aggregate(results: list) -> list:
    """把单仓库结果汇总为统一列口径的行（供 CSV / run_flow 共用）。"""
    rows = []
    for _path, data in results:
        hits = data.get("hits") or []
        sev_count = Counter(h.get("severity", "MEDIUM") for h in hits)
        row = {
            "repo": data.get("repo", ""),
            "verdict": data.get("verdict", "unknown"),
            "files_scanned": int(data.get("files_scanned") or 0),
            "hits": len(hits),
            "top_severity": top_severity(hits),
            "fetch_method": data.get("fetch_method", ""),
            "confidence": data.get("confidence", 0),
            "reason": (data.get("reason") or "").replace("\n", " ")[:200],
        }
        for s in SEVERITIES:
            row[s] = sev_count.get(s, 0)
        rows.append(row)

    rows.sort(key=lambda r: (VERDICT_ORDER.get(r["verdict"], 9),
                             SEV_ORDER.get(r["top_severity"], 9)))
    return rows


# ---------------------------------------------------------------------------
# 3. 报告
# ---------------------------------------------------------------------------
def report(results: list, rows: list) -> None:
    """打印统计报告（模式命中 / 严重性 / 隐藏行为 / 未扫描）。"""
    patterns = Counter()
    severities = Counter()
    shadow = []
    not_scanned = []
    total_hits = 0

    for _path, data in results:
        if data.get("verdict") == "not_scanned":
            not_scanned.append((data.get("repo", ""), (data.get("reason") or "")[:80]))
            continue
        for h in data.get("hits") or []:
            patterns[h.get("pattern_id", "?")] += 1
            severities[h.get("severity", "?")] += 1
            total_hits += 1
        if data.get("shadow_features"):
            shadow.append((data.get("repo", ""), data["shadow_features"]))

    print("=== 仓库判定分布 ===")
    for k, v in Counter(r["verdict"] for r in rows).most_common():
        print(f"  {k}: {v}")
    print("=== 严重性分布（已扫描仓库）===")
    for k, v in Counter(r["top_severity"] for r in rows
                        if r["verdict"] != "not_scanned").most_common():
        print(f"  {k}: {v}")
    print("=== 模式命中分布（hits）===")
    for k, v in patterns.most_common():
        print(f"  {k}: {v}")
    print(f"total repos: {len(rows)}")
    print(f"total hits (scanned repos): {total_hits}")
    print(f"hits by severity: {dict(severities)}")

    print("\n=== shadow_features 仓库 ===")
    for repo, feats in shadow:
        print(f"  {repo}:")
        for x in feats:
            print(f"    - {x}")
    if not shadow:
        print("  （无）")

    print(f"\n=== not_scanned ({len(not_scanned)}) ===")
    for repo, reason in not_scanned:
        print(f"  {repo} | {reason}")

    print("\n=== 需人工复核（suspicious / malicious）===")
    flagged = [r for r in rows if r["verdict"] in ("suspicious", "malicious")]
    for r in flagged:
        print(f"  [{r['verdict']}] {r['repo']} conf={r['confidence']} "
              f"hits={r['hits']} top={r['top_severity']} | {r['reason'][:120]}")
    if not flagged:
        print("  （无）")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="扫描结果规范化 / 汇总 / 报告")
    ap.add_argument("--results-dir", default="",
                    help="单仓库扫描结果目录（默认 config.SCAN_OUTPUT_DIR）")
    ap.add_argument("--stage", choices=["all", "normalize", "aggregate", "report"],
                    default="all", help="执行阶段（默认 all）")
    ap.add_argument("--summary-out", default="",
                    help=f"汇总 CSV 输出路径（默认 {SCAN_SUMMARY_CSV}）")
    ap.add_argument("--no-write", action="store_true", help="只统计不落盘")
    args = ap.parse_args()

    results = list(iter_scan_results(Path(args.results_dir) if args.results_dir else None))
    if not results:
        print(f"[错误] 未找到扫描结果 JSON（目录: {args.results_dir or SCAN_SUMMARY_CSV.parent}）")
        return 1
    print(f"[summary] 读取 {len(results)} 个单仓库结果，生成于 {now_iso()}\n")

    demoted: list = []
    if args.stage in ("all", "normalize"):
        demoted = normalize(results)
        print(f"[normalize] benign→not_scanned: {len(demoted)} 个")
        for repo in demoted[:20]:
            print(f"  - {repo}")
        if len(demoted) > 20:
            print(f"  ...（其余 {len(demoted) - 20} 个略）")
        print()

    rows = aggregate(results)
    if args.stage in ("all", "aggregate"):
        out = Path(args.summary_out) if args.summary_out else SCAN_SUMMARY_CSV
        if args.no_write:
            print(f"[aggregate] --no-write，跳过写入 {out}")
        else:
            write_csv(out, rows, SCAN_SUMMARY_FIELDS)
            print(f"[aggregate] 汇总 {len(rows)} 个仓库 -> {out}\n")

    if args.stage in ("all", "report"):
        report(results, rows)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
