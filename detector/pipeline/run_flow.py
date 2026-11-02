#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
MPV-Detector 一键跑完编排器
============================
把「docgen(生成语义文档) → align(语义对齐率) → verdict(综合判定) → report(汇总报告)」
整条可自动化的链路串成一次运行，断点续跑、可重复执行、写完整报告。

自动跳过已完成的环节：
  - docgen：已存在的 generated_doc.md 跳过（不覆盖）
  - align：已存在的 align_result.json 跳过（除非 --force）

前提：
  - 本地 Ollama 已装默认模型（deps.ensure_ollama 会自动尝试拉起 ollama serve）
    地址可用 OLLAMA_HOST 环境变量覆盖
  - 目标仓库本地代码在 --local-root（其下为 <owner_repo> 文件夹）
    不传该参数时取 config 的 LARGE_REPO_SOURCE（默认项目内 dateset/）
  - --scan-summary 提供静态扫描命中（CRITICAL/HIGH），用于综合判定

参数全部有默认值，最小用法（Windows）::

  python -m detector.cli flow
  python -m detector.cli flow --scan-summary output\\scan_summary.csv
  python -m detector.cli flow --targets output\\targets.txt --out-dir output\\gen_docs

  --targets       目标清单文件（默认 output/targets.txt；每行一个 owner_repo，
                  可含 # 注释；文件不存在且给了 --scan-summary 时自动生成）
  --out-dir       输出目录（默认 output/gen_docs；doc 与 align json 都写这里）
  --scan-summary  静态扫描汇总 CSV（含 repo,CRITICAL,HIGH,hits），可为空
  --local-root    本地完整仓库根（默认 config.LARGE_REPO_SOURCE）
  --model         LLM 模型名
  --force         强制重算 align（默认跳过已算）
  --no-docgen     跳过 docgen（只做 align+verdict）
  --no-ollama-check  不检查/不自动拉起 Ollama

目标清单可用 ``python -m detector.cli targets`` 自动生成。
"""

import argparse
import sys
import time
from collections import Counter
from pathlib import Path

from detector.analyzer.align_rate import compute_alignment
from detector.deps import (
    CONFIG,
    DOC_GEN_CONFIG,
    GEN_DOCS_DIR,
    LARGE_REPO_SOURCE,
    PROJECT_ROOT,
    TARGETS_FILE,
    ensure_ollama,
    ensure_utf8_stdio,
    load_scan_summary,
    load_targets,
    normalize_repo_key,
    read_json,
    write_csv,
    write_json,
    write_text,
)

VERDICT_CFG = CONFIG["verdict"]
OUTPUT_FIELDS = [
    "repo", "align_signal", "alignment_rate", "conflict_rate", "sec_conflict_rate",
    "hard_facts", "languages", "scan_crit", "scan_high", "scan_hits", "final_verdict",
]


def run_docgen(local_root: str, targets_file: str, out_dir: str, model: str) -> int:
    """批量 docgen（本地代码模式）；子进程走统一 CLI，避免重复实现。"""
    import os
    import subprocess

    print("\n[step 1/4] docgen：生成缺失的语义文档 ...")
    cmd = [sys.executable, "-m", "detector.cli", "docgen",
           "--local-root", local_root,
           "--repo-list", targets_file,
           "--out-dir", out_dir,
           "--delay", "0"]
    if model:
        cmd += ["--model", model]
    env = dict(os.environ, PYTHONUNBUFFERED="1")
    try:
        return subprocess.run(cmd, cwd=str(PROJECT_ROOT), env=env, check=False).returncode
    except KeyboardInterrupt:
        print("[step 1/4] docgen 被中断，继续后续步骤（已有文档不受影响）")
        return 130


def final_verdict(align_signal: str, scan: dict) -> str:
    """综合 align 信号 + 静态扫描命中，给最终判定档位。"""
    crit = scan.get("crit", 0)
    high = scan.get("high", 0)
    if (align_signal == "DANGER" or crit >= VERDICT_CFG["CRIT_TIER_HIGH"]
            or high >= VERDICT_CFG["HIGH_TIER_HIGH"]):
        return "HIGH_RISK_REVIEW"
    if (align_signal == "WARN" or crit >= VERDICT_CFG["CRIT_TIER_MED"]
            or high >= VERDICT_CFG["HIGH_TIER_MED"]):
        return "REVIEW"
    return "LOW"


def main() -> int:
    ensure_utf8_stdio()
    ap = argparse.ArgumentParser(description="MPV-Detector 一键跑完编排器")
    ap.add_argument("--local-root", default=str(LARGE_REPO_SOURCE),
                    help="本地完整仓库根（默认 config.LARGE_REPO_SOURCE）")
    ap.add_argument("--targets", default=str(TARGETS_FILE),
                    help=f"目标清单文件（默认 {TARGETS_FILE}；不存在且给了 --scan-summary 时自动生成）")
    ap.add_argument("--out-dir", default=str(GEN_DOCS_DIR),
                    help=f"输出目录（默认 {GEN_DOCS_DIR}）")
    ap.add_argument("--scan-summary", default="", help="扫描汇总 CSV（用于综合判定）")
    ap.add_argument("--model", default=DOC_GEN_CONFIG["model"], help="LLM 模型名")
    ap.add_argument("--force", action="store_true", help="强制重算 align")
    ap.add_argument("--no-docgen", action="store_true", help="跳过 docgen")
    ap.add_argument("--no-ollama-check", action="store_true", help="不检查 Ollama")
    args = ap.parse_args()

    # 统一转绝对路径：docgen 子进程以项目根为 cwd，
    # 相对路径（如 "output\x.txt"）在别处解析不到会导致静默生成 0 篇
    local_root = str(Path(args.local_root).resolve())
    out_dir = Path(args.out_dir).resolve()
    targets_file = Path(args.targets).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # ---- 目标清单：缺失时从扫描汇总自动生成（闭环）----
    if not targets_file.exists():
        if args.scan_summary and Path(args.scan_summary).exists():
            from detector.targets import from_scan_summary
            rows = from_scan_summary(args.scan_summary)
            names = [r[0] for r in rows]
            if names:
                write_text(targets_file, "\n".join(names) + "\n")
                print(f"[flow] 目标清单缺失，已从扫描汇总自动生成 {len(names)} 个目标:")
                print(f"       {targets_file}")
        if not targets_file.exists():
            print(f"[错误] 目标清单不存在: {targets_file}")
            print("       生成方式: python -m detector.cli targets --from-scan-summary")
            print("                （或 --from-dir 枚举本地全部仓库）")
            return 1

    targets = load_targets(targets_file)
    if not targets:
        print(f"[错误] 目标清单为空或不存在: {targets_file}")
        return 1
    print(f"[flow] 目标数量: {len(targets)}  代码根: {local_root}  输出: {out_dir}")

    # ---- prereq: 本地 LLM ----
    if not args.no_ollama_check and not args.no_docgen:
        ensure_ollama(args.model)

    # ---- step 1: docgen ----
    if not args.no_docgen:
        missing = [t for t in targets
                   if not (out_dir / t / "generated_doc.md").exists()]
        if missing:
            print(f"[flow] 缺失文档 {len(missing)}/{len(targets)} 个，调用 docgen 补齐 ...")
            run_docgen(local_root, str(targets_file), str(out_dir), args.model)
        else:
            print("[step 1/4] docgen：全部目标已有文档，跳过")

    # ---- step 2: align ----
    scan_map = load_scan_summary(args.scan_summary) if args.scan_summary else {}
    print(f"\n[step 2/4] align：逐仓库计算语义对齐率（{len(targets)} 个）...")
    rows = []
    for i, repo in enumerate(targets, 1):
        repo_dir = Path(local_root) / repo
        align_json = out_dir / repo / "align_result.json"
        align_json.parent.mkdir(parents=True, exist_ok=True)

        if align_json.exists() and not args.force:
            res = read_json(align_json)
        else:
            if not repo_dir.is_dir():
                print(f"  [{i}/{len(targets)}] {repo}: 本地目录不存在，跳过")
                continue
            res = compute_alignment(repo_dir)
            write_json(align_json, res)
        if not isinstance(res, dict) or "verdict_signal" not in res:
            print(f"  [{i}/{len(targets)}] {repo}: 对齐结果损坏，跳过")
            continue

        scan = scan_map.get(normalize_repo_key(repo), {"crit": 0, "high": 0, "hits": 0})
        verdict = final_verdict(res["verdict_signal"], scan)
        rows.append({
            "repo": repo,
            "align_signal": res["verdict_signal"],
            "alignment_rate": res["alignment_rate"],
            "conflict_rate": res["conflict_rate"],
            "sec_conflict_rate": res["security_conflict_rate"],
            "hard_facts": res["has_hard_facts"],
            "languages": ",".join(res.get("_languages", [])),
            "scan_crit": scan["crit"],
            "scan_high": scan["high"],
            "scan_hits": scan["hits"],
            "final_verdict": verdict,
        })
        print(f"  [{i}/{len(targets)}] {repo}: align={res['verdict_signal']} "
              f"aln={res['alignment_rate']} conf={res['conflict_rate']} "
              f"sec={res['security_conflict_rate']} verdict={verdict}")

    # ---- step 3: verdict 汇总 ----
    print(f"\n[step 3/4] verdict：综合判定完成 {len(rows)}/{len(targets)}")

    # ---- step 4: 报告 ----
    csv_out = write_csv(out_dir / "flow_results.csv", rows, OUTPUT_FIELDS)
    sig = Counter(r["align_signal"] for r in rows)
    vd = Counter(r["final_verdict"] for r in rows)

    def _md_table(counter: Counter, head: str) -> str:
        lines = [f"### {head}", "", "| 取值 | 数量 |", "|---|---|"]
        lines += [f"| {k} | {v} |" for k, v in counter.most_common()]
        return "\n".join(lines)

    detail = ["| repo | 对齐信号 | 对齐率 | 矛盾率 | 安全矛盾率 | CRIT | HIGH | 判定 |",
              "|---|---|---|---|---|---|---|---|"]
    detail += [f"| {r['repo']} | {r['align_signal']} | {r['alignment_rate']} | "
               f"{r['conflict_rate']} | {r['sec_conflict_rate']} | {r['scan_crit']} | "
               f"{r['scan_high']} | {r['final_verdict']} |" for r in rows]

    report = "\n".join([
        "# MCP 投毒检测 · 一键跑完报告",
        "",
        f"- 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- 目标数: {len(targets)}，成功分析: {len(rows)}",
        f"- 模型: {args.model}",
        f"- 本地代码根: `{local_root}`",
        "",
        _md_table(sig, "对齐信号分布"),
        "",
        _md_table(vd, "最终判定分布"),
        "",
        "### 逐仓库明细",
        "",
        *detail,
        "",
    ])
    md_out = write_text(out_dir / "flow_report.md", report)

    print("\n[step 4/4] 报告已写入:")
    print(f"  明细 CSV : {csv_out}")
    print(f"  汇总报告 : {md_out}")
    print(f"\n=== 一键跑完完成：成功 {len(rows)}/{len(targets)} ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
