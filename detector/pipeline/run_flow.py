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
  - 本地 Ollama 已装 qwen3-coder:30b（脚本会自动尝试拉起 ollama serve）
    地址可用 OLLAMA_HOST 环境变量覆盖，默认 http://localhost:11434
  - 目标仓库本地代码在 --local-root（其下为 <owner_repo> 文件夹）
    不传该参数时，取 detector/config.py 解析的 LARGE_REPO_SOURCE
    （默认项目内 mcp插件/，可用 MPV_LARGE_REPO_SOURCE 环境变量覆盖）
  - --scan-summary 提供静态扫描命中（CRITICAL/HIGH），用于综合判定

用法（Windows）：
  # 对 40 个可疑子集一键跑完（docgen 已完成后，主要走 align+verdict）
  python -m detector.pipeline.run_flow ^
      --targets  output\gen_docs_800_targets.txt ^
      --out-dir  output\gen_docs_800 ^
      --scan-summary output\scan_results_800_summary.csv ^
      --model qwen3-coder:30b

  # 对全量 800 跑（docgen 会按缺补跑，耗时长，可随时中断后重跑续跑）
  # --targets output\all_800_targets.txt

参数：
  --local-root    本地完整仓库根（其下为 <owner_repo> 文件夹）
  --targets       目标清单文件（每行一个 owner_repo，可含 # 注释）
  --out-dir       输出目录（doc 与 align json 都写这里）
  --scan-summary  静态扫描汇总 CSV（含 repo,CRITICAL,HIGH,hits），可为空
  --model         Ollama 模型名（默认 qwen3-coder:30b）
  --force         强制重算 align（默认跳过已算）
  --no-docgen     跳过 docgen（只做 align+verdict）
  --no-ollama-check  不检查/不自动拉起 Ollama
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

# 项目根（detector/pipeline 上三级）
ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "detector"))
sys.path.insert(0, str(ROOT / "detector" / "analyzer"))

from analyzer.align_rate import compute_alignment  # noqa: E402
from config import DEFAULT_MODEL  # noqa: E402

# 静态扫描的"严重"阈值（用于综合判定 tier）
CRIT_TIER_HIGH = 10      # CRITICAL >= 10 → 高
HIGH_TIER_HIGH = 50      # HIGH >= 50     → 高
CRIT_TIER_MED = 1        # CRITICAL >= 1  → 中
HIGH_TIER_MED = 5        # HIGH >= 5      → 中


def ensure_ollama(model: str) -> bool:
    """检查本地 Ollama 是否可用且含指定模型；不可用则尝试自动拉起。"""
    import requests
    from config import OLLAMA_HOST
    url = f"{OLLAMA_HOST}/api/tags"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            names = [m.get("name") for m in r.json().get("models", [])]
            if model in names:
                print(f"[prereq] Ollama 就绪，模型 {model} 可用")
                return True
            print(f"[prereq] Ollama 在跑，但模型 {model} 未拉取。请先: ollama pull {model}")
            return False
    except Exception:
        pass
    # Ollama 未起 → 尝试自动启动（Windows: ollama serve）
    print("[prereq] Ollama 未运行，尝试自动启动 ollama serve ...")
    # 依次探测，避免依赖具体用户名/安装盘符
    candidates = []
    from_path = shutil.which("ollama")
    if from_path:
        candidates.append(from_path)
    candidates += [
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Ollama", "ollama.exe"),
        os.path.join(os.environ.get("ProgramFiles", ""), "Ollama", "ollama.exe"),
        os.path.join(os.environ.get("ProgramFiles(x86)", ""), "Ollama", "ollama.exe"),
    ]
    exe = next((c for c in candidates if os.path.isfile(c)), None)
    if exe:
        subprocess.Popen([exe, "serve"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        for _ in range(12):
            time.sleep(2)
            try:
                if requests.get(url, timeout=2).status_code == 200:
                    print("[prereq] Ollama 已自动启动")
                    return True
            except Exception:
                continue
        print("[prereq] Ollama 启动超时，请手动启动后重试")
        return False
    print("[prereq] 未找到 ollama.exe，请手动启动 Ollama")
    return False


def run_docgen(local_root, targets_file, out_dir, model):
    """批量 docgen（本地代码模式），已存在的跳过，断点续跑。"""
    print("\n[step 1/4] docgen：生成缺失的语义文档 ...")
    cmd = [sys.executable, "-m", "analyzer.docgen",
           "--local-root", local_root,
           "--repo-list", targets_file,
           "--out-dir", out_dir,
           "--model", model,
           "--delay", "0"]
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    try:
        subprocess.run(cmd, cwd=str(ROOT / "detector"), env=env, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[step 1/4] docgen 退出码 {e.returncode}，继续后续步骤（已有文档不受影响）")


def load_targets(path):
    if not path or not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out


def load_scan_summary(path):
    """读取扫描汇总 CSV → {owner_repo: (crit, high, hits)}"""
    if not path or not os.path.exists(path):
        return {}
    import csv
    data = {}
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            repo = row.get("repo", "").strip()
            if not repo:
                continue
            data[repo] = {
                "crit": int(row.get("CRITICAL") or 0),
                "high": int(row.get("HIGH") or 0),
                "hits": int(row.get("hits") or 0),
            }
    return data


def final_verdict(align_signal, scan):
    """综合 align 信号 + 静态扫描命中，给最终判定档位。"""
    crit = scan.get("crit", 0)
    high = scan.get("high", 0)
    if align_signal == "DANGER" or crit >= CRIT_TIER_HIGH or high >= HIGH_TIER_HIGH:
        return "HIGH_RISK_REVIEW"
    if align_signal == "WARN" or crit >= CRIT_TIER_MED or high >= HIGH_TIER_MED:
        return "REVIEW"
    return "LOW"


def main():
    ap = argparse.ArgumentParser(description="MPV-Detector 一键跑完编排器")
    ap.add_argument("--local-root", default="",
                    help="本地完整仓库根（默认取 config.LARGE_REPO_SOURCE，"
                         "可用 MPV_LARGE_REPO_SOURCE 环境变量覆盖）")
    ap.add_argument("--targets", required=True, help="目标清单文件")
    ap.add_argument("--out-dir", required=True, help="输出目录")
    ap.add_argument("--scan-summary", default="", help="扫描汇总 CSV")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--force", action="store_true", help="强制重算 align")
    ap.add_argument("--no-docgen", action="store_true", help="跳过 docgen")
    ap.add_argument("--no-ollama-check", action="store_true")
    args = ap.parse_args()

    if not args.local_root:
        from config import LARGE_REPO_SOURCE
        args.local_root = str(LARGE_REPO_SOURCE)
    local_root = args.local_root
    out_dir = args.out_dir
    os.makedirs(out_dir, exist_ok=True)

    targets = load_targets(args.targets)
    if not targets:
        print("[错误] 目标清单为空或不存在")
        return 1
    print(f"[flow] 目标数量: {len(targets)}")

    # ---- prereq ----
    if not args.no_ollama_check and not args.no_docgen:
        ensure_ollama(args.model)

    # ---- step 1: docgen ----
    if not args.no_docgen:
        missing = [t for t in targets
                   if not os.path.exists(os.path.join(out_dir, t, "generated_doc.md"))]
        if missing:
            print(f"[flow] 缺失文档 {len(missing)}/{len(targets)} 个，调用 docgen 补齐 ...")
            run_docgen(local_root, args.targets, out_dir, args.model)
        else:
            print("[step 1/4] docgen：全部目标已有文档，跳过")

    # ---- step 2: align ----
    scan_map = load_scan_summary(args.scan_summary)
    print(f"\n[step 2/4] align：逐仓库计算语义对齐率（{len(targets)} 个）...")
    rows = []
    for i, repo in enumerate(targets, 1):
        repo_dir = os.path.join(local_root, repo)
        align_json = os.path.join(out_dir, repo, "align_result.json")
        os.makedirs(os.path.dirname(align_json), exist_ok=True)

        if os.path.exists(align_json) and not args.force:
            with open(align_json, "r", encoding="utf-8") as f:
                res = json.load(f)
        else:
            if not os.path.isdir(repo_dir):
                print(f"  [{i}/{len(targets)}] {repo}: 本地目录不存在，跳过")
                continue
            res = compute_alignment(Path(repo_dir))
            with open(align_json, "w", encoding="utf-8") as f:
                json.dump(res, f, ensure_ascii=False, indent=2)

        scan = scan_map.get(repo, {"crit": 0, "high": 0, "hits": 0})
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
        flag = "DANGER" if res["verdict_signal"] == "DANGER" else ""
        print(f"  [{i}/{len(targets)}] {repo}: align={res['verdict_signal']} "
              f"aln={res['alignment_rate']} conf={res['conflict_rate']} "
              f"sec={res['security_conflict_rate']} verdict={verdict} {flag}")

    # ---- step 3: verdict 汇总 ----
    print(f"\n[step 3/4] verdict：综合判定完成 {len(rows)}/{len(targets)}")

    # ---- step 4: 报告 ----
    csv_out = os.path.join(out_dir, "flow_results.csv")
    import csv as _csv
    with open(csv_out, "w", encoding="utf-8-sig", newline="") as f:
        w = _csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else [
            "repo", "align_signal", "alignment_rate", "conflict_rate", "sec_conflict_rate",
            "hard_facts", "languages", "scan_crit", "scan_high", "scan_hits", "final_verdict"])
        w.writeheader()
        for r in rows:
            w.writerow(r)

    md_out = os.path.join(out_dir, "flow_report.md")
    with open(md_out, "w", encoding="utf-8") as f:
        f.write(f"# MCP 投毒检测 · 一键跑完报告\n\n")
        f.write(f"- 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- 目标数: {len(targets)}，成功分析: {len(rows)}\n")
        f.write(f"- 模型: {args.model}\n")
        f.write(f"- 本地代码根: `{local_root}`\n\n")
        from collections import Counter
        sig = Counter(r["align_signal"] for r in rows)
        vd = Counter(r["final_verdict"] for r in rows)
        f.write(f"### 对齐信号分布\n\n| 信号 | 数量 |\n|---|---|\n")
        for k, v in sig.most_common():
            f.write(f"| {k} | {v} |\n")
        f.write(f"\n### 最终判定分布\n\n| 判定 | 数量 |\n|---|---|\n")
        for k, v in vd.most_common():
            f.write(f"| {k} | {v} |\n")
        f.write(f"\n### 逐仓库明细\n\n| repo | 对齐信号 | 对齐率 | 矛盾率 | 安全矛盾率 | CRIT | HIGH | 判定 |\n|---|---|---|---|---|---|---|---|\n")
        for r in rows:
            f.write(f"| {r['repo']} | {r['align_signal']} | {r['alignment_rate']} | "
                    f"{r['conflict_rate']} | {r['sec_conflict_rate']} | {r['scan_crit']} | "
                    f"{r['scan_high']} | {r['final_verdict']} |\n")

    print("\n[step 4/4] 报告已写入:")
    print(f"  明细 CSV : {csv_out}")
    print(f"  汇总报告 : {md_out}")
    print(f"\n=== 一键跑完完成：成功 {len(rows)}/{len(targets)} ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
