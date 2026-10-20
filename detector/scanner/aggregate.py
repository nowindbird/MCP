#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
汇总 102 仓库扫描结果: 生成 output/scan_summary.csv 并打印报告所需统计。
依赖: output/scan_results/*.json (每仓库一个, verdict 已由语义审查写回)。
"""
import csv, json          # csv 写汇总表 / json 读扫描结果
from pathlib import Path  # 跨平台路径处理

BASE = Path(__file__).resolve().parent.parent.parent  # 项目根（detector/scanner 上两级）
OUT = BASE / "output"      # output 目录
res_dir = OUT / "scan_results"  # 每仓库扫描 JSON 目录

# 严重性排序权重（值越小越严重），用于计算 top_severity 与最终排序
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

def top_severity(hits):
    """返回一个仓库所有命中中最严重的等级（CRITICAL 优先）。

    遍历 hits，取 SEV_ORDER 权重最小的等级作为该仓库的 top_severity；
    无命中时返回 "NONE"。
    """
    sev = "NONE"
    for h in hits:
        s = h.get("severity", "MEDIUM")
        if SEV_ORDER.get(s, 9) < SEV_ORDER.get(sev, 9):  # 找到更严重的
            sev = s
    return sev

rows = []  # 汇总行列表
files = sorted(res_dir.glob("*.json"))  # 遍历全部扫描 JSON（按文件名排序）
for f in files:
    if f.name.startswith("_"):  # 跳过 _shard_summary 等汇总文件
        continue
    j = json.loads(f.read_text(encoding="utf-8"))  # 读取单仓库扫描结果
    hits = j.get("hits", []) or []  # 命中列表（容错空值）
    # 提取汇总所需字段
    rows.append({
        "repo": j["repo"],                        # 仓库 full_name
        "language": j.get("language", ""),        # 主要语言
        "size_kb": j.get("size_kb", 0),           # 仓库大小（KB）
        "stars": j.get("stars", 0),               # star 数
        "fetch_method": j.get("fetch_method", ""),# 获取方式（clone/api_selective/tarball）
        "fetch_ok": j.get("fetch_ok", False),     # 是否成功获取
        "files_scanned": j.get("files_scanned", 0), # 扫描文件数
        "hit_count": len(hits),                   # 静态命中总数
        "top_severity": top_severity(hits),       # 最严重等级
        "verdict": j.get("verdict", "unknown"),   # 判定：benign/suspicious/malicious/not_scanned
        "confidence": j.get("confidence", 0),     # 判定置信度 1-3
        "shadow_features_count": len(j.get("shadow_features", []) or []), # 隐藏行为观察项数
        "reason": (j.get("reason", "") or "").replace("\n", " ")[:200],   # 判定理由（单行截断）
    })

# 排序：先按 verdict（malicious>suspicious>benign>not_scanned>其他），再按 top_severity
rows.sort(key=lambda r: ({"malicious":0,"suspicious":1,"benign":2,"not_scanned":3}.get(r["verdict"],4),
                          SEV_ORDER.get(r["top_severity"], 9)))

# 写 scan_summary.csv（utf-8-sig 带 BOM，方便 Excel 打开）
with open(OUT / "scan_summary.csv", "w", newline="", encoding="utf-8-sig") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
    w.writeheader()      # 表头
    w.writerows(rows)    # 数据行

# 统计输出（供报告使用）
from collections import Counter
vc = Counter(r["verdict"] for r in rows)   # verdict 分布
sev = Counter(r["top_severity"] for r in rows if r["verdict"] not in ("not_scanned",))  # 已扫描仓库的严重性分布
fm = Counter(r["fetch_method"] for r in rows)  # 获取方式分布
print(f"total repos: {len(rows)}")
print("verdict:", dict(vc))
print("top_severity (scanned only):", dict(sev))
print("fetch_method:", dict(fm))
print("scanned files total:", sum(r["files_scanned"] for r in rows))
print("hits total:", sum(r["hit_count"] for r in rows))
print("shadow_features repos:", sum(1 for r in rows if r["shadow_features_count"] > 0))
print("\nsuspicious/malicious:")
for r in rows:
    if r["verdict"] in ("suspicious", "malicious"):  # 列出嫌疑/恶意仓库明细
        print(f"  [{r['verdict']}] {r['repo']} conf={r['confidence']} hits={r['hit_count']} top={r['top_severity']} | {r['reason'][:120]}")
print("\nwrote", OUT / "scan_summary.csv")
