#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
报告统计: 模式命中分布 / shadow_features 明细 / not_scanned 清单 / 严重性分布。
供撰写检测报告时直接读取统计结果。
"""
import json       # JSON 读取
from pathlib import Path  # 跨平台路径处理
from collections import Counter  # 统计分布

res_dir = Path(__file__).resolve().parent.parent.parent / "output" / "scan_results"  # 项目根/output/scan_results
pat = Counter()   # 模式命中分布（按 pattern_id）
sev = Counter()   # 严重性分布
shadow = []       # 含 shadow_features 的仓库及明细
notscanned = []   # not_scanned 仓库清单（含 reason）
benign_with_crit = 0  # （预留）有 CRITICAL 命中但判 benign 的计数
total_hits = 0    # 已扫描仓库命中总数
for f in sorted(res_dir.glob("*.json")):  # 遍历全部扫描 JSON
    if f.name.startswith("_"):  # 跳过汇总文件
        continue
    j = json.loads(f.read_text(encoding="utf-8"))
    if j.get("verdict") == "not_scanned":  # 未扫描仓库单独收集，不进命中统计
        notscanned.append((j["repo"], j.get("reason", "")[:80]))
        continue
    for h in j.get("hits", []):  # 累计每个命中的模式与严重性
        pat[h["pattern_id"]] += 1
        sev[h.get("severity", "?")] += 1
        total_hits += 1
    if j.get("shadow_features"):  # 记录含隐藏行为观察项的仓库
        shadow.append((j["repo"], j["shadow_features"]))

print("=== pattern distribution (hits) ===")
for k, v in pat.most_common():  # 按命中数降序输出各模式命中
    print(f"  {k}: {v}")
print("=== severity distribution ===")
for k, v in sev.most_common():  # 按命中数降序输出各严重性
    print(f"  {k}: {v}")
print(f"total hits (scanned repos): {total_hits}")
print("\n=== shadow_features repos ===")
for r, s in shadow:  # 输出隐藏行为明细
    print(f"  {r}:")
    for x in s:
        print(f"    - {x}")
print("\n=== not_scanned (27) ===")
for r, reason in notscanned:  # 输出未扫描仓库清单
    print(f"  {r} | {reason[:60]}")
