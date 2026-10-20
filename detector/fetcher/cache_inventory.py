#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
缓存盘点: 对照 shard1-4.csv 检查每个仓库的 cache_dir 是否已落盘。
输出: 控制台状态表 + output/cache_inventory.json
用于在扫描前确认哪些仓库代码已成功获取（present），哪些缺失（需补拉）。
"""
import csv, json, os, sys  # csv 读分片清单 / json 写盘点结果 / os 目录遍历
from pathlib import Path   # 跨平台路径处理

BASE = Path(__file__).resolve().parent.parent.parent  # 项目根（detector/fetcher 上两级）
OUT = BASE / "output"  # output 目录

rows = []  # 合并 4 个分片清单的行
for i in range(1, 5):  # 遍历 shard1.csv ~ shard4.csv
    with open(OUT / f"shard{i}.csv", "r", encoding="utf-8-sig") as fh:
        rows.extend(csv.DictReader(fh))  # 累加各分片的仓库行

inv = []  # 盘点结果列表
for r in rows:
    cache = Path(r["cache_dir"])  # 该仓库的缓存目录
    nfiles = 0  # 缓存内文件数
    if cache.exists() and cache.is_dir():  # 目录存在才统计
        try:
            nfiles = sum(len(fs) for _, _, fs in os.walk(str(cache)))  # 递归统计文件数
        except Exception:
            nfiles = -1  # 统计出错标记 -1
    inv.append({
        "full_name": r["full_name"],  # 仓库 full_name
        "shard": r["full_name"].split("/")[0][0] if False else None,  # 占位字段（恒 None）
        "fetch_method": r["fetch_method"],  # 获取方式
        "size_kb": int(r["size_kb"]),       # 仓库大小（KB）
        "stars": int(r["stars"]),           # star 数
        "language": r["language"],          # 语言
        "cache_dir": str(cache),            # 缓存绝对路径
        "files": nfiles,                    # 落盘文件数
        "present": nfiles > 0,              # 是否已成功落盘（文件数>0）
    })

total_present = sum(1 for x in inv if x["present"])   # 已落盘仓库数
total_files = sum(x["files"] for x in inv if x["present"])  # 已落盘文件总数
print(f"repos total={len(inv)} present={total_present} missing={len(inv)-total_present} total_files={total_files}")
print("\n--- missing/empty ---")  # 列出缺失/空目录的仓库
for x in inv:
    if not x["present"]:
        print(f"  {x['full_name']:<50} {x['fetch_method']}")
print("\n--- present with low file count (<20) ---")  # 列出文件数过少（覆盖受限）的仓库
for x in inv:
    if 0 < x["files"] < 20:
        print(f"  {x['full_name']:<50} files={x['files']}")

# 写盘点结果 JSON
with open(OUT / "cache_inventory.json", "w", encoding="utf-8") as fh:
    json.dump(inv, fh, ensure_ascii=False, indent=1)
print("\nwrote output/cache_inventory.json")
