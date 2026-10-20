#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
最终规范化: files_scanned==0 且无命中却标 benign 的仓库 -> not_scanned (无代码即无审查依据)。
并打印最终 verdict 分布, 校验全部 JSON。

原理：若某仓库没有任何可扫描源码/文本文件，则不存在静态审查依据，
即便之前被标为 benign 也应降级为 not_scanned，保证判定口径一致。
"""
import json       # JSON 读写
from pathlib import Path  # 跨平台路径处理
from collections import Counter  # 统计分布

res_dir = Path(__file__).resolve().parent.parent.parent / "output" / "scan_results"  # 项目根/output/scan_results
normalized = []  # 被规范化（benign→not_scanned）的仓库列表
for f in sorted(res_dir.glob("*.json")):  # 遍历全部扫描 JSON
    if f.name.startswith("_"):  # 跳过汇总文件
        continue
    j = json.loads(f.read_text(encoding="utf-8"))  # 读取单仓库结果
    hits = j.get("hits", []) or []
    # 规范化条件：当前标 benign 但没扫到任何文件且无命中
    if j.get("verdict") == "benign" and j.get("files_scanned", 0) == 0 and not hits:
        j["verdict"] = "not_scanned"  # 无代码即无审查依据
        j["confidence"] = 0
        j["reason"] = "缓存目录无可用源码/文本文件（代码获取未成功或为空），无静态审查依据"
        normalized.append(j["repo"])
        f.write_text(json.dumps(j, ensure_ascii=False, indent=2), encoding="utf-8")  # 写回
    # 合法性校验：verdict 必须是四值之一
    assert j["verdict"] in ("benign", "suspicious", "malicious", "not_scanned"), f.name

vc = Counter()  # verdict 分布
fc = Counter()  # fetch_method 分布
for f in sorted(res_dir.glob("*.json")):
    if f.name.startswith("_"):
        continue
    j = json.loads(f.read_text(encoding="utf-8"))
    vc[j["verdict"]] += 1
    fc[j["fetch_method"]] += 1

print("normalized to not_scanned:", normalized)  # 列出被降级的仓库
print("verdict:", dict(vc))
print("fetch_method:", dict(fc))
total = sum(vc.values())
print("total:", total)
