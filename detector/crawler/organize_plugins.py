#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
将抓取到的 MCP 插件逐个存入 mcp插件 文件夹，并生成路径清单。
每个插件一个子文件夹，内含 info.json（元数据）。
"""

import json       # JSON 读写（元数据 / 清单）
import os         # 目录与路径操作
import re         # 文件名安全化正则
import sys
from pathlib import Path

# 路径配置（项目根 = detector/crawler 上两级）
BASE_DIR = str(Path(__file__).resolve().parent.parent.parent)
# 抓取结果源文件（注意：文件名带时间戳，重新抓取后需同步更新）
SRC_JSON = os.path.join(BASE_DIR, "output", "mcp_repos_20260927_205656.json")
PLUGIN_DIR = os.path.join(BASE_DIR, "mcp插件")  # 插件落盘根目录


def safe_folder_name(full_name: str) -> str:
    """将 owner/repo 转为安全的文件夹名 owner_repo。

    把 Windows/文件系统不允许出现在路径中的字符（< > : " / \ | ? *）替换为下划线。
    """
    return re.sub(r'[<>:"/\\|?*]', '_', full_name)


def main():
    # 读取抓取结果 JSON（列表）
    with open(SRC_JSON, "r", encoding="utf-8") as f:
        repos = json.load(f)

    print(f"共读取 {len(repos)} 个 MCP 插件")

    # 确保 mcp插件 目录存在
    os.makedirs(PLUGIN_DIR, exist_ok=True)

    # 路径清单（后续写入 JSON / Markdown）
    path_list = []

    for idx, repo in enumerate(repos, 1):  # 遍历每个插件
        full_name = repo.get("full_name", f"unknown_{idx}")  # 仓库 full_name
        folder_name = safe_folder_name(full_name)            # 安全文件夹名
        plugin_path = os.path.join(PLUGIN_DIR, folder_name)  # 插件子目录

        # 创建插件子文件夹
        os.makedirs(plugin_path, exist_ok=True)

        # 写入元数据 info.json
        info_path = os.path.join(plugin_path, "info.json")
        with open(info_path, "w", encoding="utf-8") as f:
            json.dump(repo, f, ensure_ascii=False, indent=2)

        # 记录路径信息
        path_list.append({
            "index": idx,
            "full_name": full_name,
            "stars": repo.get("stars", 0),
            "language": repo.get("language", ""),
            "storage_path": plugin_path,
            "info_file": info_path,
            "html_url": repo.get("html_url", ""),
        })

        if idx % 20 == 0 or idx == len(repos):  # 每 20 个或最后一个打印进度
            print(f"  已处理 {idx}/{len(repos)}")

    # 生成路径清单 JSON
    index_json_path = os.path.join(PLUGIN_DIR, "插件路径清单.json")
    with open(index_json_path, "w", encoding="utf-8") as f:
        json.dump({
            "total": len(path_list),
            "generated_at": __import__("datetime").datetime.now().isoformat(),
            "plugins": path_list,
        }, f, ensure_ascii=False, indent=2)
    print(f"\n路径清单 JSON -> {index_json_path}")

    # 生成路径清单 Markdown（表格）
    index_md_path = os.path.join(PLUGIN_DIR, "插件路径清单.md")
    with open(index_md_path, "w", encoding="utf-8") as f:
        f.write("# MCP 插件存储路径清单\n\n")
        f.write(f"> 共 {len(path_list)} 个插件，按 Star 数降序排列\n\n")
        f.write("| 序号 | 插件名称 | Star | 语言 | 存储路径 |\n")
        f.write("|------|---------|------|------|----------|\n")
        for p in path_list:
            f.write(f"| {p['index']} | {p['full_name']} | {p['stars']} | "
                    f"{p['language'] or 'N/A'} | `{p['storage_path']}` |\n")
    print(f"路径清单 MD  -> {index_md_path}")

    # 删除之前的旧文件（抓取文件路径.md）
    old_file = os.path.join(PLUGIN_DIR, "抓取文件路径.md")
    if os.path.exists(old_file):
        os.remove(old_file)
        print(f"已删除旧文件: {old_file}")

    print(f"\n完成！{len(path_list)} 个插件已存入 {PLUGIN_DIR}")


if __name__ == "__main__":
    main()  # 程序入口
